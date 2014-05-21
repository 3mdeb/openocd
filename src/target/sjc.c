/***************************************************************************
 *   Copyright (C) 2014 Roy Spliet <rspliet@mpi-sws.org>                   *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <helper/log.h>
#include <jtag/jtag.h>
#include <inttypes.h>
#include "target.h"
#include "register.h"
#include "target_request.h"
#include "target_type.h"

#define SJC_SEC_TAP_SELECT 0x7
#define SJC_SEC_CHALLENGE 0xc
#define SJC_SEC_RESPONSE 0xd

/* For given file containing Challenge Response pairs, find the right
 * response for requested challenge
 *
 * File contains only lines <challenge> <response>, both in hexadecimal format
 */
static int64_t
sjc_db_find(const char *file, uint64_t challenge)
{
	uint64_t entry_chal;
	int64_t entry_resp, response = ERROR_COMMAND_NOTFOUND;

	FILE *fp;

	fp = fopen(file, "r");
	if (!fp)
		return ERROR_COMMAND_ARGUMENT_INVALID;

	while (fscanf(fp, "%"SCNx64" %"SCNx64"\n",
			&entry_chal, &entry_resp) == 2){
		if (challenge == entry_chal) {
			if (entry_resp < 0 || entry_resp > 0xffffffffffffff)
				response = ERROR_COMMAND_ARGUMENT_OVERFLOW;
			else
				response = entry_resp;

			break;
		}
	}

	fclose(fp);

	return response;
}

/**
 * Authenticate with SJC: request challenge, send response from "database"
 */
static COMMAND_HELPER(sjc_auth, struct jtag_tap *tap, const char *file)
{
	struct scan_field ir_fields[1];
	struct scan_field out_fields[2];
	int retval = ERROR_OK;
	uint8_t sjccmd = SJC_SEC_CHALLENGE;
	uint64_t sjcid = 0;
	int64_t sjcres = 0;

	/* Prepare for fetching challenge */
	ir_fields[0].num_bits = 5;
	ir_fields[0].in_value = NULL;
	ir_fields[0].out_value = &sjccmd;

	out_fields[0].num_bits = 32;
	out_fields[0].out_value = NULL;
	out_fields[0].in_value = (uint8_t *)&sjcid;
	out_fields[1].num_bits = 24;
	out_fields[1].out_value = NULL;
	out_fields[1].in_value = ((uint8_t *)&sjcid)+4;

	jtag_add_ir_scan(tap, &ir_fields[0], TAP_IDLE);
	jtag_add_dr_scan(tap, 2, &out_fields[0], TAP_IDLE);
	jtag_execute_queue();

	command_print(CMD_CTX, "SJC  : Using database %s", file);
	command_print(CMD_CTX, "SJC  : Challenge 0x%014"PRIx64, sjcid);

	if (sjcid == 0) {
		command_print(CMD_CTX,
				"SJC  : Invalid Challenge, not authenticating");
		return retval;
	}

	/*
	 * Find the response in the text file.
	 * If not found, abort authentication
	 */
	sjcres = sjc_db_find(file, sjcid);
	if (sjcres == ERROR_COMMAND_NOTFOUND) {
		command_print(CMD_CTX,
			"SJC  : Device not in database, not authenticating");
		return retval;
	} else if (sjcres == ERROR_COMMAND_ARGUMENT_INVALID) {
		command_print(CMD_CTX,
			"SJC  : Database not found, not authenticating");
		return retval;
	} else if (sjcres == ERROR_COMMAND_ARGUMENT_OVERFLOW) {
		command_print(CMD_CTX,
			"SJC  : Response value too large, not authenticating");
		return retval;
	}

	command_print(CMD_CTX, "SJC  : Response  0x%014"PRIx64, sjcres);

	/* Authenticate */
	sjccmd = SJC_SEC_RESPONSE;
	out_fields[0].out_value = (uint8_t *)&sjcres;
	out_fields[0].in_value = NULL;
	out_fields[1].out_value = ((uint8_t *)&sjcres)+4;
	out_fields[1].in_value = NULL;

	jtag_add_ir_scan(tap, &ir_fields[0], TAP_IDLE);
	jtag_add_dr_scan(tap, 2, &out_fields[0], TAP_IDLE);
	jtag_execute_queue();

	return ERROR_OK;
}

/**
 * Enable SDMA through SJC
 */
static COMMAND_HELPER(sjc_enable_sdma, struct jtag_tap *tap)
{
	struct scan_field ir_fields[1];
	struct scan_field out_fields[1];
	uint8_t sjccmd = SJC_SEC_TAP_SELECT;
	uint8_t sjcdata = 1;

	ir_fields[0].num_bits = 5;
	ir_fields[0].in_value = NULL;
	ir_fields[0].out_value = &sjccmd;

	out_fields[0].num_bits = 1;
	out_fields[0].out_value = &sjcdata;
	out_fields[0].in_value = NULL;

	jtag_add_ir_scan(tap, &ir_fields[0], TAP_IDLE);
	jtag_add_dr_scan(tap, 2, &out_fields[0], TAP_IDLE);
	jtag_add_tms_seq(1, 0, TAP_IDLE);
	jtag_execute_queue();

	return ERROR_OK;
}

/**
 * Put the full scan chain in IDMODE, pull them all out of bypass
 * required for scan chain interrogation;
 */
int
sjc_scan_chain_set(struct jtag_tap *sjc)
{
	struct jtag_tap *tap = NULL;
	int chain_len = 0;
	uint64_t value = 0;

	while ((tap = jtag_tap_next_enabled(tap)) != NULL) {
		/*
		 * This is kind of a hack.
		 * - ARM CoreSight JTAG controller has IDMODE cmd 0xe
		 * - the SDMA doesn't have IDMODE but 0xe is reserved and BYPASS
		 * - the SJC has IDMODE cmd 0x0
		 * For I.MX6 this works, but not sure about others...
		 */
		if (tap != sjc)
			value |= (0xe << chain_len);

		chain_len += tap->ir_length;
		tap->bypass = 0;
	}

	jtag_add_plain_ir_scan(chain_len, (uint8_t *)&value, NULL, TAP_IDLE);
	jtag_execute_queue();

	return ERROR_OK;
}

static COMMAND_HELPER(sjc_auth_args, const char **file, const char **name)
{
	/* Defaults */
	*file = "tcl/target/imx6_sjcauth.txt";
	*name = "imx6.sjc";

	if (CMD_ARGC > 2)
		return ERROR_COMMAND_SYNTAX_ERROR;
	switch (CMD_ARGC) {
	case 2:
		*file = CMD_ARGV[1];
		/* no break */
	case 1:
		*name = CMD_ARGV[0];
		/* no break */
	default:
		break;
	}

	return ERROR_OK;
}

COMMAND_HANDLER(sjc_init)
{
	const char *file, *name;
	struct jtag_tap *tap;

	int retval = CALL_COMMAND_HANDLER(sjc_auth_args, &file, &name);
	if (ERROR_OK == retval) {
		tap = jtag_tap_by_string(name);
		if (tap == NULL) {
			command_print(CMD_CTX, "SJC not found");
			return ERROR_COMMAND_NOTFOUND;
		}

		CALL_COMMAND_HANDLER(sjc_auth, tap, file);
		CALL_COMMAND_HANDLER(sjc_enable_sdma, tap);
		sjc_scan_chain_set(tap);

	}
	return retval;
}

static int
sjc_target_init(struct command_context *cmd_ctx, struct target *target)
{
	return ERROR_OK;
}

static int
sjc_target_poll(struct target *target)
{
	return ERROR_OK;
}

static const struct command_registration sjc_cmd[] = {
	{
		.name = "sjc_init",
		.handler = sjc_init,
		.mode = COMMAND_EXEC,
		.help = "Initialise (authenticate) SJC",
		.usage = "[name][database]",
	},
	COMMAND_REGISTRATION_DONE
};

static int sjc_target_create(struct target *target, Jim_Interp *interp)
{
	return ERROR_OK;
}

struct target_type sjc_target = {
	.name = "sjc",
	.deprecated_name = "sjc",

	.poll = sjc_target_poll,

	.commands = sjc_cmd,
	.target_create = sjc_target_create,
	.init_target = sjc_target_init,
	.examine = NULL,
};
