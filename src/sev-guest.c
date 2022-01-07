/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#ifndef PROG_NAME
#define PROG_NAME	"sev-guest"
#endif

#define MIN_NR_ARGS	(2)
#define CMD_INDEX	(1)

#define ARRAY_SIZE(x)	(sizeof(x)/sizeof(x[0]))

void print_usage(void)
{
	fprintf(stderr, "Usage: " PROG_NAME " command [args...]\n"
		"\n"
		"commands:\n"
		"    get-report:   Retrieve the attestation report from \n"
		"                  the firmware.\n"
		"    parse-report: Print select fields from the attestation report.\n"
		"    kdf:          Request a key from the firmware optionally derived\n"
		"                  from guest key material.\n"
		"\n");
}

int main(int argc, char *argv[])
{
	int rc = EXIT_FAILURE;
	const char *command = NULL;

	struct entry {
		const char *command;
		char *exec_name;
	} commands[] = {
		{ "get-report",   PROG_NAME "-get-report"   },
		{ "parse-report", PROG_NAME "-parse-report" },
		{ "kdf",          PROG_NAME "-kdf" },
	};

	if (argc < MIN_NR_ARGS) {
		fprintf(stderr, PROG_NAME ": no command specified.\n\n");
		print_usage();
		rc = -EINVAL;
		goto exit;
	}

	command = argv[CMD_INDEX];

	for (size_t i = 0; i < ARRAY_SIZE(commands); i++) {
		/*
		 * strlen() is safe here, because the command name is
		 * initialized from a static string that is guaranteed to be
		 * null-terminated.
		 */
		if (!strncmp(command, commands[i].command, strlen(commands[i].command))) {
			char **args = argv + CMD_INDEX;
			args[0] = commands[i].exec_name;
			errno = 0;
			execvp(commands[i].exec_name, args);

			/* If exec returned, then an error occured */
			rc = errno;
			perror("execlp");
			goto exit;
		}
	}

	/* If we made it here, then the requested command is not supported */
	rc = EOPNOTSUPP;
	fprintf(stderr, PROG_NAME ": unsupported command.\n");
	print_usage();
exit:
	exit(rc);
}

