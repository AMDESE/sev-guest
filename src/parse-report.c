/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <attestation.h>
#include <report.h>

#ifndef PROG_NAME
#define PROG_NAME	"sev-guest-parse-report"
#endif

#define NR_ARGS_REQUIRED	(2)

union operations {
	struct {
		bool print_data  : 1;
		bool print_help : 1;
		bool print_tcb : 1;
	};
	uint64_t raw;
};

void print_usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME " [-d|--data] [-t|--tcb] report_file\n"
		"\n"
		"  report_file: the attestation report.\n"
		"\n"
		"Print the attestation report in full, or only select fields indicated\n"
		"by command-line options.\n"
		"\n"
		"options:\n"
		"  -d|--data\n"
		"    Print the guest data in hex.\n"
		"\n"
		"  -h|--help\n"
		"    Print this help message.\n"
		"\n"
		"  -t|--tcb\n"
		"    Print the TCB string needed to derive the VCEK.\n"
		"\n");
}

int parse_options(int argc, char *argv[], union operations *ops, char **report_filename)
{
	int rc = EXIT_FAILURE;
	char *short_options = "dth";
	struct option long_options[] = {
		{ "data", no_argument, NULL, 'd' },
		{ "tcb",  no_argument, NULL, 't' },
		{ "help", no_argument, NULL, 'h' },
		{ 0 },
	};

	if (argc < NR_ARGS_REQUIRED) {
		rc = EINVAL;
		goto out;
	}

	*report_filename = NULL;

	do {
		char option = getopt_long(argc, argv,
					  short_options, long_options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'd':
			ops->print_data = true;
			break;
		case 't':
			ops->print_tcb = true;
			break;
		case 'h':
			ops->print_help = true;
			break;
		case ':':
		case '?':
		default:
			putchar('\n');
			rc = EINVAL;
			goto out;
		}
	} while (1);

	if (optind < argc) {
		*report_filename = argv[optind];
		optind++;
	}

	if (optind < argc) {
		fprintf(stderr, PROG_NAME ": too many arguments.\n\n");
		rc = EINVAL;
		goto out;
	}

	rc = EXIT_SUCCESS;
out:
	return rc;
}

int main(int argc, char *argv[])
{
	int rc = EXIT_FAILURE;
	union operations ops = { .raw = 0 };
	char *report_filename = NULL;
	FILE *report_file = NULL;
	struct attestation_report report;

	/* Initialize data structures */
	memset(&report, 0, sizeof(report));

	/* Parse command line options */
	rc = parse_options(argc, argv, &ops, &report_filename);
	if (rc != EXIT_SUCCESS || ops.print_help) {
		print_usage();
		goto exit;
	}

	/* Open the input report file */
	errno = 0;
	report_file = fopen(report_filename, "r");
	if (!report_file) {
		rc = errno;
		perror("fopen");
		goto exit;
	}

	/* Read the report into memory */
	errno = 0;
	int count = fread(&report, sizeof(char), sizeof(report), report_file);
	if (count != sizeof(report)) {
		fprintf(stderr, "fread() failed.\n");
		rc = EIO;
		goto exit_close_report;
	}

	if (ops.print_data) {
		print_report_data(&report);
	}

	if (ops.print_tcb) {
		print_reported_tcb(&report);
	}

	/* TODO: If no operations were requested, just print the report */

exit_close_report:
	if (report_file) {
		fclose(report_file);
		report_file = NULL;
	}

exit:
	exit(rc);
}

