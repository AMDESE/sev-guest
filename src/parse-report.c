/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <attestation.h>
#include <report.h>

#ifndef PROG_NAME
#define PROG_NAME	"sev-guest-parse-report"
#endif

#define NR_ARGS_REQUIRED	(2)

union operations {
	struct {
		bool print_tcb  : 1;
		bool export_key : 1;
	};
	uint64_t raw;
};

void print_usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME " [-k|--key key_file] [-t|--tcb] report_file\n"
		"\n"
		"  key_file:    output file for the SSH key included in the report.\n"
		"  report_file: the attestation report.\n"
		"\n"
		"Print the attestation report in full, or only select fields indicated\n"
		"by command-line options.\n"
		"\n");
}

int parse_options(int argc, char *argv[], union operations *ops,
		  char **key_filename, char **report_filename)
{
	int rc = EXIT_FAILURE;
	char *short_options = "k:t";
	struct option long_options[] = {
		{ "key",  no_argument,       NULL, 'k' },
		{ "tcb",  no_argument,       NULL, 't' },
		{ 0 },
	};

	if (argc < NR_ARGS_REQUIRED) {
		rc = EINVAL;
		goto out;
	}

	*key_filename = NULL;
	*report_filename = NULL;

	do {
		char option = getopt_long(argc, argv,
					  short_options, long_options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'k':
			ops->export_key = true;
			*key_filename = optarg;
			break;
		case 't':
			ops->print_tcb = true;
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
	char *key_filename = NULL, *report_filename = NULL;
	FILE *key_file = NULL, *report_file = NULL;
	struct attestation_report report;

	/* Initialize data structures */
	memset(&report, 0, sizeof(report));

	/* Parse command line options */
	rc = parse_options(argc, argv, &ops, &key_filename, &report_filename);
	if (rc != EXIT_SUCCESS) {
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

	if (ops.print_tcb) {
		print_reported_tcb(&report);
	}

	/* If a key file was specified, write out the key */
	if (ops.export_key && key_filename) {
		errno = 0;
		key_file = fopen(key_filename, "w+");
		if (!key_file) {
			rc = errno;
			perror("fopen");
			goto exit_close_report;
		}

		const char *name = "RSA Public Key";
		const char *header = "";
		if (!PEM_write(key_file, name, header, (uint8_t *)&report.report_data, sizeof(report.report_data))) {
			ERR_print_errors_fp(stderr);
			rc = EIO;
			goto exit_close_key;
		}
	}

	/* If no operations were requested, just print the report */

exit_close_key:
	if (key_file) {
		fclose(key_file);
		key_file = NULL;
	}

exit_close_report:
	if (report_file) {
		fclose(report_file);
		report_file = NULL;
	}

exit:
	exit(rc);
}

