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
#define PROG_NAME	"sev-guest-export-key"
#endif

#define NR_ARGS_REQUIRED	(2)

#define BITS_PER_BYTE		(8)

void print_usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME " [-b|--bytes key_bytes ] \n"
		"                     [-a|--algo key_algo] report_file [report_file...]\n"
		"\n"
		"  key_bytes:   Size in bytes of the key data to export.\n"
		"  key_algo:    Public key algorithm to be added to the PEM BEGIN marker.\n"
		"  report_file: The attestation report. Multiple reports with the same\n"
		"               report ID will have their report data concatenated.\n"
		"\n"
		"Extract a public key from one or more attestation reports.\n"
		"\n");
}

int parse_options(int argc, char *argv[], char **algo, size_t *key_bytes)
{
	int rc = EXIT_FAILURE;
	char *short_options = "a:b:";
	struct option long_options[] = {
		{ "algo",  required_argument, NULL, 'a' },
		{ "bytes", required_argument, NULL, 'b' },
	};

	if (argc < NR_ARGS_REQUIRED) {
		rc = EINVAL;
		goto out;
	}

	do {
		size_t bytes = 0;
		char *end = NULL;
		char option = getopt_long(argc, argv, short_options, long_options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'a':
			*algo = optarg;
			break;
		case 'b':
			errno = 0;
			bytes = strtoull(optarg, &end, 10);
			if (*end != '\0') {
				fprintf(stderr, "invalid character '%c'.\n", *end);
				rc = EINVAL;
				goto out;
			}
			else if (errno) {
				rc = errno;
				perror("strtoull");
				goto out;
			}
			*key_bytes = bytes;
			break;
		case ':':
		case '?':
		default:
			putchar('\n');
			rc = EINVAL;
			goto out;
		}
	} while (1);

	rc = EXIT_SUCCESS;
out:
	return rc;
}

int main(int argc, char *argv[])
{
	int rc = EXIT_FAILURE;
	char *algo = "RSA";
	size_t key_bytes = 0, bytes_copied = 0;
	struct attestation_report report;
	const size_t report_data_size = sizeof(report.report_data);
	size_t nr_reports = 0;
	uint8_t *key = NULL;

	memset(&report, 0, sizeof(report));

	/* Parse command line options */
	rc = parse_options(argc, argv, &algo, &key_bytes);
	if (rc != EXIT_SUCCESS) {
		print_usage();
		goto exit;
	}

	/* Allocate a buffer for the key bytes from each report */
	nr_reports = argc - optind;
	key = calloc(report_data_size, nr_reports);
	if (!key) {
		rc = ENOMEM;
		errno = rc;
		perror("calloc");
		goto exit;
	}

	if (key_bytes == 0) {
		key_bytes = nr_reports * report_data_size;
		if (key_bytes < nr_reports || key_bytes < report_data_size) {
			rc = EOVERFLOW;
			errno = rc;
			perror(PROG_NAME);
			goto exit_free;
		}
	}

	for (size_t i = optind; i < argc; i++) {
		FILE *report_file = NULL;
		int count = 0;
		size_t size = 0;
	
		/* Open the input report file */
		errno = 0;
		report_file = fopen(argv[i], "r");
		if (!report_file) {
			rc = errno;
			perror("fopen");
			goto exit_free;
		}

		/* Read the report into memory */
		errno = 0;
		count = fread(&report, sizeof(char), sizeof(report), report_file);
		if (count != sizeof(report)) {
			fprintf(stderr, "fread() failed.\n");
			rc = EIO;
			goto close_report;
		}

		/* Extract and append the key bits */
		//printf("Extracting key bits from %s\n", argv[i]);
		size = bytes_copied + report_data_size > key_bytes ? key_bytes - bytes_copied
								   : report_data_size;
		memcpy(key + bytes_copied, report.report_data, size);
		bytes_copied += size;
close_report:
		fclose(report_file);
		report_file = NULL;

		if (rc != EXIT_SUCCESS)
			goto exit_free;
	}

	const char *name = "RSA PUBLIC KEY";
	const char *header = "";
	if (!PEM_write(stdout, name, header, key, key_bytes)) {
		ERR_print_errors_fp(stderr);
		rc = EIO;
		goto exit_free;
	}

	rc = EXIT_SUCCESS;

exit_free:
	if (key) {
		free(key);
		key = NULL;
	}
exit:
	exit(rc);
}

