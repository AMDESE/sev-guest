/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/sev-guest.h>
#include <linux/psp-sev.h>
#include <attestation.h>

#ifndef PROG_NAME
#define PROG_NAME	"sev-guest-get-report"
#endif

#define NR_ARGS_REQUIRED	(2)

#define SEV_GUEST_DEVICE	"/dev/sev-guest"

void print_usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME " [-k|--key key_file] report_file\n"
		"\n"
		"  key_file:    optional SSH key to be included in the report.\n"
		"  report_file: output file for the attestation report.\n"
		"\n");
}

int parse_options(int argc, char *argv[],
		  char **key_filename, char **report_filename)
{
	int rc = EXIT_FAILURE;
	char *short_options = "k:";
	struct option long_options[] = {
		{ "key", required_argument, NULL, 'k' },
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
			*key_filename = optarg;
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

int read_key_file(const char *file_name, uint8_t *buffer, size_t *size)
{
	int rc = EXIT_FAILURE;
	FILE *key_file = NULL;
	char *name = NULL, *header = NULL;
	uint8_t	*data = NULL;
	long key_size = 0;

	errno = 0;
	key_file = fopen(file_name, "r");
	if (!key_file) {
		rc = errno;
		perror("fopen");
		goto out;
	}

	if (!PEM_read(key_file, &name, &header, &data, &key_size)) {
		ERR_print_errors_fp(stderr);
		rc = EIO;
		goto out_close;
	}

	memcpy(buffer, data, key_size);
	*size = key_size;
	rc = EXIT_SUCCESS;

	OPENSSL_free(name);
	OPENSSL_free(header);
	OPENSSL_free(data);
	name = NULL;
	header = NULL;
	data = NULL;

out_close:
	if (key_file) {
		fclose(key_file);
		key_file = NULL;
	}
out:
	return rc;
}

int get_report(const uint8_t *data, size_t data_size,
	       struct attestation_report *report)
{
	int rc = EXIT_FAILURE;
	int fd = -1;
	struct snp_report_req req;
	struct snp_report_resp resp;
	struct snp_user_guest_request guest_req;
	struct msg_report_resp *report_resp = (struct msg_report_resp *)&resp.data;

	if (!report) {
		rc = EINVAL;
		goto out;
	}

	if (data && (data_size > sizeof(req.user_data) || data_size == 0)) {
		rc = EINVAL;
		goto out;
	}

	/* Initialize data structures */
	memset(&req, 0, sizeof(req));
	req.msg_version = 1;
	if (data)
		memcpy(&req.user_data, data, data_size);

	memset(&resp, 0, sizeof(resp));

	memset(&guest_req, 0, sizeof(guest_req));
	guest_req.req_data = (__u64) &req;
	guest_req.resp_data = (__u64) &resp;

	/* Open the sev-guest device */
	errno = 0;
	fd = open(SEV_GUEST_DEVICE, O_RDWR);
	if (fd == -1) {
		rc = errno;
		perror("open");
		goto out;
	}

	/* Issue the guest request IOCTL */
	errno = 0;
	rc = ioctl(fd, SNP_GET_REPORT, &guest_req);
	if (rc == -1) {
		rc = errno;
		perror("ioctl");
		goto out_close;
	}

	/* Check that the report was successfully generated */
	if (report_resp->status != 0 ) {
		fprintf(stderr, "firmware error %x\n", report_resp->status);
		rc = report_resp->status;
		goto out_close;
	}
	else if (report_resp->report_size > sizeof(*report)) {
		fprintf(stderr, "report size is %u bytes (expected %lu)!\n",
			report_resp->report_size, sizeof(*report));
		rc = EFBIG;
		goto out_close;
	}

	memcpy(report, &report_resp->report, report_resp->report_size);
	rc = EXIT_SUCCESS;

out_close:
	if (fd > 0) {
		close(fd);
		fd = -1;
	}
out:
	return rc;
}

int write_report(const char *file_name, struct attestation_report *report)
{
	int rc = EXIT_FAILURE;
	FILE *report_file = NULL;

	/* Open the output report file */
	errno = 0;
	report_file = fopen(file_name, "w+");
	if (!report_file) {
		rc = errno;
		perror("fopen");
		goto out;
	}

	/* Write the report to the output */
	int count = fwrite(report, sizeof(char), sizeof(*report), report_file);
	if (count != sizeof(*report)) {
		rc = EIO;
		fprintf(stderr, "fwrite failed.\n");
		goto out_close;
	}

	printf("wrote %s\n", file_name);
	rc = EXIT_SUCCESS;

out_close:
	if (report_file) {
		fclose(report_file);
		report_file = NULL;
	}
out:
	return rc;
}

int main(int argc, char *argv[])
{
	int rc = EXIT_FAILURE;
	char *key_filename = NULL, *report_filename = NULL;
	struct attestation_report report;
	uint8_t key_data[sizeof(report.report_data)] = {0};
	size_t data_size = sizeof(report.report_data);

	memset(&report, 0, sizeof(report));

	/* Parse command line options */
	rc = parse_options(argc, argv, &key_filename, &report_filename);
	if (rc != EXIT_SUCCESS) {
		print_usage();
		goto exit;
	}

	/* If a key file was specified, add the key to the request */
	if (key_filename) {
		rc = read_key_file(key_filename, key_data, &data_size);
		if (rc != EXIT_SUCCESS) {
			errno = rc;
			perror("read_key_file");
			goto exit;
		}
	}

	/*
	 * The attestation report can only contain 512 bits of user
	 * data, which is not enough to store an entire encryption
	 * key. As such, we must generate multiple reports, each
	 * with 512 bits of the key, until all key bytes are consumed.
	 */
	const size_t bytes_per_report = sizeof(report.report_data);
	size_t nr_reports = data_size/bytes_per_report;
	if (data_size % bytes_per_report > 0)
		nr_reports++;

	for (size_t i = 0; i < nr_reports; i++) {
		uint8_t *block = key_data + i*bytes_per_report;
		size_t block_size = data_size >= bytes_per_report ? bytes_per_report
								  : data_size;
		char *file_name = NULL;
		size_t length = 0;

		/* Retrieve the attestation report from the SEV FW */
		rc = get_report(block, block_size, &report);
		if (rc != EXIT_SUCCESS) {
			errno = rc;
			perror("get_report");
			goto exit;
		}

		length = 1 + snprintf(file_name, length, "%s.%03ld", report_filename, i);
		if (length < 0) {
			rc = EIO;
			errno = rc;
			perror("snprintf");
			goto exit;
		}

		file_name = calloc(sizeof(char), length);
		if (!file_name) {
			rc = ENOMEM;
			errno = rc;
			perror("calloc");
			goto exit;
		}

		length = snprintf(file_name, length, "%s.%03ld", report_filename, i);
		if (length < 0) {
			rc = EIO;
			errno = rc;
			perror("snprintf");
			goto exit;
		}

		/* Write the report to the output file */
		rc = write_report(file_name, &report);
		if (rc != EXIT_SUCCESS) {
			errno = rc;
			perror("write_report");
			goto exit;
		}

		data_size -= bytes_per_report;

		/* Cleanup */
		free(file_name);
		file_name = NULL;
	}

	rc = EXIT_SUCCESS;
exit:
	exit(rc);
}

