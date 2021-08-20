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

/*
 * Print the reported TCB version needed to retreive the VCEK
 * from the AMD KDS.
 */
void print_reported_tcb(struct attestation_report *report)
{
	printf("reported TCB: %02u%02u%02u%02u%02u%02u%02u%02u\n",
	       (unsigned) report->reported_tcb[0],
	       (unsigned) report->reported_tcb[1],
	       (unsigned) report->reported_tcb[2],
	       (unsigned) report->reported_tcb[3],
	       (unsigned) report->reported_tcb[4],
	       (unsigned) report->reported_tcb[5],
	       (unsigned) report->reported_tcb[6],
	       (unsigned) report->reported_tcb[7]);
	return;
}

int main(int argc, char *argv[])
{
	int rc = EXIT_FAILURE;
	char *key_filename = NULL, *report_filename = NULL;
	FILE *key_file = NULL, *report_file = NULL;
	char *name = NULL, *header = NULL;
	int fd = -1;
	struct snp_report_req req;
	struct snp_report_resp resp;
	struct snp_user_guest_request guest_req;
	long user_data_size = sizeof(req.user_data);
	struct msg_report_resp *report_resp = (struct msg_report_resp *)&resp.data;
	struct attestation_report *report = &report_resp->report;

	/* Initialize data structures */
	memset(&req, 0, sizeof(req));
	req.msg_version = 1;

	memset(&resp, 0, sizeof(resp));

	memset(&guest_req, 0, sizeof(guest_req));
	guest_req.req_data = (__u64) &req;
	guest_req.resp_data = (__u64) &resp;

	/* Parse command line options */
	rc = parse_options(argc, argv, &key_filename, &report_filename);
	if (rc != EXIT_SUCCESS) {
		print_usage();
		goto exit;
	}

	/* If a key file was specified, add the key to the request */
	if (key_filename) {
		errno = 0;
		key_file = fopen(key_filename, "r");
		if (!key_file) {
			rc = errno;
			perror("fopen");
			goto exit;
		}

		if (!PEM_read(key_file, &name, &header, (__u8 **) &req.user_data, &user_data_size)) {
			ERR_print_errors_fp(stderr);
			rc = EIO;
			goto exit_close_key;
		}
	}

	/* Open the output report file */
	errno = 0;
	report_file = fopen(report_filename, "w+");
	if (!report_file) {
		rc = errno;
		perror("fopen");
		goto exit_close_key;
	}

	/* Open the sev-guest device */
	errno = 0;
	fd = open(SEV_GUEST_DEVICE, O_RDWR);
	if (fd == -1) {
		rc = errno;
		perror("open");
		goto exit_close_report;
	}

	/* Issue the guest request IOCTL */
	errno = 0;
	rc = ioctl(fd, SNP_GET_REPORT, &guest_req);
	if (rc == -1) {
		rc = errno;
		perror("ioctl");
		goto exit_close_fd;
	}

	/* Check that the report was successfully generated */
	if (report_resp->status != 0) {
		fprintf(stderr, "firmware error %x\n", report_resp->status);
		rc = report_resp->status;
		goto exit_close_fd;
	}

	print_reported_tcb(report);

	/* Write the report to the output */
	int written = fwrite(report, sizeof(char), report_resp->report_size,
			     report_file);
	if (written != report_resp->report_size) {
		rc = EIO;
		fprintf(stderr, "fwrite failed.\n");
		goto exit_close_fd;
	}

exit_close_fd:
	if (fd > 0) {
		close(fd);
		fd = -1;
	}

exit_close_report:
	if (report_file) {
		fclose(report_file);
		report_file = NULL;
	}

exit_close_key:
	if (key_file) {
		fclose(key_file);
		key_file = NULL;
	}
exit:
	exit(rc);
}

