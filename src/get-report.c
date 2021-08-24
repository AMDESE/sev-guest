/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
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
		"Usage: " PROG_NAME " [-f|--data-file data_file] [-d--digest digest_name] report_file\n"
		"       " PROG_NAME " [-h|--help]\n"
		"\n"
		"  data_file:   file whose contents will be hashed and included\n"
		"               in the report.\n"
		"  digest_name: name of the openssl digest to use.\n"
		"  report_file: output file for the attestation report.\n"
		"\n");
}

int parse_options(int argc, char *argv[],
		  char **data_filename, char **report_filename, char **digest_name)
{
	int rc = EXIT_FAILURE;
	char *short_options = "d:f:h";
	struct option long_options[] = {
		{ "data_file", required_argument, NULL, 'f' },
		{ "digest",    required_argument, NULL, 'd' },
		{ "help",      no_argument,       NULL, 'h' },
		{0},
	};

	if (argc < NR_ARGS_REQUIRED) {
		rc = EINVAL;
		goto out;
	}

	*data_filename = NULL;
	*report_filename = NULL;
	*digest_name = NULL;

	do {
		char option = getopt_long(argc, argv,
					  short_options, long_options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'f':
			*data_filename = optarg;
			break;
		case 'd':
			*digest_name = optarg;
			break;
		case 'h':
			print_usage();
			rc = EXIT_SUCCESS;
			goto exit;
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

	if (digest_name && !data_filename) {
		fprintf(stderr, "-d specified, but no data file specified!\n");
		rc = EINVAL;
		goto out;
	}

	if (optind < argc) {
		fprintf(stderr, PROG_NAME ": too many arguments.\n\n");
		rc = EINVAL;
		goto out;
	}

	rc = EXIT_SUCCESS;
out:
	return rc;
exit:
	exit(rc);
}

int hash_data_file(const char *file_name, uint8_t *buffer, size_t *size, const char *digest_name)
{
	int rc = EXIT_FAILURE;
	FILE *data_file = NULL;
	struct stat file_stats;;
	char *file_buffer = NULL;
	EVP_MD_CTX *ctx = NULL;
	const EVP_MD *md = NULL;
	size_t count = 0;
	unsigned digest_size = 0;

	if (!file_name || !buffer || !size || *size < EVP_MAX_MD_SIZE) {
		rc = EINVAL;
		goto out;
	}

	memset(&file_stats, 0, sizeof(file_stats));

	errno = 0;
	data_file = fopen(file_name, "r");
	if (!data_file) {
		rc = errno;
		perror("fopen");
		goto out;
	}

	errno = 0;
	rc = fstat(fileno(data_file), &file_stats);
	if (rc != 0) {
		rc = errno;
		perror("fstat");
		goto out_close;
	}

	file_buffer = malloc(file_stats.st_size);
	if (!file_buffer) {
		rc = ENOMEM;
		perror("malloc");
		goto out_close;
	}

	count = fread(file_buffer, sizeof(char), file_stats.st_size, data_file);
	if (count != file_stats.st_size || ferror(data_file)) {
		rc = EIO;
		perror("fread");
		goto out_free;
	}

	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		rc = ENOMEM;
		goto out_free;
	}

	md = EVP_get_digestbyname(digest_name);
	if (!md) {
		rc = EINVAL;
		perror("EVP_get_digestbyname");
		ERR_print_errors_fp(stderr);
		goto out_free_ctx;
	}

	digest_size = (unsigned) *size;
	if (!EVP_Digest(file_buffer, file_stats.st_size, buffer, &digest_size, md, NULL)) {
		ERR_print_errors_fp(stderr);
		rc = EIO;
		goto out_free_ctx;
	}

	*size = digest_size;
	rc = EXIT_SUCCESS;

out_free_ctx:
	if (ctx) {
		EVP_MD_CTX_free(ctx);
		ctx = NULL;
	}

out_free:
	if (file_buffer) {
		free(file_buffer);
		file_buffer = NULL;
	}

out_close:
	if (data_file) {
		fclose(data_file);
		data_file = NULL;
	}
out:
	return rc;
}

void print_digest(const uint8_t *digest, size_t size)
{
	if (!digest || size == 0)
		return;

	for (size_t i = 0; i < size; i++)
		printf("%02x", digest[i]);
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
	char *data_filename = NULL, *report_filename = NULL;
	struct attestation_report report;
	uint8_t hash[EVP_MAX_MD_SIZE] = {0};
	size_t hash_size = sizeof(hash);
	char *digest_name = NULL;

	memset(&report, 0, sizeof(report));

	/* Parse command line options */
	rc = parse_options(argc, argv, &data_filename, &report_filename, &digest_name);
	if (rc != EXIT_SUCCESS) {
		print_usage();
		goto exit;
	}

	if (!digest_name)
		digest_name = "sha256";

	/* If a data file was specified, add the hash of the data to the request */
	if (data_filename) {
		rc = hash_data_file(data_filename, hash, &hash_size, digest_name);
		if (rc != EXIT_SUCCESS) {
			errno = rc;
			perror("hash_data_file");
			goto exit;
		}
	}

	printf("Generating report using the following hash: ");
	print_digest(hash, hash_size);
	putchar('\n');

	/* Retrieve the attestation report from the SEV FW */
	rc = get_report(hash, hash_size, &report);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("get_report");
		goto exit;
	}

	/* Write the report to the output file */
	rc = write_report(report_filename, &report);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("write_report");
		goto exit;
	}

	rc = EXIT_SUCCESS;
exit:
	exit(rc);
}

