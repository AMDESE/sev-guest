/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/psp-sev.h>

#ifndef PROG_NAME
#define PROG_NAME	"sev-host-set-cert-chain"
#endif

#define NR_ARGS_REQUIRED	(2)

#define SEV_DEVICE		"/dev/sev"

void print_usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME " certs_file\n"
		"\n"
		"  certs_file:  certificate blob to make available to the guest.\n"
		"\n"
		"Store the certificate chain needed to validate an SEV-SNP attestation report.\n"
		"\n");
}

/*
 * The memory for the certificate chain will be allocated using malloc() and
 * returned in **buffer. *size will be set to the size of the data in **buffer.
 */
int read_certs(const char *certs_filename, uint8_t **buffer, size_t *size)
{
	int rc = EXIT_FAILURE;
	FILE *certs_file = NULL;
	uint8_t *certs_data = NULL;
	size_t count = 0, page_size = 0, nr_pages = 0;
	struct stat stats;

	if (!certs_filename || !buffer || !size ) {
		rc = EINVAL;
		goto out;
	}

	memset(&stats, 0, sizeof(stats));

	/* Open the input certificates file */
	errno = 0;
	certs_file = fopen(certs_filename, "r");
	if (!certs_file) {
		rc = errno;
		perror("fopen");
		goto out;
	}

	errno = 0;
	rc = fstat(fileno(certs_file), &stats);
	if (rc != 0) {
		rc = errno;
		perror("fstat");
		goto out_close;
	}

	errno = 0;
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size == -1) {
		rc = errno;
		perror("sysconf");
		goto out_close;
	}

	/* The certificate memory must be page-aligned */
	nr_pages = stats.st_size/page_size;
	if (stats.st_size % page_size > 0)
		nr_pages++;

	certs_data = calloc(page_size, nr_pages);
	if (!certs_data) {
		rc = ENOMEM;
		perror("calloc");
		goto out_close;
	}

	count = fread(certs_data, sizeof(char), stats.st_size, certs_file);
	if (count != stats.st_size || ferror(certs_file)) {
		rc = EIO;
		perror("fread");
		goto out_free;
	}

	*buffer = certs_data;
	*size = page_size * nr_pages;

out_free:
	if (rc != EXIT_SUCCESS && certs_data) {
		free(certs_data);
		certs_data = NULL;
	}

out_close:
	if (certs_file) {
		fclose(certs_file);
		certs_file = NULL;
	}

out:
	return rc;
}

int store_certs(const uint8_t *data, size_t size)
{
	int rc = EXIT_FAILURE;
	int fd = -1;
	struct sev_user_data_ext_snp_config ext_config = {
		.config_address = 0,
		.certs_address = (__u64)data,
		.certs_len = size,
	};
	struct sev_issue_cmd cmd = {
		.cmd = SNP_SET_EXT_CONFIG,
		.data = (__u64)&ext_config,
		.error = 0,
	};

	if (!data || size == 0) {
		rc = EINVAL;
		goto out;
	}

	/* Open the sev-guest device */
	errno = 0;
	fd = open(SEV_DEVICE, O_RDWR);
	if (fd == -1) {
		rc = errno;
		perror("open");
		goto out;
	}

	/* Store the cert chain */
	errno = 0;
	rc = ioctl(fd, SEV_ISSUE_CMD, &cmd);
	if (rc == -1) {
		rc = errno;
		perror("ioctl");
		goto out_close;
	}

out_close:
	if (fd > 0) {
		close(fd);
		fd = -1;
	}
out:
	return rc;
}

int main(int argc, char *argv[])
{
	int rc = EXIT_FAILURE;
	char *certs_filename = NULL;
	uint8_t *certs = NULL;
	size_t certs_size = 0;

	if (argc != NR_ARGS_REQUIRED) {
		print_usage();
		rc = EINVAL;
		goto exit;
	}

	certs_filename = argv[1];

	rc = read_certs(certs_filename, &certs, &certs_size);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("read_certs");
		goto exit;
	}

	rc = store_certs(certs, certs_size);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("store_certs");
		goto exit_free;
	}

	rc = EXIT_SUCCESS;

exit_free:
	if (certs) {
		free(certs);
		certs = NULL;
	}

exit:
	exit(rc);
}

