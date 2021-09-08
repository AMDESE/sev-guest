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
#define PROG_NAME	"sev-guest-get-cert-chain"
#endif

#define NR_ARGS_REQUIRED	(2)

#define SEV_GUEST_DEVICE	"/dev/sev-guest"

void print_usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME " certs_file\n"
		"\n"
		"  certs_file: certificate chain stored by the host.\n"
		"\n"
		"Retrieve the certificate chain needed to validate an SEV-SNP attestation report.\n"
		"\n");
}

/*
 * The memory for the certificate chain will be allocated using malloc() and
 * returned in **data. *size will be set to the full size of the **data buffer.
 */
int get_certs(uint8_t **data, size_t *size)
{
	int rc = EXIT_FAILURE;
	int fd = -1;
	struct sev_user_data_ext_snp_config ext_config;
	struct sev_issue_cmd cmd;
	uint8_t *certs_data = NULL;
	size_t page_size = 0, nr_pages = 0;

	if (!data || !size) {
		rc = EINVAL;
		goto out;
	}

	/*
	 * certs_address must be non-zero initially in order to retrieve the
	 * length of the certificate chain, so set it to an invalid address.
	 */
	memset(&ext_config, 0, sizeof(ext_config));
	ext_config.config_address = 0;
	ext_config.certs_address = (__u64) -1;
	ext_config.certs_len = 0;

	memset(&cmd, 0, sizeof(cmd));
	cmd.cmd = SNP_GET_EXT_CONFIG;
	cmd.data = (__u64)&ext_config;
	cmd.error = 0;

	/* Open the sev-guest device */
	errno = 0;
	fd = open(SEV_GUEST_DEVICE, O_RDWR);
	if (fd == -1) {
		rc = errno;
		perror("open");
		goto out;
	}

	/* Get the size of the cert chain */
	errno = 0;
	rc = ioctl(fd, SEV_ISSUE_CMD, &cmd);
	if (rc == -1) {
		rc = errno;
		perror("ioctl");
		goto out_close;
	}

	if (ext_config.certs_len == 0) {
		fprintf(stderr, "The cert chain storage is empty.\n");
		rc = ENODATA;
		goto out_close;
	}

	/* The certificate storage is always page-aligned */
	page_size = sysconf(_SC_PAGESIZE);
	nr_pages = ext_config.certs_len/page_size;
	if (ext_config.certs_len % page_size != 0)
		nr_pages++;	/* Just to be safe */

	certs_data = calloc(page_size, nr_pages);
	if (!certs_data) {
		rc = ENOMEM;
		errno = rc;
		perror("calloc");
		goto out_close;
	}

	/* Retrieve the cert chain */
	ext_config.certs_address = (__u64)certs_data;
	errno = 0;
	rc = ioctl(fd, SEV_ISSUE_CMD, &cmd);
	if (rc == -1) {
		rc = errno;
		perror("ioctl");
		goto out_free;
	}

	*data = certs_data;
	*size = ext_config.certs_len;
	rc = EXIT_SUCCESS;

out_free:
	if (rc != EXIT_SUCCESS && certs_data) {
		free(certs_data);
		certs_data = NULL;
	}

out_close:
	if (fd > 0) {
		close(fd);
		fd = -1;
	}
out:
	return rc;
}

int write_certs(const char *certs_filename, const uint8_t *buffer, size_t size)
{
	int rc = EXIT_FAILURE;
	FILE *certs_file = NULL;
	size_t count = 0;

	if (!certs_filename || !buffer || size == 0) {
		rc = EINVAL;
		goto out;
	}

	/* Open the input certificates file */
	errno = 0;
	certs_file = fopen(certs_filename, "r");
	if (!certs_file) {
		rc = errno;
		perror("fopen");
		goto out;
	}

	count = fwrite(buffer, sizeof(char), size, certs_file);
	if (count != size || ferror(certs_file)) {
		rc = EIO;
		perror("fwrite");
		goto out_close;
	}

	rc = EXIT_SUCCESS;

out_close:
	if (certs_file) {
		fclose(certs_file);
		certs_file = NULL;
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

	rc = get_certs(&certs, &certs_size);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("store_certs");
		goto exit_free;
	}

	rc = write_certs(certs_filename, certs, certs_size);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("write_certs");
		goto exit;
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

