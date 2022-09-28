/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
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
#include <cert-table.h>

#ifndef PROG_NAME
#define PROG_NAME	"sev-guest-get-report"
#endif

#define NR_ARGS_REQUIRED	(2)

#define SEV_GUEST_DEVICE	"/dev/sev-guest"

struct options {
	const char *data_filename;
	const char *digest_name;
	const char *report_filename;
	const char *cert_dirname;
	uint8_t     vmpl;
	bool        do_extended_report;
	bool        do_custom_digest;
	bool	    do_help;
};

void print_usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME " [-f|--data-file data_file] [-d|--digest digest_name]\n"
		"       [-x|--extended] [-v|--vmpl level] [-h|--help] report_file\n"
		"\n"
		"Retrieve the attestation report from the SEV-SNP firmware and write it to\n"
		"'report_file'.\n"
		"\n"
		"options:\n"
		"  -f|--data-file file\n"
		"    File whose contents will be hashed and included in the report.\n"
		"    E.g. an SSH public key file.\n"
		"\n"
		"  -d|--digest name\n"
		"    Name of the openssl digest to use when hashing the data file.\n"
		"    Ignored unless -f is also specified.\n"
		"\n"
		"  -x|--extended\n"
		"    In addition to retrieving the report, also retrieve the certificate chain\n"
		"    required to validate the report. The certificate chain must have been\n"
		"    stored previously on the host using the sev-host-set-cert-chain command.\n"
		"    The certificates will each be written to a file named according to the\n"
		"    GUID that identifies the certificate.\n"
		"\n"
		"  -c|--cert-dir dir\n"
		"    Write any certificates retrieved with -x to 'dir'. Ignored unless -x is\n"
		"    also specified.\n"
		"\n"
		"  -v|--vmpl level\n"
		"    Request a report for VM Permission Level 'level' (0-3). Default: 0.\n"
		"\n");
}

int parse_options(int argc, char *argv[], struct options *options)
{
	int rc = EXIT_FAILURE;
	char *short_options = "c:d:f:v:hx";
	struct option long_options[] = {
		{ "cert-dir",  required_argument, NULL, 'c' },
		{ "digest",    required_argument, NULL, 'd' },
		{ "data-file", required_argument, NULL, 'f' },
		{ "vmpl",      required_argument, NULL, 'v' },
		{ "help",      no_argument,       NULL, 'h' },
		{ "extended",  no_argument,       NULL, 'x' },
		{0},
	};

	if (argc < NR_ARGS_REQUIRED || !argv || !options) {
		rc = EINVAL;
		goto out;
	}

	do {
		unsigned long value;
		char *end;
		char option = getopt_long(argc, argv,
					  short_options, long_options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'c':
			options->cert_dirname = optarg;
			break;
		case 'd':
			options->do_custom_digest = true;
			options->digest_name = optarg;
			break;
		case 'f':
			options->data_filename = optarg;
			break;
		case 'v':
			if (*optarg == '\0') {
				fprintf(stderr, "-%c: VMPL is empty!\n", option);
				rc = EINVAL;
				goto out;
			}

			errno = 0;
			value = strtoul(optarg, &end, 10);
			if (end && *end != '\0') {
				fprintf(stderr, "-%c: invalid decimal digit '%c'.\n", option, *end);
				rc = EINVAL;
				goto out;
			}
			else if (errno != 0) {
				fprintf(stderr, "-%c: %s\n", option, strerror(errno));
				rc = errno;
				goto out;
			}

			if (value > 3) {
				fprintf(stderr, "-%c: invalid VMPL value %lu.\n", option, value);
				rc = EINVAL;
				goto out;
			}
			options->vmpl = (uint8_t)value;
			break;
		case 'x':
			options->do_extended_report = true;
			break;
		case 'h':
			options->do_help = true;
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
		options->report_filename = argv[optind];
		optind++;
	}

	if (options->do_custom_digest && !options->data_filename) {
		/* TODO: read data from stdin */
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
#define BYTES_PER_LINE	32
#define INDENT		"    "

	if (!digest || size == 0)
		return;

	for (size_t i = 0; i < size; i++) {
		if (i % BYTES_PER_LINE == 0)
			printf("\n" INDENT);
		printf("%02x", digest[i]);
	}
	putchar('\n');
}

int get_report(uint8_t vmpl, const uint8_t *data, size_t data_size,
	       struct attestation_report *report)
{
	int rc = EXIT_FAILURE;
	int fd = -1;
	struct snp_report_req req;
	struct snp_report_resp resp;
	struct snp_guest_request_ioctl guest_req;
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
	req.vmpl = vmpl;
	if (data)
		memcpy(&req.user_data, data, data_size);

	memset(&resp, 0, sizeof(resp));

	memset(&guest_req, 0, sizeof(guest_req));
	guest_req.msg_version = 1;
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
		fprintf(stderr, "firmware error %llu\n", guest_req.fw_err);
		goto out_close;
	}

	/* Check that the report was successfully generated */
	if (report_resp->status != 0 ) {
		fprintf(stderr, "firmware error %#x\n", report_resp->status);
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

int get_extended_report(uint8_t vmpl, const uint8_t *data, size_t data_size,
			struct attestation_report *report,
			uint8_t **certs, size_t *certs_size)
{
	int rc = EXIT_FAILURE;
	int fd = -1;
	struct snp_ext_report_req req;
	struct snp_report_resp resp;
	struct snp_guest_request_ioctl guest_req;
	struct msg_report_resp *report_resp = (struct msg_report_resp *)&resp.data;
	struct cert_table certs_data;
	size_t page_size = 0, nr_pages = 0;

	if (!report || !certs || !certs_size) {
		rc = EINVAL;
		goto out;
	}

	if (data && (data_size > sizeof(req.data.user_data) || data_size == 0)) {
		rc = EINVAL;
		goto out;
	}

	/* Initialize data structures */
	memset(&req, 0, sizeof(req));
	req.data.vmpl = vmpl;
#if 1
	req.certs_address = (__u64)-1;	/* Invalid, non-zero address */
#endif
	if (data)
		memcpy(&req.data.user_data, data, data_size);

	memset(&resp, 0, sizeof(resp));

	memset(&guest_req, 0, sizeof(guest_req));
	guest_req.msg_version = 1;
	guest_req.req_data = (__u64) &req;
	guest_req.resp_data = (__u64) &resp;

	memset(&certs_data, 0, sizeof(certs_data));

	/* Open the sev-guest device */
	errno = 0;
	fd = open(SEV_GUEST_DEVICE, O_RDWR);
	if (fd == -1) {
		rc = errno;
		perror("open");
		goto out;
	}

	/* Query the size of the stored certificates */
	errno = 0;
	rc = ioctl(fd, SNP_GET_EXT_REPORT, &guest_req);
	if (rc == -1 && guest_req.fw_err != 0x100000000) {
		rc = errno;
		perror("ioctl");
		fprintf(stderr, "firmware error %#llx\n", guest_req.fw_err);
		fprintf(stderr, "report error %#x\n", report_resp->status);
		fprintf(stderr, "certs_len %#x\n", req.certs_len);
		goto out_close;
	}

	if (req.certs_len == 0) {
		fprintf(stderr, "The cert chain storage is empty.\n");
		rc = ENODATA;
		goto out_close;
	}

	/* The certificate storage is always page-aligned */
	page_size = sysconf(_SC_PAGESIZE);
	nr_pages = req.certs_len/page_size;
	if (req.certs_len % page_size != 0)
		nr_pages++;	/* Just to be safe */

	certs_data.entry = calloc(page_size, nr_pages);
	if (!certs_data.entry) {
		rc = ENOMEM;
		errno = rc;
		perror("calloc");
		goto out_close;
	}

	/* Retrieve the cert chain */
	req.certs_address = (__u64)certs_data.entry;
	errno = 0;
	rc = ioctl(fd, SNP_GET_EXT_REPORT, &guest_req);
	if (rc == -1) {
		rc = errno;
		perror("ioctl");
		fprintf(stderr, "errno is %u\n", errno);
		fprintf(stderr, "firmware error %#llx\n", guest_req.fw_err);
		fprintf(stderr, "report error %x\n", report_resp->status);
		goto out_free;
	}

	/* Check that the report was successfully generated */
	if (report_resp->status != 0 ) {
		fprintf(stderr, "firmware error %x\n", report_resp->status);
		rc = report_resp->status;
		goto out_free;
	}
	else if (report_resp->report_size > sizeof(*report)) {
		fprintf(stderr, "report size is %u bytes (expected %lu)!\n",
			report_resp->report_size, sizeof(*report));
		rc = EFBIG;
		goto out_free;
	}

	memcpy(report, &report_resp->report, report_resp->report_size);
	*certs = (uint8_t *)certs_data.entry;
	*certs_size = req.certs_len;
	rc = EXIT_SUCCESS;

out_free:
	if (rc != EXIT_SUCCESS && certs_data.entry) {
		free(certs_data.entry);
		certs_data.entry = NULL;
	}

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

int write_cert(const struct cert_table_entry *entry, const uint8_t *buffer, size_t size)
{
	int rc = EXIT_FAILURE;
	FILE *file = NULL;
	size_t count = 0, cert_end = 0;
	char uuid_str[UUID_STR_LEN] = {0};
	char *filename = NULL;

	if (!entry || !buffer || size == 0) {
		rc = EINVAL;
		goto out;
	}

	if (entry->offset > size || entry->length > size) {
		rc = EINVAL;
		goto out;
	}

	/* Ensure that the entry describes a certificate within the bounds of the buffer */
	cert_end = entry->offset + entry->length;
	if (cert_end < entry->offset || cert_end < entry->length || cert_end > size) {
		rc = EOVERFLOW;
		goto out;
	}

	/* Get the GUID as a character string */
	uuid_unparse(entry->guid, uuid_str);

	/*
	 * If the GUID is defined in the GHCB spec, use the defined
	 * name in the spec as the file name with a .cert extension.
	 * Otherwise, just use the GUID as the file name.
	 */
	if (memcmp(uuid_str, vcek_guid, sizeof(uuid_str)) == 0) {
		filename = "vcek.cert";
	} else if (memcmp(uuid_str, ask_guid, sizeof(uuid_str)) == 0) {
		filename = "ask.cert";
	} else if (memcmp(uuid_str, ark_guid, sizeof(uuid_str)) == 0) {
		filename = "ark.cert";
	} else {
		filename = uuid_str;
	}

	/* Open the output certificate file */
	errno = 0;
	file = fopen(filename, "w+");
	if (!file) {
		rc = errno;
		perror("fopen");
		goto out;
	}

	/* Write the cert to the output */
	count = fwrite(buffer + entry->offset, sizeof(char), entry->length, file);
	if (count != entry->length) {
		rc = EIO;
		fprintf(stderr, "fwrite failed.\n");
		goto out_close;
	}

	printf("wrote %s\n", filename);
	rc = EXIT_SUCCESS;

out_close:
	if (file) {
		fclose(file);
		file = NULL;
	}
out:
	return rc;
}

int write_certs(const uint8_t *certs, size_t size)
{
	int rc = EXIT_FAILURE;
	const struct cert_table table = {
		.entry = (struct cert_table_entry *)certs,
	};
	size_t table_size = 0, certs_size = 0, total_size = 0;

	if (!certs || size == 0) {
		rc = EINVAL;
		goto out;
	}

	/* Determine the size of the certificate chain including the cert table */
	table_size = cert_table_get_size(&table);
	if (table_size == 0) {
		rc = ENODATA;
		errno = rc;
		perror("cert_table_get_size");
		goto out;
	}

	rc = cert_table_get_certs_size(&table, &certs_size);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("cert_table_get_certs");
		goto out;
	}

	total_size = certs_size + table_size;
	if (total_size < table_size || total_size < certs_size) {
		rc = EOVERFLOW;
		goto out;
	}

	if (total_size > size) {
		rc = ENOBUFS;
		goto out;
	}

	for (size_t i = 0; table.entry[i].length > 0; i++) {
		struct cert_table_entry *entry = table.entry + i;

		rc = write_cert(entry, certs, size);
		if (rc != EXIT_SUCCESS) {
			errno = rc;
			perror("write_cert");
			goto out;
		}
	}

	rc = EXIT_SUCCESS;
out:
	return rc;
}

int main(int argc, char *argv[])
{
	int rc = EXIT_FAILURE;
	struct options options;
	struct attestation_report report;
	uint8_t hash[EVP_MAX_MD_SIZE] = {0};
	size_t hash_size = sizeof(hash), certs_size = 0;
	uint8_t *certs = NULL;

	memset(&report,  0, sizeof(report));
	memset(&options, 0, sizeof(options));
	memset(&certs, 0, sizeof(certs));

	/* Set default options */
	options.digest_name = "sha512";

	/* Parse command line options */
	rc = parse_options(argc, argv, &options);
	if (rc != EXIT_SUCCESS || options.do_help == true) {
		print_usage();
		goto exit;
	}

	/* If a data file was specified, add the hash of the data to the request */
	if (options.data_filename) {
		rc = hash_data_file(options.data_filename, hash, &hash_size, options.digest_name);
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
	if (options.do_extended_report) {
		rc = get_extended_report(options.vmpl, hash, hash_size, &report, &certs, &certs_size);
		if (rc != EXIT_SUCCESS) {
			errno = rc;
			perror("get_extended_report");
			goto exit;
		}

		rc = write_certs(certs, certs_size);
		if (rc != EXIT_SUCCESS) {
			errno = rc;
			perror("write_certs");
			goto exit_free;
		}
	}
	else {
		rc = get_report(options.vmpl, hash, hash_size, &report);
		if (rc != EXIT_SUCCESS) {
			errno = rc;
			perror("get_report");
			goto exit;
		}
	}

	/* Write the report to the output file */
	rc = write_report(options.report_filename, &report);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("write_report");
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

