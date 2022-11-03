/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/psp-sev.h>
#include <cert-table.h>

#define  SNP_SET_EXT_CONFIG 10
#define  SNP_GET_EXT_CONFIG 11


struct sev_user_data_ext_snp_config {
	uint64_t config_address;		/* In */
	uint64_t certs_address;		/* In */
	uint32_t certs_len;		/* In */
};

#ifndef PROG_NAME
#define PROG_NAME	"sev-host-set-cert-chain"
#endif

#define NR_ARGS_REQUIRED	(3)

#define NR_AMD_CERTS	(3)
#define AMD_CERT_VCEK	(0)
#define AMD_CERT_ASK	(1)
#define AMD_CERT_ARK	(2)

#define SEV_DEVICE	"/dev/sev"

struct guid_map {
	const char *guid;
	const char *cert_filename;
};

struct options {
	const char *amd_certs[NR_AMD_CERTS];
	struct guid_map *maps;
	size_t nr_guids;
	size_t nr_amd_certs;
	bool do_help;
};

void print_usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME " [-r|--ark cert] [-s|--ask cert] [-v|--vcek cert]\n"
		"       [[-g guid]...] [[cert]...]\n"
		"\n"
		"Store the certificate chain needed to validate an SEV-SNP attestation report.\n"
		"\n"
		"options:\n"
		"  -g|--guid guid\n"
		"    Specify a guid not already defined in the GHCB protocol spec version 2.\n"
		"    Multiple -g options may be specified, and each guid will be applied to the\n"
		"    corresponding non-option certificate argument in order.\n"
		"\n"
		"  -r|--ark cert\n"
		"    Indicates that the ARK GUID should be used for certificate 'cert'.\n"
		"\n"
		"  -s|--ask cert\n"
		"    Indicates that the ASK GUID should be used for certificate 'cert'.\n"
		"\n"
		"  -v|--vcek cert\n"
		"    Indicates that the VCEK GUID should be used for certificate 'cert'.\n"
		"\n");
}

int parse_options(int argc, char *argv[], struct options *options)
{
#define NR_ARGS_PER_MAP		(3)
#define MIN_ARGC_WITH_MAP	(NR_ARGS_PER_MAP + 1)

	int rc = EXIT_FAILURE;
	size_t i = 0;
	char *short_options = "g:r:s:v:h";
	struct option long_options[] = {
		{ "guid", required_argument, NULL, 'g' },
		{ "ark",  required_argument, NULL, 'r' },
		{ "ask",  required_argument, NULL, 's' },
		{ "vcek", required_argument, NULL, 'v' },
		{ "help", no_argument,       NULL, 'h' },
		{0},
	};

	if (argc < NR_ARGS_REQUIRED || !argv || !options) {
		rc = EINVAL;
		goto out;
	}

	if (argc >= MIN_ARGC_WITH_MAP) {
		size_t max_maps = (argc - 1)/NR_ARGS_PER_MAP;
		options->maps = calloc(sizeof(struct guid_map), max_maps);
		if (!options->maps) {
			rc = ENOMEM;
			goto out;
		}
	}

	do {
		char option = getopt_long(argc, argv,
					  short_options, long_options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'g':
			options->maps[options->nr_guids++].guid = optarg;
			break;
		case 'r':
			options->amd_certs[AMD_CERT_ARK] = optarg;
			options->nr_amd_certs++;
			break;
		case 's':
			options->amd_certs[AMD_CERT_ASK] = optarg;
			options->nr_amd_certs++;
			break;
		case 'v':
			options->amd_certs[AMD_CERT_VCEK] = optarg;
			options->nr_amd_certs++;
			break;
		case 'h':
			options->do_help = true;
			break;
		case ':':
		case '?':
		default:
			putchar('\n');
			rc = EINVAL;
			goto out_free;
		}
	} while (1);

	for (i = 0; optind < argc && i < options->nr_guids; i++, optind++) {
		options->maps[i].cert_filename = argv[optind];
	}

	if (optind < argc && i == options->nr_guids) {
		fprintf(stderr, "ERROR: no guid specified for certificate: %s\n\n", argv[optind]);
		rc = EINVAL;
		goto out_free;
	}

	if (optind == argc && i < options->nr_guids) {
		fprintf(stderr, "ERROR: no certificate specified for guid: %s\n\n", options->maps[i].guid);
		rc = EINVAL;
		goto out_free;
	}

	rc = EXIT_SUCCESS;

out_free:
	if (rc != EXIT_SUCCESS && options->maps) {
		free(options->maps);
		options->maps = NULL;
	}
out:
	return rc;
}

int update_cert_table(const struct options *options, struct cert_table *table)
{
	int rc = EXIT_FAILURE;

	if (!options || !table) {
		rc = EINVAL;
		goto out;
	}

	/* Initialize the cert table */
	rc = cert_table_alloc(table, options->nr_amd_certs + options->nr_guids);
	if (rc != EXIT_SUCCESS)
		goto out;

	/* Determine the size of any AMD certificates and update the table entries */
	for (size_t i = 0; i < options->nr_amd_certs; i++) {
		struct stat stats = { .st_size = 0 };

		if (!options->amd_certs[i])
			continue;

		errno = 0;
		rc = stat(options->amd_certs[i], &stats);
		if (rc != 0) {
			rc = errno;
			goto out_free;
		}

		switch (i) {
		case AMD_CERT_VCEK:
			rc = cert_table_add_entry(table, vcek_guid, stats.st_size);
			break;
		case AMD_CERT_ASK:
			rc = cert_table_add_entry(table, ask_guid, stats.st_size);
			break;
		case AMD_CERT_ARK:
			rc = cert_table_add_entry(table, ark_guid, stats.st_size);
			break;
		default:
			rc = EXIT_FAILURE;
		}

		if (rc != EXIT_SUCCESS)
			goto out_free;
	}

	/* Determine the size of any other certificates and update the table entries */
	for (size_t i = 0; i < options->nr_guids; i++) {
		struct guid_map *map = options->maps + i;
		struct stat stats = { .st_size = 0 };

		errno = 0;
		rc = stat(map->cert_filename, &stats);
		if (rc != 0) {
			rc = errno;
			goto out_free;
		}

		rc = cert_table_add_entry(table, map->guid, stats.st_size);
		if (rc != EXIT_SUCCESS)
			goto out_free;
	}

	rc = EXIT_SUCCESS;

out_free:
	if (rc != EXIT_SUCCESS)
		cert_table_free(table);
out:
	return rc;
}

/*
 * The memory for the certificate will be allocated using malloc() and returned
 * in **buffer. *size will be set to the size of the data in **buffer.
 */
int read_cert(const char *filename, uint8_t **buffer, size_t *size)
{
	int rc = EXIT_FAILURE;
	FILE *certs_file = NULL;
	uint8_t *certs_data = NULL;
	size_t count = 0;
	struct stat stats;

	if (!filename || !buffer || !size ) {
		rc = EINVAL;
		goto out;
	}

	memset(&stats, 0, sizeof(stats));

	/* Open the input certificate file */
	errno = 0;
	certs_file = fopen(filename, "r");
	if (!certs_file) {
		rc = errno;
		goto out;
	}

	errno = 0;
	rc = fstat(fileno(certs_file), &stats);
	if (rc != 0) {
		rc = errno;
		goto out_close;
	}

	certs_data = calloc(sizeof(char), stats.st_size);
	if (!certs_data) {
		rc = ENOMEM;
		goto out_close;
	}

	count = fread(certs_data, sizeof(char), stats.st_size, certs_file);
	if (count != stats.st_size || ferror(certs_file)) {
		rc = EIO;
		goto out_free;
	}

	*buffer = certs_data;
	*size = stats.st_size;
	rc = EXIT_SUCCESS;

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

/*
 * The memory for the certificate chain will be allocated using malloc() and
 * returned in **buffer. *size will be set to the size of the data in **buffer.
 */
int read_certs(const struct options *options, uint8_t **buffer, size_t *size)
{
	int rc = EXIT_FAILURE;
	struct cert_table table;
	size_t table_size = 0, certs_size = 0, total_size = 0;
	size_t page_size = 0, nr_pages = 0, certs_data_size = 0;
	uint8_t *certs_data = NULL;

	if (!options || !buffer || !size) {
		rc = EINVAL;
		goto out;
	}

	memset(&table, 0, sizeof(table));

	/* Populate the cert table entries */
	rc = update_cert_table(options, &table);
	if (rc != EXIT_SUCCESS)
		goto out_free;

	/* Determine the size of the certificate chain including the cert table */
	table_size = cert_table_get_size(&table);
	if (table_size == 0) {
		rc = ENODATA;
		goto out_free_table;
	}

	rc = cert_table_get_certs_size(&table, &certs_size);
	if (rc != EXIT_SUCCESS)
		goto out_free_table;

	total_size = certs_size + table_size;
	if (total_size < table_size || total_size < certs_size) {
		rc = EOVERFLOW;
		goto out_free_table;
	}

	/* The certificate memory must be a multiple of the page size */
	errno = 0;
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size == -1) {
		rc = errno;
		goto out_free_table;
	}

	nr_pages = certs_size/page_size;
	if (certs_size % page_size > 0)
		nr_pages++;

	certs_data_size = page_size * nr_pages;
	if (certs_data_size < nr_pages) {
		rc = EOVERFLOW;
		goto out_free_table;
	}

	/* Allocate the required number of pages */
	certs_data = calloc(page_size, nr_pages);
	if (!certs_data) {
		rc = ENOMEM;
		perror("calloc");
		goto out_free_table;
	}

	/* Copy the cert table to offset 0 of the data buffer */
	rc = cert_table_copy(&table, certs_data, certs_data_size);
	if (rc != EXIT_SUCCESS)
		goto out_free;

	/* Use the cert table entries to place the AMD certs into the buffer */
	for (size_t i = 0; i < options->nr_amd_certs; i++) {
		FILE *file = NULL;
		size_t count = 0;
		struct cert_table_entry entry;

		if (!options->amd_certs[i])
			continue;

		switch (i) {
		case AMD_CERT_VCEK:
			rc = cert_table_get_entry(&table, &entry, vcek_guid);
			break;
		case AMD_CERT_ASK:
			rc = cert_table_get_entry(&table, &entry, ask_guid);
			break;
		case AMD_CERT_ARK:
			rc = cert_table_get_entry(&table, &entry, ark_guid);
			break;
		default:
			rc = EXIT_FAILURE;
		}

		if (rc != EXIT_SUCCESS)
			goto out_free;

		if (entry.offset + entry.length > certs_data_size) {
			rc = ENOBUFS;
			goto out_free;
		}

		errno = 0;
		file = fopen(options->amd_certs[i], "r");
		if (!file) {
			rc = errno;
			goto out_free;
		}

		count = fread(certs_data + entry.offset, sizeof(char), entry.length, file);
		if (count != entry.length) {
			rc = EIO;
			goto out_free;
		}
	}

	/* Use the cert table entries to place the non-AMD certs into the buffer */
	for (size_t i = 0; i < options->nr_guids; i++) {
		FILE *file = NULL;
		size_t count = 0;
		struct cert_table_entry entry;
		struct guid_map map = options->maps[i];

		rc = cert_table_get_entry(&table, &entry, map.guid);
		if (rc != EXIT_SUCCESS)
			goto out_free;

		if (entry.offset + entry.length > certs_data_size) {
			rc = ENOBUFS;
			goto out_free;
		}

		errno = 0;
		file = fopen(map.cert_filename, "r");
		if (!file) {
			rc = errno;
			goto out_free;
		}

		count = fread(certs_data + entry.offset, sizeof(char), entry.length, file);
		if (count != entry.length) {
			rc = EIO;
			goto out_free;
		}
	}

	*buffer = certs_data;
	*size = certs_data_size;
	rc = EXIT_SUCCESS;

out_free:
	if (rc != EXIT_SUCCESS && certs_data) {
		free(certs_data);
		certs_data = NULL;
	}

out_free_table:
	if (rc != EXIT_SUCCESS)
		cert_table_free(&table);
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

	/* Open the sev device */
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
	uint8_t *certs = NULL;
	size_t certs_size = 0;
	struct options options;

	memset(&options, 0, sizeof(options));

	rc = parse_options(argc, argv, &options);
	if (rc != EXIT_SUCCESS || options.do_help == true) {
		print_usage();
		goto exit;
	}

	rc = read_certs(&options, &certs, &certs_size);
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

