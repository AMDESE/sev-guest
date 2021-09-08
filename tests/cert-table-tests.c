
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <cert-table.h>

#define CERT_SIZE	128
#define NR_CERTS	3

int build_cert_table(struct cert_table *table)
{
	int rc = EXIT_FAILURE;

	if (!table) {
		rc = EINVAL;
		goto out;
	}

	rc = cert_table_alloc(table, NR_CERTS);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("cert_table_alloc");
		goto out;
	}

	rc = cert_table_add_entry(table, vcek_guid, CERT_SIZE);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("cert_table_add_entry");
		goto out_free;
	}

	rc = cert_table_add_entry(table, ask_guid, CERT_SIZE);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("cert_table_add_entry");
		goto out_free;
	}

	rc = cert_table_add_entry(table, ark_guid, CERT_SIZE);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("cert_table_add_entry");
		goto out_free;
	}

	rc = EXIT_SUCCESS;

out_free:
	if (rc != EXIT_SUCCESS && table->entry) {
		cert_table_free(table);
		table = NULL;
	}

out:
	return rc;
}

int build_cert_buffer(struct cert_table *table, uint8_t **buffer, size_t *buffer_size)
{
	int rc = EXIT_FAILURE;
	uint8_t cert[CERT_SIZE] = {'a'};
	size_t cert_size = sizeof(cert);
	size_t table_size = 0, certs_size = 0, total_size = 0;
	uint8_t *certs = NULL;

	if (!table) {
		rc = EINVAL;
		goto out;
	}

	table_size = cert_table_get_size(table);
	if (table_size == 0) {
		rc = ENODATA;
		errno = rc;
		perror("cert_table_get_size");
		goto out;
	}
	else if (table_size != sizeof(struct cert_table_entry)*(NR_CERTS + 1)) {
		rc = EMSGSIZE;
		errno = rc;
		perror("cert_table_get_size");
		goto out;
	}

	rc = cert_table_get_certs_size(table, &certs_size);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("cert_table_get_certs_size");
		goto out;
	}
	else if (certs_size != NR_CERTS*CERT_SIZE) {
		rc = EMSGSIZE;
		errno = rc;
		perror("cert_table_get_size");
		goto out;
	}

	total_size = table_size + certs_size;
	certs = calloc(sizeof(char), total_size);
	if (!certs) {
		rc = ENOMEM;
		errno = rc;
		perror("calloc");
		goto out;
	}

	memset(cert, 'a', cert_size);
	rc = cert_table_append_cert(table, certs, total_size, vcek_guid, cert, cert_size);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("cert_table_append_cert");
		goto out_free;
	}

	memset(cert, 'b', cert_size);
	rc = cert_table_append_cert(table, certs, total_size, vcek_guid, cert, cert_size);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("cert_table_append_cert");
		goto out_free;
	}

	memset(cert, 'c', cert_size);
	rc = cert_table_append_cert(table, certs, total_size, vcek_guid, cert, cert_size);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("cert_table_append_cert");
		goto out_free;
	}

	*buffer = certs;
	*buffer_size = total_size;
	rc = EXIT_SUCCESS;

out_free:
	if (rc != EXIT_SUCCESS && buffer) {
		free(buffer);
		buffer = NULL;
	}

out:
	return rc;
}

int main (int argc, char *argv[])
{
	int rc = EXIT_FAILURE;
	struct cert_table table = {};
	uint8_t *certs = NULL;
	size_t certs_size = 0, table_size = 0;
	uuid_t zero_uuid = {0};

	rc = build_cert_table(&table);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("build_cert_table");
		goto exit;
	}

	rc = build_cert_buffer(&table, &certs, &certs_size);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("build_cert_buffer");
		goto exit_free;
	}

	table_size = cert_table_get_size(&table);
	if (table_size == 0) {
		rc = ENODATA;
		errno = rc;
		perror("cert_table_get_size");
		goto exit_free_certs;
	}
	else if (table_size != sizeof(struct cert_table_entry)*(NR_CERTS + 1)) {
		rc = EMSGSIZE;
		errno = rc;
		perror("cert_table_get_size");
		goto exit_free_certs;
	}

	for (size_t i = 0; i < NR_CERTS && table.entry[i].length != 0; i++) {
		struct cert_table_entry *entry = table.entry + i;
		uint64_t table_end_addr = (uint64_t)&table.entry[0] + table_size;
		char guid[UUID_STR_LEN] = {'\0'};

		if ((uint64_t)entry >= table_end_addr) {
			rc = EOVERFLOW;
			fprintf(stderr, "cert table has no terminator entry!\n");
			goto exit_free_certs;
		}

		uuid_unparse(entry->guid, guid);

		printf("cert table entry %lu:\n", i);
		printf("    guid:   %s\n", guid);
		printf("    offset: %u\n", entry->offset);
		printf("    length: %u\n", entry->length);
		putchar('\n');
	}

	/* Ensure that the table is properly terminated */
	if (memcmp(table.entry[NR_CERTS+1].guid, zero_uuid, sizeof(zero_uuid) != 0 ||
	    table.entry[NR_CERTS+1].offset != 0 ||
	    table.entry[NR_CERTS+1].length !=0)) {
		rc = EBADR;
		fprintf(stderr, "terminating table entry is not empty!\n");
		goto exit_free_certs;
	}

	printf("All tests passed!\n");
	rc = EXIT_SUCCESS;

exit_free_certs:
	if (certs) {
		free(certs);
		certs = NULL;
	}

exit_free:
	cert_table_free(&table);
exit:
	exit(rc);
}

