/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#ifndef CERT_TABLE_H
#define CERT_TABLE_H

#include <stdint.h>
#include <uuid/uuid.h>

extern const char vcek_guid[];
extern const char ask_guid[];
extern const char ark_guid[];

/*
 * Per the GHCB spec version 2, this table must be terminated
 * by an entry containing all zeros.
 */
struct cert_table {
	struct cert_table_entry {
		uuid_t   guid;
		uint32_t offset;
		uint32_t length;
	} *entry;
};

int cert_table_alloc(struct cert_table *table, size_t nr_entries);
void cert_table_free(struct cert_table *table);
size_t cert_table_get_size(const struct cert_table *table);
int cert_table_get_certs_size(const struct cert_table *table, size_t *size);
int cert_table_add_entry(struct cert_table *table, const char *guid, size_t cert_size);
int cert_table_get_entry(const struct cert_table *table, struct cert_table_entry *entry, const char *guid);
int cert_table_copy(const struct cert_table *table, uint8_t *buffer, size_t size);
int cert_table_append_cert(const struct cert_table *table,
			   uint8_t *buffer, size_t buffer_size,
			   const char *guid, uint8_t *cert, size_t cert_size);

#endif	/* CERT_TABLE_H */
