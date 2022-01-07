/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#ifndef ID_BLOCK_H
#define ID_BLOCK_H

#include <stdint.h>
#include <openssl/evp.h>
#include <sev-ecdsa.h>

#define ID_BLK_DIGEST_BITS	(384)
#define ID_BLK_DIGEST_BYTES	((ID_BLK_DIGEST_BITS)/(BITS_PER_BYTE))

#define ID_BLK_FAMILY_ID_BITS	(128)
#define ID_BLK_FAMILY_ID_BYTES	((ID_BLK_FAMILY_ID_BITS)/(BITS_PER_BYTE))

#define ID_BLK_IMAGE_ID_BITS	(128)
#define ID_BLK_IMAGE_ID_BYTES	((ID_BLK_IMAGE_ID_BITS)/(BITS_PER_BYTE))

#define ID_BLK_VERSION		(1u)

struct id_block {
	uint8_t  ld[ID_BLK_DIGEST_BYTES];
	uint8_t  family_id[ID_BLK_FAMILY_ID_BYTES];
	uint8_t  image_id[ID_BLK_IMAGE_ID_BYTES];
	uint32_t version;
	uint32_t guest_svn;
	uint64_t policy;
};

#define ID_AUTH_INFO_RESERVED1_BYTES	(0x03F - 0x008 + 1)
#define ID_AUTH_INFO_RESERVED2_BYTES	(0x67F - 0x644 + 1)
#define ID_AUTH_INFO_RESERVED3_BYTES	(0xFFF - 0xC84 + 1)

struct id_auth_info {
	uint32_t id_key_algo;
	uint32_t author_key_algo;

	uint8_t reserved1[ID_AUTH_INFO_RESERVED1_BYTES];

	union  sev_ecdsa_sig    id_block_sig;
	struct sev_ecdsa_pubkey id_pubkey;

	uint8_t reserved2[ID_AUTH_INFO_RESERVED2_BYTES];

	union  sev_ecdsa_sig    id_key_sig;
	struct sev_ecdsa_pubkey author_pubkey;

	uint8_t reserved3[ID_AUTH_INFO_RESERVED3_BYTES];
};

void id_block_init(struct id_block *id);
void id_block_auth_info_init(struct id_auth_info *info);
int id_block_get_auth_info(struct id_block *id, EVP_PKEY *id_key,
			   EVP_PKEY *author_key, struct id_auth_info *info);

#endif	/* ID_BLOCK_H */
