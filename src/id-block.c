/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <id-block.h>
#include <sev-ecdsa.h>

void id_block_init(struct id_block *id)
{
	if (id) {
		memset(id, 0, sizeof(*id));
		id->version = ID_BLK_VERSION;
	}
}

void id_block_auth_info_init(struct id_auth_info *info)
{
	if (info) {
		memset(info, 0, sizeof(*info));
	}
}

int id_block_get_auth_info(struct id_block *id, EVP_PKEY *id_key,
			   EVP_PKEY *author_key, struct id_auth_info *info)
{
	int rc = EXIT_FAILURE;
	struct id_auth_info auth;

	if (!id || !id_key || !info) {
		rc = EINVAL;
		goto out;
	}

	id_block_auth_info_init(&auth);

	/*
	 * Check that the ID key meets SEV requirements and
	 * store the public portion in SEV format.
	 */
	rc = sev_ecdsa_pubkey_init(&auth.id_pubkey, id_key);
	if (rc != EXIT_SUCCESS)
		goto out;

	auth.id_key_algo = SEV_ALGO_ECDSA_P384_SHA384;

	/* Sign ID block with the ID key */
	rc = sev_ecdsa_sign(id, sizeof(*id), id_key, &auth.id_block_sig);
	if (rc != EXIT_SUCCESS)
		goto out;

	if (author_key) {
		/*
		 * Check that the Author key meets SEV requirements and
		 * store the public portion in SEV format.
		 */
		rc = sev_ecdsa_pubkey_init(&auth.author_pubkey, author_key);
		if (rc != EXIT_SUCCESS)
			goto out;

		auth.author_key_algo = SEV_ALGO_ECDSA_P384_SHA384;

		/* Sign the ID key with the Author key */
		rc = sev_ecdsa_sign(&auth.id_pubkey, sizeof(auth.id_pubkey),
				    author_key, &auth.id_key_sig);
		if (rc != EXIT_SUCCESS)
			goto out;
	}

	memcpy(info, &auth, sizeof(*info));
	rc = EXIT_SUCCESS;
out:
	return rc;
}

