/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#ifndef SEV_ECDSA_H
#define SEV_ECDSA_H

#include <stdint.h>
#include <openssl/evp.h>
#include <secg-sec1.h>

#define BITS_PER_BYTE	(8)

#define ECDSA_POINT_SIZE_BITS	(576)
#define ECDSA_POINT_SIZE	((ECDSA_POINT_SIZE_BITS)/(BITS_PER_BYTE))
#define ECDSA_PUBKEY_RSVD_SIZE	(0x403 - 0x94 + 1)
#define ECDSA_SIG_RSVD_SIZE	(0x1ff - 0x90 + 1)
#define ECDSA_PUBKEY_SIZE	(0x404)
#define ECDSA_SIG_SIZE		(0x200)

enum sev_algo {
	SEV_ALGO_INVALID = 0,
	SEV_ALGO_ECDSA_P384_SHA384 = 1,

	SEV_ALGO_LIMIT,
};

enum ecdsa_curve {
	ECDSA_CURVE_INVALID = 0,
	ECDSA_CURVE_P384 = 2,

	ECDSA_CURVE_LIMIT,
};

struct sev_ecdsa_pubkey {
	uint32_t curve;
	union {
		struct {
			uint8_t qx[ECDSA_POINT_SIZE];
			uint8_t qy[ECDSA_POINT_SIZE];
			uint8_t reserved[ECDSA_PUBKEY_RSVD_SIZE];
		};
		uint8_t bytes[2*ECDSA_POINT_SIZE];
	};
};

union sev_ecdsa_sig {
	struct {
		uint8_t r[ECDSA_POINT_SIZE];
		uint8_t s[ECDSA_POINT_SIZE];
		uint8_t reserved[ECDSA_SIG_RSVD_SIZE];
	};
	uint8_t bytes[2*ECDSA_POINT_SIZE];
};

int  sev_ecdsa_pubkey_init(struct sev_ecdsa_pubkey *pubkey, EVP_PKEY *evp_key);
int  sev_ecdsa_sign(const void *msg, size_t msg_size, EVP_PKEY *key, union sev_ecdsa_sig *sig);

#endif	/* SEV_ECDSA_H */
