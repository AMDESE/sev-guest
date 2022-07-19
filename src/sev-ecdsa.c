/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <sev-ecdsa.h>
#include <secg-sec1.h>

#define CURVE_NAME_SIZE	(16)
#define SEV_CURVE_NAME	"secp384r1"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

static int validate_evp_key(EVP_PKEY *key)
{
	int rc = -EXIT_FAILURE;
	char curve[CURVE_NAME_SIZE] = {'\0'};

	if (!key) {
		rc = EINVAL;
		goto out;
	}

	if (!EVP_PKEY_is_a(key, "EC")) {
		rc = ENOKEY;
		goto out;
	}

	if (!EVP_PKEY_can_sign(key)) {
		rc = EOPNOTSUPP;
		goto out;
	}

	if (!EVP_PKEY_get_group_name(key, curve, sizeof(curve), NULL)) {
		rc = ENOBUFS;
		goto out;
	}

	if (strncmp(curve, SEV_CURVE_NAME, sizeof(curve))) {
		fprintf(stderr, "input key is %s.\n", curve);
		fprintf(stderr, "SEV keys must use curve %s.\n", SEV_CURVE_NAME);
		rc = ENOKEY;
	}

	rc = EXIT_SUCCESS;
out:
	return rc;
}

#else

static int validate_evp_key(EVP_PKEY *key)
{
	return EXIT_SUCCESS;
}

#endif

static bool is_curve_valid(enum ecdsa_curve curve)
{
	bool result = false;

	switch (curve) {
	case ECDSA_CURVE_P384:
		result = true;
		break;
	default:
		result = false;
	}
	return result;
}

static int sev_ecdsa_pubkey_set_curve(struct sev_ecdsa_pubkey *pubkey, enum ecdsa_curve curve)
{
	int rc = -EXIT_FAILURE;

	if (!pubkey || !is_curve_valid(curve)) {
		rc = EINVAL;
		goto out;
	}

	pubkey->curve = curve;
	rc = EXIT_SUCCESS;
out:
	return rc;
}

static void reverse_bytes(uint8_t *buffer, size_t size)
{
	if (!buffer || size == 0)
		return;

	for (uint8_t *start = buffer, *end = buffer + size - 1; start < end; start++, end--) {
		uint8_t temp = *start;
		*start = *end;
		*end = temp;
	}
}

static int sev_ecdsa_pubkey_set_point(struct sev_ecdsa_pubkey *pubkey,
				      const union secg_ec_point_384 *point)
{
	int rc = -EXIT_FAILURE;

	if (!pubkey || !point) {
		rc = EINVAL;
		goto out;
	}

	if (point->point.w != 0x04) {
		rc = EKEYREJECTED;
		goto out;
	}

	memcpy(pubkey->qx, point->point.x, sizeof(point->point.x));
	memcpy(pubkey->qy, point->point.y, sizeof(point->point.y));

	reverse_bytes(pubkey->qx, sizeof(point->point.x));
	reverse_bytes(pubkey->qy, sizeof(point->point.y));

	rc = EXIT_SUCCESS;
out:
	return rc;
}

int sev_ecdsa_pubkey_init(struct sev_ecdsa_pubkey *pubkey, EVP_PKEY *evp_key)
{
	int rc = -EXIT_FAILURE;
	struct sev_ecdsa_pubkey key;
	size_t size = 0;
	union secg_ec_point_384 q;

	if (!pubkey || !evp_key) {
		rc = EINVAL;
		goto out;
	}

	memset(&key, 0, sizeof(key));

	rc = validate_evp_key(evp_key);
	if (rc != EXIT_SUCCESS) {
		rc = ENOKEY;
		goto out;
	}

	rc = sev_ecdsa_pubkey_set_curve(&key, ECDSA_CURVE_P384);
	if (rc != EXIT_SUCCESS)
		goto out;

	EVP_PKEY_get_raw_public_key(evp_key, NULL, &size);
	if (size - 1 > sizeof(pubkey->bytes)) {
		rc = ENOBUFS;
		goto out;
	}

	if (!EVP_PKEY_get_raw_public_key(evp_key, q.bytes, &size)) {
		ERR_print_errors_fp(stderr);
		rc = -EXIT_FAILURE;
		goto out;
	}

	rc = sev_ecdsa_pubkey_set_point(&key, &q);
	if (rc != EXIT_SUCCESS)
		goto out;

	memcpy(pubkey, &key, sizeof(*pubkey));
	rc = EXIT_SUCCESS;
out:
	return rc;
}

/*
 * Extract r and s from an ecdsa signature.
 *
 * Based on get_ecdsa_sig_rs_bytes() in test/acvp_test.c from OpenSSL.
 */
static int get_ecdsa_sig_rs_bytes(const unsigned char *sig, size_t sig_len,
				  unsigned char *r, unsigned char *s,
				  size_t *rlen, size_t *slen)
{
	int rc = -EXIT_FAILURE;
	unsigned char *rbuf = NULL, *sbuf = NULL;
	size_t r1_len, s1_len;
	const BIGNUM *r1, *s1;
	ECDSA_SIG *sign = d2i_ECDSA_SIG(NULL, &sig, sig_len);

	if (sign == NULL || !r || !s || !rlen || !slen) {
		rc = EINVAL;
		goto out;
	}

	r1 = ECDSA_SIG_get0_r(sign);
	s1 = ECDSA_SIG_get0_s(sign);
	if (r1 == NULL || s1 == NULL) {
		rc = EINVAL;
		goto err_sign;
	}

	r1_len = BN_num_bytes(r1);
	s1_len = BN_num_bytes(s1);
	if (r1_len > *rlen || s1_len > *slen) {
		rc = ENOBUFS;
		goto err_sign;
	}

	rbuf = OPENSSL_zalloc(r1_len);
	sbuf = OPENSSL_zalloc(s1_len);
	if (rbuf == NULL || sbuf == NULL) {
		rc = ENOMEM;
		goto err_buf;
	}
	if (BN_bn2binpad(r1, rbuf, r1_len) <= 0) {
		rc = EINVAL;
		goto err_buf;
	}
	if (BN_bn2binpad(s1, sbuf, s1_len) <= 0) {
		rc = EINVAL;
		goto err_buf;
	}

	memcpy(r, rbuf, r1_len);
	memcpy(s, sbuf, s1_len);
	*rlen = r1_len;
	*slen = s1_len;

	rc = EXIT_SUCCESS;

err_buf:
	if (rbuf) {
		OPENSSL_free(rbuf);
		rbuf = NULL;
	}
	if (sbuf) {
		OPENSSL_free(sbuf);
		sbuf = NULL;
	}

err_sign:
	if (sign) {
		ECDSA_SIG_free(sign);
		sign = NULL;
	}
out:
	return rc;
}

int sev_ecdsa_sign(const void *msg, size_t msg_size, EVP_PKEY *key, union sev_ecdsa_sig *sig)
{
	int rc = -EXIT_FAILURE;
	EVP_MD_CTX *md_ctx = NULL;
	EVP_PKEY_CTX *sign_ctx = NULL;
	uint8_t *ossl_sig = NULL;
	size_t expected_size = 0, sig_size = 0;
	size_t r_size = sizeof(sig->r);
	size_t s_size = sizeof(sig->s);

	if (!msg || msg_size == 0 || !key || !sig) {
		rc = EINVAL;
		goto out;
	}

	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx) {
		ERR_print_errors_fp(stderr);
		rc = ENOMEM;
		goto out;
	}

	if (!EVP_DigestSignInit(md_ctx, &sign_ctx, EVP_sha384(), NULL, key)) {
		ERR_print_errors_fp(stderr);
		rc = -EXIT_FAILURE;
		goto out_md_ctx;
	}

	/* Get the expected size of the signature */
	if (!EVP_DigestSign(md_ctx, NULL, &expected_size, msg, msg_size)) {
		ERR_print_errors_fp(stderr);
		rc = -EXIT_FAILURE;
		goto out_md_ctx;
	}

	ossl_sig = (uint8_t *) OPENSSL_zalloc(expected_size);
	if (!sig) {
		rc = ENOMEM;
		goto out_md_ctx;
	}

	sig_size = expected_size;

	if (!EVP_DigestSign(md_ctx, ossl_sig, &sig_size, msg, msg_size)) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "sig_size = %lu (was %lu)\n", sig_size, expected_size);
		fprintf(stderr, "DRBG status: %s\n", RAND_status() ? "good" : "bad");
		rc = -EXIT_FAILURE;
		goto out_sig;
	}

	if (sig_size > expected_size) {
		fprintf(stderr, "%s: signature requires %lu bytes! (%lu allocated)\n",
			__func__, sig_size, expected_size);
		rc = ENOBUFS;
		goto out_sig;
	}

	/* Store the R & S components of the ID block signature */
	rc = get_ecdsa_sig_rs_bytes(ossl_sig, sig_size, sig->r, sig->s, &r_size, &s_size);
	if (rc != EXIT_SUCCESS)
		goto out_sig;

	reverse_bytes(sig->r, r_size);
	reverse_bytes(sig->s, s_size);

	rc = EXIT_SUCCESS;

out_sig:
	if (ossl_sig) {
		OPENSSL_free(ossl_sig);
		ossl_sig = NULL;
	}

out_md_ctx:
	if (md_ctx) {
		EVP_MD_CTX_free(md_ctx);
		md_ctx = NULL;
	}
out:
	return rc;
}

