/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>
#include <id-block.h>

#ifndef PROG_NAME
#define PROG_NAME	"sev-host-identity"
#endif

#define NR_ARGS_REQUIRED	(2)

#define DEFAULT_POLICY	(0x300000U)

struct options {
	struct id_block id;
	char *key_file;
	char *id_block_file;
	char *auth_info_file;
	char *author_key_file;
	bool do_help;
	bool do_base64;
	bool do_fingerprint;
};

void print_usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME " [-a|--auth-info file] [-d|--digest hash]\n"
		"       [-f|--family-id id] [-h|--help] [-i|--id-block file]\n"
		"       [-m|--image-id id] [-p|--policy policy_bits] [-s|--svn svn]\n"
		"       id_key [author_key]\n"
		"\n"
		"       " PROG_NAME " -g|--fingerprint id_key [author_key]\n"
		"\n"
		"The first form constructs an ID block with the given metadata. The ID block\n"
		"will include the public portion of the key specified in 'id_key' and will be\n"
		"signed using the private portion of the same key.\n"
		"\n"
		"The second form calcualates the SHA-384 fingerprint of the given public key\n"
		"files after converting them to the SEV public key format.\n"
		"\n"
		"options:\n"
		"  -a|--auth-info file\n"
		"    The authentication information structure will be written to 'file'.\n"
		"    This option is required.\n"
		"\n"
		"  -b|--base64\n"
		"    When writing the ID block and authentication information, base64-encode\n"
		"    the binary data.\n"
		"    Default is off.\n"
		"\n"
		"  -d|--digest hash\n"
		"    'hash' is the expected launch digest of the guest image represented as a\n"
		"    hex string.\n"
		"    Default is 0x0.\n"
		"\n"
		"  -f|--famiy-id id\n"
		"    Specifies an optional Family ID of the guest image.\n"
		"    Default is 0.\n"
		"\n"
		"  -g|--fingerprint\n"
		"    Only calculate the SHA-384 fingerprint of the input key files.\n"
		"    Default is off.\n"
		"\n"
		"  -h|--help\n"
		"    Print this help message.\n"
		"\n"
		"  -i|--id-block file\n"
		"    Write the ID block structure to 'file'.\n"
		"    This option is required.\n"
		"\n"
		"  -m|--image-id id\n"
		"    Specifies an optional Image ID of the guest image.\n"
		"    Default is 0.\n"
		"\n"
		"  -p|--policy policy\n"
		"    Specifies the policy bits of the guest as a hex string. 'policy' must\n"
		"    match the policy specified by the hypervisor during guest launch.\n"
		"    Default is %#0x.\n"
		"\n"
		"  -s|--svn svn\n"
		"    Specifies the Security Version Number (SVN) of the guest image.\n"
		"    Default is 0.\n"
		"\n",
		DEFAULT_POLICY);
}

int hex_string_to_bytes(const char *src, size_t src_size, uint8_t *dst, size_t dst_size)
{
#define HEX_PREFIX		"0x"
#define NIBBLES_PER_BYTE	(2)

	int rc = -EXIT_FAILURE;
	const char *hex = src;
	size_t hex_size = src_size;

	if (!src || src_size == 0 || !dst || dst_size == 0) {
		rc = EINVAL;
		goto out;
	}

	if (strncmp(src, HEX_PREFIX, sizeof(HEX_PREFIX)) == 0) {
		hex += sizeof(HEX_PREFIX);
		hex_size -= sizeof(HEX_PREFIX);
	}

	for (int i = 0, j = 0; i < hex_size; i += NIBBLES_PER_BYTE) {
		char hex_byte[NIBBLES_PER_BYTE + 1] = {'\0'};
		char *end = NULL;
		long byte = 0;

		memcpy(hex_byte, hex + i, NIBBLES_PER_BYTE);

		if (hex_byte[0] == '\0')
			break;

		errno = 0;
		byte = strtoul(hex_byte, &end, 16);
		if (*end != '\0') {
			rc = EINVAL;
			goto out;
		}
		else if (errno != 0) {
			rc = errno;
			goto out;
		}

		if (j < dst_size) {
			dst[j++] = byte;
		}
		else {
			rc = ENOBUFS;
			goto out;
		}
	}

	rc = EXIT_SUCCESS;
out:
	return rc;
}

int parse_options(int argc, char *argv[], struct options *options)
{
	int rc = -EXIT_FAILURE;
	char *short_options = "a:bd:f:ghi:m:p:s:";
	struct option long_options[] = {
		{ "auth-info",   required_argument, NULL, 'a' },
		{ "base64",      no_argument,       NULL, 'b' },
		{ "digest",      required_argument, NULL, 'd' },
		{ "family-id",   required_argument, NULL, 'f' },
		{ "fingerprint", no_argument,       NULL, 'g' },
		{ "help",        no_argument,       NULL, 'h' },
		{ "id-block",    required_argument, NULL, 'i' },
		{ "image-id",    required_argument, NULL, 'm' },
		{ "policy",      required_argument, NULL, 'p' },
		{ "svn",         required_argument, NULL, 's' },
		{0},
	};

	if (argc < NR_ARGS_REQUIRED || !argv || !options) {
		rc = EINVAL;
		goto out;
	}

	do {
		unsigned long long value = 0;
		char *end = NULL;
		size_t length = 0;
		char option = getopt_long(argc, argv,
					  short_options, long_options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'a':
			options->auth_info_file = optarg;
			break;
		case 'b':
			options->do_base64 = true;
			break;
		case 'd':
			rc = hex_string_to_bytes(optarg, strlen(optarg),
						 options->id.ld, sizeof(options->id.ld));
			if (rc != EXIT_SUCCESS) {
				fprintf(stderr, "-%c: %s\n", option, strerror(rc));
				goto out;
			}
			break;
		case 'f':
			length = strlen(optarg);
			if (length >= sizeof(options->id.family_id)) {
				fprintf(stderr, "-%c: Family ID must be < %lu bytes.\n",
					option, sizeof(options->id.family_id));
				rc = EOVERFLOW;
				goto out;
			}
			memcpy(options->id.family_id, optarg, length);
			break;
		case 'g':
			options->do_fingerprint = true;
			break;
		case 'h':
			options->do_help = true;
			break;
		case 'i':
			options->id_block_file = optarg;
			break;
		case 'm':
			length = strlen(optarg);
			if (length >= sizeof(options->id.image_id)) {
				fprintf(stderr, "-%c: Image ID must be < %lu bytes.\n",
					option, sizeof(options->id.image_id));
				rc = EOVERFLOW;
				goto out;
			}
			memcpy(options->id.image_id, optarg, length);
			break;
		case 'p':
			if (*optarg == '\0') {
				fprintf(stderr, "-%c: policy is empty!\n", option);
				rc = EINVAL;
				goto out;
			}

			errno = 0;
			value = strtoull(optarg, &end, 16);
			if (end && *end != '\0') {
				fprintf(stderr, "-%c: invalid hex digit '%c'.\n", option, *end);
				rc = EINVAL;
				goto out;
			}
			else if (errno != 0) {
				fprintf(stderr, "-%c: %s\n", option, strerror(errno));
				rc = errno;
				goto out;
			}

			options->id.policy = value;
			break;
		case 's':
			if (*optarg == '\0') {
				fprintf(stderr, "-%c: SVN is empty!\n", option);
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

			options->id.guest_svn = (uint32_t)value;
			break;
		case ':':
		case '?':
		default:
			putchar('\n');
			rc = EINVAL;
			goto out;
		}
	} while (1);

	if (optind == argc) {
		fprintf(stderr, "ERROR: key file not specified!\n");
		rc = EINVAL;
		goto out;
	}

	options->key_file = argv[optind];
	optind++;

	if (optind < argc) {
		options->author_key_file = argv[optind];
		optind++;
	}

	if (optind != argc) {
		fprintf(stderr, "ERROR: too many arguments supplied!\n");
		rc = EINVAL;
		goto out;
	}

	if (!options->id_block_file && !options->do_fingerprint) {
		fprintf(stderr, "id block file is required!\n"
				"See -i for details.\n");
		rc = EINVAL;
		goto out;
	}

	if (!options->auth_info_file && !options->do_fingerprint) {
		fprintf(stderr, "authentication information file is required!\n"
				"See -a for details.\n");
		rc = EINVAL;
		goto out;
	}

	rc = EXIT_SUCCESS;
out:
	return rc;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#include <openssl/decoder.h>

int read_key_file(const char *filename, EVP_PKEY **key)
{
	int rc = -EXIT_FAILURE;
	FILE *file = NULL;
	OSSL_DECODER_CTX *dctx = NULL;

	if (!filename || !key) {
		rc = EINVAL;
		goto out;
	}

	/* Open the file for reading */
	file = fopen(filename, "r");
	if (!file) {
		rc = EIO;
		goto out;
	}

	dctx = OSSL_DECODER_CTX_new_for_pkey(key, NULL, NULL, NULL, 0, NULL, NULL);
	if (!dctx) {
		rc = ENOMEM;
		goto out;
	}

	if (OSSL_DECODER_CTX_get_num_decoders(dctx) == 0) {
		fprintf(stderr, "no suitable decoder found.\n");
		rc = ENODEV;
		goto out_ctx;
	}

	if (OSSL_DECODER_from_fp(dctx, file) == 0) {
		rc = EIO;
		goto out_ctx;
	}

	rc = EXIT_SUCCESS;

out_ctx:
	if (dctx) {
		OSSL_DECODER_CTX_free(dctx);
		dctx = NULL;
	}
out:
	return rc;
}

#else

#include <openssl/pem.h>
#include <openssl/x509.h>

int read_key_file(const char *filename, EVP_PKEY **key)
{
	int rc = -EXIT_FAILURE;
	BIO* bio = NULL;
	EVP_PKEY *pkey;

	if (!filename || !key) {
		rc = EINVAL;
		goto out;
	}

	/* Open for reading */
	bio = BIO_new_file(filename, "r");
	if (!bio) {
		rc = - EXIT_FAILURE;
		goto out;
	}

	rc = EXIT_SUCCESS;

    if ((pkey = d2i_PrivateKey_bio(bio, NULL))) {
		goto out;
	}

    BIO_reset(bio);
    if ((*key = d2i_PKCS8PrivateKey_bio(bio, NULL, NULL, NULL))) {
		goto out;
	}

	BIO_reset(bio);
    if ((*key = d2i_PUBKEY_bio(bio, NULL))) {
		goto out;
	}

	BIO_reset(bio);
    /* PEM_read_bio_PrivateKey() also parses PKCS #8 formats */
    if ((*key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL))) {
		goto out;
	}

    BIO_reset(bio);
    if ((*key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL))) {
		goto out;
	}

    BIO_reset(bio);
	if ((pkey = PEM_read_bio_Parameters(bio, NULL))) {
		goto out;
	}
	rc = -EXIT_FAILURE;

out:
	if (bio) {
		BIO_free(bio);
		bio = NULL;
	}

	return rc;
}

#endif

void print_byte_array(const char *label, const uint8_t *array, size_t size)
{
	if (label)
		printf("%s: ", label);

	if (!array) {
		printf("(null)\n");
		return;
	}

	for (size_t i = 0; i < size; i++) {
		printf("%02x", array[i]);
	}

	putchar('\n');
}

int print_pubkey_fingerprint(EVP_PKEY *key, const char *label)
{
	int rc = -EXIT_FAILURE;
	struct sev_ecdsa_pubkey sev_pubkey;
	uint8_t md[EVP_MAX_MD_SIZE] = {0};
	unsigned int size = sizeof(md);
	const EVP_MD* md_ctx = EVP_sha384();

	if (!key) {
		rc = EINVAL;
		goto out;
	}

	/* Convert the key to SEV format */
	rc = sev_ecdsa_pubkey_init(&sev_pubkey, key);
	if (rc != EXIT_SUCCESS)
		goto out;

	/* Hash the SEV public key */
	rc = EVP_Digest(&sev_pubkey, sizeof(sev_pubkey), md, &size, md_ctx, NULL);

	if (!rc) {
		rc = -EXIT_FAILURE;
		goto out;
	}

	/* Print the hash bytes */
	print_byte_array(label, md, size);

	rc = EXIT_SUCCESS;
out:
	return rc;
}

int write_buffer(void *buffer, size_t size, const char *filename, bool do_base64)
{
	int rc = -EXIT_FAILURE;
	BIO *bio = NULL, *base64 = NULL, *file = NULL;

	if (!buffer || size == 0 || !filename) {
		rc = EINVAL;
		goto out;
	}

	file = BIO_new_file(filename, "w");
	if (!file) {
		rc = EIO;
		goto out;
	}

	bio = file;

	if (do_base64) {
		base64 = BIO_new(BIO_f_base64());
		if (!base64) {
			rc = ENOMEM;
			goto out_bio;
		}

		BIO_set_flags(base64, BIO_FLAGS_BASE64_NO_NL);
		BIO_push(base64, file);
		bio = base64;
	}

	BIO_write(bio, buffer, size);
	BIO_flush(bio);

	rc = EXIT_SUCCESS;

out_bio:
	if (bio) {
		BIO_free_all(bio);
		base64 = NULL;
		file = NULL;
		bio = NULL;
	}
out:
	return rc;
}

int main(int argc, char *argv[])
{
	int rc = -EXIT_FAILURE;
	struct options options;
	EVP_PKEY *id_key = NULL, *author_key = NULL;
	struct id_auth_info info;

	memset(&options, 0, sizeof(options));
	id_block_init(&options.id);

	/* Set defaults */
	options.id.policy = DEFAULT_POLICY;

	/* Parse user input */
	rc = parse_options(argc, argv, &options);
	if (rc != EXIT_SUCCESS || options.do_help == true) {
		putchar('\n');
		print_usage();
		goto exit;
	}

	/* Read the ID key file */
	rc = read_key_file(options.key_file, &id_key);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("read_key_file");
		goto exit;
	}

	/* Read the author key file */
	if (options.author_key_file) {
		rc = read_key_file(options.author_key_file, &author_key);
		if (rc != EXIT_SUCCESS) {
			errno = rc;
			perror("read_key_file");
			goto exit_keys;
		}
	}

	/* Print the pubkey fingerprints, if requested */
	if (options.do_fingerprint) {
		rc = print_pubkey_fingerprint(id_key, "Identity Key");
		if (rc != EXIT_SUCCESS)
			goto exit_keys;

		if (author_key) {
			rc = print_pubkey_fingerprint(author_key, "Author Key");
			if (rc != EXIT_SUCCESS)
				goto exit_keys;
		}

		/* Stop processing here */
		goto exit_keys;
	}

	/* Construct the ID Authentication Information structure */
	rc = id_block_get_auth_info(&options.id, id_key, author_key, &info);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("id_block_get_auth_info");
		goto exit_keys;
	}

	/* Write the output files */
	rc = write_buffer(&options.id, sizeof(options.id),
			  options.id_block_file, options.do_base64);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("write_buffer");
		goto exit_keys;
	}

	rc = write_buffer(&info, sizeof(info), options.auth_info_file,
			  options.do_base64);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("write_buffer");
		goto exit_keys;
	}

	rc = EXIT_SUCCESS;

exit_keys:
	if (id_key) {
		EVP_PKEY_free(id_key);
		id_key = NULL;
	}
	if (author_key) {
		EVP_PKEY_free(author_key);
		author_key = NULL;
	}
exit:
	exit(rc);
}

