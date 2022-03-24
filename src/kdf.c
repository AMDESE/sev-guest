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
#include <linux/sev-guest.h>
#include <linux/psp-sev.h>
#include <attestation.h>
#include <snp-derive-key.h>

#ifndef PROG_NAME
#define PROG_NAME	"sev-guest-kdf"
#endif

#define NR_ARGS_REQUIRED	(2)

#define SEV_GUEST_DEVICE	"/dev/sev-guest"

struct options {
	union tcb_version tcb;

	const char *key_filename;

	uint64_t fields;
	uint32_t svn;

	bool do_help;
	bool do_root_key;
};

void print_usage(void)
{
	fprintf(stderr,
		"Usage: " PROG_NAME " [-f|--family-id] [-h|--help] [-i|--image-id]\n"
		"       [-m|--measurement] [-p|--policy] [-r|--root-key]\n"
	        "       [-s|--guest-svn svn] [-t|--tcb-version version] key_file\n"
		"\n"
		"Derive a key bound to either the guest identity or the host platform.\n"
		"The key will be written to 'key_file'.\n"
		"\n"
		"options:\n"
		"  -f|--family-id\n"
		"    Mix the Family ID of the guest into the derived key.\n"
		"    Default: '0000000000000000'\n"
		"\n"
		"  -h|--help\n"
		"    Print this help message.\n"
		"\n"
		"  -i|--image-id\n"
		"    Mix the Image ID of the guest into the derived key.\n"
		"    Default: '0000000000000000'\n"
		"\n"
		"  -m|--measurement\n"
		"    Mix the launch digest of the guest into the derived key.\n"
		"    Default: '00000000000000000000000000000000'\n"
		"\n"
		"  -p|--policy\n"
		"    Mix the guest policy into the derived key.\n"
		"    Default: '0000000000000000'\n"
		"\n"
		"  -r|--root-key\n"
		"    Derive the key from the hash of the VM Root Key supplied during VM launch.\n"
		"    By default, the platform VCEK is used for key derivation.\n"
		"\n"
		"  -s|--guest-svn svn\n"
		"    Mix the given security version number (SVN) into the derived key.\n"
		"    The SVN specified must not exceed the SVN supplied at VM launch.\n"
		"    Default: '00000000'\n"
		"\n"
		"  -t|--tcb-version version\n"
		"    Mix the given TCB version string into the derived key.\n"
		"    The given TCB version string must not exceed the current TCB version.\n"
		"    Default: '0000000000000000'\n"
		"\n");
}

int set_tcb_version(union tcb_version *tcb, const char *input, size_t size)
{
	int rc = EXIT_FAILURE;
	const char reserved[4] = { '0', '0', '0', '0' };
	char *end = NULL, *error = NULL;
	char in[2*sizeof(*tcb)] = {0};

	if (!tcb || !input || size < sizeof(*tcb)) {
		rc = EINVAL;
		goto out;
	}

	if (memcmp(input + 4, reserved, sizeof(reserved)) != 0) {
		rc = EINVAL;
		goto out;
	}

	/* Copy the input, and get a pointer to the NULL terminator */
	strncpy(in, input, sizeof(in));
	end = in + strnlen(in, sizeof(in));

	/*
	 * Decode the TCB string two bytes at a time,
	 * moving from the end of the string to the front.
	 */

	/* Convert the 2-byte microcode patch level */
	errno = 0;
	tcb->microcode = strtoul(end - 2, &error, 10);
	if (errno != 0 || (error && *error != '\0')) {
		rc = EINVAL;
		goto out;
	}
	end -= 2;
	*end = '\0';

	/* Convert the 2-byte SNP patch level */
	errno = 0;
	tcb->snp = strtoul(end - 2, &error, 10);
	if (errno != 0 || (error && *error != '\0')) {
		rc = EINVAL;
		goto out;
	}
	end = in + 4;
	*end = '\0';

	/* Convert the TEE patch level */
	errno = 0;
	tcb->tee = strtoul(end - 2, &error, 10);
	if (errno != 0 || (error && *error != '\0')) {
		rc = EINVAL;
		goto out;
	}
	end -= 2;
	*end = '\0';

	/* Convert the boot loader patch level */
	errno = 0;
	tcb->boot_loader = strtoul(in, &error, 10);
	if (errno != 0 || (error && *error != '\0')) {
		rc = EINVAL;
		goto out;
	}

	rc = EXIT_SUCCESS;
out:
	return rc;
}

int parse_options(int argc, char *argv[], struct options *options)
{
	int rc = EXIT_FAILURE;
	char *short_options = "fhimprs:t:";
	struct option long_options[] = {
		{ "family-id",    no_argument,       NULL, 'f' },
		{ "help",         no_argument,       NULL, 'h' },
		{ "image-id",     no_argument,       NULL, 'i' },
		{ "measurement",  no_argument,       NULL, 'm' },
		{ "policy",       no_argument,       NULL, 'p' },
		{ "root-key",     no_argument,       NULL, 'r' },
		{ "guest-svn",    required_argument, NULL, 's' },
		{ "tcb-version",  required_argument, NULL, 't' },
		{0},
	};

	if (argc < NR_ARGS_REQUIRED || !argv || !options) {
		rc = EINVAL;
		goto out;
	}

	do {
		char *end = NULL;
		char option = getopt_long(argc, argv,
					  short_options, long_options, NULL);
		if (option == -1)
			break;

		switch (option) {
		case 'f':
			options->fields |= FIELD_FAMILY_ID_MASK;
			break;
		case 'h':
			options->do_help = true;
			break;
		case 'i':
			options->fields |= FIELD_IMAGE_ID_MASK;
			break;
		case 'm':
			options->fields |= FIELD_MEASUREMENT_MASK;
			break;
		case 'p':
			options->fields |= FIELD_POLICY_MASK;
			break;
		case 'r':
			options->do_root_key = true;
			break;
		case 's':
			options->fields |= FIELD_GUEST_SVN_MASK;

			errno = 0;
			options->svn = strtoul(optarg, &end, 10);
			if (errno != 0 || *end != '\0') {
				rc = EINVAL;
				goto out;
			}
			break;
		case 't':
			options->fields |= FIELD_TCB_VERSION_MASK;

			rc = set_tcb_version(&options->tcb, optarg, strlen(optarg));
			if (rc != EXIT_SUCCESS)
				goto out;
			break;
		case ':':
		case '?':
		default:
			putchar('\n');
			rc = EINVAL;
			goto out;
		}
	} while (1);

	if (optind == argc && !options->do_help) {
		fprintf(stderr, PROG_NAME ": must specify a key file.\n\n");
		rc = EINVAL;
		goto out;
	}

	if (optind < argc) {
		options->key_filename = argv[optind];
		optind++;
	}

	if (optind < argc) {
		fprintf(stderr, PROG_NAME ": too many non-option arguments.\n\n");
		rc = EINVAL;
		goto out;
	}

	rc = EXIT_SUCCESS;
out:
	return rc;
}

int request_key(struct options *options, uint8_t *key, size_t size)
{
	int rc = EXIT_FAILURE;
	int fd = -1;
	struct snp_derived_key_req req;
	struct snp_derived_key_resp resp;
	struct snp_guest_request_ioctl guest_req;
	struct msg_key_resp *key_resp = (struct msg_key_resp *)&resp.data;

	if (!options || !key || size < sizeof(key_resp->derived_key)) {
		rc = EINVAL;
		goto out;
	}

	/* Initialize data structures */
	memset(&req, 0, sizeof(req));
	req.root_key_select = options->do_root_key ? MSG_KEY_REQ_ROOT_KEY_SELECT_MASK
							: 0;
	req.guest_field_select = options->fields;
	req.guest_svn = options->svn;
	memcpy(&req.tcb_version, &options->tcb, sizeof(req.tcb_version));

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
	rc = ioctl(fd, SNP_GET_DERIVED_KEY, &guest_req);
	if (rc == -1) {
		rc = errno;
		perror("ioctl");
		fprintf(stderr, "firmware error %llu\n", guest_req.fw_err);
		goto out_close;
	}

	/* Check that the key was successfully derived */
	if (key_resp->status != 0 ) {
		fprintf(stderr, "firmware error %#x\n", key_resp->status);
		rc = key_resp->status;
		goto out_close;
	}

	memcpy(key, &key_resp->derived_key, size);
	rc = EXIT_SUCCESS;

out_close:
	if (fd > 0) {
		close(fd);
		fd = -1;
	}
out:
	return rc;
}

int write_key(const char *file_name, uint8_t *key, size_t size)
{
	int rc = EXIT_FAILURE;
	FILE *key_file = NULL;

	/* Open the output key file */
	errno = 0;
	key_file = fopen(file_name, "w+");
	if (!key_file) {
		rc = errno;
		perror("fopen");
		goto out;
	}

	/* Write the key to the output */
	int count = fwrite(key, sizeof(char), size, key_file);
	if (count != size) {
		rc = EIO;
		fprintf(stderr, "fwrite failed.\n");
		goto out_close;
	}

	printf("wrote %s\n", file_name);
	rc = EXIT_SUCCESS;

out_close:
	if (key_file != stdin) {
		fclose(key_file);
		key_file = NULL;
	}
out:
	return rc;
}

int main(int argc, char *argv[])
{
	int rc = EXIT_FAILURE;
	struct options options;
	uint8_t key[MSG_KEY_RSP_DERIVED_KEY_SIZE] = {0};

	memset(&options, 0, sizeof(options));

	/* Parse command line options */
	rc = parse_options(argc, argv, &options);
	if (rc != EXIT_SUCCESS) {
		print_usage();
		goto exit;
	}

	if (options.do_help == true) {
		print_usage();
		goto exit;
	}

	/* Retrieve the derived key from the SEV FW */
	rc = request_key(&options, key, sizeof(key));
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("request_key");
		goto exit;
	}

	/* Write the key to the output file */
	rc = write_key(options.key_filename, key, sizeof(key));
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("write_key");
		goto exit;
	}

	rc = EXIT_SUCCESS;
exit:
	exit(rc);
}

