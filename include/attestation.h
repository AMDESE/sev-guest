/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdint.h>

struct attestation_report {
	uint32_t version;
	uint32_t guest_svn;
	uint64_t policy;
	uint8_t  family_id[16];
	uint8_t  image_id[16];
	uint32_t vmpl;
	uint32_t signature_algo;
	uint64_t platform_version;
	uint64_t platform_info;
	uint32_t flags;
	uint32_t reserved0;
	uint8_t  report_data[64];
	uint8_t  measurement[48];
	uint8_t  host_data[32];
	uint8_t  id_key_digest[48];
	uint8_t  author_key_digest[48];
	uint8_t  report_id[32];
	uint8_t  report_id_ma[32];
	uint8_t  reported_tcb[8];
	uint8_t  reserved1[24];
	uint8_t  chip_id[64];
	uint8_t  reserved2[192];
	uint8_t  signature[64];
};

struct msg_report_resp {
	uint32_t status;
	uint32_t report_size;
	uint8_t  reserved[0x20-0x8];
	struct attestation_report report;
};

