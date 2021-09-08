/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <stdint.h>

struct attestation_report {
	uint32_t version;		/* 0x000 */
	uint32_t guest_svn;		/* 0x004 */
	uint64_t policy;		/* 0x008 */
	uint8_t  family_id[16];		/* 0x010 */
	uint8_t  image_id[16];		/* 0x020 */
	uint32_t vmpl;			/* 0x030 */
	uint32_t signature_algo;	/* 0x034 */
	uint8_t  platform_version[8];	/* 0x038 */
	uint64_t platform_info;		/* 0x040 */
	uint32_t flags;			/* 0x048 */
	uint32_t reserved0;		/* 0x04C */
	uint8_t  report_data[64];	/* 0x050 */
	uint8_t  measurement[48];	/* 0x090 */
	uint8_t  host_data[32];		/* 0x0C0 */
	uint8_t  id_key_digest[48];	/* 0x0E0 */
	uint8_t  author_key_digest[48];	/* 0x110 */
	uint8_t  report_id[32];		/* 0x140 */
	uint8_t  report_id_ma[32];	/* 0x160 */
	uint8_t  reported_tcb[8];	/* 0x180 */
	uint8_t  reserved1[24];		/* 0x188 */
	uint8_t  chip_id[64];		/* 0x1A0 */
	uint8_t  reserved2[192];	/* 0x1E0 */
	uint8_t  signature[512];	/* 0x2A0 */
};

struct msg_report_resp {
	uint32_t status;
	uint32_t report_size;
	uint8_t  reserved[0x20-0x8];
	struct attestation_report report;
};

#endif	/* ATTESTATION_H */
