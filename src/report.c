/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdio.h>
#include <attestation.h>
#include <report.h>

/*
 * Print the platform version.
 */
void print_platform_version(struct attestation_report *report)
{
	printf("Platform Version: %02u%02u%02u%02u%02u%02u%02u%02u\n",
	       (unsigned) report->platform_version[0],
	       (unsigned) report->platform_version[1],
	       (unsigned) report->platform_version[2],
	       (unsigned) report->platform_version[3],
	       (unsigned) report->platform_version[4],
	       (unsigned) report->platform_version[5],
	       (unsigned) report->platform_version[6],
	       (unsigned) report->platform_version[7]);
	return;
}

/*
 * Print the reported TCB version needed to retreive the VCEK
 * from the AMD KDS.
 */
void print_reported_tcb(struct attestation_report *report)
{
	printf("Reported TCB: %02u%02u%02u%02u%02u%02u%02u%02u\n",
	       (unsigned) report->reported_tcb[0],
	       (unsigned) report->reported_tcb[1],
	       (unsigned) report->reported_tcb[2],
	       (unsigned) report->reported_tcb[3],
	       (unsigned) report->reported_tcb[4],
	       (unsigned) report->reported_tcb[5],
	       (unsigned) report->reported_tcb[6],
	       (unsigned) report->reported_tcb[7]);
	return;
}

