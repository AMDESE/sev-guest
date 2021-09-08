/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdio.h>
#include <attestation.h>
#include <report.h>

/*
 * Print the platform version.
 */
void print_platform_version(struct attestation_report *report)
{
	if (report) {
		printf("Platform Version: %02u%02u%02u%02u%02u%02u%02u%02u\n",
		       (unsigned) report->platform_version[0],
		       (unsigned) report->platform_version[1],
		       (unsigned) report->platform_version[2],
		       (unsigned) report->platform_version[3],
		       (unsigned) report->platform_version[4],
		       (unsigned) report->platform_version[5],
		       (unsigned) report->platform_version[6],
		       (unsigned) report->platform_version[7]);
	}
	return;
}

/*
 * Print the reported TCB version needed to retreive the VCEK
 * from the AMD KDS.
 */
void print_reported_tcb(struct attestation_report *report)
{
	if (report) {
		printf("Reported TCB: %02u%02u%02u%02u%02u%02u%02u%02u\n",
		       (unsigned) report->reported_tcb[0],
		       (unsigned) report->reported_tcb[1],
		       (unsigned) report->reported_tcb[2],
		       (unsigned) report->reported_tcb[3],
		       (unsigned) report->reported_tcb[4],
		       (unsigned) report->reported_tcb[5],
		       (unsigned) report->reported_tcb[6],
		       (unsigned) report->reported_tcb[7]);
	}
	return;
}

/*
 * Print the report data (in hex) supplied by the guest.
 */
void print_report_data(struct attestation_report *report)
{
#define BYTES_PER_LINE	32
#define INDENT	"    "

	if (report) {
		printf("Report Data: ");
		for (size_t i = 0; i < sizeof(report->report_data); i++) {
			if (i % BYTES_PER_LINE == 0)
				printf("\n"
				       INDENT);
			printf("%02x", report->report_data[i]);
		}
		putchar('\n');
	}
	return;
}

