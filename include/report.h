/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#ifndef REPORT_H
#define REPORT_H

#include <attestation.h>

/*
 * Print the reported TCB version needed to retreive the VCEK
 * from the AMD KDS.
 */
void print_reported_tcb(struct attestation_report *report);

/*
 * Print the TCB version.
 */
void print_tcb(struct attestation_report *report);

/*
 * Print the report data (in hex) supplied by the guest.
 */
void print_report_data(struct attestation_report *report);

#endif	/* REPORT_H */
