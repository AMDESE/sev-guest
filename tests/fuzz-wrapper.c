/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define NR_REQ_ARGS	1

int main(int argc, char *argv[])
{
	int rc = 0;
	char *line = NULL;
	size_t line_size = 0, count = 0;

	if (argc != NR_REQ_ARGS) {
		rc = EINVAL;
		errno = rc;
		perror(argv[0]);
		goto exit;
	}

	/*
	 * Get the command to execute from the file.
	 * NOTE: the full command must be on a single line.
	 */
	errno = 0;
	count = getline(&line, &line_size, stdin);
	if (count == -1) {
		rc = errno;
		perror("getline");
		goto exit_free;
	}

	/* Check that there are no additional lines in the file */
	errno = 0;
	count = getline(&line, &line_size, stdin);
	if (count != -1) {
		rc = EFBIG;
		errno = rc;
		perror("getline");
		goto exit_free;
	}

	errno = 0;
	rc = system(line);
	if (rc == -1) {
		rc = errno;
		perror("system");
		goto exit_free;
	}
	else if (WIFEXITED(rc) && WEXITSTATUS(rc) != EXIT_SUCCESS) {
		rc = WEXITSTATUS(rc);
		errno = rc;
		perror("command failed");
		goto exit_free;
	}

	rc = EXIT_SUCCESS;

exit_free:
	if (line) {
		free(line);
		line = NULL;
	}

exit:
	exit(rc);
}

