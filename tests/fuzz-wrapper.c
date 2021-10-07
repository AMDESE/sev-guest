/* Copyright (C) 2021 Advanced Micro Devices, Inc. */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#ifndef PROG_NAME
#define PROG_NAME	"sev-guest-get-report"
#endif

#define NR_REQ_ARGS	1

int build_cmd(const char *prog_name, const char *args, char **cmd, size_t *cmd_size)
{
	int rc = EXIT_FAILURE;
	size_t size = 0, buffer_size = 0;
	char *buffer = NULL;

	if (!prog_name || !args || !cmd || !cmd_size) {
		rc = EINVAL;
		goto out;
	}

	size = snprintf(NULL, 0, "%s %s", prog_name, args);
	if (size < 0) {
		rc = EIO;
		goto out;
	}

	buffer_size = size + 1;
	buffer = calloc(buffer_size, sizeof(char));
	if (!buffer) {
		rc = ENOMEM;
		goto out;
	}

	size = snprintf(buffer, buffer_size, "%s %s", prog_name, args);
	if (size >= buffer_size) {
		rc = ENOBUFS;
		goto out_free;
	}

	*cmd = buffer;
	*cmd_size = size;
	rc = EXIT_SUCCESS;

out_free:
	if (buffer && rc != EXIT_SUCCESS) {
		free(buffer);
		buffer = NULL;
	}
out:
	return rc;
}

int main(int argc, char *argv[])
{
	int rc = 0;
	char *line = NULL, *cmd = NULL;
	size_t line_size = 0, count = 0, cmd_size = 0;

	if (argc != NR_REQ_ARGS) {
		rc = EINVAL;
		errno = rc;
		perror(argv[0]);
		goto exit;
	}

	/*
	 * Get the command line arguments from the file.
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

	/* Build the full command */
	rc = build_cmd(PROG_NAME, line, &cmd, &cmd_size);
	if (rc != EXIT_SUCCESS) {
		errno = rc;
		perror("build_cmd");
		goto exit_free;
	}

	errno = 0;
	rc = system(cmd);
	if (rc == -1) {
		rc = errno;
		perror("system");
		goto exit_free_cmd;
	}
	else if (WIFEXITED(rc) && WEXITSTATUS(rc) != EXIT_SUCCESS) {
		rc = WEXITSTATUS(rc);
		errno = rc;
		perror("command failed");
		goto exit_free_cmd;
	}

	rc = EXIT_SUCCESS;

exit_free_cmd:
	if (cmd) {
		free(cmd);
		cmd = NULL;
	}

exit_free:
	if (line) {
		free(line);
		line = NULL;
	}

exit:
	exit(rc);
}

