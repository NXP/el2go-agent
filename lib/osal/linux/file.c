// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>

#include "el2go_agent_status.h"
#include "osal.h"

struct osal_file {
	FILE *fp;
};

osal_file_t *osal_fopen(const char *filename, const char *mode)
{
	osal_file_t *file = NULL;

	if (!filename || !mode)
		goto exit;

	file = malloc(sizeof(osal_file_t));
	if (!file)
		goto exit;

	file->fp = fopen(filename, mode);
	if (!file->fp) {
		free(file);
		file = NULL;
		goto exit;
	}

exit:
	return file;
}

el2go_agent_t osal_fclose(osal_file_t *file)
{
	el2go_agent_t status = EL2GO_AGENT_SUCCESS;

	if (!file) {
		status = EL2GO_AGENT_INVALID_POINTER;
		goto exit;
	}

	if (file->fp) {
		if (fclose(file->fp))
			status = EL2GO_AGENT_FILE_CLOSE_ERROR;
		file->fp = NULL;
	}

	free(file);

exit:
	return status;
}

size_t osal_fread(void *ptr, size_t size, size_t nmemb, osal_file_t *file)
{
	size_t result = 0;

	if (!file || !file->fp || !ptr)
		goto exit;

	result = fread(ptr, size, nmemb, file->fp);

exit:
	return result;
}

size_t osal_fwrite(const void *ptr, size_t size, size_t nmemb,
		   osal_file_t *file)
{
	size_t result = 0;

	if (!file || !file->fp || !ptr)
		goto exit;

	result = fwrite(ptr, size, nmemb, file->fp);

exit:
	return result;
}

el2go_agent_t osal_fseek(osal_file_t *file, long offset,
			 osal_seek_origin_t origin)
{
	el2go_agent_t status = EL2GO_AGENT_SUCCESS;
	int whence = 0;

	if (!file || !file->fp) {
		status = EL2GO_AGENT_INVALID_POINTER;
		goto exit;
	}

	switch (origin) {
	case OSAL_SEEK_SET:
		whence = SEEK_SET;
		break;
	case OSAL_SEEK_CUR:
		whence = SEEK_CUR;
		break;
	case OSAL_SEEK_END:
		whence = SEEK_END;
		break;
	default:
		status = EL2GO_AGENT_FILE_SEEK_ERROR;
		goto exit;
	}

	if (fseek(file->fp, offset, whence)) {
		status = EL2GO_AGENT_FILE_SEEK_ERROR;
		goto exit;
	}

exit:
	return status;
}

long osal_ftell(osal_file_t *file)
{
	long result = -1;

	if (!file || !file->fp)
		goto exit;

	result = ftell(file->fp);

exit:
	return result;
}

el2go_agent_t osal_fflush(osal_file_t *file)
{
	el2go_agent_t status = EL2GO_AGENT_SUCCESS;

	if (!file || !file->fp) {
		status = EL2GO_AGENT_INVALID_POINTER;
		goto exit;
	}

	if (fflush(file->fp))
		status = EL2GO_AGENT_FILE_WRITE_ERROR;

exit:
	return status;
}
