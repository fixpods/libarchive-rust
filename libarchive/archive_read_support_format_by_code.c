/*-
 * Copyright (c) 2003-2011 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "archive_platform.h"
__FBSDID("$FreeBSD$");

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "archive.h"
#include "archive_private.h"

#ifndef COMPILE_WITH_RUST
struct archive_by_code_defined_param
{
	unsigned int archive_read_magic;
	unsigned int archive_state_new;
	int archive_format_base_mask;
	int archive_format_7zip;
	int archive_format_ar;
	int archive_format_cab;
	int archive_format_cpio;
	int archive_format_empty;
	int archive_format_iso9660;
	int archive_format_lha;
	int archive_format_mtree;
	int archive_format_rar;
	int archive_format_rar_v5;
	int archive_format_raw;
	int archive_format_tar;
	int archive_format_warc;
	int archive_format_xar;
	int archive_format_zip;
	int archive_errno_programmer;
	int archive_fatal;
};

struct archive_by_code_defined_param get_archive_by_code_defined_param();
struct archive_by_code_defined_param get_archive_by_code_defined_param()
{
	struct archive_by_code_defined_param defined_param;
	defined_param.archive_read_magic = ARCHIVE_READ_MAGIC;
	defined_param.archive_state_new = ARCHIVE_STATE_NEW;
	defined_param.archive_format_base_mask = ARCHIVE_FORMAT_BASE_MASK;
	defined_param.archive_format_7zip = ARCHIVE_FORMAT_7ZIP;
	defined_param.archive_format_ar = ARCHIVE_FORMAT_AR;
	defined_param.archive_format_cab = ARCHIVE_FORMAT_CAB;
	defined_param.archive_format_cpio = ARCHIVE_FORMAT_CPIO;
	defined_param.archive_format_empty = ARCHIVE_FORMAT_EMPTY;
	defined_param.archive_format_iso9660 = ARCHIVE_FORMAT_ISO9660;
	defined_param.archive_format_lha = ARCHIVE_FORMAT_LHA;
	defined_param.archive_format_mtree = ARCHIVE_FORMAT_MTREE;
	defined_param.archive_format_rar = ARCHIVE_FORMAT_RAR;
	defined_param.archive_format_rar_v5 = ARCHIVE_FORMAT_RAR_V5;
	defined_param.archive_format_raw = ARCHIVE_FORMAT_RAW;
	defined_param.archive_format_tar = ARCHIVE_FORMAT_TAR;
	defined_param.archive_format_warc = ARCHIVE_FORMAT_WARC;
	defined_param.archive_format_xar = ARCHIVE_FORMAT_XAR;
	defined_param.archive_format_zip = ARCHIVE_FORMAT_ZIP;
	defined_param.archive_errno_programmer = ARCHIVE_ERRNO_PROGRAMMER;
	defined_param.archive_fatal = ARCHIVE_FATAL;
	return defined_param;
}

int archive_read_support_format_by_code(struct archive *_a, int format_code)
{
	return 0;
}

#endif