/*-
 * Copyright (c) 2003-2009 Tim Kientzle
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
__FBSDID("$FreeBSD: head/lib/libarchive/archive_read_support_format_raw.c 201107 2009-12-28 03:25:33Z kientzle $");

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "archive.h"
#include "archive_entry.h"
#include "archive_private.h"
#include "archive_read_private.h"

#ifndef COMPILE_WITH_RUST

struct archive_raw_defined_param
{
	unsigned int archive_read_magic;
	unsigned int archive_state_new;
	int archive_format_raw;
	int enomem;
	int archive_ok;
	int archive_eof;
	int archive_fatal;
	unsigned int ae_ifreg;
};

struct archive_raw_defined_param get_archive_raw_defined_param();

struct archive_raw_defined_param get_archive_raw_defined_param()
{
	struct archive_raw_defined_param defined_param;
	defined_param.archive_read_magic = ARCHIVE_READ_MAGIC;
	defined_param.archive_state_new = ARCHIVE_STATE_NEW;
	defined_param.archive_format_raw = ARCHIVE_FORMAT_RAW;
	defined_param.enomem = ENOMEM;
	defined_param.archive_ok = ARCHIVE_OK;
	defined_param.archive_eof = ARCHIVE_EOF;
	defined_param.archive_fatal = ARCHIVE_FATAL;
	defined_param.ae_ifreg = AE_IFREG;
	return defined_param;
}

int archive_read_support_format_raw(struct archive *_a)
{
	return 0;
}

#endif