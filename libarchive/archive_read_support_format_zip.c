/*-
 * Copyright (c) 2004-2013 Tim Kientzle
 * Copyright (c) 2011-2012,2014 Michihiro NAKAJIMA
 * Copyright (c) 2013 Konrad Kleine
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
__FBSDID("$FreeBSD: head/lib/libarchive/archive_read_support_format_zip.c 201102 2009-12-28 03:11:36Z kientzle $");

/*
 * The definitive documentation of the Zip file format is:
 *   http://www.pkware.com/documents/casestudies/APPNOTE.TXT
 *
 * The Info-Zip project has pioneered various extensions to better
 * support Zip on Unix, including the 0x5455 "UT", 0x5855 "UX", 0x7855
 * "Ux", and 0x7875 "ux" extensions for time and ownership
 * information.
 *
 * History of this code: The streaming Zip reader was first added to
 * libarchive in January 2005.  Support for seekable input sources was
 * added in Nov 2011.  Zip64 support (including a significant code
 * refactoring) was added in 2014.
 */

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif
#ifdef HAVE_LZMA_H
#include <lzma.h>
#endif

#include "archive.h"
#include "archive_digest_private.h"
#include "archive_cryptor_private.h"
#include "archive_endian.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_hmac_private.h"
#include "archive_private.h"
#include "archive_rb.h"
#include "archive_read_private.h"
#include "archive_ppmd8_private.h"

#ifndef HAVE_ZLIB_H
#include "archive_crc32.h"
#endif

/* Bits used in zip_flags. */
#define ZIP_ENCRYPTED (1 << 0)
#define ZIP_LENGTH_AT_END (1 << 3)
#define ZIP_STRONG_ENCRYPTED (1 << 6)
#define ZIP_UTF8_NAME (1 << 11)
/* See "7.2 Single Password Symmetric Encryption Method"
   in http://www.pkware.com/documents/casestudies/APPNOTE.TXT */
#define ZIP_CENTRAL_DIRECTORY_ENCRYPTED (1 << 13)

/* Bits used in flags. */
#define LA_USED_ZIP64 (1 << 0)
#define LA_FROM_CENTRAL_DIRECTORY (1 << 1)

/*
 * See "WinZip - AES Encryption Information"
 *     http://www.winzip.com/aes_info.htm
 */
/* Value used in compression method. */
#define WINZIP_AES_ENCRYPTION 99
/* Authentication code size. */
#define AUTH_CODE_SIZE 10
/**/
#define MAX_DERIVED_KEY_BUF_SIZE (AES_MAX_KEY_SIZE * 2 + 2)

/* Many systems define min or MIN, but not all. */
#define zipmin(a, b) ((a) < (b) ? (a) : (b))

int archive_read_support_format_zip(struct archive *a)
{

	int r;
	r = archive_read_support_format_zip_streamable(a);
	if (r != ARCHIVE_OK)
		return r;
	return (archive_read_support_format_zip_seekable(a));
}

#ifndef COMPILE_WITH_RUST

// 编译时使用
int archive_read_support_format_zip_seekable(struct archive *_a)
{
	return 0;
}

int archive_read_support_format_zip_streamable(struct archive *_a)
{
	return 0;
}

#endif
