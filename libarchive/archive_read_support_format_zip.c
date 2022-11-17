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

#define AES_VENDOR_AE_1	0x0001
#define AES_VENDOR_AE_2	0x0002
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
#define zipmin(a, b) ((a) < (b) ? (a) : (b))
/* Many systems define min or MIN, but not all. */
#define MD_SIZE 20
#define ENC_HEADER_SIZE	12

int archive_read_support_format_zip(struct archive *a)
{
	int r;
	r = archive_read_support_format_zip_streamable(a);
	if (r != ARCHIVE_OK)
		return r;
	return (archive_read_support_format_zip_seekable(a));
}

#ifndef COMPILE_WITH_RUST

struct archive_zip_defined_param
{
	unsigned int archive_read_magic;
	unsigned int archive_state_new;
	unsigned int ae_ifdir;
	unsigned int ae_ifmt;
	unsigned int ae_ififo;
	unsigned int ae_iflnk;
	unsigned int ae_ifreg;
	unsigned int uint32_max;
	int enomem;
	int archive_ok;
	int archive_fatal;
	int archive_errno_misc;
	int archive_errno_programmer;
	int archive_read_format_encryption_dont_know;
	int archive_eof;
	int archive_errno_file_format;
	int archive_warn;
	int archive_read_format_caps_encrypt_metadata;
	int archive_read_format_caps_encrypt_data;
	int archive_format_zip;
	int seek_set;
	int seek_end;
	int archive_rb_dir_right;
	int aes_vendor_ae_1;
	int aes_vendor_ae_2;
	int zip_encrypted;
	int zip_length_at_end;
	int zip_strong_encrypted;
	int zip_utf8_name;
	int zip_central_directory_encrypted;
	int la_used_zip64;
	int la_from_central_directory;
	int winzip_aes_encryption;
	int auth_code_size;
	int max_derived_key_buf_size;
	int md_size;
	int enc_header_size;
	int archive_failed;
};

struct archive_zip_defined_param get_archive_zip_defined_param();

struct archive_zip_defined_param get_archive_zip_defined_param(){
  	struct archive_zip_defined_param param;
	param.archive_read_magic = ARCHIVE_READ_MAGIC;
	param.archive_state_new = ARCHIVE_STATE_NEW;
	param.ae_ifdir = AE_IFDIR;
	param.ae_ifmt = AE_IFMT;
	param.ae_ififo = AE_IFIFO;
	param.ae_iflnk = AE_IFLNK;
	param.uint32_max = UINT32_MAX;
	param.enomem = ENOMEM;
	param.archive_ok = ARCHIVE_OK;
	param.archive_fatal = ARCHIVE_FATAL;
	param.archive_errno_misc = ARCHIVE_ERRNO_MISC;
	param.ae_ifreg = AE_IFREG;
	param.archive_errno_programmer = ARCHIVE_ERRNO_PROGRAMMER;
	param.archive_read_format_encryption_dont_know = ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW;
	param.archive_eof = ARCHIVE_EOF;
	param.archive_errno_file_format = ARCHIVE_ERRNO_FILE_FORMAT;
	param.archive_warn = ARCHIVE_WARN;
	param.archive_read_format_caps_encrypt_metadata = ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_METADATA;
	param.archive_read_format_caps_encrypt_data = ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_DATA;
	param.archive_format_zip = ARCHIVE_FORMAT_ZIP;
	param.seek_set = SEEK_SET;
	param.seek_end = SEEK_END;
	param.archive_rb_dir_right = ARCHIVE_RB_DIR_RIGHT;
	param.aes_vendor_ae_1 = AES_VENDOR_AE_1;
	param.aes_vendor_ae_2 = AES_VENDOR_AE_2;
	param.zip_encrypted = ZIP_ENCRYPTED;
	param.zip_length_at_end = ZIP_LENGTH_AT_END;
	param.zip_strong_encrypted = ZIP_STRONG_ENCRYPTED;
	param.zip_utf8_name = ZIP_UTF8_NAME;
	param.zip_central_directory_encrypted = ZIP_CENTRAL_DIRECTORY_ENCRYPTED;
	param.la_used_zip64 = LA_USED_ZIP64;
	param.la_from_central_directory = LA_FROM_CENTRAL_DIRECTORY;
	param.winzip_aes_encryption = WINZIP_AES_ENCRYPTION;
	param.auth_code_size = AUTH_CODE_SIZE;
	param.max_derived_key_buf_size = MAX_DERIVED_KEY_BUF_SIZE;
	param.md_size = MD_SIZE;
	param.enc_header_size = ENC_HEADER_SIZE;
	param.archive_failed = ARCHIVE_FAILED;
	return param;
}



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
