/*-
 * Copyright (c) 2011 Michihiro NAKAJIMA
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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif
#ifdef HAVE_LZMA_H
#include <lzma.h>
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "archive.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_ppmd7_private.h"
#include "archive_private.h"
#include "archive_read_private.h"
#include "archive_endian.h"

#ifndef HAVE_ZLIB_H
#include "archive_crc32.h"
#endif

#define _7ZIP_SIGNATURE	"7z\xBC\xAF\x27\x1C"
#define SFX_MIN_ADDR	0x27000
#define SFX_MAX_ADDR	0x60000


/*
 * Codec ID
 */
#define _7Z_COPY	0
#define _7Z_LZMA	0x030101
#define _7Z_LZMA2	0x21
#define _7Z_DEFLATE	0x040108
#define _7Z_BZ2		0x040202
#define _7Z_PPMD	0x030401
#define _7Z_DELTA	0x03
#define _7Z_CRYPTO_MAIN_ZIP			0x06F10101 /* Main Zip crypto algo */
#define _7Z_CRYPTO_RAR_29			0x06F10303 /* Rar29 AES-128 + (modified SHA-1) */
#define _7Z_CRYPTO_AES_256_SHA_256	0x06F10701 /* AES-256 + SHA-256 */


#define _7Z_X86		0x03030103
#define _7Z_X86_BCJ2	0x0303011B
#define _7Z_POWERPC	0x03030205
#define _7Z_IA64	0x03030401
#define _7Z_ARM		0x03030501
#define _7Z_ARMTHUMB	0x03030701
#define _7Z_SPARC	0x03030805

/*
 * 7-Zip header property IDs.
 */
#define kEnd			0x00
#define kHeader			0x01
#define kArchiveProperties	0x02
#define kAdditionalStreamsInfo	0x03
#define kMainStreamsInfo	0x04
#define kFilesInfo		0x05
#define kPackInfo		0x06
#define kUnPackInfo		0x07
#define kSubStreamsInfo		0x08
#define kSize			0x09
#define kCRC			0x0A
#define kFolder			0x0B
#define kCodersUnPackSize	0x0C
#define kNumUnPackStream	0x0D
#define kEmptyStream		0x0E
#define kEmptyFile		0x0F
#define kAnti			0x10
#define kName			0x11
#define kCTime			0x12
#define kATime			0x13
#define kMTime			0x14
#define kAttributes		0x15
#define kEncodedHeader		0x17
#define kDummy			0x19





/* Maximum entry size. This limitation prevents reading intentional
 * corrupted 7-zip files on assuming there are not so many entries in
 * the files. */
#define UMAX_ENTRY	ARCHIVE_LITERAL_ULL(100000000)

#ifndef COMPILE_WITH_RUST
// 编译时使用

int
archive_read_support_format_7zip(struct archive *_a)
{

	return 0;
}

#endif
