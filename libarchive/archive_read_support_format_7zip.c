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

#define _7ZIP_SIGNATURE "7z\xBC\xAF\x27\x1C"
#define SFX_MIN_ADDR 0x27000
#define SFX_MAX_ADDR 0x60000

/*
 * Codec ID
 */
#define _7Z_COPY 0
#define _7Z_LZMA 0x030101
#define _7Z_LZMA2 0x21
#define _7Z_DEFLATE 0x040108
#define _7Z_BZ2 0x040202
#define _7Z_PPMD 0x030401
#define _7Z_DELTA 0x03
#define _7Z_CRYPTO_MAIN_ZIP 0x06F10101		  /* Main Zip crypto algo */
#define _7Z_CRYPTO_RAR_29 0x06F10303		  /* Rar29 AES-128 + (modified SHA-1) */
#define _7Z_CRYPTO_AES_256_SHA_256 0x06F10701 /* AES-256 + SHA-256 */

#define _7Z_X86 0x03030103
#define _7Z_X86_BCJ2 0x0303011B
#define _7Z_POWERPC 0x03030205
#define _7Z_IA64 0x03030401
#define _7Z_ARM 0x03030501
#define _7Z_ARMTHUMB 0x03030701
#define _7Z_SPARC 0x03030805

/*
 * 7-Zip header property IDs.
 */
#define kEnd 0x00
#define kHeader 0x01
#define kArchiveProperties 0x02
#define kAdditionalStreamsInfo 0x03
#define kMainStreamsInfo 0x04
#define kFilesInfo 0x05
#define kPackInfo 0x06
#define kUnPackInfo 0x07
#define kSubStreamsInfo 0x08
#define kSize 0x09
#define kCRC 0x0A
#define kFolder 0x0B
#define kCodersUnPackSize 0x0C
#define kNumUnPackStream 0x0D
#define kEmptyStream 0x0E
#define kEmptyFile 0x0F
#define kAnti 0x10
#define kName 0x11
#define kCTime 0x12
#define kATime 0x13
#define kMTime 0x14
#define kAttributes 0x15
#define kEncodedHeader 0x17
#define kDummy 0x19

#define MTIME_IS_SET	(1<<0)
#define ATIME_IS_SET	(1<<1)
#define CTIME_IS_SET	(1<<2)
#define CRC32_IS_SET	(1<<3)
#define HAS_STREAM	(1<<4)

#define UBUFF_SIZE	(64 * 1024)

/* Maximum entry size. This limitation prevents reading intentional
 * corrupted 7-zip files on assuming there are not so many entries in
 * the files. */
#define UMAX_ENTRY ARCHIVE_LITERAL_ULL(100000000)
#define SZ_ERROR_DATA	 ARCHIVE_FAILED

#define kNumTopBits 24

#define kNumBitModelTotalBits 11
#define kBitModelTotal (1 << kNumBitModelTotalBits)
#define kNumMoveBits 5



#ifndef COMPILE_WITH_RUST
// 编译时使用
struct archive_7zip_defined_param
{
  unsigned int archive_read_magic;
  unsigned int archive_state_new;
  int enomem;
  int archive_ok;
  int archive_fatal;
  int archive_errno_misc;
  int ae_ifreg;
  int archive_eof;
  int archive_errno_file_format;
  int archive_warn;
  int sfx_min_addr;
  int sfx_max_addr;
  int _7z_copy;
  int _7z_lzma;
  int _7z_lzma2;
  int _7z_deflate;
  int _7z_bz2;
  int _7z_ppmd;
  int _7z_delta;
  int _7z_crypto_main_zip;
  int _7z_crypto_rar_29;
  int _7z_crypto_aes_256_sha_256;
  int _7z_x86;
  int _7z_x86_bcj2;
  int _7z_powerpc;
  int _7z_ia64;
  int _7z_arm;
  int _7z_armthumb;
  int _7z_sparc;
  int kend;
  int kheader;
  int karchiveproperties;
  int kadditionalstreamsinfo;
  int kmainstreamsinfo;
  int kfilesinfo;
  int kpackinfo;
  int kunpackinfo;
  int ksubstreamsinfo;
  int ksize;
  int kcrc;
  int kfolder;
  int kcodersunpacksize;
  int knumunpackstream;
  int kemptystream;
  int kemptyfile;
  int kanti;
  int kname;
  int kctime;
  int katime;
  int kmtime;
  int kattributes;
  int kencodedheader;
  int kdummy;
  int mtime_is_set;
  int atime_is_set;
  int ctime_is_set;
  int crc32_is_set;
  int has_stream;
  int ubuff_size;
  int sz_error_data;
  int knumtopbits;
  int knumbitmodeltotalbits;
  int kbitmodeltotal;
  int knummovebits;
  int archive_failed;
#ifdef HAVE_LZMA_H
  int lzma_stream_end;
  int lzma_ok;
  int lzma_mem_error;
  int lzma_memlimit_error;
  int lzma_format_error;
  int lzma_options_error;
  int lzma_data_error;
  int lzma_buf_error;
#endif
#if defined(HAVE_BZLIB_H) && defined(BZ_CONFIG_ERROR)
  int bz_param_error;
  int bz_mem_error;
  int bz_config_error;
#endif
};

struct archive_7zip_defined_param get_archive_7zip_defined_param();

struct archive_7zip_defined_param get_archive_7zip_defined_param(){
  struct archive_7zip_defined_param param;
  unsigned int archive_read_magic = ARCHIVE_READ_MAGIC;
  unsigned int archive_state_new = ARCHIVE_STATE_NEW;
  param.enomem = ENOMEM;
  param.archive_ok = ARCHIVE_OK;
  param.archive_fatal = ARCHIVE_FATAL;
  param.archive_errno_misc = ARCHIVE_ERRNO_MISC;
  param.ae_ifreg = AE_IFREG;
  param.archive_eof = ARCHIVE_EOF;
  param.archive_errno_file_format = ARCHIVE_ERRNO_FILE_FORMAT;
  param.archive_warn = ARCHIVE_WARN;
  param.sfx_min_addr = SFX_MIN_ADDR;
  param.sfx_max_addr = SFX_MAX_ADDR;
  param._7z_copy = _7Z_COPY;
  param._7z_lzma = _7Z_LZMA;
  param._7z_lzma2 = _7Z_LZMA2;
  param._7z_deflate = _7Z_DEFLATE;
  param._7z_bz2 = _7Z_BZ2;
  param._7z_ppmd = _7Z_PPMD;
  param._7z_delta = _7Z_DELTA;
  param._7z_crypto_main_zip = _7Z_CRYPTO_MAIN_ZIP;
  param._7z_crypto_rar_29 = _7Z_CRYPTO_RAR_29;
  param._7z_crypto_aes_256_sha_256 = _7Z_CRYPTO_AES_256_SHA_256;
  param._7z_x86 = _7Z_X86;
  param._7z_x86_bcj2 = _7Z_X86_BCJ2;
  param._7z_powerpc = _7Z_POWERPC;
  param._7z_ia64 = _7Z_IA64;
  param._7z_arm = _7Z_ARM;
  param._7z_armthumb = _7Z_ARMTHUMB;
  param._7z_sparc = _7Z_SPARC;
  param.kend = kEnd;
  param.kheader = kHeader;
  param.karchiveproperties = kArchiveProperties;
  param.kadditionalstreamsinfo = kAdditionalStreamsInfo;
  param.kmainstreamsinfo = kMainStreamsInfo;
  param.kfilesinfo = kFilesInfo;
  param.kpackinfo = kPackInfo;
  param.kunpackinfo = kUnPackInfo;
  param.ksubstreamsinfo = kSubStreamsInfo;
  param.ksize = kSize;
  param.kcrc = kCRC;
  param.kfolder = kFolder;
  param.kcodersunpacksize = kCodersUnPackSize;
  param.knumunpackstream = kNumUnPackStream;
  param.kemptystream = kEmptyStream;
  param.kemptyfile = kEmptyFile;
  param.kanti = kAnti;
  param.kname = kName;
  param.kctime = kCTime;
  param.katime = kATime;
  param.kmtime = kMTime;
  param.kattributes = kAttributes;
  param.kencodedheader = kEncodedHeader;
  param.kdummy = kDummy;
  param.mtime_is_set = MTIME_IS_SET;
  param.atime_is_set = ATIME_IS_SET;
  param.ctime_is_set = CTIME_IS_SET;
  param.crc32_is_set = CRC32_IS_SET;
  param.has_stream = HAS_STREAM;
  param.ubuff_size = UBUFF_SIZE;
  param.sz_error_data = SZ_ERROR_DATA;
  param.knumtopbits = kNumTopBits;
  param.knumbitmodeltotalbits = kNumBitModelTotalBits;
  param.kbitmodeltotal = kBitModelTotal;
  param.knummovebits = kNumMoveBits;
  param.archive_failed = ARCHIVE_FAILED;
#ifdef HAVE_LZMA_H
  param.lzma_stream_end = LZMA_STREAM_END;
  param.lzma_ok = LZMA_OK;
  param.lzma_mem_error = LZMA_MEM_ERROR;
  param.lzma_memlimit_error = LZMA_MEMLIMIT_ERROR;
  param.lzma_format_error = LZMA_FORMAT_ERROR;
  param.lzma_options_error = LZMA_OPTIONS_ERROR;
  param.lzma_data_error = LZMA_DATA_ERROR;
  param.lzma_buf_error = LZMA_BUF_ERROR;
#endif
#if defined(HAVE_BZLIB_H) && defined(BZ_CONFIG_ERROR)
  param.bz_param_error = BZ_PARAM_ERROR;
  param.bz_mem_error = BZ_MEM_ERROR;
  param.bz_config_error = BZ_CONFIG_ERROR;
#endif
  return param;
}

int archive_read_support_format_7zip(struct archive *_a)
{
  return 0;
}

#endif
