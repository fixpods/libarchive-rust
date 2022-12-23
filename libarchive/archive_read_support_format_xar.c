/*-
 * Copyright (c) 2009 Michihiro NAKAJIMA
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
#if HAVE_LIBXML_XMLREADER_H
#include <libxml/xmlreader.h>
#elif HAVE_BSDXML_H
#include <bsdxml.h>
#elif HAVE_EXPAT_H
#include <expat.h>
#endif
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif
#if HAVE_LZMA_H
#include <lzma.h>
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "archive.h"
#include "archive_digest_private.h"
#include "archive_endian.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_private.h"
#include "archive_read_private.h"

#if (!defined(HAVE_LIBXML_XMLREADER_H) &&                  \
     !defined(HAVE_BSDXML_H) && !defined(HAVE_EXPAT_H)) || \
    !defined(HAVE_ZLIB_H) ||                               \
    !defined(ARCHIVE_HAS_MD5) || !defined(ARCHIVE_HAS_SHA1)

#ifdef COMPILE_WITH_RUST
int archive_read_support_format_xar(struct archive *_a)
{
  struct archive_read *a = (struct archive_read *)_a;
  archive_check_magic(_a, ARCHIVE_READ_MAGIC,
                      ARCHIVE_STATE_NEW, "archive_read_support_format_xar");

  archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                    "Xar not supported on this platform");
  return (ARCHIVE_WARN);
}
#endif

#else /* Support xar format */

#define HEADER_MAGIC 0x78617221
#define HEADER_SIZE 28
#define HEADER_VERSION 1
#define CKSUM_NONE 0
#define CKSUM_SHA1 1
#define CKSUM_MD5 2

#define MD5_SIZE 16
#define SHA1_SIZE 20
#define MAX_SUM_SIZE 20

#endif

#ifndef COMPILE_WITH_RUST
struct archive_xar_defined_param
{
  unsigned int archive_read_magic;
  unsigned int archive_state_new;
  int enomem;
  int archive_fatal;
  int archive_ok;
  int archive_eof;
  int archive_warn;
  int archive_failed;
  int archive_errno_file_format;
  int archive_errno_misc;
  int archive_format_xar;
  int seek_set;
  unsigned int ae_ifreg;
  unsigned int ae_ifmt;
  unsigned int ae_ifdir;
  unsigned int ae_iflnk;
  unsigned int ae_ifchr;
  unsigned int ae_ifblk;
  unsigned int ae_ifsock;
  unsigned int ae_ififo;
};

struct archive_xar_defined_param get_archive_xar_defined_param();
struct archive_xar_defined_param get_archive_xar_defined_param()
{
  struct archive_xar_defined_param param;
  param.ae_ififo = AE_IFIFO;
  param.ae_ifsock = AE_IFSOCK;
  param.ae_ifblk = AE_IFBLK;
  param.ae_ifchr = AE_IFCHR;
  param.ae_iflnk = AE_IFLNK;
  param.ae_ifmt = AE_IFMT;
  param.ae_ifdir = AE_IFDIR;
  param.ae_ifreg = AE_IFREG;
  param.archive_failed = ARCHIVE_FAILED;
  param.seek_set = SEEK_SET;
  param.archive_warn = ARCHIVE_WARN;
  param.archive_eof = ARCHIVE_EOF;
  param.archive_format_xar = ARCHIVE_FORMAT_XAR;
  param.archive_errno_misc = ARCHIVE_ERRNO_MISC;
  param.archive_errno_file_format = ARCHIVE_ERRNO_FILE_FORMAT;
  param.archive_read_magic = ARCHIVE_READ_MAGIC;
  param.archive_state_new = ARCHIVE_STATE_NEW;
  param.enomem = ENOMEM;
  param.archive_fatal = ARCHIVE_FATAL;
  param.archive_ok = ARCHIVE_OK;
  return param;
}
int archive_read_support_format_xar(struct archive *_a)
{

  return 0;
}

#endif
