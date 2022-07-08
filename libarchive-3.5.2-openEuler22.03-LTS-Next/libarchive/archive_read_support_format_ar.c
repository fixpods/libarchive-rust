/*-
 * Copyright (c) 2007 Kai Wang
 * Copyright (c) 2007 Tim Kientzle
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
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
__FBSDID("$FreeBSD: head/lib/libarchive/archive_read_support_format_ar.c 201101 2009-12-28 03:06:27Z kientzle $");

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include "archive.h"
#include "archive_entry.h"
#include "archive_private.h"
#include "archive_read_private.h"

struct ar
{
  int64_t entry_bytes_remaining;
  /* unconsumed is purely to track data we've gotten from readahead,
   * but haven't yet marked as consumed.  Must be paired with
   * entry_bytes_remaining usage/modification.
   */
  size_t entry_bytes_unconsumed;
  int64_t entry_offset;
  int64_t entry_padding;
  char *strtab;
  size_t strtab_size;
  char read_global_header;
};

/*
 * Define structure of the "ar" header.
 */
#define AR_name_offset 0
#define AR_name_size 16
#define AR_date_offset 16
#define AR_date_size 12
#define AR_uid_offset 28
#define AR_uid_size 6
#define AR_gid_offset 34
#define AR_gid_size 6
#define AR_mode_offset 40
#define AR_mode_size 8
#define AR_size_offset 48
#define AR_size_size 10
#define AR_fmag_offset 58
#define AR_fmag_size 2

#ifndef COMPILE_WITH_RUST
struct archive_ar_defined_param
{
  unsigned int archive_read_magic;
  unsigned int archive_state_new;
  int enomem;
  int archive_ok;
  int einval;
  int archive_fatal;
  int ar_name_size;
  int ar_name_offset;
  int archive_format_ar;
  int archive_format_ar_bsd;
  int archive_format_ar_gnu;
  int archive_errno_misc;
  int ae_ifreg;
  int ar_size_offset;
  int ar_size_size;
  int archive_eof;
  int ar_date_offset;
  int ar_date_size;
  int ar_uid_offset;
  int ar_uid_size;
  int ar_gid_offset;
  int ar_gid_size;
  int ar_mode_offset;
  int ar_mode_size;
  unsigned long uint64_max;
  int ar_fmag_offset;
  int ar_fmag_size;
};

struct archive_ar_defined_param get_archive_ar_defined_param();

struct archive_ar_defined_param get_archive_ar_defined_param()
{
  struct archive_ar_defined_param param;
  param.archive_read_magic = ARCHIVE_READ_MAGIC;
  param.archive_state_new = ARCHIVE_STATE_NEW;
  param.enomem = ENOMEM;
  param.archive_ok = ARCHIVE_OK;
  param.einval = EINVAL;
  param.archive_fatal = ARCHIVE_FATAL;
  param.ar_name_size = AR_name_size;
  param.ar_name_offset = AR_name_offset;
  param.archive_format_ar = ARCHIVE_FORMAT_AR;
  param.archive_format_ar_bsd = ARCHIVE_FORMAT_AR_BSD;
  param.archive_format_ar_gnu = ARCHIVE_FORMAT_AR_GNU;
  param.archive_errno_misc = ARCHIVE_ERRNO_MISC;
  param.ae_ifreg = AE_IFREG;
  param.ar_size_offset = AR_size_offset;
  param.ar_size_size = AR_size_size;
  param.archive_eof = ARCHIVE_EOF;
  param.ar_date_offset = AR_date_offset;
  param.ar_date_size = AR_date_size;
  param.ar_uid_offset = AR_uid_offset;
  param.ar_uid_size = AR_uid_size;
  param.ar_gid_offset = AR_gid_offset;
  param.ar_gid_size = AR_gid_size;
  param.ar_mode_offset = AR_mode_offset;
  param.ar_mode_size = AR_mode_size;
  param.uint64_max = UINT64_MAX;
  param.ar_fmag_offset = AR_fmag_offset;
  param.ar_fmag_size = AR_fmag_size;

  return param;
}

int archive_read_support_format_ar(struct archive *_a)
{
  return 0;
}

#endif