/*-
 * Copyright (c) 2014 Sebastian Freundt
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

/**
 * WARC is standardised by ISO TC46/SC4/WG12 and currently available as
 * ISO 28500:2009.
 * For the purposes of this file we used the final draft from:
 * http://bibnum.bnf.fr/warc/WARC_ISO_28500_version1_latestdraft.pdf
 *
 * Todo:
 * [ ] real-world warcs can contain resources at endpoints ending in /
 *     e.g. http://bibnum.bnf.fr/warc/
 *     if you're lucky their response contains a Content-Location: header
 *     pointing to a unix-compliant filename, in the example above it's
 *     Content-Location: http://bibnum.bnf.fr/warc/index.html
 *     however, that's not mandated and github for example doesn't follow
 *     this convention.
 *     We need a set of archive options to control what to do with
 *     entries like these, at the moment care is taken to skip them.
 *
 **/

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
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#include "archive.h"
#include "archive_entry.h"
#include "archive_private.h"
#include "archive_read_private.h"

#ifndef COMPILE_WITH_RUST
struct archive_warc_defined_param
{
  unsigned int archive_read_magic;
  unsigned int archive_state_new;
  int enomem;
  int archive_fatal;
  int archive_ok;
  int archive_errno_misc;
  int archive_eof;
  int einval;
  int archive_format_warc;
  int ae_ifreg;
};

struct archive_warc_defined_param get_archive_warc_defined_param();
struct archive_warc_defined_param get_archive_warc_defined_param()
{
  struct archive_warc_defined_param param;
  param.archive_read_magic = ARCHIVE_READ_MAGIC;
  param.archive_state_new = ARCHIVE_STATE_NEW;
  param.enomem = ENOMEM;
  param.archive_fatal = ARCHIVE_FATAL;
  param.archive_ok = ARCHIVE_OK;
  param.archive_errno_misc = ARCHIVE_ERRNO_MISC;
  param.archive_eof = ARCHIVE_EOF;
  param.einval = EINVAL;
  param.archive_format_warc = ARCHIVE_FORMAT_WARC;
  param.ae_ifreg = AE_IFREG;
  return param;
}
int archive_read_support_format_warc(struct archive *_a)
{

  return 0;
}

#endif
