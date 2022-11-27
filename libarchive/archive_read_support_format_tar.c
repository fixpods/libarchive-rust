/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2011-2012 Michihiro NAKAJIMA
 * Copyright (c) 2016 Martin Matuska
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
__FBSDID("$FreeBSD: head/lib/libarchive/archive_read_support_format_tar.c 201161 2009-12-29 05:44:39Z kientzle $");

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <stddef.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "archive.h"
#include "archive_acl_private.h" /* For ACL parsing routines. */
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_private.h"
#include "archive_read_private.h"

#ifndef COMPILE_WITH_RUST
struct archive_tar_defined_param
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
    unsigned int ae_ifreg;
    int archive_failed;
    int archive_warn;
    unsigned int ae_ifdir;
    int archive_errno_file_format;
    int archive_format_tar;
    int archive_format_tar_pax_interchange;
    int archive_format_tar_gnutar;
    int archive_format_tar_ustar;
    int archive_entry_acl_type_nfs4;
    int archive_entry_acl_type_access;
    unsigned int ae_iflnk;
    unsigned int ae_ifchr;
    unsigned int ae_ifblk;
    unsigned int ae_ififo;
    int sconv_set_opt_utf8_libarchive2x;
    int archive_entry_acl_type_default;
    int ae_symlink_type_directory;
    int archive_retry;
    int ae_symlink_type_file;
    long int64_max;
};

struct archive_tar_defined_param get_archive_tar_defined_param();

struct archive_tar_defined_param get_archive_tar_defined_param()
{
    struct archive_tar_defined_param param;
    param.ae_symlink_type_file = AE_SYMLINK_TYPE_FILE;
    param.archive_retry = ARCHIVE_RETRY;
    param.ae_symlink_type_directory = AE_SYMLINK_TYPE_DIRECTORY;
    param.archive_entry_acl_type_default = ARCHIVE_ENTRY_ACL_TYPE_DEFAULT;
    param.sconv_set_opt_utf8_libarchive2x = SCONV_SET_OPT_UTF8_LIBARCHIVE2X;
    param.archive_read_magic = ARCHIVE_READ_MAGIC;
    param.archive_state_new = ARCHIVE_STATE_NEW;
    param.enomem = ENOMEM;
    param.archive_fatal = ARCHIVE_FATAL;
    param.archive_ok = ARCHIVE_OK;
    param.archive_errno_misc = ARCHIVE_ERRNO_MISC;
    param.archive_eof = ARCHIVE_EOF;
    param.einval = EINVAL;
    param.ae_ifreg = AE_IFREG;
    param.archive_failed = ARCHIVE_FAILED;
    param.archive_warn = ARCHIVE_WARN;
    param.ae_ifdir = AE_IFDIR;
    param.archive_errno_file_format = ARCHIVE_ERRNO_FILE_FORMAT;
    param.archive_format_tar = ARCHIVE_FORMAT_TAR;
    param.archive_format_tar_pax_interchange = ARCHIVE_FORMAT_TAR_PAX_INTERCHANGE;
    param.archive_format_tar_gnutar = ARCHIVE_FORMAT_TAR_GNUTAR;
    param.archive_format_tar_ustar = ARCHIVE_FORMAT_TAR_USTAR;
    param.archive_entry_acl_type_nfs4 = ARCHIVE_ENTRY_ACL_TYPE_NFS4;
    param.archive_entry_acl_type_access = ARCHIVE_ENTRY_ACL_TYPE_ACCESS;
    param.ae_iflnk = AE_IFLNK;
    param.ae_ifchr = AE_IFCHR;
    param.ae_ifblk = AE_IFBLK;
    param.ae_ififo = AE_IFIFO;
    param.int64_max = INT64_MAX;
    return param;
}

int archive_read_support_format_gnutar(struct archive *a)
{
    return 0;
}

int archive_read_support_format_tar(struct archive *_a)
{
    return 0;
}

#endif
