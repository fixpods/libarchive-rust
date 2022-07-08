/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2008 Joerg Sonnenberger
 * Copyright (c) 2011-2012 Michihiro NAKAJIMA
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
__FBSDID("$FreeBSD: head/lib/libarchive/archive_read_support_format_mtree.c 201165 2009-12-29 05:52:13Z kientzle $");

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <stddef.h>
/* #include <stdint.h> */ /* See archive_platform.h */
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#include "archive.h"
#include "archive_entry.h"
#include "archive_entry_private.h"
#include "archive_private.h"
#include "archive_rb.h"
#include "archive_read_private.h"
#include "archive_string.h"
#include "archive_pack_dev.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define MTREE_HAS_DEVICE 0x0001
#define MTREE_HAS_FFLAGS 0x0002
#define MTREE_HAS_GID 0x0004
#define MTREE_HAS_GNAME 0x0008
#define MTREE_HAS_MTIME 0x0010
#define MTREE_HAS_NLINK 0x0020
#define MTREE_HAS_PERM 0x0040
#define MTREE_HAS_SIZE 0x0080
#define MTREE_HAS_TYPE 0x0100
#define MTREE_HAS_UID 0x0200
#define MTREE_HAS_UNAME 0x0400

#define MTREE_HAS_OPTIONAL 0x0800
#define MTREE_HAS_NOCHANGE 0x1000 /* FreeBSD specific */

#define MAX_LINE_LEN (1024 * 1024)

struct mtree_option
{
	struct mtree_option *next;
	char *value;
};

struct mtree_entry
{
	struct archive_rb_node rbnode;
	struct mtree_entry *next_dup;
	struct mtree_entry *next;
	struct mtree_option *options;
	char *name;
	char full;
	char used;
};

struct mtree
{
	struct archive_string line;
	size_t buffsize;
	char *buff;
	int64_t offset;
	int fd;
	int archive_format;
	const char *archive_format_name;
	struct mtree_entry *entries;
	struct mtree_entry *this_entry;
	struct archive_rb_tree entry_rbtree;
	struct archive_string current_dir;
	struct archive_string contents_name;

	struct archive_entry_linkresolver *resolver;
	struct archive_rb_tree rbtree;

	int64_t cur_size;
	char checkfs;
};

#ifdef HAVE_STRNLEN
#define mtree_strnlen(a, b) strnlen(a, b)
#endif

#define MAX_BID_ENTRY 3

#define MAX_PACK_ARGS 3

#ifndef COMPILE_WITH_RUST
struct archive_mtree_defined_param
{
	int s_iflnk;
	int s_ifsock;
	int s_ifchr;
	int s_ifblk;
	int s_ififo;
	int s_ifmt;
	int s_ifreg;
	int ae_ifreg;
	int ae_iflnk;
	int ae_ifsock;
	int ae_ifchr;
	int ae_ifblk;
	int ae_ifdir;
	int ae_ififo;
	int s_ifdir;
	int archive_ok;
	int archive_fatal;
	int archive_warn;
	int archive_failed;
	int archive_eof;
	int enomem;
	long int max_line_len;
	int max_bid_entry;
	int archive_errno_misc;
	int archive_format_mtree;
	int archive_errno_file_format;
	int o_rdonly;
	int o_binary;
	int o_cloexec;
	int enoent;
	int mtree_has_optional;
	int mtree_has_device;
	int mtree_has_nochange;
	int mtree_has_gid;
	int mtree_has_gname;
	int mtree_has_uid;
	int mtree_has_uname;
	int mtree_has_mtime;
	int mtree_has_nlink;
	int mtree_has_perm;
	int mtree_has_size;
	int mtree_has_type;
	int max_pack_args;
	int archive_entry_digest_md5;
	int archive_entry_digest_rmd160;
	int archive_entry_digest_sha1;
	int archive_entry_digest_sha256;
	int archive_entry_digest_sha384;
	int archive_entry_digest_sha512;
	int archive_errno_programmer;
	int mtree_has_fflags;
	long int int64_max;
	long int int32_max;
	long int int64_min;
	long int int32_min;
	long int time_t_min;
	long int time_t_max;
};

struct archive_mtree_defined_param get_archive_mtree_defined_param();
struct archive_mtree_defined_param get_archive_mtree_defined_param()
{
	struct archive_mtree_defined_param defined_param;
	defined_param.s_iflnk = S_IFLNK;
	defined_param.s_ifsock = S_IFSOCK;
	defined_param.s_ifchr = S_IFCHR;
	defined_param.s_ifblk = S_IFBLK;
	defined_param.s_ififo = S_IFIFO;
	defined_param.s_ifmt = S_IFMT;
	defined_param.s_ifreg = S_IFREG;
	defined_param.ae_ifreg = AE_IFREG;
	defined_param.ae_iflnk = AE_IFLNK;
	defined_param.ae_ifsock = AE_IFSOCK;
	defined_param.ae_ifchr = AE_IFCHR;
	defined_param.ae_ifblk = AE_IFBLK;
	defined_param.ae_ifdir = AE_IFDIR;
	defined_param.ae_ififo = AE_IFIFO;
	defined_param.s_ifdir = S_IFDIR;
	defined_param.archive_ok = ARCHIVE_OK;
	defined_param.archive_fatal = ARCHIVE_FATAL;
	defined_param.archive_warn = ARCHIVE_WARN;
	defined_param.archive_failed = ARCHIVE_FAILED;
	defined_param.archive_eof = ARCHIVE_EOF;
	defined_param.enomem = ENOMEM;
	defined_param.max_line_len = MAX_LINE_LEN;
	defined_param.max_bid_entry = MAX_BID_ENTRY;
	defined_param.archive_errno_misc = ARCHIVE_ERRNO_MISC;
	defined_param.archive_format_mtree = ARCHIVE_FORMAT_MTREE;
	defined_param.archive_errno_file_format = ARCHIVE_ERRNO_FILE_FORMAT;
	defined_param.o_rdonly = O_RDONLY;
	defined_param.o_binary = O_BINARY;
	defined_param.o_cloexec = O_CLOEXEC;
	defined_param.enoent = ENOENT;
	defined_param.mtree_has_optional = MTREE_HAS_OPTIONAL;
	defined_param.mtree_has_device = MTREE_HAS_DEVICE;
	defined_param.mtree_has_nochange = MTREE_HAS_NOCHANGE;
	defined_param.mtree_has_gid = MTREE_HAS_GID;
	defined_param.mtree_has_gname = MTREE_HAS_GNAME;
	defined_param.mtree_has_uid = MTREE_HAS_UID;
	defined_param.mtree_has_uname = MTREE_HAS_UNAME;
	defined_param.mtree_has_mtime = MTREE_HAS_MTIME;
	defined_param.mtree_has_nlink = MTREE_HAS_NLINK;
	defined_param.mtree_has_perm = MTREE_HAS_PERM;
	defined_param.mtree_has_size = MTREE_HAS_SIZE;
	defined_param.mtree_has_type = MTREE_HAS_TYPE;
	defined_param.max_pack_args = MAX_PACK_ARGS;
	defined_param.archive_entry_digest_md5 = ARCHIVE_ENTRY_DIGEST_MD5;
	defined_param.archive_entry_digest_rmd160 = ARCHIVE_ENTRY_DIGEST_RMD160;
	defined_param.archive_entry_digest_sha1 = ARCHIVE_ENTRY_DIGEST_SHA1;
	defined_param.archive_entry_digest_sha256 = ARCHIVE_ENTRY_DIGEST_SHA256;
	defined_param.archive_entry_digest_sha384 = ARCHIVE_ENTRY_DIGEST_SHA384;
	defined_param.archive_entry_digest_sha512 = ARCHIVE_ENTRY_DIGEST_SHA512;
	defined_param.archive_errno_programmer = ARCHIVE_ERRNO_PROGRAMMER;
	defined_param.mtree_has_fflags = MTREE_HAS_FFLAGS;
	defined_param.int64_max = INT64_MAX;
	defined_param.int32_max = INT32_MAX;
	defined_param.int64_min = INT64_MIN;
	defined_param.int32_min = INT32_MIN;
#if defined(TIME_T_MIN)
	defined_param.time_t_min = TIME_T_MIN;
#endif
#if defined(TIME_T_MAX)
	defined_param.time_t_max = TIME_T_MAX;
#endif
	return defined_param;
}

int get_have_strnlen();
int get_time_t_max();
int get_time_t_min();
int get_s_iflnk();
int get_s_ifsock();
int get_s_ifchr();
int get_s_ifblk();
int get_s_ififo();
int get_have_struct_stat_st_mtimespec_tv_nsec();
int get_have_struct_stat_st_mtim_tv_nsec();
int get_have_struct_stat_st_mtime_n();
int get_have_struct_stat_st_umtime();
int get_have_struct_stat_st_mtime_usec();

int get_have_strnlen()
{
#ifdef HAVE_STRNLEN
	return 1;
#else
	return 0;
#endif
}

int get_time_t_max()
{
#if defined(TIME_T_MAX)
	return 1;
#else
	return 0;
#endif
}

int get_time_t_min()
{
#if defined(TIME_T_MIN)
	return 1;
#else
	return 0;
#endif
}

int get_have_struct_stat_st_mtimespec_tv_nsec()
{
#if HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC
	return 1;
#else
	return 0;
#endif
}

int get_have_struct_stat_st_mtim_tv_nsec()
{
#if HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC
	return 1;
#else
	return 0;
#endif
}

int get_have_struct_stat_st_mtime_n()
{
#if HAVE_STRUCT_STAT_ST_MTIME_N
	return 1;
#else
	return 0;
#endif
}

int get_have_struct_stat_st_umtime()
{
#if HAVE_STRUCT_STAT_ST_UMTIME
	return 1;
#else
	return 0;
#endif
}

int get_have_struct_stat_st_mtime_usec()
{
#if HAVE_STRUCT_STAT_ST_MTIME_USEC
	return 1;
#else
	return 0;
#endif
}

int get_s_iflnk()
{
#ifdef S_IFLNK
	return 1;
#else
	return 0;
#endif
}

int get_s_ifsock()
{
#ifdef S_IFSOCK
	return 1;
#else
	return 0;
#endif
}

int get_s_ifchr()
{
#ifdef S_IFCHR
	return 1;
#else
	return 0;
#endif
}

int get_s_ifblk()
{
#ifdef S_IFBLK
	return 1;
#else
	return 0;
#endif
}

int get_s_ififo()
{
#ifdef S_IFIFO
	return 1;
#else
	return 0;
#endif
}

int archive_read_support_format_mtree(struct archive *_a)
{
	return 0;
}

#endif