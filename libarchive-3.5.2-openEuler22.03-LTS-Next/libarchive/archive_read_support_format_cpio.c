/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2010-2012 Michihiro NAKAJIMA
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
__FBSDID("$FreeBSD: head/lib/libarchive/archive_read_support_format_cpio.c 201163 2009-12-29 05:50:34Z kientzle $");

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
/* #include <stdint.h> */ /* See archive_platform.h */
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "archive.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_private.h"
#include "archive_read_private.h"

#define	bin_magic_offset 0
#define	bin_magic_size 2
#define	bin_dev_offset 2
#define	bin_dev_size 2
#define	bin_ino_offset 4
#define	bin_ino_size 2
#define	bin_mode_offset 6
#define	bin_mode_size 2
#define	bin_uid_offset 8
#define	bin_uid_size 2
#define	bin_gid_offset 10
#define	bin_gid_size 2
#define	bin_nlink_offset 12
#define	bin_nlink_size 2
#define	bin_rdev_offset 14
#define	bin_rdev_size 2
#define	bin_mtime_offset 16
#define	bin_mtime_size 4
#define	bin_namesize_offset 20
#define	bin_namesize_size 2
#define	bin_filesize_offset 22
#define	bin_filesize_size 4
#define	bin_header_size 26

#define	odc_magic_offset 0
#define	odc_magic_size 6
#define	odc_dev_offset 6
#define	odc_dev_size 6
#define	odc_ino_offset 12
#define	odc_ino_size 6
#define	odc_mode_offset 18
#define	odc_mode_size 6
#define	odc_uid_offset 24
#define	odc_uid_size 6
#define	odc_gid_offset 30
#define	odc_gid_size 6
#define	odc_nlink_offset 36
#define	odc_nlink_size 6
#define	odc_rdev_offset 42
#define	odc_rdev_size 6
#define	odc_mtime_offset 48
#define	odc_mtime_size 11
#define	odc_namesize_offset 59
#define	odc_namesize_size 6
#define	odc_filesize_offset 65
#define	odc_filesize_size 11
#define	odc_header_size 76

#define	newc_magic_offset 0
#define	newc_magic_size 6
#define	newc_ino_offset 6
#define	newc_ino_size 8
#define	newc_mode_offset 14
#define	newc_mode_size 8
#define	newc_uid_offset 22
#define	newc_uid_size 8
#define	newc_gid_offset 30
#define	newc_gid_size 8
#define	newc_nlink_offset 38
#define	newc_nlink_size 8
#define	newc_mtime_offset 46
#define	newc_mtime_size 8
#define	newc_filesize_offset 54
#define	newc_filesize_size 8
#define	newc_devmajor_offset 62
#define	newc_devmajor_size 8
#define	newc_devminor_offset 70
#define	newc_devminor_size 8
#define	newc_rdevmajor_offset 78
#define	newc_rdevmajor_size 8
#define	newc_rdevminor_offset 86
#define	newc_rdevminor_size 8
#define	newc_namesize_offset 94
#define	newc_namesize_size 8
#define	newc_checksum_offset 102
#define	newc_checksum_size 8
#define	newc_header_size 110

/*
 * An afio large ASCII header, which they named itself.
 * afio utility uses this header, if a file size is larger than 2G bytes
 * or inode/uid/gid is bigger than 65535(0xFFFF) or mtime is bigger than
 * 0x7fffffff, which we cannot record to odc header because of its limit.
 * If not, uses odc header.
 */
#define	afiol_magic_offset 0
#define	afiol_magic_size 6
#define	afiol_dev_offset 6
#define	afiol_dev_size 8	/* hex */
#define	afiol_ino_offset 14
#define	afiol_ino_size 16	/* hex */
#define	afiol_ino_m_offset 30	/* 'm' */
#define	afiol_mode_offset 31
#define	afiol_mode_size 6	/* oct */
#define	afiol_uid_offset 37
#define	afiol_uid_size 8	/* hex */
#define	afiol_gid_offset 45
#define	afiol_gid_size 8	/* hex */
#define	afiol_nlink_offset 53
#define	afiol_nlink_size 8	/* hex */
#define	afiol_rdev_offset 61
#define	afiol_rdev_size 8	/* hex */
#define	afiol_mtime_offset 69
#define	afiol_mtime_size 16	/* hex */
#define	afiol_mtime_n_offset 85	/* 'n' */
#define	afiol_namesize_offset 86
#define	afiol_namesize_size 4	/* hex */
#define	afiol_flag_offset 90
#define	afiol_flag_size 4	/* hex */
#define	afiol_xsize_offset 94
#define	afiol_xsize_size 4	/* hex */
#define	afiol_xsize_s_offset 98	/* 's' */
#define	afiol_filesize_offset 99
#define	afiol_filesize_size 16	/* hex */
#define	afiol_filesize_c_offset 115	/* ':' */
#define afiol_header_size 116


struct links_entry {
        struct links_entry      *next;
        struct links_entry      *previous;
        unsigned int             links;
        dev_t                    dev;
        int64_t                  ino;
        char                    *name;
};

#define	CPIO_MAGIC   0x13141516
struct cpio {
	int			  magic;
	int			(*read_header)(struct archive_read *, struct cpio *,
				     struct archive_entry *, size_t *, size_t *);
	struct links_entry	 *links_head;
	int64_t			  entry_bytes_remaining;
	int64_t			  entry_bytes_unconsumed;
	int64_t			  entry_offset;
	int64_t			  entry_padding;

	struct archive_string_conv *opt_sconv;
	struct archive_string_conv *sconv_default;
	int			  init_default_conversion;

	int			  option_pwb;
};

struct archive_cpio_defined_param{
    unsigned int archive_read_magic;
	unsigned int archive_state_new;
	int enomem;
	int archive_errno_misc;
	int archive_ok;
	int archive_fatal;
	int archive_warn;
	int archive_failed;
	int archive_errno_file_format;
	int archive_eof;
	int ae_ifmt;
	unsigned int ae_iflnk;
	int ae_ifreg;
    int	BIN_MAGIC_OFFSET;
    int	BIN_MAGIC_SIZE;
    int	BIN_DEV_OFFSET;
    int	BIN_DEV_SIZE;
    int	BIN_INO_OFFSET;
    int	BIN_INO_SIZE;
    int	BIN_MODE_OFFSET;
    int	BIN_MODE_SIZE;
    int	BIN_UID_OFFSET;
    int	BIN_UID_SIZE;
    int	BIN_GID_OFFSET;
    int	BIN_GID_SIZE;
    int	BIN_NLINK_OFFSET;
    int	BIN_NLINK_SIZE;
    int	BIN_RDEV_OFFSET;
    int	BIN_RDEV_SIZE;
    int	BIN_MTIME_OFFSET;
    int	BIN_MTIME_SIZE;
    int	BIN_NAMESIZE_OFFSET;
    int	BIN_NAMESIZE_SIZE;
    int	BIN_FILESIZE_OFFSET;
    int	BIN_FILESIZE_SIZE;
    int	BIN_HEADER_SIZE;

    int	ODC_MAGIC_OFFSET;
    int	ODC_MAGIC_SIZE;
    int	ODC_DEV_OFFSET;
    int	ODC_DEV_SIZE;
    int	ODC_INO_OFFSET;
    int	ODC_INO_SIZE;
    int	ODC_MODE_OFFSET;
    int	ODC_MODE_SIZE;
    int	ODC_UID_OFFSET;
    int	ODC_UID_SIZE;
    int	ODC_GID_OFFSET;
    int	ODC_GID_SIZE;
    int	ODC_NLINK_OFFSET;
    int	ODC_NLINK_SIZE;
    int	ODC_RDEV_OFFSET;
    int	ODC_RDEV_SIZE;
    int	ODC_MTIME_OFFSET;
    int	ODC_MTIME_SIZE;
    int	ODC_NAMESIZE_OFFSET;
    int	ODC_NAMESIZE_SIZE;
    int	ODC_FILESIZE_OFFSET;
    int	ODC_FILESIZE_SIZE;
    int	ODC_HEADER_SIZE;

    int	NEWC_MAGIC_OFFSET;
    int	NEWC_MAGIC_SIZE;
    int	NEWC_INO_OFFSET;
    int	NEWC_INO_SIZE;
    int	NEWC_MODE_OFFSET;
    int	NEWC_MODE_SIZE;
    int	NEWC_UID_OFFSET;
    int	NEWC_UID_SIZE;
    int	NEWC_GID_OFFSET;
    int	NEWC_GID_SIZE;
    int	NEWC_NLINK_OFFSET;
    int	NEWC_NLINK_SIZE;
    int	NEWC_MTIME_OFFSET;
    int	NEWC_MTIME_SIZE;
    int	NEWC_FILESIZE_OFFSET;
    int	NEWC_FILESIZE_SIZE;
    int	NEWC_DEVMAJOR_OFFSET;
    int	NEWC_DEVMAJOR_SIZE;
    int	NEWC_DEVMINOR_OFFSET;
    int	NEWC_DEVMINOR_SIZE;
    int	NEWC_RDEVMAJOR_OFFSET;
    int	NEWC_RDEVMAJOR_SIZE;
    int	NEWC_RDEVMINOR_OFFSET;
    int	NEWC_RDEVMINOR_SIZE;
    int	NEWC_NAMESIZE_OFFSET;
    int	NEWC_NAMESIZE_SIZE;
    int	NEWC_CHECKSUM_OFFSET;
    int	NEWC_CHECKSUM_SIZE;
    unsigned long NEWC_HEADER_SIZE;

    int	AFIOL_MAGIC_OFFSET;
    int	AFIOL_MAGIC_SIZE;
    int	AFIOL_DEV_OFFSET;
    int	AFIOL_DEV_SIZE;	/* HEX */
    int	AFIOL_INO_OFFSET;
    int	AFIOL_INO_SIZE;	/* HEX */
    int	AFIOL_INO_M_OFFSET;	/* 'M' */
    int	AFIOL_MODE_OFFSET;
    int	AFIOL_MODE_SIZE;	/* OCT */
    int	AFIOL_UID_OFFSET;
    int	AFIOL_UID_SIZE;	/* HEX */
    int	AFIOL_GID_OFFSET;
    int	AFIOL_GID_SIZE;	/* HEX */
    int	AFIOL_NLINK_OFFSET;
    int	AFIOL_NLINK_SIZE;	/* HEX */
    int	AFIOL_RDEV_OFFSET;
    int	AFIOL_RDEV_SIZE; /* HEX */
    int	AFIOL_MTIME_OFFSET;
    int	AFIOL_MTIME_SIZE;	/* HEX */
    int	AFIOL_MTIME_N_OFFSET; /* 'N' */
    int	AFIOL_NAMESIZE_OFFSET;
    int	AFIOL_NAMESIZE_SIZE;	/* HEX */
    int	AFIOL_FLAG_OFFSET;
    int	AFIOL_FLAG_SIZE;	/* HEX */
    int	AFIOL_XSIZE_OFFSET;
    int	AFIOL_XSIZE_SIZE;	/* HEX */
    int	AFIOL_XSIZE_S_OFFSET;	/* 'S' */
    int	AFIOL_FILESIZE_OFFSET;
    int	AFIOL_FILESIZE_SIZE; /* HEX */
    int	AFIOL_FILESIZE_C_OFFSET;	/* ':' */
    int AFIOL_HEADER_SIZE;
    int cpio_magic;
	int archive_format_cpio_svr4_nocrc;
	int archive_format_cpio_svr4_crc;
	int archive_format_cpio_afio_large; 
	int archive_format_cpio_posix;  
	int archive_format_cpio_bin_le;
	int archive_format_cpio_bin_be;
};

#ifndef COMPILE_WITH_RUST

struct archive_cpio_defined_param get_archive_cpio_defined_param();
struct archive_cpio_defined_param get_archive_cpio_defined_param()
{
    struct archive_cpio_defined_param defined_param;
	defined_param.archive_read_magic = ARCHIVE_READ_MAGIC;
	defined_param.archive_state_new = ARCHIVE_STATE_NEW;
	defined_param.enomem = ENOMEM;
	defined_param.archive_errno_misc = ARCHIVE_ERRNO_MISC;
	defined_param.archive_ok = ARCHIVE_OK;
	defined_param.archive_fatal = ARCHIVE_FATAL;
	defined_param.archive_warn = ARCHIVE_WARN;
	defined_param.archive_failed = ARCHIVE_FAILED;
	defined_param.archive_errno_file_format = ARCHIVE_ERRNO_FILE_FORMAT;
	defined_param.archive_eof = ARCHIVE_EOF;
	defined_param.ae_ifmt = AE_IFMT;
	defined_param.ae_iflnk = AE_IFLNK;
	defined_param.ae_ifreg = AE_IFREG;
    defined_param.BIN_MAGIC_OFFSET = bin_magic_offset;
    defined_param.BIN_MAGIC_SIZE = bin_magic_size;
    defined_param.BIN_DEV_OFFSET = bin_dev_offset;
    defined_param.BIN_DEV_SIZE = bin_dev_size;
    defined_param.BIN_INO_OFFSET = bin_ino_offset;
    defined_param.BIN_INO_SIZE = bin_ino_size;
    defined_param.BIN_MODE_OFFSET = bin_mode_offset;
    defined_param.BIN_MODE_SIZE = bin_mode_size;
    defined_param.BIN_UID_OFFSET = bin_uid_offset;
    defined_param.BIN_UID_SIZE = bin_uid_size;
    defined_param.BIN_GID_OFFSET = bin_gid_offset;
    defined_param.BIN_GID_SIZE = bin_gid_size;
    defined_param.BIN_NLINK_OFFSET = bin_nlink_offset;
    defined_param.BIN_NLINK_SIZE = bin_nlink_size;
    defined_param.BIN_RDEV_OFFSET = bin_rdev_offset;
    defined_param.BIN_RDEV_SIZE = bin_rdev_size;
    defined_param.BIN_MTIME_OFFSET = bin_mtime_offset;
    defined_param.BIN_MTIME_SIZE = bin_mtime_size;
    defined_param.BIN_NAMESIZE_OFFSET = bin_namesize_offset;
    defined_param.BIN_NAMESIZE_SIZE = bin_namesize_size;
    defined_param.BIN_FILESIZE_OFFSET = bin_filesize_offset;
    defined_param.BIN_FILESIZE_SIZE = bin_filesize_size;
    defined_param.BIN_HEADER_SIZE = bin_header_size;

    defined_param.ODC_MAGIC_OFFSET = odc_magic_offset;
    defined_param.ODC_MAGIC_SIZE = odc_magic_size;
    defined_param.ODC_DEV_OFFSET = odc_dev_offset;
    defined_param.ODC_DEV_SIZE = odc_dev_size;
    defined_param.ODC_INO_OFFSET = odc_ino_offset;
    defined_param.ODC_INO_SIZE = odc_ino_size;
    defined_param.ODC_MODE_OFFSET = odc_mode_offset;
    defined_param.ODC_MODE_SIZE = odc_mode_size;
    defined_param.ODC_UID_OFFSET = odc_uid_offset;
    defined_param.ODC_UID_SIZE = odc_uid_size;
    defined_param.ODC_GID_OFFSET = odc_gid_offset;
    defined_param.ODC_GID_SIZE = odc_gid_size;
    defined_param.ODC_NLINK_OFFSET = odc_nlink_offset;
    defined_param.ODC_NLINK_SIZE = odc_nlink_size;
    defined_param.ODC_RDEV_OFFSET = odc_rdev_offset;
    defined_param.ODC_RDEV_SIZE = odc_rdev_size;
    defined_param.ODC_MTIME_OFFSET = odc_mtime_offset;
    defined_param.ODC_MTIME_SIZE = odc_mtime_size;
    defined_param.ODC_NAMESIZE_OFFSET = odc_namesize_offset;
    defined_param.ODC_NAMESIZE_SIZE = odc_namesize_size;
    defined_param.ODC_FILESIZE_OFFSET = odc_filesize_offset;
    defined_param.ODC_FILESIZE_SIZE = odc_filesize_size;
    defined_param.ODC_HEADER_SIZE = odc_header_size;

    defined_param.NEWC_MAGIC_OFFSET = newc_magic_offset;
    defined_param.NEWC_MAGIC_SIZE = newc_magic_size;
    defined_param.NEWC_INO_OFFSET = newc_ino_offset;
    defined_param.NEWC_INO_SIZE = newc_ino_size;
    defined_param.NEWC_MODE_OFFSET = newc_mode_offset;
    defined_param.NEWC_MODE_SIZE = newc_mode_size;
    defined_param.NEWC_UID_OFFSET = newc_uid_offset;
    defined_param.NEWC_UID_SIZE = newc_uid_size;
    defined_param.NEWC_GID_OFFSET = newc_gid_offset;
    defined_param.NEWC_GID_SIZE = newc_gid_size;
    defined_param.NEWC_NLINK_OFFSET = newc_nlink_offset;
    defined_param.NEWC_NLINK_SIZE = newc_nlink_size;
    defined_param.NEWC_MTIME_OFFSET = newc_mtime_offset;
    defined_param.NEWC_MTIME_SIZE = newc_mtime_size;
    defined_param.NEWC_FILESIZE_OFFSET = newc_filesize_offset;
    defined_param.NEWC_FILESIZE_SIZE = newc_filesize_size;
    defined_param.NEWC_DEVMAJOR_OFFSET = newc_devmajor_offset;
    defined_param.NEWC_DEVMAJOR_SIZE = newc_devmajor_size;
    defined_param.NEWC_DEVMINOR_OFFSET = newc_devminor_offset;
    defined_param.NEWC_DEVMINOR_SIZE = newc_devminor_size;
    defined_param.NEWC_RDEVMAJOR_OFFSET = newc_rdevmajor_offset;
    defined_param.NEWC_RDEVMAJOR_SIZE = newc_rdevmajor_size;
    defined_param.NEWC_RDEVMINOR_OFFSET = newc_rdevminor_offset;
    defined_param.NEWC_RDEVMINOR_SIZE = newc_rdevminor_size;
    defined_param.NEWC_NAMESIZE_OFFSET = newc_namesize_offset;
    defined_param.NEWC_NAMESIZE_SIZE = newc_namesize_size;
    defined_param.NEWC_CHECKSUM_OFFSET = newc_checksum_offset;
    defined_param.NEWC_CHECKSUM_SIZE = newc_checksum_size;
    defined_param.NEWC_HEADER_SIZE = newc_header_size;

    defined_param.AFIOL_MAGIC_OFFSET = afiol_magic_offset;
    defined_param.AFIOL_MAGIC_SIZE = afiol_magic_size;
    defined_param.AFIOL_DEV_OFFSET = afiol_dev_offset;
    defined_param.AFIOL_DEV_SIZE = afiol_dev_size;	/* HEX */
    defined_param.AFIOL_INO_OFFSET = afiol_ino_offset;
    defined_param.AFIOL_INO_SIZE = afiol_ino_size;	/* HEX */
    defined_param.AFIOL_INO_M_OFFSET = afiol_ino_m_offset;	/* 'M' */
    defined_param.AFIOL_MODE_OFFSET = afiol_mode_offset;
    defined_param.AFIOL_MODE_SIZE = afiol_mode_size;	/* OCT */
    defined_param.AFIOL_UID_OFFSET = afiol_uid_offset;
    defined_param.AFIOL_UID_SIZE = afiol_uid_size;	/* HEX */
    defined_param.AFIOL_GID_OFFSET = afiol_gid_offset;
    defined_param.AFIOL_GID_SIZE = afiol_gid_size;	/* HEX */
    defined_param.AFIOL_NLINK_OFFSET = afiol_nlink_offset;
    defined_param.AFIOL_NLINK_SIZE = afiol_nlink_size;	/* HEX */
    defined_param.AFIOL_RDEV_OFFSET = afiol_rdev_offset;
    defined_param.AFIOL_RDEV_SIZE = afiol_rdev_size; /* HEX */
    defined_param.AFIOL_MTIME_OFFSET = afiol_mtime_offset;
    defined_param.AFIOL_MTIME_SIZE = afiol_mtime_size;	/* HEX */
    defined_param.AFIOL_MTIME_N_OFFSET = afiol_mtime_n_offset; /* 'N' */
    defined_param.AFIOL_NAMESIZE_OFFSET = afiol_namesize_offset;
    defined_param.AFIOL_NAMESIZE_SIZE = afiol_namesize_size;	/* HEX */
    defined_param.AFIOL_FLAG_OFFSET = afiol_flag_offset;
    defined_param.AFIOL_FLAG_SIZE = afiol_flag_size;	/* HEX */
    defined_param.AFIOL_XSIZE_OFFSET = afiol_xsize_offset;
    defined_param.AFIOL_XSIZE_SIZE = afiol_xsize_size;	/* HEX */
    defined_param.AFIOL_XSIZE_S_OFFSET = afiol_xsize_s_offset;	/* 'S' */
    defined_param.AFIOL_FILESIZE_OFFSET = afiol_filesize_offset;
    defined_param.AFIOL_FILESIZE_SIZE = afiol_filesize_size; /* HEX */
    defined_param.AFIOL_FILESIZE_C_OFFSET = afiol_filesize_c_offset;	/* ':' */
    defined_param. AFIOL_HEADER_SIZE = afiol_header_size;
    defined_param.cpio_magic = CPIO_MAGIC;
	defined_param.archive_format_cpio_svr4_nocrc = ARCHIVE_FORMAT_CPIO_SVR4_NOCRC;
	defined_param.archive_format_cpio_svr4_crc = ARCHIVE_FORMAT_CPIO_SVR4_CRC;
	defined_param.archive_format_cpio_afio_large = ARCHIVE_FORMAT_CPIO_AFIO_LARGE;
	defined_param.archive_format_cpio_posix = ARCHIVE_FORMAT_CPIO_POSIX;
	defined_param.archive_format_cpio_bin_le = ARCHIVE_FORMAT_CPIO_BIN_LE;
	defined_param.archive_format_cpio_bin_be = ARCHIVE_FORMAT_CPIO_BIN_BE;
	return defined_param;
}

int
archive_read_support_format_cpio(struct archive *_a)
{
	return 0;
}

#endif