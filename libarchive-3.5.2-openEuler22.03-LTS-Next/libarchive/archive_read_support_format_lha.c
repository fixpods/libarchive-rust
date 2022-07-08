/*-
 * Copyright (c) 2008-2014 Michihiro NAKAJIMA
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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
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
#include "archive_endian.h"


#define MAXMATCH		256	/* Maximum match length. */
#define MINMATCH		3	/* Minimum match length. */
/*
 * Literal table format:
 * +0              +256                      +510
 * +---------------+-------------------------+
 * | literal code  |       match length      |
 * |   0 ... 255   |  MINMATCH ... MAXMATCH  |
 * +---------------+-------------------------+
 *  <---          LT_BITLEN_SIZE         --->
 */
/* Literal table size. */
#define LT_BITLEN_SIZE		(UCHAR_MAX + 1 + MAXMATCH - MINMATCH + 1)
/* Position table size.
 * Note: this used for both position table and pre literal table.*/
#define PT_BITLEN_SIZE		(3 + 16)

#define CACHE_TYPE		uint64_t
#define CACHE_BITS		(8 * sizeof(CACHE_TYPE))
#define HTBL_BITS	10

#define BIRTHTIME_IS_SET	1
#define ATIME_IS_SET		2
#define UNIX_MODE_IS_SET	4
#define CRC_IS_SET		8
/*
 * LHA header common member offset.
 */
#define H_METHOD_OFFSET	2	/* Compress type. */
#define H_ATTR_OFFSET	19	/* DOS attribute. */
#define H_LEVEL_OFFSET	20	/* Header Level.  */
#define H_SIZE		22	/* Minimum header size. */

#define H0_HEADER_SIZE_OFFSET	0
#define H0_HEADER_SUM_OFFSET	1
#define H0_COMP_SIZE_OFFSET	7
#define H0_ORIG_SIZE_OFFSET	11
#define H0_DOS_TIME_OFFSET	15
#define H0_NAME_LEN_OFFSET	21
#define H0_FILE_NAME_OFFSET	22
#define H0_FIXED_SIZE		24

#define H1_HEADER_SIZE_OFFSET	0
#define H1_HEADER_SUM_OFFSET	1
#define H1_COMP_SIZE_OFFSET	7
#define H1_ORIG_SIZE_OFFSET	11
#define H1_DOS_TIME_OFFSET	15
#define H1_NAME_LEN_OFFSET	21
#define H1_FILE_NAME_OFFSET	22
#define H1_FIXED_SIZE		27

#define H2_HEADER_SIZE_OFFSET	0
#define H2_COMP_SIZE_OFFSET	7
#define H2_ORIG_SIZE_OFFSET	11
#define H2_TIME_OFFSET		15
#define H2_CRC_OFFSET		21
#define H2_FIXED_SIZE		24

#define H3_FIELD_LEN_OFFSET	0
#define H3_COMP_SIZE_OFFSET	7
#define H3_ORIG_SIZE_OFFSET	11
#define H3_TIME_OFFSET		15
#define H3_CRC_OFFSET		21
#define H3_HEADER_SIZE_OFFSET	24
#define H3_FIXED_SIZE		28

#define EXT_HEADER_CRC		0x00		/* Header CRC and information*/
#define EXT_FILENAME		0x01		/* Filename 		    */
#define EXT_DIRECTORY		0x02		/* Directory name	    */
#define EXT_DOS_ATTR		0x40		/* MS-DOS attribute	    */
#define EXT_TIMESTAMP		0x41		/* Windows time stamp	    */
#define EXT_FILESIZE		0x42		/* Large file size	    */
#define EXT_TIMEZONE		0x43		/* Time zone		    */
#define EXT_UTF16_FILENAME	0x44		/* UTF-16 filename 	    */
#define EXT_UTF16_DIRECTORY	0x45		/* UTF-16 directory name    */
#define EXT_CODEPAGE		0x46		/* Codepage		    */
#define EXT_UNIX_MODE		0x50		/* File permission	    */
#define EXT_UNIX_GID_UID	0x51		/* gid,uid		    */
#define EXT_UNIX_GNAME		0x52		/* Group name		    */
#define EXT_UNIX_UNAME		0x53		/* User name		    */
#define EXT_UNIX_MTIME		0x54		/* Modified time	    */
#define EXT_OS2_NEW_ATTR	0x7f		/* new attribute(OS/2 only) */
#define EXT_NEW_ATTR		0xff		/* new attribute	    */

#define EPOC_TIME ARCHIVE_LITERAL_ULL(116444736000000000)

/* This if statement expects compiler optimization will
	* remove the statement which will not be executed. */
#undef bswap16
#if defined(_MSC_VER) && _MSC_VER >= 1400  /* Visual Studio */
#  define bswap16(x) _byteswap_ushort(x)
#elif defined(__GNUC__) && ((__GNUC__ == 4 && __GNUC_MINOR__ >= 8) || __GNUC__ > 4)
/* GCC 4.8 and later has __builtin_bswap16() */
#  define bswap16(x) __builtin_bswap16(x)
#elif defined(__clang__)
/* All clang versions have __builtin_bswap16() */
#  define bswap16(x) __builtin_bswap16(x)
#else
#  define bswap16(x) ((((x) >> 8) & 0xff) | ((x) << 8))
#endif
#define CRC16W	do { 	\
		if(u.c[0] == 1) { /* Big endian */		\
			crc ^= bswap16(*buff); buff++;		\
		} else						\
			crc ^= *buff++;				\
		crc = crc16tbl[1][crc & 0xff] ^ crc16tbl[0][crc >> 8];\
} while (0)
#undef CRC16W
#undef bswap16

/*
 * Bit stream reader.
 */
/* Check that the cache buffer has enough bits. */
#define lzh_br_has(br, n)	((br)->cache_avail >= n)
/* Get compressed data by bit. */
#define lzh_br_bits(br, n)				\
	(((uint16_t)((br)->cache_buffer >>		\
		((br)->cache_avail - (n)))) & cache_masks[n])
#define lzh_br_bits_forced(br, n)			\
	(((uint16_t)((br)->cache_buffer <<		\
		((n) - (br)->cache_avail))) & cache_masks[n])
/* Read ahead to make sure the cache buffer has enough compressed data we
 * will use.
 *  True  : completed, there is enough data in the cache buffer.
 *  False : we met that strm->next_in is empty, we have to get following
 *          bytes. */
#define lzh_br_read_ahead_0(strm, br, n)	\
	(lzh_br_has(br, (n)) || lzh_br_fillup(strm, br))
/*  True  : the cache buffer has some bits as much as we need.
 *  False : there are no enough bits in the cache buffer to be used,
 *          we have to get following bytes if we could. */
#define lzh_br_read_ahead(strm, br, n)	\
	(lzh_br_read_ahead_0((strm), (br), (n)) || lzh_br_has((br), (n)))

/* Notify how many bits we consumed. */
#define lzh_br_consume(br, n)	((br)->cache_avail -= (n))
#define lzh_br_unconsume(br, n)	((br)->cache_avail += (n))

#define ST_RD_BLOCK		0
#define ST_RD_PT_1		1
#define ST_RD_PT_2		2
#define ST_RD_PT_3		3
#define ST_RD_PT_4		4
#define ST_RD_LITERAL_1		5
#define ST_RD_LITERAL_2		6
#define ST_RD_LITERAL_3		7
#define ST_RD_POS_DATA_1	8
#define ST_GET_LITERAL		9
#define ST_GET_POS_1		10
#define ST_GET_POS_2		11
#define ST_COPY_DATA		12

#ifndef COMPILE_WITH_RUST

struct archive_lha_defined_param{
	unsigned int archive_read_magic;
	unsigned int archive_state_new;
	int enomem;
	int h_method_offset;
	int h_level_offset;
	int h_attr_offset;
	int h_size;
	int archive_failed;
	int archive_errno_misc;
	int archive_ok;
	int archive_fatal;
	int archive_warn;
	int archive_errno_file_format;
	int archive_format_lha;
	int archive_eof;
	int ae_ifmt;
	int ae_iflnk;
	int ae_ifdir;
	int ae_ifreg;
	int atime_is_set;
	int birthtime_is_set;
	int crc_is_set;
	int unix_mode_is_set;
	int h0_fixed_size;
	int h0_header_size_offset;
	int h0_header_sum_offset;
	int h0_comp_size_offset;
	int h0_orig_size_offset;
	int h0_dos_time_offset;
	int h0_name_len_offset;
	int h0_file_name_offset;
	int h1_header_size_offset;
	int h1_header_sum_offset;
	int h1_comp_size_offset;
	int h1_orig_size_offset;
	int h1_dos_time_offset;
	int h1_name_len_offset;
	int h1_file_name_offset;
	int h1_fixed_size;
	int h2_header_size_offset;
	int h2_comp_size_offset;
	int h2_orig_size_offset;
	int h2_time_offset;
	int h2_crc_offset;
	int h2_fixed_size;
	int h3_field_len_offset;
	int h3_comp_size_offset;
	int h3_orig_size_offset;
	int h3_time_offset;
	int h3_crc_offset;
	int h3_header_size_offset;
	int h3_fixed_size;
	int ext_header_crc;
	int ext_filename;
	int ext_utf16_filename;
	int ext_directory;
	int ext_utf16_directory;
	int ext_dos_attr;
	int ext_timestamp;
	int ext_filesize;
	int ext_codepage;
	int ext_unix_mode;
	int ext_unix_gid_uid;
	int ext_unix_gname;
	int ext_unix_uname;
	int ext_unix_mtime;
	int ext_os2_new_attr;
	int ext_new_attr;
	int ext_timezone;
	unsigned long long epoc_time;
	int pt_bitlen_size;
	int lt_bitlen_size;
	int st_get_literal;
	int st_rd_block;
	int st_rd_pt_1;
	int st_rd_pt_2;
	int st_rd_pt_3;
	int st_rd_pt_4;
	int st_rd_literal_1;
	int st_rd_literal_2;
	int st_rd_literal_3;
	int st_rd_pos_data_1;
	int st_get_pos_1;
	int st_get_pos_2;
	int st_copy_data;
	int uchar_max;
	int minmatch;
	int cache_bits;
	int htbl_bits;
};

struct archive_lha_defined_param get_archive_lha_defined_param();

struct archive_lha_defined_param get_archive_lha_defined_param(){
	struct archive_lha_defined_param defined_param;
	defined_param.archive_read_magic = ARCHIVE_READ_MAGIC;
	defined_param.archive_state_new = ARCHIVE_STATE_NEW;
	defined_param.enomem = ENOMEM;
	defined_param.h_method_offset = H_METHOD_OFFSET;
	defined_param.h_level_offset = H_LEVEL_OFFSET;
	defined_param.h_attr_offset = H_ATTR_OFFSET;
	defined_param.h_size = H_SIZE;
	defined_param.archive_failed = ARCHIVE_FAILED;
	defined_param.archive_errno_misc = ARCHIVE_ERRNO_MISC;
	defined_param.archive_ok = ARCHIVE_OK;
	defined_param.archive_fatal = ARCHIVE_FATAL;
	defined_param.archive_warn = ARCHIVE_WARN;
	defined_param.archive_errno_file_format = ARCHIVE_ERRNO_FILE_FORMAT;
	defined_param.archive_format_lha = ARCHIVE_FORMAT_LHA;
	defined_param.archive_eof = ARCHIVE_EOF;
	defined_param.ae_ifmt = AE_IFMT;
	defined_param.ae_iflnk = AE_IFLNK;
	defined_param.ae_ifdir = AE_IFDIR;
	defined_param.ae_ifreg = AE_IFREG;
	defined_param.atime_is_set = ATIME_IS_SET;
	defined_param.birthtime_is_set = BIRTHTIME_IS_SET;
	defined_param.crc_is_set = CRC_IS_SET;
	defined_param.unix_mode_is_set = UNIX_MODE_IS_SET;
	defined_param.h0_fixed_size = H0_FIXED_SIZE;
	defined_param.h0_header_size_offset = H0_HEADER_SIZE_OFFSET;
	defined_param.h0_header_sum_offset = H0_HEADER_SUM_OFFSET;
	defined_param.h0_comp_size_offset = H0_COMP_SIZE_OFFSET;
	defined_param.h0_orig_size_offset = H0_ORIG_SIZE_OFFSET;
	defined_param.h0_dos_time_offset = H0_DOS_TIME_OFFSET;
	defined_param.h0_name_len_offset = H0_NAME_LEN_OFFSET;
	defined_param.h0_file_name_offset = H0_FILE_NAME_OFFSET;
	defined_param.h1_header_size_offset = H1_HEADER_SIZE_OFFSET;
	defined_param.h1_header_sum_offset = H1_HEADER_SUM_OFFSET;
	defined_param.h1_comp_size_offset = H1_COMP_SIZE_OFFSET;
	defined_param.h1_orig_size_offset = H1_ORIG_SIZE_OFFSET;
	defined_param.h1_dos_time_offset = H1_DOS_TIME_OFFSET;
	defined_param.h1_name_len_offset = H1_NAME_LEN_OFFSET;
	defined_param.h1_file_name_offset = H1_FILE_NAME_OFFSET;
	defined_param.h1_fixed_size = H1_FIXED_SIZE;
	defined_param.h2_header_size_offset = H2_HEADER_SIZE_OFFSET;
	defined_param.h2_comp_size_offset = H2_COMP_SIZE_OFFSET;
	defined_param.h2_orig_size_offset = H2_ORIG_SIZE_OFFSET;
	defined_param.h2_time_offset = H2_TIME_OFFSET;
	defined_param.h2_crc_offset = H2_CRC_OFFSET;
	defined_param.h2_fixed_size = H2_FIXED_SIZE;
	defined_param.h3_field_len_offset = H3_FIELD_LEN_OFFSET;
	defined_param.h3_comp_size_offset = H3_COMP_SIZE_OFFSET;
	defined_param.h3_orig_size_offset = H3_ORIG_SIZE_OFFSET;
	defined_param.h3_time_offset = H3_TIME_OFFSET;
	defined_param.h3_crc_offset = H3_CRC_OFFSET;
	defined_param.h3_header_size_offset = H3_HEADER_SIZE_OFFSET;
	defined_param.h3_fixed_size = H3_FIXED_SIZE;
	defined_param.ext_header_crc = EXT_HEADER_CRC;
	defined_param.ext_filename = EXT_FILENAME;
	defined_param.ext_utf16_filename = EXT_UTF16_FILENAME;
	defined_param.ext_directory = EXT_DIRECTORY;
	defined_param.ext_utf16_directory = EXT_UTF16_DIRECTORY;
	defined_param.ext_dos_attr = EXT_DOS_ATTR;
	defined_param.ext_timestamp = EXT_TIMESTAMP;
	defined_param.ext_filesize = EXT_FILESIZE;
	defined_param.ext_codepage = EXT_CODEPAGE;
	defined_param.ext_unix_mode = EXT_UNIX_MODE;
	defined_param.ext_unix_gid_uid = EXT_UNIX_GID_UID;
	defined_param.ext_unix_gname = EXT_UNIX_GNAME;
	defined_param.ext_unix_uname = EXT_UNIX_UNAME;
	defined_param.ext_unix_mtime = EXT_UNIX_MTIME;
	defined_param.ext_os2_new_attr = EXT_OS2_NEW_ATTR;
	defined_param.ext_new_attr = EXT_NEW_ATTR;
	defined_param.ext_timezone = EXT_TIMEZONE;
	defined_param.epoc_time = EPOC_TIME;
	defined_param.pt_bitlen_size = PT_BITLEN_SIZE;
	defined_param.lt_bitlen_size = LT_BITLEN_SIZE;
	defined_param.st_get_literal = ST_GET_LITERAL;
	defined_param.st_rd_block = ST_RD_BLOCK;
	defined_param.st_rd_pt_1 = ST_RD_PT_1;
	defined_param.st_rd_pt_2 = ST_RD_PT_2;
	defined_param.st_rd_pt_3 = ST_RD_PT_3;
	defined_param.st_rd_pt_4 = ST_RD_PT_4;
	defined_param.st_rd_literal_1 = ST_RD_LITERAL_1;
	defined_param.st_rd_literal_2 = ST_RD_LITERAL_2;
	defined_param.st_rd_literal_3 = ST_RD_LITERAL_3;
	defined_param.st_rd_pos_data_1 = ST_RD_POS_DATA_1;
	defined_param.st_get_pos_1 = ST_GET_POS_1;
	defined_param.st_get_pos_2 = ST_GET_POS_2;
	defined_param.st_copy_data = ST_COPY_DATA;
	defined_param.uchar_max = UCHAR_MAX;
	defined_param.minmatch = MINMATCH;
	defined_param.cache_bits = CACHE_BITS;
	defined_param.htbl_bits = HTBL_BITS;
	return defined_param;
}

int
archive_read_support_format_lha(struct archive *_a)
{
	return 0;
}

#endif