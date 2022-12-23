/*-
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
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "archive.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_private.h"
#include "archive_read_private.h"
#include "archive_endian.h"

struct lzx_dec
{
	/* Decoding status. */
	int state;

	/*
	 * Window to see last decoded data, from 32KBi to 2MBi.
	 */
	int w_size;
	int w_mask;
	/* Window buffer, which is a loop buffer. */
	unsigned char *w_buff;
	/* The insert position to the window. */
	int w_pos;
	/* The position where we can copy decoded code from the window. */
	int copy_pos;
	/* The length how many bytes we can copy decoded code from
	 * the window. */
	int copy_len;
	/* Translation reversal for x86 processor CALL byte sequence(E8).
	 * This is used for LZX only. */
	uint32_t translation_size;
	char translation;
	char block_type;
#define VERBATIM_BLOCK 1
#define ALIGNED_OFFSET_BLOCK 2
#define UNCOMPRESSED_BLOCK 3
	size_t block_size;
	size_t block_bytes_avail;
	/* Repeated offset. */
	int r0, r1, r2;
	unsigned char rbytes[4];
	int rbytes_avail;
	int length_header;
	int position_slot;
	int offset_bits;

	struct lzx_pos_tbl
	{
		int base;
		int footer_bits;
	} * pos_tbl;
	/*
	 * Bit stream reader.
	 */
	struct lzx_br
	{
#define CACHE_TYPE uint64_t
#define CACHE_BITS (8 * sizeof(CACHE_TYPE))
		/* Cache buffer. */
		CACHE_TYPE cache_buffer;
		/* Indicates how many bits avail in cache_buffer. */
		int cache_avail;
		unsigned char odd;
		char have_odd;
	} br;

	/*
	 * Huffman coding.
	 */
	struct huffman
	{
		int len_size;
		int freq[17];
		unsigned char *bitlen;

		/*
		 * Use a index table. It's faster than searching a huffman
		 * coding tree, which is a binary tree. But a use of a large
		 * index table causes L1 cache read miss many times.
		 */
		int max_bits;
		int tbl_bits;
		int tree_used;
		/* Direct access table. */
		uint16_t *tbl;
	} at, lt, mt, pt;

	int loop;
	int error;
};

#define SLOT_BASE 15
#define SLOT_MAX 21 /*->25*/

struct lzx_stream
{
	const unsigned char *next_in;
	int64_t avail_in;
	int64_t total_in;
	unsigned char *next_out;
	int64_t avail_out;
	int64_t total_out;
	struct lzx_dec *ds;
};

/*
 * Cabinet file definitions.
 */
/* CFHEADER offset */
#define CFHEADER_signature 0
#define CFHEADER_cbCabinet 8
#define CFHEADER_coffFiles 16
#define CFHEADER_versionMinor 24
#define CFHEADER_versionMajor 25
#define CFHEADER_cFolders 26
#define CFHEADER_cFiles 28
#define CFHEADER_flags 30
#define CFHEADER_setID 32
#define CFHEADER_iCabinet 34
#define CFHEADER_cbCFHeader 36
#define CFHEADER_cbCFFolder 38
#define CFHEADER_cbCFData 39

/* CFFOLDER offset */
#define CFFOLDER_coffCabStart 0
#define CFFOLDER_cCFData 4
#define CFFOLDER_typeCompress 6
#define CFFOLDER_abReserve 8

/* CFFILE offset */
#define CFFILE_cbFile 0
#define CFFILE_uoffFolderStart 4
#define CFFILE_iFolder 8
#define CFFILE_date_time 10
#define CFFILE_attribs 14

/* CFDATA offset */
#define CFDATA_csum 0
#define CFDATA_cbData 4
#define CFDATA_cbUncomp 6

struct cfdata
{
	/* Sum value of this CFDATA. */
	uint32_t sum;
	uint16_t compressed_size;
	uint16_t compressed_bytes_remaining;
	uint16_t uncompressed_size;
	uint16_t uncompressed_bytes_remaining;
	/* To know how many bytes we have decompressed. */
	uint16_t uncompressed_avail;
	/* Offset from the beginning of compressed data of this CFDATA */
	uint16_t read_offset;
	int64_t unconsumed;
	/* To keep memory image of this CFDATA to compute the sum. */
	size_t memimage_size;
	unsigned char *memimage;
	/* Result of calculation of sum. */
	uint32_t sum_calculated;
	unsigned char sum_extra[4];
	int sum_extra_avail;
	const void *sum_ptr;
};

struct cffolder
{
	uint32_t cfdata_offset_in_cab;
	uint16_t cfdata_count;
	uint16_t comptype;
#define COMPTYPE_NONE 0x0000
#define COMPTYPE_MSZIP 0x0001
#define COMPTYPE_QUANTUM 0x0002
#define COMPTYPE_LZX 0x0003
	uint16_t compdata;
	const char *compname;
	/* At the time reading CFDATA */
	struct cfdata cfdata;
	int cfdata_index;
	/* Flags to mark progress of decompression. */
	char decompress_init;
};

struct cffile
{
	uint32_t uncompressed_size;
	uint32_t offset;
	time_t mtime;
	uint16_t folder;
#define iFoldCONTINUED_FROM_PREV 0xFFFD
#define iFoldCONTINUED_TO_NEXT 0xFFFE
#define iFoldCONTINUED_PREV_AND_NEXT 0xFFFF
	unsigned char attr;
#define ATTR_RDONLY 0x01
#define ATTR_NAME_IS_UTF 0x80
	struct archive_string pathname;
};

struct cfheader
{
	/* Total bytes of all file size in a Cabinet. */
	uint32_t total_bytes;
	uint32_t files_offset;
	uint16_t folder_count;
	uint16_t file_count;
	uint16_t flags;
#define PREV_CABINET 0x0001
#define NEXT_CABINET 0x0002
#define RESERVE_PRESENT 0x0004
	uint16_t setid;
	uint16_t cabinet;
	/* Version number. */
	unsigned char major;
	unsigned char minor;
	unsigned char cffolder;
	unsigned char cfdata;
	/* All folders in a cabinet. */
	struct cffolder *folder_array;
	/* All files in a cabinet. */
	struct cffile *file_array;
	int file_index;
};

struct cab
{
	/* entry_bytes_remaining is the number of bytes we expect.	    */
	int64_t entry_offset;
	int64_t entry_bytes_remaining;
	int64_t entry_unconsumed;
	int64_t entry_compressed_bytes_read;
	int64_t entry_uncompressed_bytes_read;
	struct cffolder *entry_cffolder;
	struct cffile *entry_cffile;
	struct cfdata *entry_cfdata;

	/* Offset from beginning of a cabinet file. */
	int64_t cab_offset;
	struct cfheader cfheader;
	struct archive_wstring ws;

	/* Flag to mark progress that an archive was read their first header.*/
	char found_header;
	char end_of_archive;
	char end_of_entry;
	char end_of_entry_cleanup;
	char read_data_invoked;
	int64_t bytes_skipped;

	unsigned char *uncompressed_buffer;
	size_t uncompressed_buffer_size;

	int init_default_conversion;
	struct archive_string_conv *sconv;
	struct archive_string_conv *sconv_default;
	struct archive_string_conv *sconv_utf8;
	char format_name[64];

#ifdef HAVE_ZLIB_H
	z_stream stream;
	char stream_valid;
#endif
	struct lzx_stream xstrm;
};

/*
 * Bit stream reader.
 */
/* Check that the cache buffer has enough bits. */
#define lzx_br_has(br, n) ((br)->cache_avail >= n)
/* Get compressed data by bit. */
#define lzx_br_bits(br, n)                     \
	(((uint32_t)((br)->cache_buffer >>         \
				 ((br)->cache_avail - (n)))) & \
	 cache_masks[n])
#define lzx_br_bits_forced(br, n) \
	(((uint32_t)((br)->cache_buffer << ((n) - (br)->cache_avail))) & cache_masks[n])
/* Read ahead to make sure the cache buffer has enough compressed data we
 * will use.
 *  True  : completed, there is enough data in the cache buffer.
 *  False : we met that strm->next_in is empty, we have to get following
 *          bytes. */
#define lzx_br_read_ahead_0(strm, br, n) \
	(lzx_br_has((br), (n)) || lzx_br_fillup(strm, br))
/*  True  : the cache buffer has some bits as much as we need.
 *  False : there are no enough bits in the cache buffer to be used,
 *          we have to get following bytes if we could. */
#define lzx_br_read_ahead(strm, br, n) \
	(lzx_br_read_ahead_0((strm), (br), (n)) || lzx_br_has((br), (n)))

/* Notify how many bits we consumed. */
#define lzx_br_consume(br, n) ((br)->cache_avail -= (n))
#define lzx_br_consume_unaligned_bits(br) ((br)->cache_avail &= ~0x0f)

#define lzx_br_is_unaligned(br) ((br)->cache_avail & 0x0f)

#define ST_RD_TRANSLATION 0
#define ST_RD_TRANSLATION_SIZE 1
#define ST_RD_BLOCK_TYPE 2
#define ST_RD_BLOCK_SIZE 3
#define ST_RD_ALIGNMENT 4
#define ST_RD_R0 5
#define ST_RD_R1 6
#define ST_RD_R2 7
#define ST_COPY_UNCOMP1 8
#define ST_COPY_UNCOMP2 9
#define ST_RD_ALIGNED_OFFSET 10
#define ST_RD_VERBATIM 11
#define ST_RD_PRE_MAIN_TREE_256 12
#define ST_MAIN_TREE_256 13
#define ST_RD_PRE_MAIN_TREE_REM 14
#define ST_MAIN_TREE_REM 15
#define ST_RD_PRE_LENGTH_TREE 16
#define ST_LENGTH_TREE 17
#define ST_MAIN 18
#define ST_LENGTH 19
#define ST_OFFSET 20
#define ST_REAL_POS 21
#define ST_COPY 22

#ifndef COMPILE_WITH_RUST

struct archive_cab_defined_param
{
	int archive_ok;
	int archive_fatal;
	int archive_warn;
	int archive_failed;
	int archive_eof;
	int archive_errno_misc;
	int archive_errno_file_format;
	int attr_name_is_utf;
	int archive_format_cab;
	int cfheader_signature;
	int cfheader_cbcabinet;
	int cfheader_cofffiles;
	int cfheader_versionminor;
	int cfheader_cfolders;
	int cfheader_cfiles;
	int cfheader_flags;
	int cfheader_setid;
	int cfheader_icabinet;
	int cfheader_cbcfheader;
	int cfheader_cbcffolder;
	int cfheader_cbcfdata;
	int prev_cabinet;
	int next_cabinet;
	int reserve_present;
	int cffolder_coffcabstart;
	int cffolder_ccfdata;
	int cffolder_typecompress;
	int cffile_cbfile;
	int cffile_uofffolderstart;
	int cffile_ifolder;
	int cffile_date_time;
	int cffile_attribs;
	int enomem;
	int attr_rdonly;
	int ae_ifreg;
	int cfdata_cbdata;
	int cfdata_csum;
	int cfdata_cbuncomp;
	int comptype_none;
	#ifdef HAVE_ZLIB_H
	int z_ok;
	int z_stream_end;
	int z_mem_error;
	#endif
	int ifoldcontinued_to_next;
	int ifoldcontinued_prev_and_next;
	int ifoldcontinued_from_prev;
	int slot_base;
	int slot_max;
	int st_main;
	int st_rd_translation;
	int st_rd_translation_size;
	int st_rd_block_type;
	int st_rd_block_size;
	int uncompressed_block;
	int verbatim_block;
	int st_rd_verbatim;
	int st_rd_aligned_offset;
	int st_rd_alignment;
	int st_rd_r0;
	int st_rd_r1;
	int st_rd_r2;
	int st_copy_uncomp1;
	int st_copy_uncomp2;
	int st_rd_pre_main_tree_256;
	int st_main_tree_256;
	int st_rd_pre_main_tree_rem;
	int st_main_tree_rem;
	int st_rd_pre_length_tree;
	int st_length_tree;
	int st_length;
	int st_real_pos;
	int aligned_offset_block;
	int st_offset;
	int st_copy;
	int cfheader_versionmajor;
};

// extern int
// archive_read_support_format_cab_rust(struct archive *_a, struct archive_cab_defined_param defined_param);

struct archive_cab_defined_param get_archive_cab_defined_param();
struct archive_cab_defined_param get_archive_cab_defined_param()
{
	struct archive_cab_defined_param defined_param;
	defined_param.archive_ok = ARCHIVE_OK;
	defined_param.archive_fatal = ARCHIVE_FATAL;
	defined_param.archive_warn = ARCHIVE_WARN;
	defined_param.archive_failed = ARCHIVE_FAILED;
	defined_param.archive_eof = ARCHIVE_EOF;
	defined_param.archive_errno_misc = ARCHIVE_ERRNO_MISC;
	defined_param.archive_errno_file_format = ARCHIVE_ERRNO_FILE_FORMAT;
	defined_param.attr_name_is_utf = ATTR_NAME_IS_UTF;
	defined_param.archive_format_cab = ARCHIVE_FORMAT_CAB;
	defined_param.cfheader_signature = CFHEADER_signature;
	defined_param.cfheader_cbcabinet = CFHEADER_cbCabinet;
	defined_param.cfheader_cofffiles = CFHEADER_coffFiles;
	defined_param.cfheader_versionminor = CFHEADER_versionMinor;
	defined_param.cfheader_cfolders = CFHEADER_cFolders;
	defined_param.cfheader_cfiles = CFHEADER_cFiles;
	defined_param.cfheader_flags = CFHEADER_flags;
	defined_param.cfheader_setid = CFHEADER_setID;
	defined_param.cfheader_icabinet = CFHEADER_iCabinet;
	defined_param.cfheader_cbcfheader = CFHEADER_cbCFHeader;
	defined_param.cfheader_cbcffolder = CFHEADER_cbCFFolder;
	defined_param.cfheader_cbcfdata = CFHEADER_cbCFData;
	defined_param.prev_cabinet = PREV_CABINET;
	defined_param.next_cabinet = NEXT_CABINET;
	defined_param.reserve_present = RESERVE_PRESENT;
	defined_param.cffolder_coffcabstart = CFFOLDER_coffCabStart;
	defined_param.cffolder_ccfdata = CFFOLDER_cCFData;
	defined_param.cffolder_typecompress = CFFOLDER_typeCompress;
	defined_param.cffile_cbfile = CFFILE_cbFile;
	defined_param.cffile_uofffolderstart = CFFILE_uoffFolderStart;
	defined_param.cffile_ifolder = CFFILE_iFolder;
	defined_param.cffile_date_time = CFFILE_date_time;
	defined_param.cffile_attribs = CFFILE_attribs;
	defined_param.enomem = ENOMEM;
	defined_param.attr_rdonly = ATTR_RDONLY;
	defined_param.ae_ifreg = AE_IFREG;
	defined_param.cfdata_cbdata = CFDATA_cbData;
	defined_param.cfdata_csum = CFDATA_csum;
	defined_param.cfdata_cbuncomp = CFDATA_cbUncomp;
	defined_param.comptype_none = COMPTYPE_NONE;
	#ifdef HAVE_ZLIB_H
	defined_param.z_ok = Z_OK;
	defined_param.z_stream_end = Z_STREAM_END;
	defined_param.z_mem_error = Z_MEM_ERROR;
	#endif
	defined_param.ifoldcontinued_to_next = iFoldCONTINUED_TO_NEXT;
	defined_param.ifoldcontinued_prev_and_next = iFoldCONTINUED_PREV_AND_NEXT;
	defined_param.ifoldcontinued_from_prev = iFoldCONTINUED_FROM_PREV;
	defined_param.slot_base = SLOT_BASE;
	defined_param.slot_max = SLOT_MAX;
	defined_param.st_main = ST_MAIN;
	defined_param.st_rd_translation = ST_RD_TRANSLATION;
	defined_param.st_rd_translation_size = ST_RD_TRANSLATION_SIZE;
	defined_param.st_rd_block_type = ST_RD_BLOCK_TYPE;
	defined_param.st_rd_block_size = ST_RD_BLOCK_SIZE;
	defined_param.uncompressed_block = UNCOMPRESSED_BLOCK;
	defined_param.verbatim_block = VERBATIM_BLOCK;
	defined_param.st_rd_verbatim = ST_RD_VERBATIM;
	defined_param.st_rd_aligned_offset = ST_RD_ALIGNED_OFFSET;
	defined_param.st_rd_alignment = ST_RD_ALIGNMENT;
	defined_param.st_rd_r0 = ST_RD_R0;
	defined_param.st_rd_r1 = ST_RD_R1;
	defined_param.st_rd_r2 = ST_RD_R2;
	defined_param.st_copy_uncomp1 = ST_COPY_UNCOMP1;
	defined_param.st_copy_uncomp2 = ST_COPY_UNCOMP2;
	defined_param.st_rd_pre_main_tree_256 = ST_RD_PRE_MAIN_TREE_256;
	defined_param.st_main_tree_256 = ST_MAIN_TREE_256;
	defined_param.st_rd_pre_main_tree_rem = ST_RD_PRE_MAIN_TREE_REM;
	defined_param.st_main_tree_rem = ST_MAIN_TREE_REM;
	defined_param.st_rd_pre_length_tree = ST_RD_PRE_LENGTH_TREE;
	defined_param.st_length_tree = ST_LENGTH_TREE;
	defined_param.st_length = ST_LENGTH;
	defined_param.st_real_pos = ST_REAL_POS;
	defined_param.aligned_offset_block = ALIGNED_OFFSET_BLOCK;
	defined_param.st_offset = ST_OFFSET;
	defined_param.st_copy = ST_COPY;
	defined_param.cfheader_versionmajor = CFHEADER_versionMajor;
	return defined_param;
}

int archive_read_support_format_cab(struct archive *_a)
{
	return 0;
}

#endif