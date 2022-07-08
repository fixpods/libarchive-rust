/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2009 Andreas Henriksson <andreas@fatal.se>
 * Copyright (c) 2009-2012 Michihiro NAKAJIMA
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
__FBSDID("$FreeBSD: head/lib/libarchive/archive_read_support_format_iso9660.c 201246 2009-12-30 05:30:35Z kientzle $");

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
/* #include <stdint.h> */ /* See archive_platform.h */
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <time.h>
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "archive.h"
#include "archive_endian.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_private.h"
#include "archive_read_private.h"
#include "archive_string.h"

/*
 * An overview of ISO 9660 format:
 *
 * Each disk is laid out as follows:
 *   * 32k reserved for private use
 *   * Volume descriptor table.  Each volume descriptor
 *     is 2k and specifies basic format information.
 *     The "Primary Volume Descriptor" (PVD) is defined by the
 *     standard and should always be present; other volume
 *     descriptors include various vendor-specific extensions.
 *   * Files and directories.  Each file/dir is specified by
 *     an "extent" (starting sector and length in bytes).
 *     Dirs are just files with directory records packed one
 *     after another.  The PVD contains a single dir entry
 *     specifying the location of the root directory.  Everything
 *     else follows from there.
 *
 * This module works by first reading the volume descriptors, then
 * building a list of directory entries, sorted by starting
 * sector.  At each step, I look for the earliest dir entry that
 * hasn't yet been read, seek forward to that location and read
 * that entry.  If it's a dir, I slurp in the new dir entries and
 * add them to the heap; if it's a regular file, I return the
 * corresponding archive_entry and wait for the client to request
 * the file body.  This strategy allows us to read most compliant
 * CDs with a single pass through the data, as required by libarchive.
 */
#define	LOGICAL_BLOCK_SIZE	2048
#define	SYSTEM_AREA_BLOCK	16

/* Structure of on-disk primary volume descriptor. */
#define PVD_type_offset 0
#define PVD_type_size 1
#define PVD_id_offset (PVD_type_offset + PVD_type_size)
#define PVD_id_size 5
#define PVD_version_offset (PVD_id_offset + PVD_id_size)
#define PVD_version_size 1
#define PVD_reserved1_offset (PVD_version_offset + PVD_version_size)
#define PVD_reserved1_size 1
#define PVD_system_id_offset (PVD_reserved1_offset + PVD_reserved1_size)
#define PVD_system_id_size 32
#define PVD_volume_id_offset (PVD_system_id_offset + PVD_system_id_size)
#define PVD_volume_id_size 32
#define PVD_reserved2_offset (PVD_volume_id_offset + PVD_volume_id_size)
#define PVD_reserved2_size 8
#define PVD_volume_space_size_offset (PVD_reserved2_offset + PVD_reserved2_size)
#define PVD_volume_space_size_size 8
#define PVD_reserved3_offset (PVD_volume_space_size_offset + PVD_volume_space_size_size)
#define PVD_reserved3_size 32
#define PVD_volume_set_size_offset (PVD_reserved3_offset + PVD_reserved3_size)
#define PVD_volume_set_size_size 4
#define PVD_volume_sequence_number_offset (PVD_volume_set_size_offset + PVD_volume_set_size_size)
#define PVD_volume_sequence_number_size 4
#define PVD_logical_block_size_offset (PVD_volume_sequence_number_offset + PVD_volume_sequence_number_size)
#define PVD_logical_block_size_size 4
#define PVD_path_table_size_offset (PVD_logical_block_size_offset + PVD_logical_block_size_size)
#define PVD_path_table_size_size 8
#define PVD_type_1_path_table_offset (PVD_path_table_size_offset + PVD_path_table_size_size)
#define PVD_type_1_path_table_size 4
#define PVD_opt_type_1_path_table_offset (PVD_type_1_path_table_offset + PVD_type_1_path_table_size)
#define PVD_opt_type_1_path_table_size 4
#define PVD_type_m_path_table_offset (PVD_opt_type_1_path_table_offset + PVD_opt_type_1_path_table_size)
#define PVD_type_m_path_table_size 4
#define PVD_opt_type_m_path_table_offset (PVD_type_m_path_table_offset + PVD_type_m_path_table_size)
#define PVD_opt_type_m_path_table_size 4
#define PVD_root_directory_record_offset (PVD_opt_type_m_path_table_offset + PVD_opt_type_m_path_table_size)
#define PVD_root_directory_record_size 34
#define PVD_volume_set_id_offset (PVD_root_directory_record_offset + PVD_root_directory_record_size)
#define PVD_volume_set_id_size 128
#define PVD_publisher_id_offset (PVD_volume_set_id_offset + PVD_volume_set_id_size)
#define PVD_publisher_id_size 128
#define PVD_preparer_id_offset (PVD_publisher_id_offset + PVD_publisher_id_size)
#define PVD_preparer_id_size 128
#define PVD_application_id_offset (PVD_preparer_id_offset + PVD_preparer_id_size)
#define PVD_application_id_size 128
#define PVD_copyright_file_id_offset (PVD_application_id_offset + PVD_application_id_size)
#define PVD_copyright_file_id_size 37
#define PVD_abstract_file_id_offset (PVD_copyright_file_id_offset + PVD_copyright_file_id_size)
#define PVD_abstract_file_id_size 37
#define PVD_bibliographic_file_id_offset (PVD_abstract_file_id_offset + PVD_abstract_file_id_size)
#define PVD_bibliographic_file_id_size 37
#define PVD_creation_date_offset (PVD_bibliographic_file_id_offset + PVD_bibliographic_file_id_size)
#define PVD_creation_date_size 17
#define PVD_modification_date_offset (PVD_creation_date_offset + PVD_creation_date_size)
#define PVD_modification_date_size 17
#define PVD_expiration_date_offset (PVD_modification_date_offset + PVD_modification_date_size)
#define PVD_expiration_date_size 17
#define PVD_effective_date_offset (PVD_expiration_date_offset + PVD_expiration_date_size)
#define PVD_effective_date_size 17
#define PVD_file_structure_version_offset (PVD_effective_date_offset + PVD_effective_date_size)
#define PVD_file_structure_version_size 1
#define PVD_reserved4_offset (PVD_file_structure_version_offset + PVD_file_structure_version_size)
#define PVD_reserved4_size 1
#define PVD_application_data_offset (PVD_reserved4_offset + PVD_reserved4_size)
#define PVD_application_data_size 512
#define PVD_reserved5_offset (PVD_application_data_offset + PVD_application_data_size)
#define PVD_reserved5_size (2048 - PVD_reserved5_offset)

/* TODO: It would make future maintenance easier to just hardcode the
 * above values.  In particular, ECMA119 states the offsets as part of
 * the standard.  That would eliminate the need for the following check.*/
#if PVD_reserved5_offset != 1395
#error PVD offset and size definitions are wrong.
#endif


/* Structure of optional on-disk supplementary volume descriptor. */
#define SVD_type_offset 0
#define SVD_type_size 1
#define SVD_id_offset (SVD_type_offset + SVD_type_size)
#define SVD_id_size 5
#define SVD_version_offset (SVD_id_offset + SVD_id_size)
#define SVD_version_size 1
/* ... */
#define SVD_reserved1_offset	72
#define SVD_reserved1_size	8
#define SVD_volume_space_size_offset 80
#define SVD_volume_space_size_size 8
#define SVD_escape_sequences_offset (SVD_volume_space_size_offset + SVD_volume_space_size_size)
#define SVD_escape_sequences_size 32
/* ... */
#define SVD_logical_block_size_offset 128
#define SVD_logical_block_size_size 4
#define SVD_type_L_path_table_offset 140
#define SVD_type_M_path_table_offset 148
/* ... */
#define SVD_root_directory_record_offset 156
#define SVD_root_directory_record_size 34
#define SVD_file_structure_version_offset 881
#define SVD_reserved2_offset	882
#define SVD_reserved2_size	1
#define SVD_reserved3_offset	1395
#define SVD_reserved3_size	653
/* ... */
/* FIXME: validate correctness of last SVD entry offset. */

/* Structure of an on-disk directory record. */
/* Note:  ISO9660 stores each multi-byte integer twice, once in
 * each byte order.  The sizes here are the size of just one
 * of the two integers.  (This is why the offset of a field isn't
 * the same as the offset+size of the previous field.) */
#define DR_length_offset 0
#define DR_length_size 1
#define DR_ext_attr_length_offset 1
#define DR_ext_attr_length_size 1
#define DR_extent_offset 2
#define DR_extent_size 4
#define DR_size_offset 10
#define DR_size_size 4
#define DR_date_offset 18
#define DR_date_size 7
#define DR_flags_offset 25
#define DR_flags_size 1
#define DR_file_unit_size_offset 26
#define DR_file_unit_size_size 1
#define DR_interleave_offset 27
#define DR_interleave_size 1
#define DR_volume_sequence_number_offset 28
#define DR_volume_sequence_number_size 2
#define DR_name_len_offset 32
#define DR_name_len_size 1
#define DR_name_offset 33

#define ISO9660_MAGIC   0x96609660
#define UTF16_NAME_MAX	1024

#define add_entry(arch, iso9660, file)	\
	heap_add_entry(arch, &((iso9660)->pending_files), file, file->offset)
#define next_entry(iso9660)		\
	heap_get_entry(&((iso9660)->pending_files))

#define RESERVED_AREA	(SYSTEM_AREA_BLOCK * LOGICAL_BLOCK_SIZE)

#ifndef COMPILE_WITH_RUST

struct archive_iso9660_defined_param{
	unsigned int archive_read_magic;
	unsigned int archive_state_new;
	int enomem;
	int iso9660_magic;
	int logical_block_size;
	int reserved_area;
	int archive_format_iso9660;
	int archive_format_iso9660_rockridge;
	int archive_errno_misc;
	int archive_ok;
	int archive_fatal;
	int archive_warn;
	int archive_failed;
	int archive_errno_file_format;
	int archive_eof;
	int ae_ifmt;
	int ae_iflnk;
	int ae_ifdir;
	int ae_ifreg;
	int utf16_name_max;
	int system_area_block;
	int seek_set;
	int dr_extent_offset;
	int dr_extent_size;
	int dr_ext_attr_length_offset;
	int dr_ext_attr_length_size;
	int dr_size_offset;
	int dr_size_size;
	int dr_length_offset;
	int dr_length_size;
	int dr_date_offset;
	int dr_flags_offset;
	int dr_flags_size;
	int dr_file_unit_size_offset;
	int dr_file_unit_size_size;
	int dr_interleave_offset;
	int dr_interleave_size;
	int dr_name_len_offset;
	int dr_name_len_size;
	int dr_name_offset;
	int dr_volume_sequence_number_offset;
	int dr_volume_sequence_number_size;
	int svd_type_offset;
	int svd_reserved1_offset;
	int svd_reserved1_size;
	int svd_reserved2_offset;
	int svd_reserved2_size;
	int svd_reserved3_offset;
	int svd_reserved3_size;
	int svd_logical_block_size_offset;
	int svd_volume_space_size_offset;
	int svd_file_structure_version_offset;
	int svd_type_l_path_table_offset;
	int svd_type_m_path_table_offset;
	int svd_root_directory_record_offset;
	int svd_escape_sequences_offset;
	int pvd_type_offset;
	int pvd_version_offset;
	int pvd_reserved1_offset;
	int pvd_reserved2_offset;
	int pvd_reserved2_size;
	int pvd_reserved3_offset;
	int pvd_reserved3_size;
	int pvd_reserved4_offset;
	int pvd_reserved4_size;
	int pvd_reserved5_offset;
	int pvd_reserved5_size;
	int pvd_logical_block_size_offset;
	int pvd_volume_space_size_offset;
	int pvd_file_structure_version_offset;
	int pvd_type_1_path_table_offset;
	int pvd_type_m_path_table_offset;
	int pvd_root_directory_record_offset;
};

struct archive_iso9660_defined_param get_archive_iso9660_defined_param();

struct archive_iso9660_defined_param get_archive_iso9660_defined_param(){
		struct archive_iso9660_defined_param defined_param;
	defined_param.archive_read_magic = ARCHIVE_READ_MAGIC;
	defined_param.archive_state_new = ARCHIVE_STATE_NEW;
	defined_param.enomem = ENOMEM;
	defined_param.iso9660_magic = ISO9660_MAGIC;
	defined_param.logical_block_size = LOGICAL_BLOCK_SIZE;
	defined_param.reserved_area = RESERVED_AREA;
	defined_param.archive_format_iso9660 = ARCHIVE_FORMAT_ISO9660;
	defined_param.archive_format_iso9660_rockridge = ARCHIVE_FORMAT_ISO9660_ROCKRIDGE;
	defined_param.archive_errno_misc = ARCHIVE_ERRNO_MISC;
	defined_param.archive_ok = ARCHIVE_OK;
	defined_param.archive_fatal = ARCHIVE_FATAL;
	defined_param.archive_warn = ARCHIVE_WARN;
	defined_param.archive_failed = ARCHIVE_FAILED;
	defined_param.archive_errno_file_format = ARCHIVE_ERRNO_FILE_FORMAT;
	defined_param.archive_eof = ARCHIVE_EOF;
	defined_param.ae_ifmt = AE_IFMT;
	defined_param.ae_iflnk = AE_IFLNK;
	defined_param.ae_ifdir = AE_IFDIR;
	defined_param.ae_ifreg = AE_IFREG;
	defined_param.utf16_name_max = UTF16_NAME_MAX;
	defined_param.system_area_block = SYSTEM_AREA_BLOCK;
	defined_param.seek_set = SEEK_SET;
	defined_param.dr_extent_offset = DR_extent_offset;
    defined_param.dr_extent_size = DR_extent_size;
    defined_param.dr_ext_attr_length_offset = DR_ext_attr_length_offset;
    defined_param.dr_ext_attr_length_size = DR_ext_attr_length_size;
	defined_param.dr_size_offset = DR_size_offset;
	defined_param.dr_size_size = DR_size_size;
	defined_param.dr_length_offset = DR_length_offset;
	defined_param.dr_length_size = DR_length_size;
	defined_param.dr_date_offset = DR_date_offset;
	defined_param.dr_flags_offset = DR_flags_offset;
	defined_param.dr_flags_size = DR_flags_size;
    defined_param.dr_file_unit_size_offset = DR_file_unit_size_offset;
    defined_param.dr_file_unit_size_size = DR_file_unit_size_size;
    defined_param.dr_interleave_offset = DR_interleave_offset;
    defined_param.dr_interleave_size = DR_interleave_size;
	defined_param.dr_name_len_offset = DR_name_len_offset;
	defined_param.dr_name_len_size = DR_name_len_size;
	defined_param.dr_name_offset = DR_name_offset;
	defined_param.dr_volume_sequence_number_offset = DR_volume_sequence_number_offset;
    defined_param.dr_volume_sequence_number_size = DR_volume_sequence_number_size;
	defined_param.svd_type_offset = SVD_type_offset;
	defined_param.svd_reserved1_offset = SVD_reserved1_offset;
	defined_param.svd_reserved1_size = SVD_reserved1_size;
	defined_param.svd_reserved2_offset = SVD_reserved2_offset;
	defined_param.svd_reserved2_size = SVD_reserved2_size;
	defined_param.svd_reserved3_offset = SVD_reserved3_offset;
	defined_param.svd_reserved3_size = SVD_reserved3_size;
	defined_param.svd_logical_block_size_offset = SVD_logical_block_size_offset;
	defined_param.svd_volume_space_size_offset = SVD_volume_space_size_offset;
	defined_param.svd_file_structure_version_offset = SVD_file_structure_version_offset;
	defined_param.svd_type_l_path_table_offset = SVD_type_L_path_table_offset;
	defined_param.svd_type_m_path_table_offset = SVD_type_M_path_table_offset;
	defined_param.svd_root_directory_record_offset = SVD_root_directory_record_offset;
	defined_param.svd_escape_sequences_offset = SVD_escape_sequences_offset;
	defined_param.pvd_type_offset = PVD_type_offset;
	defined_param.pvd_version_offset = PVD_version_offset;
	defined_param.pvd_reserved1_offset = PVD_reserved1_offset;
	defined_param.pvd_reserved2_offset = PVD_reserved2_offset;
	defined_param.pvd_reserved2_size = PVD_reserved2_size;
	defined_param.pvd_reserved3_offset = PVD_reserved3_offset;
	defined_param.pvd_reserved3_size = PVD_reserved3_size;
	defined_param.pvd_reserved4_offset = PVD_reserved4_offset;
	defined_param.pvd_reserved4_size = PVD_reserved4_size;
	defined_param.pvd_reserved5_offset = PVD_reserved5_offset;
	defined_param.pvd_reserved5_size = PVD_reserved5_size;
	defined_param.pvd_logical_block_size_offset = PVD_logical_block_size_offset;
	defined_param.pvd_volume_space_size_offset = PVD_volume_space_size_offset;
	defined_param.pvd_file_structure_version_offset = PVD_file_structure_version_offset;
	defined_param.pvd_type_1_path_table_offset = PVD_type_1_path_table_offset;
	defined_param.pvd_type_m_path_table_offset = PVD_type_m_path_table_offset;
	defined_param.pvd_root_directory_record_offset = PVD_root_directory_record_offset;
	return defined_param;
}

int
archive_read_support_format_iso9660(struct archive *_a)
{
	return 0;
}

#endif