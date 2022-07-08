/*-
* Copyright (c) 2003-2007 Tim Kientzle
* Copyright (c) 2011 Andres Mejia
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
#include <time.h>
#include <limits.h>
#ifdef HAVE_ZLIB_H
#include <zlib.h> /* crc32 */
#endif

#include "archive.h"
#ifndef HAVE_ZLIB_H
#include "archive_crc32.h"
#endif
#include "archive_endian.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_ppmd7_private.h"
#include "archive_private.h"
#include "archive_read_private.h"

/* RAR signature, also known as the mark header */
#define RAR_SIGNATURE "\x52\x61\x72\x21\x1A\x07\x00"

/* Header types */
#define MARK_HEAD    0x72
#define MAIN_HEAD    0x73
#define FILE_HEAD    0x74
#define COMM_HEAD    0x75
#define AV_HEAD      0x76
#define SUB_HEAD     0x77
#define PROTECT_HEAD 0x78
#define SIGN_HEAD    0x79
#define NEWSUB_HEAD  0x7a
#define ENDARC_HEAD  0x7b

/* Main Header Flags */
#define MHD_VOLUME       0x0001
#define MHD_COMMENT      0x0002
#define MHD_LOCK         0x0004
#define MHD_SOLID        0x0008
#define MHD_NEWNUMBERING 0x0010
#define MHD_AV           0x0020
#define MHD_PROTECT      0x0040
#define MHD_PASSWORD     0x0080
#define MHD_FIRSTVOLUME  0x0100
#define MHD_ENCRYPTVER   0x0200

/* Flags common to all headers */
#define HD_MARKDELETION     0x4000
#define HD_ADD_SIZE_PRESENT 0x8000

/* File Header Flags */
#define FHD_SPLIT_BEFORE 0x0001
#define FHD_SPLIT_AFTER  0x0002
#define FHD_PASSWORD     0x0004
#define FHD_COMMENT      0x0008
#define FHD_SOLID        0x0010
#define FHD_LARGE        0x0100
#define FHD_UNICODE      0x0200
#define FHD_SALT         0x0400
#define FHD_VERSION      0x0800
#define FHD_EXTTIME      0x1000
#define FHD_EXTFLAGS     0x2000

/* File dictionary sizes */
#define DICTIONARY_SIZE_64   0x00
#define DICTIONARY_SIZE_128  0x20
#define DICTIONARY_SIZE_256  0x40
#define DICTIONARY_SIZE_512  0x60
#define DICTIONARY_SIZE_1024 0x80
#define DICTIONARY_SIZE_2048 0xA0
#define DICTIONARY_SIZE_4096 0xC0
#define FILE_IS_DIRECTORY    0xE0
#define DICTIONARY_MASK      FILE_IS_DIRECTORY

/* OS Flags */
#define OS_MSDOS  0
#define OS_OS2    1
#define OS_WIN32  2
#define OS_UNIX   3
#define OS_MAC_OS 4
#define OS_BEOS   5

/* Compression Methods */
#define COMPRESS_METHOD_STORE   0x30
/* LZSS */
#define COMPRESS_METHOD_FASTEST 0x31
#define COMPRESS_METHOD_FAST    0x32
#define COMPRESS_METHOD_NORMAL  0x33
/* PPMd Variant H */
#define COMPRESS_METHOD_GOOD    0x34
#define COMPRESS_METHOD_BEST    0x35

#define CRC_POLYNOMIAL 0xEDB88320

#define NS_UNIT 10000000

#define DICTIONARY_MAX_SIZE 0x400000

#define MAINCODE_SIZE      299
#define OFFSETCODE_SIZE    60
#define LOWOFFSETCODE_SIZE 17
#define LENGTHCODE_SIZE    28
#define HUFFMAN_TABLE_SIZE \
  MAINCODE_SIZE + OFFSETCODE_SIZE + LOWOFFSETCODE_SIZE + LENGTHCODE_SIZE

#define MAX_SYMBOL_LENGTH 0xF
#define MAX_SYMBOLS       20

/*
 * Considering L1,L2 cache miss and a calling of write system-call,
 * the best size of the output buffer(uncompressed buffer) is 128K.
 * If the structure of extracting process is changed, this value
 * might be researched again.
 */
#define UNP_BUFFER_SIZE   (128 * 1024)

/* Define this here for non-Windows platforms */
#if !((defined(__WIN32__) || defined(_WIN32) || defined(__WIN32)) && !defined(__CYGWIN__))
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#endif

#undef minimum
#define minimum(a, b)    ((a)<(b)?(a):(b))

/* Stack overflow check */
#define MAX_COMPRESS_DEPTH 1024

/* Fields common to all headers */
struct rar_header {
  char crc[2];
  char type;
  char flags[2];
  char size[2];
};

/* Fields common to all file headers */
struct rar_file_header {
  char pack_size[4];
  char unp_size[4];
  char host_os;
  char file_crc[4];
  char file_time[4];
  char unp_ver;
  char method;
  char name_size[2];
  char file_attr[4];
};

struct huffman_tree_node {
  int branches[2];
};

struct huffman_table_entry {
  unsigned int length;
  int value;
};

struct huffman_code {
  struct huffman_tree_node *tree;
  int numentries;
  int numallocatedentries;
  int minlength;
  int maxlength;
  int tablesize;
  struct huffman_table_entry *table;
};

struct lzss {
  unsigned char *window;
  int mask;
  int64_t position;
};

struct data_block_offsets {
  int64_t header_size;
  int64_t start_offset;
  int64_t end_offset;
};

struct rar {
  /* Entries from main RAR header */
  unsigned main_flags;
  unsigned long file_crc;
  char reserved1[2];
  char reserved2[4];
  char encryptver;

  /* File header entries */
  char compression_method;
  unsigned file_flags;
  int64_t packed_size;
  int64_t unp_size;
  time_t mtime;
  long mnsec;
  mode_t mode;
  char *filename;
  char *filename_save;
  size_t filename_save_size;
  size_t filename_allocated;

  /* File header optional entries */
  char salt[8];
  time_t atime;
  long ansec;
  time_t ctime;
  long cnsec;
  time_t arctime;
  long arcnsec;

  /* Fields to help with tracking decompression of files. */
  int64_t bytes_unconsumed;
  int64_t bytes_remaining;
  int64_t bytes_uncopied;
  int64_t offset;
  int64_t offset_outgoing;
  int64_t offset_seek;
  char valid;
  unsigned int unp_offset;
  unsigned int unp_buffer_size;
  unsigned char *unp_buffer;
  unsigned int dictionary_size;
  char start_new_block;
  char entry_eof;
  unsigned long crc_calculated;
  int found_first_header;
  char has_endarc_header;
  struct data_block_offsets *dbo;
  unsigned int cursor;
  unsigned int nodes;
  char filename_must_match;

  /* LZSS members */
  struct huffman_code maincode;
  struct huffman_code offsetcode;
  struct huffman_code lowoffsetcode;
  struct huffman_code lengthcode;
  unsigned char lengthtable[HUFFMAN_TABLE_SIZE];
  struct lzss lzss;
  char output_last_match;
  unsigned int lastlength;
  unsigned int lastoffset;
  unsigned int oldoffset[4];
  unsigned int lastlowoffset;
  unsigned int numlowoffsetrepeats;
  int64_t filterstart;
  char start_new_table;

  /* PPMd Variant H members */
  char ppmd_valid;
  char ppmd_eod;
  char is_ppmd_block;
  int ppmd_escape;
  CPpmd7 ppmd7_context;
  CPpmd7z_RangeDec range_dec;
  IByteIn bytein;

  /*
   * String conversion object.
   */
  int init_default_conversion;
  struct archive_string_conv *sconv_default;
  struct archive_string_conv *opt_sconv;
  struct archive_string_conv *sconv_utf8;
  struct archive_string_conv *sconv_utf16be;

  /*
   * Bit stream reader.
   */
  struct rar_br {
#define CACHE_TYPE    uint64_t
#define CACHE_BITS    (8 * sizeof(CACHE_TYPE))
    /* Cache buffer. */
    CACHE_TYPE cache_buffer;
    /* Indicates how many bits avail in cache_buffer. */
    int cache_avail;
    ssize_t avail_in;
    const unsigned char *next_in;
  } br;

  /*
   * Custom field to denote that this archive contains encrypted entries
   */
  int has_encrypted_entries;
};

/*
 * Bit stream reader.
 */
/* Check that the cache buffer has enough bits. */
#define rar_br_has(br, n) ((br)->cache_avail >= n)
/* Get compressed data by bit. */
#define rar_br_bits(br, n)        \
  (((uint32_t)((br)->cache_buffer >>    \
    ((br)->cache_avail - (n)))) & cache_masks[n])
#define rar_br_bits_forced(br, n)     \
  (((uint32_t)((br)->cache_buffer <<    \
    ((n) - (br)->cache_avail))) & cache_masks[n])
/* Read ahead to make sure the cache buffer has enough compressed data we
 * will use.
 *  True  : completed, there is enough data in the cache buffer.
 *  False : there is no data in the stream. */
#define rar_br_read_ahead(a, br, n) \
  ((rar_br_has(br, (n)) || rar_br_fillup(a, br)) || rar_br_has(br, (n)))
/* Notify how many bits we consumed. */
#define rar_br_consume(br, n) ((br)->cache_avail -= (n))
#define rar_br_consume_unalined_bits(br) ((br)->cache_avail &= ~7)

#ifndef COMPILE_WITH_RUST

struct archive_rar_defined_param{
  int cache_bits;
  int archive_errno_file_format;
  int archive_fatal;
  int archive_ok;
  // int rar_br_read_ahead;
  int archive_read_format_caps_encrypt_data;
  int archive_read_format_caps_encrypt_metadata;
  int archive_read_format_encryption_dont_know;
  // int rar_signature;
  int archive_failed;
  int archive_errno_misc;
  int archive_warn;
  int archive_format_rar;
  int archive_eof;
  int mark_head;
  int main_head;
  int mhd_encryptver;
  int mhd_password;
  int file_head;
  int comm_head;
  int av_head;
  int sub_head;
  int protect_head;
  int sign_head;
  int endarc_head;
  int hd_add_size_present;
  int newsub_head;
  int compress_method_store;
  int compress_method_fastest;
  int compress_method_fast;
  int compress_method_normal;
  int compress_method_good;
  int compress_method_best;
  int mhd_volume;
  int fhd_split_after;
  int seek_cur;
  int seek_end;
  int seek_set;
  int fhd_split_before;
  int fhd_solid;
  int fhd_password;
  int fhd_large;
  int enomem;
  int fhd_unicode;
  int os_msdos;
  int os_os2;
  int os_win32;
  int file_attribute_directory;
  int ae_ifdir;
  int s_ixusr;
  int s_ixgrp;
  int s_ixoth;
  int ae_ifreg;
  int s_irusr;
  int s_iwusr;
  int s_irgrp;
  int s_iroth;
  int os_unix;
  int os_mac_os;
  int os_beos;
  int unp_buffer_size;
  int ae_ifmt;
  int ae_iflnk;
  int ns_unit;
  int max_compress_depth;
  long long int64_max;
  int max_symbols;
  int max_symbol_length;
  int huffman_table_size;
  int maincode_size;
  int offsetcode_size;
  int lowoffsetcode_size;
  int lengthcode_size;
  int dictionary_max_size;
};

struct archive_rar_defined_param get_archive_rar_defined_param();

struct archive_rar_defined_param get_archive_rar_defined_param(){
  struct archive_rar_defined_param defined_param;
  defined_param.cache_bits=CACHE_BITS;
  defined_param.archive_errno_file_format=ARCHIVE_ERRNO_FILE_FORMAT;
  defined_param.archive_fatal=ARCHIVE_FATAL;
  defined_param.archive_ok=ARCHIVE_OK;
  defined_param.archive_read_format_caps_encrypt_data=ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_DATA;
  defined_param.archive_read_format_caps_encrypt_metadata=ARCHIVE_READ_FORMAT_CAPS_ENCRYPT_METADATA;
  defined_param.archive_read_format_encryption_dont_know=ARCHIVE_READ_FORMAT_ENCRYPTION_DONT_KNOW;
  defined_param.archive_failed=ARCHIVE_FAILED;
  defined_param.archive_errno_misc=ARCHIVE_ERRNO_MISC;
  defined_param.archive_warn=ARCHIVE_WARN;
  defined_param.archive_format_rar=ARCHIVE_FORMAT_RAR;
  defined_param.archive_eof=ARCHIVE_EOF;
  defined_param.mark_head=MARK_HEAD;
  defined_param.main_head=MAIN_HEAD;
  defined_param.mhd_encryptver=MHD_ENCRYPTVER;
  defined_param.mhd_password=MHD_PASSWORD;
  defined_param.file_head=FILE_HEAD;
  defined_param.comm_head=COMM_HEAD;
  defined_param.av_head=AV_HEAD;
  defined_param.sub_head=SUB_HEAD;
  defined_param.protect_head=PROTECT_HEAD;
  defined_param.sign_head=SIGN_HEAD;
  defined_param.endarc_head=ENDARC_HEAD;
  defined_param.hd_add_size_present=HD_ADD_SIZE_PRESENT;
  defined_param.newsub_head=NEWSUB_HEAD;
  defined_param.compress_method_store=COMPRESS_METHOD_STORE;
  defined_param.compress_method_fastest=COMPRESS_METHOD_FASTEST;
  defined_param.compress_method_fast=COMPRESS_METHOD_FAST;
  defined_param.compress_method_normal=COMPRESS_METHOD_NORMAL;
  defined_param.compress_method_good=COMPRESS_METHOD_GOOD;
  defined_param.compress_method_best=COMPRESS_METHOD_BEST;
  defined_param.mhd_volume=MHD_VOLUME;
  defined_param.fhd_split_after=FHD_SPLIT_AFTER;
  defined_param.seek_cur=SEEK_CUR;
  defined_param.seek_end=SEEK_END;
  defined_param.seek_set=SEEK_SET;
  defined_param.fhd_split_before=FHD_SPLIT_BEFORE;
  defined_param.fhd_solid=FHD_SOLID;
  defined_param.fhd_password=FHD_PASSWORD;
  defined_param.fhd_large=FHD_LARGE;
  defined_param.enomem=ENOMEM;
  defined_param.fhd_unicode=FHD_UNICODE;
  defined_param.os_msdos=OS_MSDOS;
  defined_param.os_os2=OS_OS2;
  defined_param.os_win32=OS_WIN32;
  defined_param.file_attribute_directory=FILE_ATTRIBUTE_DIRECTORY;
  defined_param.ae_ifdir=AE_IFDIR;
  defined_param.s_ixusr=S_IXUSR;
  defined_param.s_ixgrp=S_IXGRP;
  defined_param.s_ixoth=S_IXOTH;
  defined_param.ae_ifreg=AE_IFREG;
  defined_param.s_irusr=S_IRUSR;
  defined_param.s_iwusr=S_IWUSR;
  defined_param.s_irgrp=S_IRGRP;
  defined_param.s_iroth=S_IROTH;
  defined_param.os_unix=OS_UNIX;
  defined_param.os_mac_os=OS_MAC_OS;
  defined_param.os_beos=OS_BEOS;
  defined_param.unp_buffer_size=UNP_BUFFER_SIZE;
  defined_param.ae_ifmt=AE_IFMT;
  defined_param.ae_iflnk=AE_IFLNK;
  defined_param.ns_unit=NS_UNIT;
  defined_param.max_compress_depth=MAX_COMPRESS_DEPTH;
  defined_param.int64_max=INT64_MAX;
  defined_param.max_symbols=MAX_SYMBOLS;
  defined_param.max_symbol_length=MAX_SYMBOL_LENGTH;
  defined_param.huffman_table_size=HUFFMAN_TABLE_SIZE;
  defined_param.maincode_size=MAINCODE_SIZE;
  defined_param.offsetcode_size=OFFSETCODE_SIZE;
  defined_param.lowoffsetcode_size=LOWOFFSETCODE_SIZE;
  defined_param.lengthcode_size=LENGTHCODE_SIZE;
  defined_param.dictionary_max_size=DICTIONARY_MAX_SIZE;
  return defined_param;
}

int
archive_read_support_format_rar(struct archive *_a) {
  return 0;
}

#endif