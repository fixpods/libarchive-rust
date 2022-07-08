#include "archive_platform.h"
#include "archive_endian.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <time.h>
#ifdef HAVE_ZLIB_H
#include <zlib.h> /* crc32 */
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include "archive.h"
#ifndef HAVE_ZLIB_H
#include "archive_crc32.h"
#endif

#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_ppmd7_private.h"
#include "archive_entry_private.h"

#ifdef HAVE_BLAKE2_H
#include <blake2.h>
#else
#include "archive_blake2.h"
#endif

/*#define CHECK_CRC_ON_SOLID_SKIP*/
/*#define DONT_FAIL_ON_CRC_ERROR*/
/*#define DEBUG*/

#define rar5_min(a, b) (((a) > (b)) ? (b) : (a))
#define rar5_max(a, b) (((a) > (b)) ? (a) : (b))
#define rar5_countof(X) ((const ssize_t) (sizeof(X) / sizeof(*X)))

#if defined DEBUG
#define DEBUG_CODE if(1)
#define LOG(...) do { printf("rar5: " __VA_ARGS__); puts(""); } while(0)
#else
#define DEBUG_CODE if(0)
#endif

/* Real RAR5 magic number is:
 *
 * 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00
 * "Rar!→•☺·\x00"
 *
 * Retrieved with `rar5_signature()` by XOR'ing it with 0xA1, because I don't
 * want to put this magic sequence in each binary that uses libarchive, so
 * applications that scan through the file for this marker won't trigger on
 * this "false" one.
 *
 * The array itself is decrypted in `rar5_init` function. */

/* These could have been static const's, but they aren't, because of
 * Visual Studio. */
#define MAX_NAME_IN_CHARS 2048
#define MAX_NAME_IN_BYTES (4 * MAX_NAME_IN_CHARS)

struct file_header {
  ssize_t bytes_remaining;
  ssize_t unpacked_size;
  int64_t last_offset;         /* Used in sanity checks. */
  int64_t last_size;           /* Used in sanity checks. */

  uint8_t solid: 1;           /* Is this a solid stream? */
  uint8_t service: 1;         /* Is this file a service data? */
  uint8_t eof: 1;             /* Did we finish unpacking the file? */
  uint8_t dir: 1;             /* Is this file entry a directory? */

  /* Optional time fields. */
  uint64_t e_mtime;
  uint64_t e_ctime;
  uint64_t e_atime;
  uint32_t e_unix_ns;

  /* Optional hash fields. */
  uint32_t stored_crc32;
  uint32_t calculated_crc32;
  uint8_t blake2sp[32];
  blake2sp_state b2state;
  char has_blake2;

  /* Optional redir fields */
  uint64_t redir_type;
  uint64_t redir_flags;

  ssize_t solid_window_size; /* Used in file format check. */
};

enum EXTRA {
  EX_CRYPT = 0x01,
  EX_HASH = 0x02,
  EX_HTIME = 0x03,
  EX_VERSION = 0x04,
  EX_REDIR = 0x05,
  EX_UOWNER = 0x06,
  EX_SUBDATA = 0x07
};

#define REDIR_SYMLINK_IS_DIR    1

enum REDIR_TYPE {
  REDIR_TYPE_NONE = 0,
  REDIR_TYPE_UNIXSYMLINK = 1,
  REDIR_TYPE_WINSYMLINK = 2,
  REDIR_TYPE_JUNCTION = 3,
  REDIR_TYPE_HARDLINK = 4,
  REDIR_TYPE_FILECOPY = 5,
};

#define    OWNER_USER_NAME        0x01
#define    OWNER_GROUP_NAME    0x02
#define    OWNER_USER_UID        0x04
#define    OWNER_GROUP_GID        0x08
#define    OWNER_MAXNAMELEN    256

enum FILTER_TYPE {
  FILTER_DELTA = 0,   /* Generic pattern. */
  FILTER_E8 = 1,   /* Intel x86 code. */
  FILTER_E8E9 = 2,   /* Intel x86 code. */
  FILTER_ARM = 3,   /* ARM code. */
  FILTER_AUDIO = 4,   /* Audio filter, not used in RARv5. */
  FILTER_RGB = 5,   /* Color palette, not used in RARv5. */
  FILTER_ITANIUM = 6, /* Intel's Itanium, not used in RARv5. */
  FILTER_PPM = 7,   /* Predictive pattern matching, not used in
			       RARv5. */
  FILTER_NONE = 8,
};

struct filter_info {
  int type;
  int channels;
  int pos_r;

  int64_t block_start;
  ssize_t block_length;
  uint16_t width;
};

struct data_ready {
  char used;
  const uint8_t *buf;
  size_t size;
  int64_t offset;
};

struct cdeque {
  uint16_t beg_pos;
  uint16_t end_pos;
  uint16_t cap_mask;
  uint16_t size;
  size_t *arr;
};

struct decode_table {
  uint32_t size;
  int32_t decode_len[16];
  uint32_t decode_pos[16];
  uint32_t quick_bits;
  uint8_t quick_len[1 << 10];
  uint16_t quick_num[1 << 10];
  uint16_t decode_num[306];
};

struct comp_state {
  /* Flag used to specify if unpacker needs to reinitialize the
     uncompression context. */
  uint8_t initialized: 1;

  /* Flag used when applying filters. */
  uint8_t all_filters_applied: 1;

  /* Flag used to skip file context reinitialization, used when unpacker
     is skipping through different multivolume archives. */
  uint8_t switch_multivolume: 1;

  /* Flag used to specify if unpacker has processed the whole data block
     or just a part of it. */
  uint8_t block_parsing_finished: 1;

  signed int notused: 4;

  int flags;                   /* Uncompression flags. */
  int method;                  /* Uncompression algorithm method. */
  int version;                 /* Uncompression algorithm version. */
  ssize_t window_size;         /* Size of window_buf. */
  uint8_t *window_buf;         /* Circular buffer used during
	                                decompression. */
  uint8_t *filtered_buf;       /* Buffer used when applying filters. */
  const uint8_t *block_buf;    /* Buffer used when merging blocks. */
  size_t window_mask;          /* Convenience field; window_size - 1. */
  int64_t write_ptr;           /* This amount of data has been unpacked
					in the window buffer. */
  int64_t last_write_ptr;      /* This amount of data has been stored in
	                                the output file. */
  int64_t last_unstore_ptr;    /* Counter of bytes extracted during
	                                unstoring. This is separate from
	                                last_write_ptr because of how SERVICE
	                                base blocks are handled during skipping
	                                in solid multiarchive archives. */
  int64_t solid_offset;        /* Additional offset inside the window
	                                buffer, used in unpacking solid
	                                archives. */
  ssize_t cur_block_size;      /* Size of current data block. */
  int last_len;                /* Flag used in lzss decompression. */

  /* Decode tables used during lzss uncompression. */

#define HUFF_BC 20
  struct decode_table bd;      /* huffman bit lengths */
#define HUFF_NC 306
  struct decode_table ld;      /* literals */
#define HUFF_DC 64
  struct decode_table dd;      /* distances */
#define HUFF_LDC 16
  struct decode_table ldd;     /* lower bits of distances */
#define HUFF_RC 44
  struct decode_table rd;      /* repeating distances */
#define HUFF_TABLE_SIZE (HUFF_NC + HUFF_DC + HUFF_RC + HUFF_LDC)

  /* Circular deque for storing filters. */
  struct cdeque filters;
  int64_t last_block_start;    /* Used for sanity checking. */
  ssize_t last_block_length;   /* Used for sanity checking. */

  /* Distance cache used during lzss uncompression. */
  int dist_cache[4];

  /* Data buffer stack. */
  struct data_ready dready[2];
};

/* Bit reader state. */
struct bit_reader {
  int8_t bit_addr;    /* Current bit pointer inside current byte. */
  int in_addr;        /* Current byte pointer. */
};

/* RARv5 block header structure. Use bf_* functions to get values from
 * block_flags_u8 field. I.e. bf_byte_count, etc. */
struct compressed_block_header {
  /* block_flags_u8 contain fields encoded in little-endian bitfield:
   *
   * - table present flag (shr 7, and 1),
   * - last block flag    (shr 6, and 1),
   * - byte_count         (shr 3, and 7),
   * - bit_size           (shr 0, and 7).
   */
  uint8_t block_flags_u8;
  uint8_t block_cksum;
};

/* RARv5 main header structure. */
struct main_header {
  /* Does the archive contain solid streams? */
  uint8_t solid: 1;

  /* If this a multi-file archive? */
  uint8_t volume: 1;
  uint8_t endarc: 1;
  uint8_t notused: 5;

  unsigned int vol_no;
};

struct generic_header {
  uint8_t split_after: 1;
  uint8_t split_before: 1;
  uint8_t padding: 6;
  int size;
  int last_header_id;
};

struct multivolume {
  unsigned int expected_vol_no;
  uint8_t *push_buf;
};

/* Main context structure. */
struct rar5 {
  int header_initialized;

  /* Set to 1 if current file is positioned AFTER the magic value
   * of the archive file. This is used in header reading functions. */
  int skipped_magic;

  /* Set to not zero if we're in skip mode (either by calling
   * rar5_data_skip function or when skipping over solid streams).
   * Set to 0 when in * extraction mode. This is used during checksum
   * calculation functions. */
  int skip_mode;

  /* Set to not zero if we're in block merging mode (i.e. when switching
   * to another file in multivolume archive, last block from 1st archive
   * needs to be merged with 1st block from 2nd archive). This flag
   * guards against recursive use of the merging function, which doesn't
   * support recursive calls. */
  int merge_mode;

  /* An offset to QuickOpen list. This is not supported by this unpacker,
   * because we're focusing on streaming interface. QuickOpen is designed
   * to make things quicker for non-stream interfaces, so it's not our
   * use case. */
  uint64_t qlist_offset;

  /* An offset to additional Recovery data. This is not supported by this
   * unpacker. Recovery data are additional Reed-Solomon codes that could
   * be used to calculate bytes that are missing in archive or are
   * corrupted. */
  uint64_t rr_offset;

  /* Various context variables grouped to different structures. */
  struct generic_header generic;
  struct main_header main;
  struct comp_state cstate;
  struct file_header file;
  struct bit_reader bits;
  struct multivolume vol;

  /* The header of currently processed RARv5 block. Used in main
   * decompression logic loop. */
  struct compressed_block_header last_block_hdr;
};

#ifndef COMPILE_WITH_RUST

struct archive_rar5_defined_param{
    int archive_ok;
    int enomem;
    int archive_fatal;
    int archive_errno_file_format;
    int archive_errno_programmer;
    int archive_retry;
    int archive_warn;
    int archive_format_rar_v5;
    int archive_eof;
    int max_name_in_bytes;
    int max_name_in_chars;
    int ae_iflnk;
    int redir_symlink_is_dir;
    int ae_symlink_type_directory;
    int ae_symlink_type_file;
    int ae_ifreg;
    int owner_maxnamelen;
    int owner_user_name;
    int owner_group_name;
    int owner_user_uid;
    int owner_group_gid;
    int ae_ifdir;
    int uint_max;
    int huff_nc;
    int huff_bc;
    int huff_table_size;
    int huff_dc;
    int huff_ldc;
    int huff_rc;
    int int_max;
    int archive_failed;
    int archive_read_format_encryption_unsupported;
};

struct archive_rar5_defined_param get_archive_rar5_defined_param();

struct archive_rar5_defined_param get_archive_rar5_defined_param(){
    struct archive_rar5_defined_param defined_param;
    defined_param.archive_ok=ARCHIVE_OK;
    defined_param.enomem=ENOMEM;
    defined_param.archive_fatal=ARCHIVE_FATAL;
    defined_param.archive_errno_file_format=ARCHIVE_ERRNO_FILE_FORMAT;
    defined_param.archive_errno_programmer=ARCHIVE_ERRNO_PROGRAMMER;
    defined_param.archive_retry=ARCHIVE_RETRY;
    defined_param.archive_warn=ARCHIVE_WARN;
    defined_param.archive_format_rar_v5=ARCHIVE_FORMAT_RAR_V5;
    defined_param.archive_eof=ARCHIVE_EOF;
    defined_param.max_name_in_bytes=MAX_NAME_IN_BYTES;
    defined_param.max_name_in_chars=MAX_NAME_IN_CHARS;
    defined_param.ae_iflnk=AE_IFLNK;
    defined_param.redir_symlink_is_dir=REDIR_SYMLINK_IS_DIR;
    defined_param.ae_symlink_type_directory=AE_SYMLINK_TYPE_DIRECTORY;
    defined_param.ae_symlink_type_file=AE_SYMLINK_TYPE_FILE;
    defined_param.ae_ifreg=AE_IFREG;
    defined_param.owner_maxnamelen=OWNER_MAXNAMELEN;
    defined_param.owner_user_name=OWNER_USER_NAME;
    defined_param.owner_group_name=OWNER_GROUP_NAME;
    defined_param.owner_user_uid=OWNER_USER_UID;
    defined_param.owner_group_gid=OWNER_GROUP_GID;
    defined_param.ae_ifdir=AE_IFDIR;
    defined_param.uint_max=UINT_MAX;
    defined_param.huff_nc=HUFF_NC;
    defined_param.huff_bc=HUFF_BC;
    defined_param.huff_table_size=HUFF_TABLE_SIZE;
    defined_param.huff_dc=HUFF_DC;
    defined_param.huff_ldc=HUFF_LDC;
    defined_param.huff_rc=HUFF_RC;
    defined_param.int_max=INT_MAX;
    defined_param.archive_failed=ARCHIVE_FAILED;
    defined_param.archive_read_format_encryption_unsupported=ARCHIVE_READ_FORMAT_ENCRYPTION_UNSUPPORTED;
    return defined_param;
}

int
archive_read_support_format_rar5(struct archive *_a) {
  return 0;
}

#endif