/*-
 * Copyright (c) 2011 Tim Kientzle
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
#include "test.h"
__FBSDID("$FreeBSD$");

/*
 * Verify that the various archive_read_support_* functions
 * return appropriate errors when invoked on the wrong kind of
 * archive handle.
 */

typedef struct archive *constructor(void);
typedef int enabler(struct archive *);
typedef int destructor(struct archive *);

static int format_code = 0;
static int format_code_enabler(struct archive *a)
{
	return archive_read_support_format_by_code(a, format_code);
}

static int format_code_setter(struct archive *a)
{
	return archive_read_set_format(a, format_code);
}

static void
test_success(constructor new_, enabler enable_, destructor free_)
{
	struct archive *a = new_();
	int result = enable_(a);
	if (result == ARCHIVE_WARN) {
		assert(NULL != archive_error_string(a));
		assertEqualIntA(a, -1, archive_errno(a));
	} else {
		assertEqualIntA(a, ARCHIVE_OK, result);
		assert(NULL == archive_error_string(a));
		assertEqualIntA(a, 0, archive_errno(a));
	}
	free_(a);
}

static void
test_failure(constructor new_, enabler enable_, destructor free_)
{
	struct archive *a = new_();
	assertEqualIntA(a, ARCHIVE_FATAL, enable_(a));
	assert(NULL != archive_error_string(a));
	assertEqualIntA(a, -1, archive_errno(a));
	free_(a);
}

static void
test_filter_or_format(enabler enable)
{
	test_success(archive_read_new, enable, archive_read_free);
	test_failure(archive_write_new, enable, archive_write_free);
	test_failure(archive_read_disk_new, enable, archive_read_free);
	test_failure(archive_write_disk_new, enable, archive_write_free);
}

static void
test_7zip()
{
	archive_test_fileTimeToUtc();
	archive_test_Bcj2_Decode();
	archive_test_x86_Convert();
	char p1[6] = {0x1C,0x1C,0x1C,0x1C,0x1C,0x1C};
	char p2[6] = {0x37,0x37,0x37,0x37,0x37,0x37};
	char p3[6] = {0x7A,0x7A,0x7A,0x7A,0x7A,0x7A};
	char p4[6] = {0xBC,0xBC,0xBC,0xBC,0xBC,0xBC};
	char p5[6] = {0xAF,0xAF,0xAF,0xAF,0xAF,0xAF};
	char p6[6] = {0x27,0x27,0x27,0x27,0x27,0x27};
	char p7[6] = {0x2C,0x2C,0x2C,0x2C,0x2C,0x2C};
	char p8[6] = "7z\xBC\xAF\x27\x1C";
	char *input = p1;
	archive_test_check_7zip_header_in_sfx(input);
	input = p2;
	archive_test_check_7zip_header_in_sfx(input);
	input = p3;
	archive_test_check_7zip_header_in_sfx(input);
	input = p4;
	archive_test_check_7zip_header_in_sfx(input);
	input = p5;
	archive_test_check_7zip_header_in_sfx(input);
	input = p6;
	archive_test_check_7zip_header_in_sfx(input);
	input = p7;
	archive_test_check_7zip_header_in_sfx(input);
	input = p8;
	archive_test_check_7zip_header_in_sfx(input);
	archive_test_archive_read_support_format_7zip();
	const char *refname = "test_read_format_7zip_empty_file.7z";
	struct archive *a;
	extract_reference_file(refname);
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, refname, 10240));
	archive_test_skip_sfx(a, 0x27001);
	archive_test_skip_sfx(a, 0x27000);
	archive_test_read_stream(a);
	archive_test_archive_read_format_7zip_bid(a);
	archive_test_get_uncompressed_data(a);
	archive_test_decode_encoded_header_info(a);
	archive_test_extract_pack_stream(a);
	archive_test_seek_pack(a);
	archive_test_init_decompression(a);
	archive_test_ppmd_read(a);
	archive_test_decompress(a);
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_ar()
{
	archive_test_archive_read_support_format_ar();
	size_t size = 2;
	size_t * size2 = &size;
	int64_t offset = 1;
	int64_t * offset2 = &offset;
	void * buff = {NULL, NULL};
	void ** buff2 = &buff;
	char p[] = {'_','_','.','S','Y','M','D','E','F','1',
    '1','1','1','1','1','1','1','1','1','1',
    '1','1','1','1','1','1','1','1','1','1',
    '1','1','1','1','1','1','1','1','1','1',
    '1','1','1','1','1','1','1','1','1','1',
    '1','1','1','1','1','1','1','1', '`','\n'};
	const char *h = p;
	const char reffile[] = "test_read_format_ar.ar";
	struct archive *a;
	extract_reference_file(reffile);
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, reffile, 10240));
	struct archive_entry *entry = archive_entry_new();
	archive_test__ar_read_header(a, entry, h, 1);
	archive_test_archive_read_format_ar_read_data(a, buff2, size2, offset2);
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_cab()
{
	const void *p;
	const char refname[] = "test_read_format_cab_1.cab";
	struct archive *a;
	extract_reference_file(refname);
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, refname, 10240));
	archive_test_cab_checksum_cfdata(p, 3, 1);
	archive_test_lzx_br_fillup();
	archive_test_lzx_huffman_init(1, 1);
	archive_test_lzx_br_fixup();
	archive_test_archive_read_support_format_cab();
	archive_test_cab_consume_cfdata(a);
	archive_test_archive_read_format_cab_read_data(a);
	archive_test_cab_next_cfdata(a);
	archive_test_cab_checksum_update(a);
	archive_test_archive_read_format_cab_options(a);
	archive_test_cab_skip_sfx(a);
	archive_test_cab_read_data(a);
	archive_test_cab_read_ahead_cfdata_none(a);
	archive_test_lzx_read_blocks();
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_iso9660()
{
	archive_test_isNull("123", 1, 4096);
	unsigned char s[] = {3,-1,-1,-1,-1,-1,1,0,-1,-1};
    unsigned char *h = s;
	archive_test_isVolumePartition(h);
	archive_test_isodate17("111111111111111111111111111111");
	unsigned char data[] = {0, 0x10,0x10,0x20,0x20,0x20,0x30,0x30};
	unsigned char *data3 = data;
	archive_test_parse_rockridge_SL1(data3, 8);
	unsigned char data2[] = {0, 0x20,0x20,0x20,0x20,0x20,0x30,0x30};
	unsigned char *data4 = data2;
	archive_test_parse_rockridge_SL1(data4, 8);
	data[0] = 0x8c;
	archive_test_parse_rockridge_TF1(data3, 18);
	data[0] = 0x81;
	archive_test_parse_rockridge_TF1(data3, 18);
	data[0] = 0x82;
	archive_test_parse_rockridge_TF1(data3, 18);
	data[0] = 0x84;
	archive_test_parse_rockridge_TF1(data3, 18);
	data[0] = 0x88;
	archive_test_parse_rockridge_TF1(data3, 18);
	data[0] = 4;
	archive_test_parse_rockridge_NM1(data3, 18);
	unsigned char pp[] = {'P', 'N', 20, 1,'P','N'};
    const unsigned char *p = pp;
    const unsigned char *end = p + p[2];
	archive_test_archive_read_support_format_iso9660();
	const char *refname = "test_read_format_iso_xorriso.iso.Z";
	struct archive *a;
	extract_reference_file(refname);
	assert((a = archive_read_new()) != NULL);
	assertEqualInt(0, archive_read_support_filter_all(a));
	assertEqualInt(0, archive_read_support_format_all(a));
	assertEqualInt(ARCHIVE_OK, archive_read_open_filename(a, refname, 10240));
	archive_test_archive_read_format_iso9660_read_data(a);
	archive_test_parse_rockridge(a, p, end);
	pp[0] = 'S';
	pp[1] = 'T';
	pp[2] = 4;
	archive_test_parse_rockridge(a, p, end);
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_lha()
{
	unsigned char pp[] = {
	'1','1','-','l','z','s','-','1','1','1',
	'1','1','1','1','z','s','1','1','1','1',
	0};
	const unsigned char *p = pp;
	const void *h = (unsigned char *)p;
	struct archive *a;
	const char reffile[] = "test_read_format_lha_lh7.lzh";
	extract_reference_file(reffile);
	struct archive_entry *entry = archive_entry_new();
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, reffile, 10240));
	archive_test_lha_check_header_format(h);
	archive_test_lzh_read_blocks();
	archive_test_lzh_decode_blocks();
	archive_test_lzh_emit_window();
	archive_test_lzh_decode_huffman_tree();
	archive_test_archive_read_support_format_lha(a);
	archive_test_archive_read_format_lha_options(a, "hdrcharset", NULL);
	archive_test_lha_skip_sfx(a);
	archive_test_lha_read_data_none(a);
	archive_test_lha_read_data_lzh(a);
	archive_test_truncated_error(a);
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_mtree()
{
	archive_test_archive_read_support_format_mtree();
	int p[] = {1,2,3,4,5};
	int *p1 = p;
	char *sp1[] = {"x","x","x","x"};
	char ** sp = sp1;
	archive_test_la_strsep(sp, "2");
	sp = NULL;
	archive_test_la_strsep(sp, "2");
	archive_test_bid_keyword();
	archive_test_bid_keyword_list();
	archive_test_mtree_atol();
	struct archive *a;
	const char reffile[] = "test_read_format_mtree_noprint.mtree";
	extract_reference_file(reffile);
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, reffile, 11));
	struct archive_entry *entry = archive_entry_new();
	archive_test_archive_read_format_mtree_options(a);
	archive_test_parse_device(a);
	archive_test_read_header(a, entry);
	archive_test_parse_keyword(a, entry, p1);
	archive_test_process_global_unset(a, "123");
	archive_test_parse_digest(a, entry, "", 0x00000007);
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_rar()
{
	struct archive *a;
	const char reffile[] = "test_read_format_rar.rar";
	extract_reference_file(reffile);
	struct archive_entry *entry = archive_entry_new();
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, reffile, 10240));
	archive_test_make_table_recurse(a);
	archive_test_rar_br_preparation(a);
	archive_test_rar_skip_sfx(a);
	archive_test_archive_read_format_rar_options(a);
	size_t size = 2;
	size_t * size2 = &size;
	int64_t offset = 1;
	int64_t * offset2 = &offset;
	void * buff = {NULL, NULL};
	const void ** buff2 = &buff;
	archive_test_archive_read_format_rar_read_data(a, buff2, size2, offset2);
	archive_test_archive_read_format_rar_seek_data(a);
	archive_test_read_data_stored(a, buff2, size2, offset2);
	archive_test_copy_from_lzss_window(a, buff2, 1, 2);
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}


static void
test_zip()
{
	const char *refname = "test_read_format_zip.zip";
	extract_reference_file(refname);
	struct archive *a;
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, refname, 10240));
	const uint8_t key[12];
	uint8_t crcchk[12];
	archive_test_trad_enc_init(a, key, crcchk);
	struct archive_entry *entry = archive_entry_new();
	archive_test_zip_read_mac_metadata(a, entry);
	archive_test_expose_parent_dirs(a, "aa", 20);
	const void * _p;
	archive_test_check_authentication_code(a, _p);
	archive_test_read_format_zip_read_data(a);
	archive_test_archive_read_format_zip_options(a, "compat-2x", "");
	archive_test_archive_read_format_zip_options(a, "hdrcharset", NULL);
	archive_test_archive_read_format_zip_options(a, "ignorecrc32", NULL);
	archive_test_zipx_ppmd8_init(a);
	archive_test_cmp_key(_p);
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_tar()
{
	archive_test_tohex((int)'0');
	archive_test_tohex((int)'A');
	archive_test_tohex((int)'a');
	archive_test_tohex(-1);
	struct archive *a;
	assert((a = archive_read_new()) != NULL);
	struct archive_entry *entry = archive_entry_new();
	archive_test_pax_attribute(a, entry, "LIBARCHIVE.symlinktype", "file", 20);
	archive_test_pax_attribute(a, entry, "LIBARCHIVE.symlinktype", "dir", 20);
	archive_test_pax_attribute(a, entry, "SCHILY.devmajor", "dir", 20);
	archive_test_pax_attribute(a, entry, "SCHILY.devminor", "dir", 20);
	archive_test_pax_attribute(a, entry, "SCHILY.realsize", "dir", 20);
	archive_test_pax_attribute(a, entry, "hdrcharset", "ISO-IR 10646 2000 UTF-8", 20);
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_warc()
{
	struct archive *a = archive_read_new();
	const char reffile[] = "test_read_format_warc.warc";
	extract_reference_file(reffile);
	struct archive_entry *entry = archive_entry_new();
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, reffile, 10240));
	size_t size = 4;
	size_t * size2 = &size;
	int64_t offset = 4;
	int64_t * offset2 = &offset;
	void * buff = "test";
	const void ** buff2 = &buff;
	// archive_test__warc_read(a, buff2, size2, offset2);
	// archive_test__warc_rdhdr(a, entry);
	// archive_test_archive_read_support_format_warc();
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_string()
{
	struct archive *a;
	assert((a = archive_read_new()) != NULL);
	const void *_p;
	archive_test_best_effort_strncat_utf16(_p, 0);
	archive_test_best_effort_strncat_utf16("test", 4);
	archive_test_strncat_from_utf8_libarchive2(_p, 0);
	archive_test_strncat_from_utf8_libarchive2("test", 4);
	archive_test_archive_string_append_unicode(_p, 0);
	archive_test_archive_string_append_unicode("test", 4);
	archive_test_invalid_mbs(_p, 0);
	archive_test_best_effort_strncat_in_locale("tes？", 4);
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_raw()
{
	struct archive *a;
	const char *reffile1 = "test_read_format_raw.data";
	extract_reference_file(reffile1);
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_raw(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, reffile1, 512));
	archive_test_archive_read_format_raw_read_data_skip(a);
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}

static void
test_rar5()
{
	struct archive *a;
	const char reffile[] = "test_read_format_rar.rar";
	extract_reference_file(reffile);
	struct archive_entry *entry = archive_entry_new();
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, reffile, 10240));
	int res_empty_function = archive_test_rar5_empty_function(a);
	assertEqualInt(res_empty_function, -32);
	uint8_t dst[5] = "test";
	uint8_t window[11] = "helloworld";
	size_t size = 0;
	size_t * size2 = &size;
	int64_t offset = 1;
	int64_t * offset2 = &offset;
	void * buff = {NULL, NULL};
	const void ** buff2 = &buff;
	archive_test_circular_memcpy(dst, window, 1, 1, 2);
	int res1_rar5_read_data = archive_test_rar5_read_data(a, buff2, size2, offset2, 0);
	int res2_rar5_read_data = archive_test_rar5_read_data(a, buff2, size2, offset2, 1);
	int res_do_unpack = archive_test_do_unpack(a, buff2, size2, offset2);
	int res1_run_filter = archive_test_run_filter(a, 0);
	int res2_run_filter = archive_test_run_filter(a, 1);
	archive_test_push_data(a, dst, 1, 2);
	int res_process_head_file = archive_test_process_head_file(a, entry, 0);
	uint64_t where = 0;
	ssize_t extra_data_size = 0;
	int res1_parse_htime_item = archive_test_parse_htime_item(a, '1', &where, &extra_data_size);
	int res2_parse_htime_item = archive_test_parse_htime_item(a, 0, &where, &extra_data_size);
	archive_test_init_unpack();
	int res1_do_unstore_file = archive_test_do_unstore_file(a, buff2, size2, offset2, 0);
	int res2_do_unstore_file = archive_test_do_unstore_file(a, buff2, size2, offset2, 1);
	int res1_merge_block = archive_test_merge_block(a, extra_data_size, &dst, 1);
	int res2_merge_block = archive_test_merge_block(a, -9, &dst, 0);
	int res3_merge_block = archive_test_merge_block(a, 0, &dst, 0);
	int res_parse_tables = archive_test_parse_tables(a, dst);
	int res_parse_block_header = archive_test_parse_block_header(a, dst, &extra_data_size);
	assertEqualInt(ARCHIVE_OK, archive_read_close(a));
	assertEqualInt(ARCHIVE_OK, archive_read_free(a));
}


DEFINE_TEST(test_archive_read_support)
{
	test_filter_or_format(archive_read_support_format_7zip);
	test_filter_or_format(archive_read_support_format_all);
	test_filter_or_format(archive_read_support_format_ar);
	test_filter_or_format(archive_read_support_format_cab);
	test_filter_or_format(archive_read_support_format_cpio);
	test_filter_or_format(archive_read_support_format_empty);
	test_filter_or_format(archive_read_support_format_iso9660);
	test_filter_or_format(archive_read_support_format_lha);
	test_filter_or_format(archive_read_support_format_mtree);
	test_filter_or_format(archive_read_support_format_tar);
	test_filter_or_format(archive_read_support_format_xar);
	test_filter_or_format(archive_read_support_format_zip);

	int format_codes[] = {
	    ARCHIVE_FORMAT_CPIO,
	    ARCHIVE_FORMAT_CPIO_POSIX,
	    ARCHIVE_FORMAT_CPIO_BIN_LE,
	    ARCHIVE_FORMAT_CPIO_BIN_BE,
	    ARCHIVE_FORMAT_CPIO_SVR4_NOCRC,
	    ARCHIVE_FORMAT_CPIO_SVR4_CRC,
	    ARCHIVE_FORMAT_CPIO_AFIO_LARGE,
	    ARCHIVE_FORMAT_TAR,
	    ARCHIVE_FORMAT_TAR_USTAR,
	    ARCHIVE_FORMAT_TAR_PAX_INTERCHANGE,
	    ARCHIVE_FORMAT_TAR_PAX_RESTRICTED,
	    ARCHIVE_FORMAT_TAR_GNUTAR,
	    ARCHIVE_FORMAT_ISO9660,
	    ARCHIVE_FORMAT_ISO9660_ROCKRIDGE,
	    ARCHIVE_FORMAT_ZIP,
	    ARCHIVE_FORMAT_EMPTY,
	    ARCHIVE_FORMAT_AR,
	    ARCHIVE_FORMAT_AR_GNU,
	    ARCHIVE_FORMAT_AR_BSD,
	    ARCHIVE_FORMAT_MTREE,
	    ARCHIVE_FORMAT_RAW,
	    ARCHIVE_FORMAT_XAR,
	    ARCHIVE_FORMAT_LHA,
	    ARCHIVE_FORMAT_CAB,
	    ARCHIVE_FORMAT_RAR,
	    ARCHIVE_FORMAT_7ZIP,
	    ARCHIVE_FORMAT_WARC,
	    ARCHIVE_FORMAT_RAR_V5,
	};
	unsigned int i;

	for (i = 0; i < sizeof(format_codes) / sizeof(int); i++) {
		format_code = format_codes[i];
		test_filter_or_format(format_code_enabler);
		test_filter_or_format(format_code_setter);
	}

	test_filter_or_format(archive_read_support_filter_all);
	test_filter_or_format(archive_read_support_filter_bzip2);
	test_filter_or_format(archive_read_support_filter_compress);
	test_filter_or_format(archive_read_support_filter_gzip);
	test_filter_or_format(archive_read_support_filter_lzip);
	test_filter_or_format(archive_read_support_filter_lzma);
	test_filter_or_format(archive_read_support_filter_none);
	test_filter_or_format(archive_read_support_filter_rpm);
	test_filter_or_format(archive_read_support_filter_uu);
	test_filter_or_format(archive_read_support_filter_xz);

	test_7zip();
	test_ar();
	test_cab();
	test_iso9660();
	test_lha();
	test_mtree();
	test_rar();
	test_zip();
	test_tar();
	test_warc();
	test_string();
	test_raw();
	test_rar5();
}
