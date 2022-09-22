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

	const char *refname = "test_read_format_7zip_empty_file.7z";
	struct archive *a;
	extract_reference_file(refname);
	assert((a = archive_read_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_filter_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_support_format_all(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_read_open_filename(a, refname, 10240));
	archive_test_skip_sfx(a, 0x27001);
	archive_test_skip_sfx(a, 0x27000);
	archive_test_init_decompression(a);
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
test_mtree()
{
	struct archive *a;
	assert((a = archive_read_new()) != NULL);
	struct archive_entry *entry = archive_entry_new();
	int p[] = {1,2,3,4,5};
	int *p1 = p;
	archive_test_parse_keyword(a, entry, p1);
	archive_test_process_global_unset(a, "123");
	char *sp1[] = {"x","x","x","x"};
	char ** sp = sp1;
	archive_test_la_strsep(sp, "2");
	sp = NULL;
	archive_test_la_strsep(sp, "2");
	archive_test_parse_digest(a, entry, "", 0x00000007);
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
	test_zip();
	test_tar();
	test_mtree();
}
