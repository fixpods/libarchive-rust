/*-
 * Copyright (c) 2003-2011 Tim Kientzle
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
__FBSDID("$FreeBSD: head/lib/libarchive/archive_string.c 201095 2009-12-28 02:33:22Z kientzle $");

/*
 * Basic resizable string support, to simplify manipulating arbitrary-sized
 * strings while minimizing heap activity.
 *
 * In particular, the buffer used by a string object is only grown, it
 * never shrinks, so you can clear and reuse the same string object
 * without incurring additional memory allocations.
 */

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_ICONV_H
#include <iconv.h>
#endif
#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif
#ifdef HAVE_LOCALCHARSET_H
#include <localcharset.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif
#if defined(_WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#include <locale.h>
#endif

#include "archive_endian.h"
#include "archive_private.h"
#include "archive_string.h"
#include "archive_string_composition.h"

#if !defined(HAVE_WMEMCPY) && !defined(wmemcpy)
#define wmemcpy(a, b, i) (wchar_t *)memcpy((a), (b), (i) * sizeof(wchar_t))
#endif

#if !defined(HAVE_WMEMMOVE) && !defined(wmemmove)
#define wmemmove(a, b, i) (wchar_t *)memmove((a), (b), (i) * sizeof(wchar_t))
#endif

#undef max
#define max(a, b) ((a) > (b) ? (a) : (b))

struct archive_string_conv
{
	struct archive_string_conv *next;
	char *from_charset;
	char *to_charset;
	unsigned from_cp;
	unsigned to_cp;
	/* Set 1 if from_charset and to_charset are the same. */
	int same;
	int flag;
#define SCONV_TO_CHARSET 1				 /* MBS is being converted to specified \
										  * charset. */
#define SCONV_FROM_CHARSET (1 << 1)		 /* MBS is being converted from \
										  * specified charset. */
#define SCONV_BEST_EFFORT (1 << 2)		 /* Copy at least ASCII code. */
#define SCONV_WIN_CP (1 << 3)			 /* Use Windows API for converting \
										  * MBS. */
#define SCONV_UTF8_LIBARCHIVE_2 (1 << 4) /* Incorrect UTF-8 made by libarchive \
										  * 2.x in the wrong assumption. */
#define SCONV_NORMALIZATION_C (1 << 6)	 /* Need normalization to be Form C.     \
										  * Before UTF-8 characters are actually \
										  * processed. */
#define SCONV_NORMALIZATION_D (1 << 7)	 /* Need normalization to be Form D.     \
										  * Before UTF-8 characters are actually \
										  * processed.                           \
										  * Currently this only for MAC OS X. */
#define SCONV_TO_UTF8 (1 << 8)			 /* "to charset" side is UTF-8. */
#define SCONV_FROM_UTF8 (1 << 9)		 /* "from charset" side is UTF-8. */
#define SCONV_TO_UTF16BE (1 << 10)		 /* "to charset" side is UTF-16BE. */
#define SCONV_FROM_UTF16BE (1 << 11)	 /* "from charset" side is UTF-16BE. */
#define SCONV_TO_UTF16LE (1 << 12)		 /* "to charset" side is UTF-16LE. */
#define SCONV_FROM_UTF16LE (1 << 13)	 /* "from charset" side is UTF-16LE. */
#define SCONV_TO_UTF16 (SCONV_TO_UTF16BE | SCONV_TO_UTF16LE)
#define SCONV_FROM_UTF16 (SCONV_FROM_UTF16BE | SCONV_FROM_UTF16LE)

#if HAVE_ICONV
	iconv_t cd;
	iconv_t cd_w; /* Use at archive_mstring on
				   * Windows. */
#endif
	/* A temporary buffer for normalization. */
	struct archive_string utftmp;
	int (*converter[2])(struct archive_string *, const void *, size_t,
						struct archive_string_conv *);
	int nconverter;
};

#define CP_C_LOCALE 0 /* "C" locale only for this file. */
#define CP_UTF16LE 1200
#define CP_UTF16BE 1201

#define IS_HIGH_SURROGATE_LA(uc) ((uc) >= 0xD800 && (uc) <= 0xDBFF)
#define IS_LOW_SURROGATE_LA(uc) ((uc) >= 0xDC00 && (uc) <= 0xDFFF)
#define IS_SURROGATE_PAIR_LA(uc) ((uc) >= 0xD800 && (uc) <= 0xDFFF)
#define UNICODE_MAX 0x10FFFF
#define UNICODE_R_CHAR 0xFFFD /* Replacement character. */

#ifndef COMPILE_WITH_RUST

struct unicode_composition_table *get_u_composition_table();
char *get_u_decomposable_blocks();
unsigned char *get_ccc_val();
unsigned char *get_ccc_val_index();
unsigned char *get_ccc_index();
struct unicode_decomposition_table *get_u_decomposition_table();

struct unicode_composition_table *get_u_composition_table()
{
	struct unicode_composition_table *u_composition_table_copy = (struct unicode_composition_table *)malloc(sizeof u_composition_table);
	u_composition_table_copy = (struct unicode_composition_table *)memcpy(u_composition_table_copy, u_composition_table, sizeof u_composition_table);
	return u_composition_table_copy;
}
char *get_u_decomposable_blocks()
{
	char *u_decomposable_blocks_copy = (char *)malloc(sizeof u_decomposable_blocks);
	u_decomposable_blocks_copy = (char *)memcpy(u_decomposable_blocks_copy, u_decomposable_blocks, sizeof u_decomposable_blocks);
	return u_decomposable_blocks_copy;
}
unsigned char *get_ccc_val()
{
	unsigned char *ccc_val_copy = (unsigned char *)malloc(sizeof ccc_val);
	ccc_val_copy = (unsigned char *)memcpy(ccc_val_copy, ccc_val, sizeof ccc_val);
	return ccc_val_copy;
}
unsigned char *get_ccc_val_index()
{
	unsigned char *ccc_val_index_copy = (unsigned char *)malloc(sizeof ccc_val_index);
	ccc_val_index_copy = (unsigned char *)memcpy(ccc_val_index_copy, ccc_val_index, sizeof ccc_val_index);
	return ccc_val_index_copy;
}
unsigned char *get_ccc_index()
{
	unsigned char *ccc_index_copy = (unsigned char *)malloc(sizeof ccc_index);
	ccc_index_copy = (unsigned char *)memcpy(ccc_index_copy, ccc_index, sizeof ccc_index);
	return ccc_index_copy;
}
struct unicode_decomposition_table *get_u_decomposition_table()
{
	struct unicode_decomposition_table *u_decomposition_table_copy = (struct unicode_decomposition_table *)malloc(sizeof u_decomposition_table);
	u_decomposition_table_copy = (struct unicode_decomposition_table *)memcpy(u_decomposition_table_copy, u_decomposition_table, sizeof u_decomposition_table);
	return u_decomposition_table_copy;
}

struct archive_string *archive_strappend_char(struct archive_string *as, char c) { return NULL; }
struct archive_wstring *archive_wstrappend_wchar(struct archive_wstring *as, wchar_t c) { return NULL; }
struct archive_string *archive_array_append(struct archive_string *as, const char *p, size_t s) { return NULL; }
int archive_string_append_from_wcs(struct archive_string *as, const wchar_t *w, size_t len) { return 0; }
struct archive_string_conv *archive_string_conversion_to_charset(struct archive *a, const char *charset, int best_effort) { return NULL; }
struct archive_string_conv *archive_string_conversion_from_charset(struct archive *a, const char *charset, int best_effort) { return NULL; }
struct archive_string_conv *archive_string_default_conversion_for_read(struct archive *a) { return NULL; }
struct archive_string_conv *archive_string_default_conversion_for_write(struct archive *a) { return NULL; }
void archive_string_conversion_free(struct archive *a) {}
const char *archive_string_conversion_charset_name(struct archive_string_conv *sc) { return NULL; }
void archive_string_conversion_set_opt(struct archive_string_conv *sc, int opt) {}
int archive_strncpy_l(struct archive_string *as, const void *_p, size_t n, struct archive_string_conv *sc) { return 0; }
int archive_strncat_l(struct archive_string *as, const void *_p, size_t n, struct archive_string_conv *sc) { return 0; }
void archive_string_concat(struct archive_string *dest, struct archive_string *src) {}
void archive_wstring_concat(struct archive_wstring *dest, struct archive_wstring *src) {}
struct archive_string *archive_string_ensure(struct archive_string *as, size_t s) { return NULL; }
struct archive_wstring *archive_wstring_ensure(struct archive_wstring *as, size_t s) { return NULL; }
struct archive_string *archive_strncat(struct archive_string *as, const void *_p, size_t n) { return NULL; }
struct archive_wstring *archive_wstrncat(struct archive_wstring *as, const wchar_t *p, size_t n) { return NULL; }
struct archive_string *archive_strcat(struct archive_string *as, const void *p) { return NULL; }
struct archive_wstring *archive_wstrcat(struct archive_wstring *as, const wchar_t *p) { return NULL; }
void archive_string_free(struct archive_string *as) {}
void archive_wstring_free(struct archive_wstring *as) {}
int archive_wstring_append_from_mbs(struct archive_wstring *dest, const char *p, size_t len) { return 0; }
void archive_mstring_clean(struct archive_mstring *aes) {}
void archive_mstring_copy(struct archive_mstring *dest, struct archive_mstring *src) {}
int archive_mstring_get_mbs(struct archive *a, struct archive_mstring *aes, const char **p) { return 0; }
int archive_mstring_get_utf8(struct archive *a, struct archive_mstring *aes, const char **p) { return 0; }
int archive_mstring_get_wcs(struct archive *a, struct archive_mstring *aes, const wchar_t **wp) { return 0; }
int archive_mstring_get_mbs_l(struct archive *a, struct archive_mstring *aes, const char **p, size_t *length, struct archive_string_conv *sc) { return 0; }
int archive_mstring_copy_mbs(struct archive_mstring *aes, const char *mbs) { return 0; }
int archive_mstring_copy_mbs_len(struct archive_mstring *aes, const char *mbs, size_t len) { return 0; }
int archive_mstring_copy_utf8(struct archive_mstring *aes, const char *utf8) { return 0; }
int archive_mstring_copy_wcs(struct archive_mstring *aes, const wchar_t *wcs) { return 0; }
int archive_mstring_copy_wcs_len(struct archive_mstring *aes, const wchar_t *wcs, size_t len) { return 0; }
int archive_mstring_copy_mbs_len_l(struct archive_mstring *aes, const char *mbs, size_t len, struct archive_string_conv *sc) { return 0; }
int archive_mstring_update_utf8(struct archive *a, struct archive_mstring *aes, const char *utf8) { return 0; }

struct archive_string_defined_param
{
	unsigned int unicode_r_char;
	unsigned int unicode_max;
};


struct archive_string_defined_param get_archive_string_defined_param();
struct archive_string_defined_param get_archive_string_defined_param()
{
	struct archive_string_defined_param defined_param;
	defined_param.unicode_r_char = UNICODE_R_CHAR;
	defined_param.unicode_max = UNICODE_MAX;
	return defined_param;
}

int archive_string(struct archive *_a)
{
	return 0;
}

#endif