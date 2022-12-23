#ifndef COMPILE_WITH_RUST

#include "archive_platform.h"
__FBSDID("$FreeBSD$");

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <stddef.h>
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
#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif
#ifdef HAVE_LZMA_H
#include <lzma.h>
#endif
#if HAVE_LIBXML_XMLREADER_H
#include <libxml/xmlreader.h>
#elif HAVE_BSDXML_H
#include <bsdxml.h>
#elif HAVE_EXPAT_H
#include <expat.h>
#endif

#include "archive.h"
#include "archive_acl_private.h" /* For ACL parsing routines. */
#include "archive_digest_private.h"
#include "archive_cryptor_private.h"
#include "archive_endian.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_hmac_private.h"
#include "archive_private.h"
#include "archive_rb.h"
#include "archive_read_private.h"
#include "archive_ppmd8_private.h"
#include "archive_string.h"
#include "archive_ppmd7_private.h"

#ifndef HAVE_ZLIB_H
#include "archive_crc32.h"
#endif


int get_have_locale_charset();
int get___apple__();
int get_have_nl_langinfo();
int get__win32();
int get___cygwin__();
int get__debug();
int get_have_lzma_h();
int get_have_bzlib_h();
int get_bz_config_error();
int get__lzma_prob32();
int get_have_zlib_h();
int get_have_timegm();
int get_have__mkgmtime64();
int get_debug();
int get_have_libxml_xmlreader_h();
int get_have_bsdxml_h();
int get_have_expat_h();
int get_lzma_version_major();
int get_archive_has_md5();
int get_debug_print_toc();
int get_archive_has_sha1();
int get_have_liblzma();
int get_have_copyfile_h();
int get_have_localtime_r();
int get_have__localtime64_s();
int get_check_crc_on_solid_skip();
int get_dont_fail_on_crc_error();
int get_have_iconv();
int get_archive_endian_h_included();
int get_mtree_strnlen();
int get_WIN32();

int get_WIN32()
{
#if !defined WIN32
	return 0;
#else
	return 1;
#endif
}

int get_mtree_strnlen()
{
#ifdef HAVE_STRNLEN
	return 1;
#else
	return 0;
#endif
}

int get_archive_endian_h_included()
{
#ifdef ARCHIVE_ENDIAN_H_INCLUDED
	return 1;
#else
	return 0;
#endif
}

int get_have_locale_charset()
{
#if HAVE_LOCALE_CHARSET
	return 1;
#else
	return 0;
#endif
}

int get___apple__()
{
#ifdef __APPLE__
	return 1;
#else
	return 0;
#endif
}

int get_have_nl_langinfo()
{
#if HAVE_NL_LANGINFO
	return 1;
#else
	return 0;
#endif
}

int get__win32()
{
#ifdef _WIN32
	return 1;
#else
	return 0;
#endif
}

int get___cygwin__()
{
#ifdef __CYGWIN__
	return 1;
#else
	return 0;
#endif
}

int get__debug()
{
#ifdef _DEBUG
	return 1;
#else
	return 0;
#endif
}

int get_have_lzma_h()
{
#ifdef HAVE_LZMA_H
	return 1;
#else
	return 0;
#endif
}

int get_have_bzlib_h()
{
#ifdef HAVE_BZLIB_H
	return 1;
#else
	return 0;
#endif
}

int get_bz_config_error()
{
#ifdef BZ_CONFIG_ERROR
	return 1;
#else
	return 0;
#endif
}

int get__lzma_prob32()
{
#ifdef _LZMA_PROB32
	return 1;
#else
	return 0;
#endif
}

int get_have_zlib_h()
{
#ifdef HAVE_ZLIB_H
	return 1;
#else
	return 0;
#endif
}

int get_have_timegm()
{
#if HAVE_TIMEGM
	return 1;
#else
	return 0;
#endif
}

int get_have__mkgmtime64()
{
#if HAVE__MKGMTIME64
	return 1;
#else
	return 0;
#endif
}

int get_debug()
{
#if DEBUG
	return 1;
#else
	return 0;
#endif
}

int get_have_libxml_xmlreader_h()
{
#if defined(HAVE_LIBXML_XMLREADER_H)
	return 1;
#else
	return 0;
#endif
}

int get_have_bsdxml_h()
{
#if defined(HAVE_BSDXML_H)
	return 1;
#else
	return 0;
#endif
}

int get_have_expat_h()
{
#if defined(HAVE_EXPAT_H)
	return 1;
#else
	return 0;
#endif
}

int get_lzma_version_major()
{
#if LZMA_VERSION_MAJOR >= 5
	return 1;
#else
	return 0;
#endif
}

int get_archive_has_md5()
{
#ifdef ARCHIVE_HAS_MD5
	return 1;
#else
	return 0;
#endif
}

int get_debug_print_toc()
{
#if DEBUG_PRINT_TOC
	return 1;
#endif
	return 0;
}

int get_archive_has_sha1()
{
#ifdef ARCHIVE_HAS_SHA1
	return 1;
#endif
	return 0;
}

int get_have_liblzma()
{
#ifdef HAVE_LIBLZMA
	return 1;
#else
	return 0;
#endif
}

int get_have_copyfile_h()
{
#ifdef HAVE_COPYFILE_H
	return 1;
#else
	return 0;
#endif
}

int get_have_localtime_r()
{
#ifdef HAVE_LOCALTIME_R
	return 1;
#else
	return 0;
#endif
}

int get_have__localtime64_s()
{
#ifdef HAVE__LOCALTIME64_S
	return 1;
#else
	return 0;
#endif
}

int get_check_crc_on_solid_skip()
{
#ifdef CHECK_CRC_ON_SOLID_SKIP
	return 1;
#else
	return 0;
#endif
}

int get_dont_fail_on_crc_error()
{
#ifdef DONT_FAIL_ON_CRC_ERROR
	return 1;
#else
	return 0;
#endif
}

int get_have_iconv()
{
#ifdef HAVE_ICONV
	return 1;
#else
	return 0;
#endif
}

#endif