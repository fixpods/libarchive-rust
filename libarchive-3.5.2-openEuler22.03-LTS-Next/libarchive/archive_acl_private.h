/*-
 * Copyright (c) 2003-2010 Tim Kientzle
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
 *
 * $FreeBSD$
 */

#ifndef ARCHIVE_ACL_PRIVATE_H_INCLUDED
#define ARCHIVE_ACL_PRIVATE_H_INCLUDED

#ifndef __LIBARCHIVE_BUILD
#error This header is only to be used internally to libarchive.
#endif

#include "archive_string.h"

struct archive_acl_entry
{
  struct archive_acl_entry *next;
  int type;                    /* E.g., access or default */
  int tag;                     /* E.g., user/group/other/mask */
  int permset;                 /* r/w/x bits */
  int id;                      /* uid/gid for user/group */
  struct archive_mstring name; /* uname/gname */
};

struct archive_acl
{
  mode_t mode;
  struct archive_acl_entry *acl_head;
  struct archive_acl_entry *acl_p;
  int acl_state; /* See acl_next for details. */
  wchar_t *acl_text_w;
  char *acl_text;
  int acl_types;
};
#endif /* ARCHIVE_ENTRY_PRIVATE_H_INCLUDED */

#ifdef COMPILE_WITH_RUST
extern void archive_acl_copy(struct archive_acl *dest, struct archive_acl *src);
extern int archive_acl_reset(struct archive_acl *acl, int want_type);
extern int archive_acl_next(struct archive *a, struct archive_acl *acl, int want_type,
                            int *type, int *permset, int *tag, int *id, const char **name);
extern int archive_acl_count(struct archive_acl *acl, int want_type);
extern int archive_acl_add_entry_w_len(struct archive_acl *,
                                       int, int, int, int, const wchar_t *, size_t);
extern int archive_acl_from_text_w(struct archive_acl *, const wchar_t * /* wtext */,
                                   int /* type */);
extern int archive_acl_from_text_l(struct archive_acl *, const char * /* text */,
                                   int /* type */, struct archive_string_conv *);
extern char *archive_acl_to_text_l(struct archive_acl *, ssize_t *, int,
                                   struct archive_string_conv *);
extern wchar_t *archive_acl_to_text_w(struct archive_acl *, ssize_t *, int,
                                      struct archive *);
extern void archive_acl_clear(struct archive_acl *acl);
extern int archive_acl_types(struct archive_acl *acl);
extern int archive_acl_add_entry(struct archive_acl *, int, int, int, int, const char *);
#else
void archive_acl_copy(struct archive_acl *dest, struct archive_acl *src);
int archive_acl_reset(struct archive_acl *acl, int want_type);
int archive_acl_next(struct archive *a, struct archive_acl *acl, int want_type,
                     int *type, int *permset, int *tag, int *id, const char **name);
int archive_acl_count(struct archive_acl *acl, int want_type);
int archive_acl_add_entry_w_len(struct archive_acl *,
                                int, int, int, int, const wchar_t *, size_t);
int archive_acl_from_text_w(struct archive_acl *, const wchar_t * /* wtext */,
                            int /* type */);
int archive_acl_from_text_l(struct archive_acl *, const char * /* text */,
                            int /* type */, struct archive_string_conv *);
char *archive_acl_to_text_l(struct archive_acl *, ssize_t *, int,
                            struct archive_string_conv *);
wchar_t *archive_acl_to_text_w(struct archive_acl *, ssize_t *, int,
                               struct archive *);
void archive_acl_clear(struct archive_acl *acl);
int archive_acl_types(struct archive_acl *acl);
int archive_acl_add_entry(struct archive_acl *, int, int, int, int, const char *);
#endif