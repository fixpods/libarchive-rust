/*-
 * Copyright (c) 2003-2010 Tim Kientzle
 * Copyright (c) 2016 Martin Matuska
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
__FBSDID("$FreeBSD$");

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif

#include "archive_acl_private.h"
#include "archive_entry.h"
#include "archive_private.h"

#undef max
#define max(a, b) ((a) > (b) ? (a) : (b))

#ifndef HAVE_WMEMCMP
/* Good enough for simple equality testing, but not for sorting. */
#define wmemcmp(a, b, i) memcmp((a), (b), (i) * sizeof(wchar_t))
#endif

#ifndef COMPILE_WITH_RUST

struct archive_acl_defined_param
{
	int archive_ok;
	int archive_failed;
	int archive_fatal;
	int archive_warn;
	int archive_eof;
	int enomem;
	int archive_entry_acl_append_data;
	int archive_entry_acl_delete;
	int archive_entry_acl_delete_child;
	int archive_entry_acl_read_attributes;
	int archive_entry_acl_read_named_attrs;
	int archive_entry_acl_read;
	int archive_entry_acl_read_data;
	int archive_entry_acl_write;
	int archive_entry_acl_write_named_attrs;
	int archive_entry_acl_write_attributes;
	int archive_entry_acl_write_owner;
	int archive_entry_acl_synchronize;
	int archive_entry_acl_write_data;
	int archive_entry_acl_execute;
	int archive_entry_acl_everyone;
	int archive_entry_acl_mask;
	int archive_entry_acl_other;
	int archive_entry_acl_user;
	int archive_entry_acl_group;
	int archive_entry_acl_user_obj;
	int archive_entry_acl_group_obj;
	int archive_entry_acl_type_allow;
	int archive_entry_acl_type_alram;
	int archive_entry_acl_type_audit;
	int archive_entry_acl_type_deny;
	int archive_entry_acl_type_nfs4;
	int archive_entry_acl_type_posix1e;
	int archive_entry_acl_type_access;
	int archive_entry_acl_type_default;
	int archive_entry_acl_perms_nfs4;
	int archive_entry_acl_perms_posix1e;
	int archive_entry_acl_inheritance_nfs4;
	int archive_entry_acl_style_compact;
	int archive_entry_acl_style_extra_id;
	int archive_entry_acl_style_solaris;
	int archive_entry_acl_style_mark_default;
	int archive_entry_acl_style_separator_comma;
	int archive_entry_acl_entry_file_inherit;
	int archive_entry_acl_entry_directory_inherit;
	int archive_entry_acl_entry_inherit_only;
	int archive_entry_acl_entry_no_propagate_inherit;
	int archive_entry_acl_entry_successful_access;
	int archive_entry_acl_entry_failed_access;
	int archive_entry_acl_entry_inherited;
	int archive_entry_acl_read_acl;
	int archive_entry_acl_write_acl;
};

struct archive_acl_defined_param get_archive_acl_defined_param();

struct archive_acl_defined_param get_archive_acl_defined_param()
{
	struct archive_acl_defined_param defined_param;
	defined_param.archive_ok = ARCHIVE_OK;
	defined_param.archive_failed = ARCHIVE_FAILED;
	defined_param.archive_fatal = ARCHIVE_FATAL;
	defined_param.archive_warn = ARCHIVE_WARN;
	defined_param.archive_eof = ARCHIVE_EOF;
	defined_param.enomem = ENOMEM;
	defined_param.archive_entry_acl_append_data = ARCHIVE_ENTRY_ACL_APPEND_DATA;
	defined_param.archive_entry_acl_delete = ARCHIVE_ENTRY_ACL_DELETE;
	defined_param.archive_entry_acl_delete_child = ARCHIVE_ENTRY_ACL_DELETE_CHILD;
	defined_param.archive_entry_acl_read_attributes = ARCHIVE_ENTRY_ACL_READ_ATTRIBUTES;
	defined_param.archive_entry_acl_read_named_attrs = ARCHIVE_ENTRY_ACL_READ_NAMED_ATTRS;
	defined_param.archive_entry_acl_read = ARCHIVE_ENTRY_ACL_READ;
	defined_param.archive_entry_acl_read_data = ARCHIVE_ENTRY_ACL_READ_DATA;
	defined_param.archive_entry_acl_write = ARCHIVE_ENTRY_ACL_WRITE;
	defined_param.archive_entry_acl_write_named_attrs = ARCHIVE_ENTRY_ACL_WRITE_NAMED_ATTRS;
	defined_param.archive_entry_acl_write_attributes = ARCHIVE_ENTRY_ACL_WRITE_ATTRIBUTES;
	defined_param.archive_entry_acl_write_owner = ARCHIVE_ENTRY_ACL_WRITE_OWNER;
	defined_param.archive_entry_acl_synchronize = ARCHIVE_ENTRY_ACL_SYNCHRONIZE;
	defined_param.archive_entry_acl_write_data = ARCHIVE_ENTRY_ACL_WRITE_DATA;
	defined_param.archive_entry_acl_execute = ARCHIVE_ENTRY_ACL_EXECUTE;
	defined_param.archive_entry_acl_everyone = ARCHIVE_ENTRY_ACL_EVERYONE;
	defined_param.archive_entry_acl_mask = ARCHIVE_ENTRY_ACL_MASK;
	defined_param.archive_entry_acl_other = ARCHIVE_ENTRY_ACL_OTHER;
	defined_param.archive_entry_acl_user = ARCHIVE_ENTRY_ACL_USER;
	defined_param.archive_entry_acl_group = ARCHIVE_ENTRY_ACL_GROUP;
	defined_param.archive_entry_acl_user_obj = ARCHIVE_ENTRY_ACL_USER_OBJ;
	defined_param.archive_entry_acl_group_obj = ARCHIVE_ENTRY_ACL_GROUP_OBJ;
	defined_param.archive_entry_acl_type_allow = ARCHIVE_ENTRY_ACL_TYPE_ALLOW;
	defined_param.archive_entry_acl_type_alram = ARCHIVE_ENTRY_ACL_TYPE_ALARM;
	defined_param.archive_entry_acl_type_audit = ARCHIVE_ENTRY_ACL_TYPE_AUDIT;
	defined_param.archive_entry_acl_type_deny = ARCHIVE_ENTRY_ACL_TYPE_DENY;
	defined_param.archive_entry_acl_type_nfs4 = ARCHIVE_ENTRY_ACL_TYPE_NFS4;
	defined_param.archive_entry_acl_type_posix1e = ARCHIVE_ENTRY_ACL_TYPE_POSIX1E;
	defined_param.archive_entry_acl_type_access = ARCHIVE_ENTRY_ACL_TYPE_ACCESS;
	defined_param.archive_entry_acl_type_default = ARCHIVE_ENTRY_ACL_TYPE_DEFAULT;
	defined_param.archive_entry_acl_perms_nfs4 = ARCHIVE_ENTRY_ACL_PERMS_NFS4;
	defined_param.archive_entry_acl_perms_posix1e = ARCHIVE_ENTRY_ACL_PERMS_POSIX1E;
	defined_param.archive_entry_acl_inheritance_nfs4 = ARCHIVE_ENTRY_ACL_INHERITANCE_NFS4;
	defined_param.archive_entry_acl_style_compact = ARCHIVE_ENTRY_ACL_STYLE_COMPACT;
	defined_param.archive_entry_acl_style_extra_id = ARCHIVE_ENTRY_ACL_STYLE_EXTRA_ID;
	defined_param.archive_entry_acl_style_solaris = ARCHIVE_ENTRY_ACL_STYLE_SOLARIS;
	defined_param.archive_entry_acl_style_mark_default = ARCHIVE_ENTRY_ACL_STYLE_MARK_DEFAULT;
	defined_param.archive_entry_acl_style_separator_comma = ARCHIVE_ENTRY_ACL_STYLE_SEPARATOR_COMMA;
	defined_param.archive_entry_acl_entry_file_inherit = ARCHIVE_ENTRY_ACL_ENTRY_FILE_INHERIT;
	defined_param.archive_entry_acl_entry_directory_inherit = ARCHIVE_ENTRY_ACL_ENTRY_DIRECTORY_INHERIT;
	defined_param.archive_entry_acl_entry_inherit_only = ARCHIVE_ENTRY_ACL_ENTRY_INHERIT_ONLY;
	defined_param.archive_entry_acl_entry_no_propagate_inherit = ARCHIVE_ENTRY_ACL_ENTRY_NO_PROPAGATE_INHERIT;
	defined_param.archive_entry_acl_entry_successful_access = ARCHIVE_ENTRY_ACL_ENTRY_SUCCESSFUL_ACCESS;
	defined_param.archive_entry_acl_entry_failed_access = ARCHIVE_ENTRY_ACL_ENTRY_FAILED_ACCESS;
	defined_param.archive_entry_acl_entry_inherited = ARCHIVE_ENTRY_ACL_ENTRY_INHERITED;
	defined_param.archive_entry_acl_read_acl = ARCHIVE_ENTRY_ACL_READ_ACL;
	defined_param.archive_entry_acl_write_acl = ARCHIVE_ENTRY_ACL_WRITE_ACL;
	return defined_param;
}
void archive_acl_clear(struct archive_acl *acl)
{
}

int archive_acl_types(struct archive_acl *acl)
{
	return 0;
}

void archive_acl_copy(struct archive_acl *dest, struct archive_acl *src)
{
}

int archive_acl_add_entry(struct archive_acl *acl,
						  int type, int permset, int tag, int id, const char *name)
{
	return 0;
}

int archive_acl_add_entry_w_len(struct archive_acl *acl,
								int type, int permset, int tag, int id, const wchar_t *name, size_t len)
{
	return 0;
}

int archive_acl_count(struct archive_acl *acl, int want_type)
{
	return 0;
}

int archive_acl_reset(struct archive_acl *acl, int want_type)
{
	return 0;
}

int archive_acl_next(struct archive *a, struct archive_acl *acl, int want_type,
					 int *type, int *permset, int *tag, int *id, const char **name)
{
	return 0;
}

wchar_t *
archive_acl_to_text_w(struct archive_acl *acl, ssize_t *text_len, int flags,
					  struct archive *a)
{
	return 0;
}

char *
archive_acl_to_text_l(struct archive_acl *acl, ssize_t *text_len, int flags,
					  struct archive_string_conv *sc)
{
	return 0;
}

int archive_acl_from_text_w(struct archive_acl *acl, const wchar_t *text,
							int want_type)
{
	return 0;
}

int archive_acl_from_text_l(struct archive_acl *acl, const char *text,
							int want_type, struct archive_string_conv *sc)
{
	return 0;
}

#endif