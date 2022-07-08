use rust_ffi::ffi_struct::struct_transfer::* ;
use rust_ffi::ffi_alias::alias_set::*;

#[no_mangle]
pub extern "C" fn archive_acl_clear(mut acl: *mut archive_acl) {

}

#[no_mangle]
pub extern "C" fn archive_acl_copy(mut dest: *mut archive_acl,
                                          mut src: *mut archive_acl) {
    
}

#[no_mangle]
pub  unsafe extern "C"  fn archive_acl_add_entry(mut acl: *mut archive_acl,
                                               mut type_0: libc::c_int,
                                               mut permset: libc::c_int,
                                               mut tag: libc::c_int,
                                               mut id: libc::c_int,
                                               mut name: *const libc::c_char)
 -> libc::c_int {
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe  extern "C"  fn archive_acl_add_entry_w_len(mut acl:
                                                         *mut archive_acl,
                                                     mut type_0: libc::c_int,
                                                     mut permset: libc::c_int,
                                                     mut tag: libc::c_int,
                                                     mut id: libc::c_int,
                                                     mut name: *const wchar_t,
                                                     mut len: size_t)
 -> libc::c_int {
    return 0 as libc::c_int;
}

/*
 * Return a count of entries matching "want_type".
 */

#[no_mangle]
pub unsafe extern "C"  fn archive_acl_count(mut acl: *mut archive_acl,
                                           mut want_type: libc::c_int)
 -> libc::c_int {
    return 0 as libc::c_int;
}
/*
 * Return a bitmask of stored ACL types in an ACL list
 */

#[no_mangle]
pub unsafe extern "C" fn  archive_acl_types(mut acl: *mut archive_acl)
 -> libc::c_int {
    return 0 as libc::c_int;
}
/*
 * Prepare for reading entries from the ACL data.  Returns a count
 * of entries matching "want_type", or zero if there are no
 * non-extended ACL entries of that type.
 */

#[no_mangle]
pub unsafe extern "C" fn  archive_acl_reset(mut acl: *mut archive_acl,
                                           mut want_type: libc::c_int)
 -> libc::c_int {
    return 0 as libc::c_int;
}
/*
 * Return the next ACL entry in the list.  Fake entries for the
 * standard permissions and include them in the returned list.
 */

#[no_mangle]
pub  unsafe extern "C" fn  archive_acl_next(mut a: *mut archive,
                                          mut acl: *mut archive_acl,
                                          mut want_type: libc::c_int,
                                          mut type_0: *mut libc::c_int,
                                          mut permset: *mut libc::c_int,
                                          mut tag: *mut libc::c_int,
                                          mut id: *mut libc::c_int,
                                          mut name: *mut *const libc::c_char)
 -> libc::c_int {
    return 0 as libc::c_int;
}

/*
 * Generate a wide text version of the ACL. The flags parameter controls
 * the type and style of the generated ACL.
 */
#[no_mangle]
pub unsafe extern "C"  fn archive_acl_to_text_w(mut acl: *mut archive_acl,
                                               mut text_len: *mut ssize_t,
                                               mut flags: libc::c_int,
                                               mut a: *mut archive)
 -> *mut wchar_t {
    return 0 as *mut wchar_t;
}

/*
 * Generate a text version of the ACL. The flags parameter controls
 * the type and style of the generated ACL.
 */

#[no_mangle]
pub unsafe extern "C"  fn archive_acl_to_text_l(mut acl: *mut archive_acl,
                                               mut text_len: *mut ssize_t,
                                               mut flags: libc::c_int,
                                               mut sc:
                                                   *mut archive_string_conv)
 -> *mut libc::c_char {
    return 0 as *mut libc::c_char;
}

/*
 * Parse a wide ACL text string.
 *
 * The want_type argument may be one of the following:
 * ARCHIVE_ENTRY_ACL_TYPE_ACCESS - text is a POSIX.1e ACL of type ACCESS
 * ARCHIVE_ENTRY_ACL_TYPE_DEFAULT - text is a POSIX.1e ACL of type DEFAULT
 * ARCHIVE_ENTRY_ACL_TYPE_NFS4 - text is as a NFSv4 ACL
 *
 * POSIX.1e ACL entries prefixed with "default:" are treated as
 * ARCHIVE_ENTRY_ACL_TYPE_DEFAULT unless type is ARCHIVE_ENTRY_ACL_TYPE_NFS4
 */
#[no_mangle]
pub unsafe extern "C"  fn archive_acl_from_text_w (mut acl: *mut archive_acl,
                                                 mut text: *const wchar_t,
                                                 mut want_type: libc::c_int)
 -> libc::c_int {
    return 0 as libc::c_int;
}

/*
 * Parse an ACL text string.
 *
 * The want_type argument may be one of the following:
 * ARCHIVE_ENTRY_ACL_TYPE_ACCESS - text is a POSIX.1e ACL of type ACCESS
 * ARCHIVE_ENTRY_ACL_TYPE_DEFAULT - text is a POSIX.1e ACL of type DEFAULT
 * ARCHIVE_ENTRY_ACL_TYPE_NFS4 - text is as a NFSv4 ACL
 *
 * POSIX.1e ACL entries prefixed with "default:" are treated as
 * ARCHIVE_ENTRY_ACL_TYPE_DEFAULT unless type is ARCHIVE_ENTRY_ACL_TYPE_NFS4
 */
#[no_mangle]
pub unsafe extern "C"  fn archive_acl_from_text_l(mut acl: *mut archive_acl,
                                                 mut text:
                                                     *const libc::c_char,
                                                 mut want_type: libc::c_int,
                                                 mut sc:
                                                     *mut archive_string_conv)
 -> libc::c_int {
    return 0 as libc::c_int;
}
