use rust_ffi::ffi_struct::struct_transfer::* ;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;

static mut nfsv4_acl_perm_map: [nfsv4_acl_perm_map_struct; 14] =
    [{
         let mut init =
             nfsv4_acl_perm_map_struct{perm:  0x8 as libc::c_int | 0x8 as libc::c_int,
                             c: 'r' as i32 as libc::c_char,
                             wc: 'r' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x10 as libc::c_int | 0x10 as libc::c_int,
                             c: 'w' as i32 as libc::c_char,
                             wc: 'w' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x1 as libc::c_int,
                             c: 'x' as i32 as libc::c_char,
                             wc: 'x' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x20 as libc::c_int | 0x20 as libc::c_int,
                             c: 'p' as i32 as libc::c_char,
                             wc: 'p' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x800 as libc::c_int,
                             c: 'd' as i32 as libc::c_char,
                             wc: 'd' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x100 as libc::c_int,
                             c: 'D' as i32 as libc::c_char,
                             wc: 'D' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x200 as libc::c_int,
                             c: 'a' as i32 as libc::c_char,
                             wc: 'a' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x400 as libc::c_int,
                             c: 'A' as i32 as libc::c_char,
                             wc: 'A' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x40 as libc::c_int,
                             c: 'R' as i32 as libc::c_char,
                             wc: 'R' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x80 as libc::c_int,
                             c: 'W' as i32 as libc::c_char,
                             wc: 'W' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x1000 as libc::c_int,
                             c: 'c' as i32 as libc::c_char,
                             wc: 'c' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x2000 as libc::c_int,
                             c: 'C' as i32 as libc::c_char,
                             wc: 'C' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x4000 as libc::c_int,
                             c: 'o' as i32 as libc::c_char,
                             wc: 'o' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x8000 as libc::c_int,
                             c: 's' as i32 as libc::c_char,
                             wc: 's' as i32,};
         init
     }];
// Initialized in run_static_initializers
static mut nfsv4_acl_perm_map_size: libc::c_int = 0;
static mut nfsv4_acl_flag_map: [nfsv4_acl_perm_map_struct; 7] =
    [{
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x2000000 as libc::c_int,
                           c: 'f' as i32 as libc::c_char,
                           wc: 'f' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x4000000 as libc::c_int,
                           c: 'd' as i32 as libc::c_char,
                           wc: 'd' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x10000000 as libc::c_int,
                           c: 'i' as i32 as libc::c_char,
                           wc: 'i' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x8000000 as libc::c_int,
                           c: 'n' as i32 as libc::c_char,
                           wc: 'n' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x20000000 as libc::c_int,
                           c: 'S' as i32 as libc::c_char,
                           wc: 'S' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x40000000 as libc::c_int,
                           c: 'F' as i32 as libc::c_char,
                           wc: 'F' as i32,};
         init
     },
     {
         let mut init =
             nfsv4_acl_perm_map_struct{perm: 0x1000000 as libc::c_int,
                           c: 'I' as i32 as libc::c_char,
                           wc: 'I' as i32,};
         init
     }];
// Initialized in run_static_initializers
static mut nfsv4_acl_flag_map_size: libc::c_int = 0;

#[no_mangle]
pub extern "C" fn archive_acl_clear(mut acl: *mut archive_acl) {
    let safe_acl=unsafe{&mut *acl};
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    while !(safe_acl).acl_head.is_null() {
        ap =unsafe{(*(safe_acl.acl_head)).next};
        archive_mstring_clean_safe(unsafe{&mut (*(safe_acl.acl_head)).name});
        free_safe((safe_acl).acl_head as *mut libc::c_void);
        (safe_acl).acl_head = ap
    }
    free_safe((safe_acl).acl_text_w as *mut libc::c_void);
    (safe_acl).acl_text_w = 0 as *mut wchar_t;
    free_safe((safe_acl).acl_text as *mut libc::c_void);
    (safe_acl).acl_text = 0 as *mut libc::c_char;
    (safe_acl).acl_p = 0 as *mut archive_acl_entry;
    (safe_acl).acl_types = 0 as libc::c_int;
    (safe_acl).acl_state = 0 as libc::c_int;
    /* Not counting. */
}

#[no_mangle]
pub extern "C" fn archive_acl_copy(mut dest: *mut archive_acl,
                                          mut src: *mut archive_acl) {
    let safe_dest=unsafe{&mut *dest};
    let safe_src=unsafe{&mut *src};
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut ap2: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    archive_acl_clear(dest);
    (safe_dest).mode = (safe_src).mode;
    ap = (safe_src).acl_head;
    while !ap.is_null() {
        ap2 =
            unsafe{acl_new_entry(safe_dest, (*ap).type_0, (*ap).permset, (*ap).tag,
                          (*ap).id)};
        if !ap2.is_null() {
            unsafe{archive_mstring_copy_safe(&mut (*ap2).name, &mut (*ap).name)};
        }
        unsafe{ap = (*ap).next}
    };
}

#[no_mangle]
pub  unsafe extern "C"  fn archive_acl_add_entry(mut acl: *mut archive_acl,
                                               mut type_0: libc::c_int,
                                               mut permset: libc::c_int,
                                               mut tag: libc::c_int,
                                               mut id: libc::c_int,
                                               mut name: *const libc::c_char)
 -> libc::c_int {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    if acl_special(acl, type_0, permset, tag) == 0 as libc::c_int {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_ok
    }
    ap = acl_new_entry(acl, type_0, permset, tag, id);
    if ap.is_null() {
        /* XXX Error XXX */
        return ARCHIVE_ACL_DEFINED_PARAM.archvie_failed
    }
    if !name.is_null() && *name as libc::c_int != '\u{0}' as i32 {
        archive_mstring_copy_mbs_safe(&mut (*ap).name, name);
    } else { archive_mstring_clean_safe(&mut (*ap).name); }
    return ARCHIVE_ACL_DEFINED_PARAM.archive_ok
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
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    if acl_special(acl, type_0, permset, tag) == 0 as libc::c_int {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_ok
    }
    ap = acl_new_entry(acl, type_0, permset, tag, id);
    if ap.is_null() {
        /* XXX Error XXX */
        return ARCHIVE_ACL_DEFINED_PARAM.archvie_failed
    }
    if !name.is_null() && *name != '\u{0}' as i32 &&
           len > 0 as libc::c_int as libc::c_ulong {
        archive_mstring_copy_wcs_len_safe(&mut (*ap).name, name, len);
    } else { archive_mstring_clean_safe(&mut (*ap).name); }
    return ARCHIVE_ACL_DEFINED_PARAM.archive_ok
}
pub unsafe fn archive_acl_add_entry_len_l(mut acl: *mut archive_acl,
                                                 mut type_0: libc::c_int,
                                                 mut permset: libc::c_int,
                                                 mut tag: libc::c_int,
                                                 mut id: libc::c_int,
                                                 mut name:
                                                     *const libc::c_char,
                                                 mut len: size_t,
                                                 mut sc:
                                                     *mut archive_string_conv)
 -> libc::c_int {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut r: libc::c_int = 0;
    if acl_special(acl, type_0, permset, tag) == 0 as libc::c_int {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_ok
    }
    ap = acl_new_entry(acl, type_0, permset, tag, id);
    if ap.is_null() {
        /* XXX Error XXX */
       return ARCHIVE_ACL_DEFINED_PARAM.archvie_failed
    }
    if !name.is_null() && *name as libc::c_int != '\u{0}' as i32 &&
           len > 0 as libc::c_int as libc::c_ulong {
        r = archive_mstring_copy_mbs_len_l_safe(&mut (*ap).name, name, len, sc)
    } else { r = 0 as libc::c_int; archive_mstring_clean_safe(&mut (*ap).name); }
    if r == 0 as libc::c_int {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_ok
    } else if *__errno_location_safe() == ARCHIVE_ACL_DEFINED_PARAM.enomem as libc::c_int {
       return ARCHIVE_ACL_DEFINED_PARAM.archive_fatal
    } else { 
      return ARCHIVE_ACL_DEFINED_PARAM.archive_warn
    };
}
/*
 * If this ACL entry is part of the standard POSIX permissions set,
 * store the permissions in the stat structure and return zero.
 */
fn acl_special(mut acl: *mut archive_acl,
                                 mut type_0: libc::c_int,
                                 mut permset: libc::c_int,
                                 mut tag: libc::c_int) -> libc::c_int {
    let safe_acl=unsafe{&mut *acl};
    if type_0 ==ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access &&
           permset & !(0o7 as libc::c_int) == 0 as libc::c_int {
        match tag {
            10002 => {
                (safe_acl).mode &= !(0o700 as libc::c_int) as libc::c_uint;
                (safe_acl).mode |=
                    ((permset & 7 as libc::c_int) << 6 as libc::c_int) as
                        libc::c_uint;
                return 0 as libc::c_int
            }
            10004=> {
                (safe_acl).mode &= !(0o70 as libc::c_int) as libc::c_uint;
                (safe_acl).mode |=
                    ((permset & 7 as libc::c_int) << 3 as libc::c_int) as
                        libc::c_uint;
                return 0 as libc::c_int
            }
            10006 => {
                (safe_acl).mode &= !(0o7 as libc::c_int) as libc::c_uint;
                (safe_acl).mode |= (permset & 7 as libc::c_int) as libc::c_uint;
                return 0 as libc::c_int
            }
            _ => { }
        }
    }
    return 1 as libc::c_int;
}
/*
 * Allocate and populate a new ACL entry with everything but the
 * name.
 */
unsafe fn acl_new_entry(mut acl: *mut archive_acl,
                                   mut type_0: libc::c_int,
                                   mut permset: libc::c_int,
                                   mut tag: libc::c_int, mut id: libc::c_int)
 -> *mut archive_acl_entry {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut aq: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    /* Type argument must be a valid NFS4 or POSIX.1e type.
	 * The type must agree with anything already set and
	 * the permset must be compatible. */
    if type_0 &
    ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4 != 0 {
        if (*acl).acl_types &
               !ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4 != 0 {
            return 0 as *mut archive_acl_entry
        }
        if permset &
               !(ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_perms_nfs4|
               ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_inheritance_nfs4) != 0 {
            return 0 as *mut archive_acl_entry
        }
    } else if type_0 & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_posix1e != 0 {
        if (*acl).acl_types & !ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_posix1e
               != 0 {
            return 0 as *mut archive_acl_entry
        }
        if permset &
               !ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_perms_posix1e
               != 0 {
            return 0 as *mut archive_acl_entry
        }
    } else { return 0 as *mut archive_acl_entry }
    /* Verify the tag is valid and compatible with NFS4 or POSIX.1e. */
    match tag {
        10001 | 10002 | 10003 | 10004 => { }
        10005 | 10006 => {
            /* Tags valid only in POSIX.1e. */
            if type_0 & !ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_posix1e!= 0 {
                return 0 as *mut archive_acl_entry
            }
        }
        10107=> {
            /* Tags valid only in NFS4. */
            if type_0 &
                   !(ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4) != 0 {
                return 0 as *mut archive_acl_entry
            }
        }
        _ => {
            /* No other values are valid. */
            return 0 as *mut archive_acl_entry
        }
    }
    free_safe((*acl).acl_text_w as *mut libc::c_void);
    (*acl).acl_text_w = 0 as *mut wchar_t;
    free_safe((*acl).acl_text as *mut libc::c_void);
    (*acl).acl_text = 0 as *mut libc::c_char;
    /*
	 * If there's a matching entry already in the list, overwrite it.
	 * NFSv4 entries may be repeated and are not overwritten.
	 *
	 * TODO: compare names of no id is provided (needs more rework)
	 */
    ap = (*acl).acl_head;
    aq = 0 as *mut archive_acl_entry;
    while !ap.is_null() {
        if type_0 &
        ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4 ==
               0 as libc::c_int && (*ap).type_0 == type_0 && (*ap).tag == tag
               && (*ap).id == id {
            if id != -(1 as libc::c_int) ||
                   tag !=ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user && tag != ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group
               {
                (*ap).permset = permset;
                return ap
            }
        }
        aq = ap;
        ap = (*ap).next
    }
    /* Add a new entry to the end of the list. */
    ap =
        calloc(1 as libc::c_int as libc::c_ulong,
               ::std::mem::size_of::<archive_acl_entry>() as libc::c_ulong) as
            *mut archive_acl_entry;
    if ap.is_null() { return 0 as *mut archive_acl_entry }
    if aq.is_null() { (*acl).acl_head = ap } else { (*aq).next = ap }
    (*ap).type_0 = type_0;
    (*ap).tag = tag;
    (*ap).id = id;
    (*ap).permset = permset;
    (*acl).acl_types |= type_0;
    return ap;
}
/*
 * Return a count of entries matching "want_type".
 */

#[no_mangle]
pub unsafe extern "C"  fn archive_acl_count(mut acl: *mut archive_acl,
                                           mut want_type: libc::c_int)
 -> libc::c_int {
    let mut count: libc::c_int = 0;
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    count = 0 as libc::c_int;
    ap = (*acl).acl_head;
    while !ap.is_null() {
        if (*ap).type_0 & want_type != 0 as libc::c_int { count += 1 }
        ap = (*ap).next
    }
    if count > 0 as libc::c_int &&
           want_type & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access != 0 as libc::c_int {
        count += 3 as libc::c_int
    }
    return count;
}
/*
 * Return a bitmask of stored ACL types in an ACL list
 */

#[no_mangle]
pub unsafe extern "C" fn  archive_acl_types(mut acl: *mut archive_acl)
 -> libc::c_int {
    return (*acl).acl_types;
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
    let safe_acl=unsafe{&mut *acl};
    let mut count: libc::c_int = 0;
    let mut cutoff: libc::c_int = 0;
    count = unsafe{archive_acl_count(safe_acl, want_type)};
    /*
	 * If the only entries are the three standard ones,
	 * then don't return any ACL data.  (In this case,
	 * client can just use chmod(2) to set permissions.)
	 */
    if want_type & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access != 0 as libc::c_int {
        cutoff = 3 as libc::c_int
    } else { cutoff = 0 as libc::c_int }
    if count > cutoff {
        (safe_acl).acl_state = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user_obj as libc::c_int
    } else { (safe_acl).acl_state = 0 as libc::c_int }
    (safe_acl).acl_p = (safe_acl).acl_head;
    return count;
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
    *name = 0 as *const libc::c_char;
    *id = -(1 as libc::c_int);
    /*
	 * The acl_state is either zero (no entries available), -1
	 * (reading from list), or an entry type (retrieve that type
	 * from ae_stat.aest_mode).
	 */
    if (*acl).acl_state == 0 as libc::c_int { return ARCHIVE_ACL_DEFINED_PARAM .archive_warn }
    /* The first three access entries are special. */
    if want_type & 0x100 as libc::c_int != 0 as libc::c_int {
        match (*acl).acl_state {
            10002 => {
                *permset =
                    ((*acl).mode >> 6 as libc::c_int &
                         7 as libc::c_int as libc::c_uint) as libc::c_int;
                *type_0 = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access;
                *tag = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user_obj;
                (*acl).acl_state = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group_obj;
                return 0 as libc::c_int
            }
            10004 => {
                *permset =
                    ((*acl).mode >> 3 as libc::c_int &
                         7 as libc::c_int as libc::c_uint) as libc::c_int;
                *type_0 = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access;
                *tag = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group_obj;
                (*acl).acl_state = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_other;
                return 0 as libc::c_int
            }
            10006 => {
                *permset =
                    ((*acl).mode & 7 as libc::c_int as libc::c_uint) as
                        libc::c_int;
                *type_0 = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access;
                *tag = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_other;
                (*acl).acl_state = -(1 as libc::c_int);
                (*acl).acl_p = (*acl).acl_head;
                return ARCHIVE_ACL_DEFINED_PARAM .archive_ok;
            }
            _ => { }
        }
    }
    while !(*acl).acl_p.is_null() &&
              (*(*acl).acl_p).type_0 & want_type == 0 as libc::c_int {
        (*acl).acl_p = (*(*acl).acl_p).next
    }
    if (*acl).acl_p.is_null() {
        (*acl).acl_state = 0 as libc::c_int;
        *type_0 = 0 as libc::c_int;
        *permset = 0 as libc::c_int;
        *tag = 0 as libc::c_int;
        *id = -(1 as libc::c_int);
        *name = 0 as *const libc::c_char;
        return ARCHIVE_ACL_DEFINED_PARAM .archive_eof;
        /* End of ACL entries. */
    }
    *type_0 = (*(*acl).acl_p).type_0;
    *permset = (*(*acl).acl_p).permset;
    *tag = (*(*acl).acl_p).tag;
    *id = (*(*acl).acl_p).id;
    if archive_mstring_get_mbs_safe(a, &mut (*(*acl).acl_p).name, name) !=
           0 as libc::c_int {
        if *__errno_location_safe() == ARCHIVE_ACL_DEFINED_PARAM .enomem {
            return ARCHIVE_ACL_DEFINED_PARAM .archive_fatal
        }
        *name = 0 as *const libc::c_char
    }
    (*acl).acl_p = (*(*acl).acl_p).next;
    return ARCHIVE_ACL_DEFINED_PARAM .archive_ok;
}
/*
 * Determine what type of ACL do we want
 */
fn archive_acl_text_want_type(mut acl: *mut archive_acl,
                                                mut flags: libc::c_int)
 -> libc::c_int {
    let safe_acl=unsafe{&mut *acl};
    let mut want_type: libc::c_int = 0;
    /* Check if ACL is NFSv4 */
    if (safe_acl).acl_types &
    ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4 !=
           0 as libc::c_int {
        /* NFSv4 should never mix with POSIX.1e */
        if (safe_acl).acl_types & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_posix1e !=
               0 as libc::c_int {
            return 0 as libc::c_int
        } else {
            return ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4
        }
    }
    /* Now deal with POSIX.1e ACLs */
    want_type = 0 as libc::c_int;
    if flags &ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access != 0 as libc::c_int {
        want_type |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access
    }
    if flags & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_default != 0 as libc::c_int {
        want_type |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_default
    }
    /* By default we want both access and default ACLs */
    if want_type == 0 as libc::c_int {
        return ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_posix1e
    }
    return want_type;
}
/*
 * Calculate ACL text string length
 */
unsafe fn archive_acl_text_len(mut acl: *mut archive_acl,
                                          mut want_type: libc::c_int,
                                          mut flags: libc::c_int,
                                          mut wide: libc::c_int,
                                          mut a: *mut archive,
                                          mut sc: *mut archive_string_conv)
 -> ssize_t {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut name: *const libc::c_char = 0 as *const libc::c_char;
    let mut wname: *const wchar_t = 0 as *const wchar_t;
    let mut count: libc::c_int = 0;
    let mut idlen: libc::c_int = 0;
    let mut tmp: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut length: ssize_t = 0;
    let mut len: size_t = 0;
    count = 0 as libc::c_int;
    length = 0 as libc::c_int as ssize_t;
    ap = (*acl).acl_head;
    while !ap.is_null() {
        if !((*ap).type_0 & want_type == 0 as libc::c_int) {
            /*
		 * Filemode-mapping ACL entries are stored exclusively in
		 * ap->mode so they should not be in the list
		 */
            if !((*ap).type_0 ==ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access &&
                     ((*ap).tag ==ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user_obj ||
                          (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group_obj ||
                          (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_other)) {
                count += 1; /* "default:" */
                if want_type & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_default != 0 as libc::c_int &&
                       (*ap).type_0 & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_default != 0 as libc::c_int
                   {
                    length += 8 as libc::c_int as libc::c_long
                } /* "owner@" */
                let mut current_block_10: u64; /* "group@" */
                match (*ap).tag {
                    10002 => {
                        if want_type ==
                        ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4 {
                            length +=
                                6 as libc::c_int as
                                    libc::c_long; /* "everyone@" */
                            current_block_10 = 2719512138335094285;
                        } else { current_block_10 = 12183639489562779793; }
                    }
                    10001 | 10005 => {
                        current_block_10 = 12183639489562779793;
                    }
                    10004 => {
                        if want_type ==
                        ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4 {
                            length += 6 as libc::c_int as libc::c_long;
                            current_block_10 = 2719512138335094285;
                        } else { current_block_10 = 11171774058386854943; }
                    }
                    10003 | 10006 => {
                        current_block_10 = 11171774058386854943;
                    }
                    10107 => {
                        length += 9 as libc::c_int as libc::c_long;
                        current_block_10 = 2719512138335094285;
                    }
                    _ => { current_block_10 = 2719512138335094285; }
                }
                match current_block_10 {
                    12183639489562779793 =>
                    /* FALLTHROUGH */
                    {
                        length += 4 as libc::c_int as libc::c_long
                    }
                    11171774058386854943 =>  /* "user", "mask" */
                    /* FALLTHROUGH */
                    {
                        length += 5 as libc::c_int as libc::c_long
                    }
                    _ => { }
                } /* "group", "other" */
                length +=
                    1 as libc::c_int as libc::c_long; /* colon after tag */
                if (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user ||
                       (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group as libc::c_int {
                    if wide != 0 {
                        r =
                            archive_mstring_get_wcs_safe(a, &mut (*ap).name,
                                                    &mut wname); /* 2nd colon empty user,group or other */
                        if r == 0 as libc::c_int && !wname.is_null() {
                            length =
                                (length as
                                     libc::c_ulong).wrapping_add(wcslen(wname))
                                    as ssize_t as ssize_t
                        } else if r < 0 as libc::c_int &&
                                      *__errno_location_safe() == ARCHIVE_ACL_DEFINED_PARAM .enomem
                         {
                            return 0 as libc::c_int as ssize_t
                        } else {
                            length =(length as libc::c_ulong).wrapping_add((::std::mem::size_of::<uid_t>()
                                        as libc::c_ulong).wrapping_mul(3 as libc::c_int as libc::c_ulong).wrapping_add(1 as libc::c_int as libc::c_ulong)) as ssize_t as ssize_t
                        }
                    } else {
                        r =
                            archive_mstring_get_mbs_l_safe(a, &mut (*ap).name, &mut name, &mut len, sc);  
                        if r != 0 as libc::c_int {
                            return 0 as libc::c_int as ssize_t
                        }
                        if len > 0 as libc::c_int as libc::c_ulong &&
                               !name.is_null() {
                            length =(length as libc::c_ulong).wrapping_add(len) as ssize_t as ssize_t
                        } else {
                            length =
                                (length as libc::c_ulong).wrapping_add((::std::mem::size_of::<uid_t>()                         
                                     as libc::c_ulong).wrapping_mul(3 as libc::c_int  as  libc::c_ulong).wrapping_add(1 as libc::c_int  as  libc::c_ulong)) as ssize_t as ssize_t
                        }
                    }
                    length += 1 as libc::c_int as libc::c_long
                    /* colon after user or group name */
                } else if want_type !=
                ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4 {
                    length += 1 as libc::c_int as libc::c_long
                }
                if flags & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_solaris!= 0 as libc::c_int &&
                       want_type &
                       ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_posix1e !=
                           0 as libc::c_int &&
                       ((*ap).tag == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_other ||
                            (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_mask) {
                    /* Solaris has no colon after other: and mask: */
                    length = length - 1 as libc::c_int as libc::c_long
                } /* rwx */
                if want_type ==
                ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4 {
                    /* rwxpdDaARWcCos:fdinSFI:deny */
                    length += 27 as libc::c_int as libc::c_long;
                    if (*ap).type_0 & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_deny == 0 as libc::c_int
                       {
                        length += 1 as libc::c_int as libc::c_long
                    }
                    /* allow, alarm, audit */
                } else {
                    length += 3 as libc::c_int as libc::c_long
                } /* colon */
                if ((*ap).tag == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user||
                        (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group) &&
                       flags & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_extra_id != 0 as libc::c_int {
                    length += 1 as libc::c_int as libc::c_long;
                    /* ID digit count */
                    idlen = 1 as libc::c_int;
                    tmp = (*ap).id;
                    while tmp > 9 as libc::c_int {
                        tmp = tmp / 10 as libc::c_int;
                        idlen += 1
                    }
                    length += idlen as libc::c_long
                }
                length += 1
            }
        }
        ap = (*ap).next
        /* entry separator */
    }
    /* Add filemode-mapping access entries to the length */
    if want_type &ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access != 0 as libc::c_int {
        if flags & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_solaris != 0 as libc::c_int {
            /* "user::rwx\ngroup::rwx\nother:rwx\n" */
            length += 31 as libc::c_int as libc::c_long
        } else {
            /* "user::rwx\ngroup::rwx\nother::rwx\n" */
            length += 32 as libc::c_int as libc::c_long
        }
    } else if count == 0 as libc::c_int { return 0 as libc::c_int as ssize_t }
    /* The terminating character is included in count */
    return length;
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
    let mut count: libc::c_int = 0;
    let mut length: ssize_t = 0;
    let mut len: size_t = 0;
    let mut wname: *const wchar_t = 0 as *const wchar_t;
    let mut prefix: *const wchar_t = 0 as *const wchar_t;
    let mut separator: wchar_t = 0;
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut id: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut want_type: libc::c_int = 0;
    let mut wp: *mut wchar_t = 0 as *mut wchar_t;
    let mut ws: *mut wchar_t = 0 as *mut wchar_t;
    want_type = archive_acl_text_want_type(acl, flags);
    /* Both NFSv4 and POSIX.1 types found */
    if want_type == 0 as libc::c_int { return 0 as *mut wchar_t }
    if want_type == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_posix1e {
        flags |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_mark_default
    }
    length =
        archive_acl_text_len(acl, want_type, flags, 1 as libc::c_int, a,
                             0 as *mut archive_string_conv);
    if length == 0 as libc::c_int as libc::c_long { return 0 as *mut wchar_t }
    if flags &ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_separator_comma!= 0 {
        separator = ',' as i32
    } else { separator = '\n' as i32 }
    /* Now, allocate the string and actually populate it. */
    ws =
    malloc_safe((length as
                    libc::c_ulong).wrapping_mul(::std::mem::size_of::<wchar_t>()
                                                    as libc::c_ulong)) as
            *mut wchar_t;
    wp = ws;
    if wp.is_null() {
        if *__errno_location_safe() == ARCHIVE_ACL_DEFINED_PARAM .enomem {
            __archive_errx_safe(1 as libc::c_int,
                           b"No memory\x00" as *const u8 as
                               *const libc::c_char);
        }
        return 0 as *mut wchar_t
    }
    count = 0 as libc::c_int;
    if want_type & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access != 0 as libc::c_int {
        append_entry_w(&mut wp, 0 as *const wchar_t, ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access,
        ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user_obj, flags, 0 as *const wchar_t,
                       ((*acl).mode & 0o700 as libc::c_int as libc::c_uint) as
                           libc::c_int, -(1 as libc::c_int));
        let fresh0 = wp;
        wp = wp.offset(1);
        *fresh0 = separator;
        append_entry_w(&mut wp, 0 as *const wchar_t, ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access,
        ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group_obj, flags, 0 as *const wchar_t,
                       ((*acl).mode & 0o70 as libc::c_int as libc::c_uint) as
                           libc::c_int, -(1 as libc::c_int));
        let fresh1 = wp;
        wp = wp.offset(1);
        *fresh1 = separator;
        append_entry_w(&mut wp, 0 as *const wchar_t, ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access,
        ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_other, flags, 0 as *const wchar_t,
                       ((*acl).mode & 0o7 as libc::c_int as libc::c_uint) as
                           libc::c_int, -(1 as libc::c_int));
        count += 3 as libc::c_int
    }
    ap = (*acl).acl_head;
    while !ap.is_null() {
        if !((*ap).type_0 & want_type == 0 as libc::c_int) {
            /*
		 * Filemode-mapping ACL entries are stored exclusively in
		 * ap->mode so they should not be in the list
		 */
            if !((*ap).type_0 == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access &&
                     ((*ap).tag == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user_obj ||
                     (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group_obj ||
                          (*ap).tag ==  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_other)) {
                if (*ap).type_0 ==  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_default &&
                       flags &  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_mark_default != 0 as libc::c_int {
                    prefix = wchar::wchz!("default:").as_ptr();
                } else { prefix = 0 as *const wchar_t }
                r = archive_mstring_get_wcs_safe(a, &mut (*ap).name, &mut wname);
                if r == 0 as libc::c_int {
                    if count > 0 as libc::c_int {
                        let fresh2 = wp;
                        wp = wp.offset(1);
                        *fresh2 = separator
                    }
                    if flags &  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_extra_id != 0 {
                        id = (*ap).id 
                    } else { id = -(1 as libc::c_int) }
                    append_entry_w(&mut wp, prefix, (*ap).type_0, (*ap).tag, flags, wname, (*ap).permset, id);
                    count += 1
                } else if r < 0 as libc::c_int &&
                              *__errno_location_safe() ==  ARCHIVE_ACL_DEFINED_PARAM .enomem {
                                free_safe(ws as *mut libc::c_void);
                    return 0 as *mut wchar_t
                }
            }
        }
        ap = (*ap).next
    }
    /* Add terminating character */
    let fresh3 = wp;
    wp = wp.offset(1);
    *fresh3 = '\u{0}' as i32;
    len = wcslen(ws);
    if len as ssize_t > length - 1 as libc::c_int as libc::c_long {
        __archive_errx_safe(1 as libc::c_int,
                       b"Buffer overrun\x00" as *const u8 as
                           *const libc::c_char);
    }
    if !text_len.is_null() { *text_len = len as ssize_t }
    return ws;
}
unsafe fn append_id_w(mut wp: *mut *mut wchar_t,
                                 mut id: libc::c_int) {
    if id < 0 as libc::c_int { id = 0 as libc::c_int }
    if id > 9 as libc::c_int { append_id_w(wp, id / 10 as libc::c_int); }
    let fresh4 = *wp;
    *wp = (*wp).offset(1);
    *fresh4 = wchar::wchz!("0123456789")[(id % 10 as libc::c_int) as usize];                                                                                     
}
pub unsafe fn append_entry_w(mut wp: *mut *mut wchar_t,
                                    mut prefix: *const wchar_t,
                                    mut type_0: libc::c_int,
                                    mut tag: libc::c_int,
                                    mut flags: libc::c_int,
                                    mut wname: *const wchar_t,
                                    mut perm: libc::c_int,
                                    mut id: libc::c_int) {
    let mut i: libc::c_int = 0;
    if !prefix.is_null() {
        wcscpy_safe(*wp, prefix);
        *wp = (*wp).offset(wcslen(*wp) as isize)
    }
    let mut current_block_20: u64;
    match tag {
        10002 => {
            wname = 0 as *const wchar_t;
            id = -(1 as libc::c_int);
            if type_0 & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4!=
                   0 as libc::c_int {
                wcscpy_safe(*wp, wchar::wchz!("owner@").as_ptr());
                current_block_20 = 14818589718467733107;
            } else { current_block_20 = 13059761959729012537; }
        }
        10001 => { current_block_20 = 13059761959729012537; }
        10004 => {
            wname = 0 as *const wchar_t;
            id = -(1 as libc::c_int);
            if type_0 &
            ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4 !=
                   0 as libc::c_int {
                    wcscpy_safe(*wp, wchar::wchz!("group@").as_ptr());
                current_block_20 = 14818589718467733107;
            } else { current_block_20 = 1203188319497562805; }
        }
        10003 => { current_block_20 = 1203188319497562805; }
        10005 => {
            wcscpy_safe(*wp, wchar::wchz!("mask").as_ptr());
            wname = 0 as *const wchar_t;
            id = -(1 as libc::c_int);
            current_block_20 = 14818589718467733107;
        }
        10006 => {
            wcscpy_safe(*wp, wchar::wchz!("other").as_ptr());
            wname = 0 as *const wchar_t;
            id = -(1 as libc::c_int);
            current_block_20 = 14818589718467733107;
        }
        10107 => {
            wcscpy_safe(*wp, wchar::wchz!("everyone@").as_ptr());
            wname = 0 as *const wchar_t;
            id = -(1 as libc::c_int);
            current_block_20 = 14818589718467733107;
        }
        _ => { current_block_20 = 14818589718467733107; }
    }
    match current_block_20 {
        13059761959729012537 =>
        /* FALLTHROUGH */
        {
            wcscpy_safe(*wp, wchar::wchz!("user").as_ptr());
        }
        1203188319497562805 =>
        /* FALLTHROUGH */
        {
            wcscpy_safe(*wp, wchar::wchz!("group").as_ptr());
        }
        _ => { }
    }
    *wp = (*wp).offset(wcslen(*wp) as isize);
    let fresh5 = *wp;
    *wp = (*wp).offset(1);
    *fresh5 = ':' as i32;
    if type_0 &  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_posix1e !=
           0 as libc::c_int || tag ==  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user ||
           tag == ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group{
        if !wname.is_null() {
            wcscpy_safe(*wp, wname);
            *wp = (*wp).offset(wcslen(*wp) as isize)
        } else if tag ==  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user|| tag ==  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group {
            append_id_w(wp, id);
            if type_0 &
            ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4==
                   0 as libc::c_int {
                id = -(1 as libc::c_int)
            }
        }
        /* Solaris style has no second colon after other and mask */
        if (flags &  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_solaris == 0 as libc::c_int )||
         tag !=ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_other && tag !=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_mask{
            let fresh6 = *wp;
            *wp = (*wp).offset(1);
            *fresh6 = ':' as i32
        }
    }
    if type_0 &  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_posix1e !=
           0 as libc::c_int {
        /* POSIX.1e ACL perms */
        let fresh7 = *wp;
        *wp = (*wp).offset(1);
        *fresh7 =
            if perm & 0o444 as libc::c_int != 0 {
                'r' as i32
            } else { '-' as i32 };
        let fresh8 = *wp;
        *wp = (*wp).offset(1);
        *fresh8 =
            if perm & 0o222 as libc::c_int != 0 {
                'w' as i32
            } else { '-' as i32 };
        let fresh9 = *wp;
        *wp = (*wp).offset(1);
        *fresh9 =
            if perm & 0o111 as libc::c_int != 0 {
                'x' as i32
            } else { '-' as i32 }
    } else {
        /* NFSv4 ACL perms */
        i = 0 as libc::c_int;
        while i < nfsv4_acl_perm_map_size {
            if perm & nfsv4_acl_perm_map[i as usize].perm != 0 {
                let fresh10 = *wp;
                *wp = (*wp).offset(1);
                *fresh10 = nfsv4_acl_perm_map[i as usize].wc
            } else if flags & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_compact == 0 as libc::c_int {
                let fresh11 = *wp;
                *wp = (*wp).offset(1);
                *fresh11 = '-' as i32
            }
            i += 1
        }
        let fresh12 = *wp;
        *wp = (*wp).offset(1);
        *fresh12 = ':' as i32;
        i = 0 as libc::c_int;
        while i < nfsv4_acl_flag_map_size {
            if perm & nfsv4_acl_flag_map[i as usize].perm != 0 {
                let fresh13 = *wp;
                *wp = (*wp).offset(1);
                *fresh13 = nfsv4_acl_flag_map[i as usize].wc
            } else if flags & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_compact == 0 as libc::c_int {
                let fresh14 = *wp;
                *wp = (*wp).offset(1);
                *fresh14 = '-' as i32
            }
            i += 1
        }
        let fresh15 = *wp;
        *wp = (*wp).offset(1);
        *fresh15 = ':' as i32;
        match type_0 {
            1024 => {
                wcscpy_safe(*wp, wchar::wchz!("allow").as_ptr());
            }
            2048 => {
                wcscpy_safe(*wp, wchar::wchz!("deny").as_ptr());
            }
            4096 => {
                wcscpy_safe(*wp, wchar::wchz!("audit").as_ptr());
            }
            8192 => {
                wcscpy_safe(*wp, wchar::wchz!("alarm").as_ptr());
            }
            _ => { }
        }
        *wp = (*wp).offset(wcslen_safe(*wp) as isize)
    }
    if id != -(1 as libc::c_int) {
        let fresh16 = *wp;
        *wp = (*wp).offset(1);
        *fresh16 = ':' as i32;
        append_id_w(wp, id);
    };
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
    let mut count: libc::c_int = 0;
    let mut length: ssize_t = 0;
    let mut len: size_t = 0;
    let mut name: *const libc::c_char = 0 as *const libc::c_char;
    let mut prefix: *const libc::c_char = 0 as *const libc::c_char;
    let mut separator: libc::c_char = 0;
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut id: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut want_type: libc::c_int = 0;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    want_type = archive_acl_text_want_type(acl, flags);
    /* Both NFSv4 and POSIX.1 types found */
    if want_type == 0 as libc::c_int { return 0 as *mut libc::c_char }
    if want_type ==  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_posix1e {
        flags |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_mark_default
    }
    length =
        archive_acl_text_len(acl, want_type, flags, 0 as libc::c_int,
                             0 as *mut archive, sc);
    if length == 0 as libc::c_int as libc::c_long {
        return 0 as *mut libc::c_char
    }
    if flags &  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_separator_comma != 0 {
        separator = ',' as i32 as libc::c_char
    } else { separator = '\n' as i32 as libc::c_char }
    /* Now, allocate the string and actually populate it. */
    s =
    malloc_safe((length as
                    libc::c_ulong).wrapping_mul(::std::mem::size_of::<libc::c_char>()
                                                    as libc::c_ulong)) as
            *mut libc::c_char;
    p = s;
    if p.is_null() {
        if *__errno_location_safe() ==  ARCHIVE_ACL_DEFINED_PARAM .enomem {
            __archive_errx_safe(1 as libc::c_int,
                           b"No memory\x00" as *const u8 as
                               *const libc::c_char);
        }
        return 0 as *mut libc::c_char
    }
    count = 0 as libc::c_int;
    if want_type &  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access != 0 as libc::c_int {
        append_entry(&mut p, 0 as *const libc::c_char,  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access,
        ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user_obj, flags, 0 as *const libc::c_char,
                     ((*acl).mode & 0o700 as libc::c_int as libc::c_uint) as
                         libc::c_int, -(1 as libc::c_int));
        let fresh17 = p;
        p = p.offset(1);
        *fresh17 = separator;
        append_entry(&mut p, 0 as *const libc::c_char, ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access,
        ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group_obj, flags, 0 as *const libc::c_char,
                     ((*acl).mode & 0o70 as libc::c_int as libc::c_uint) as
                         libc::c_int, -(1 as libc::c_int));
        let fresh18 = p;
        p = p.offset(1);
        *fresh18 = separator;
        append_entry(&mut p, 0 as *const libc::c_char,  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access,
        ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_other, flags, 0 as *const libc::c_char,
                     ((*acl).mode & 0o7 as libc::c_int as libc::c_uint) as
                         libc::c_int, -(1 as libc::c_int));
        count += 3 as libc::c_int
    }
    ap = (*acl).acl_head;
    while !ap.is_null() {
        if !((*ap).type_0 & want_type == 0 as libc::c_int) {
            /*
		 * Filemode-mapping ACL entries are stored exclusively in
		 * ap->mode so they should not be in the list
		 */
            if !((*ap).type_0 ==  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_access &&
                     ((*ap).tag ==  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user_obj ||
                          (*ap).tag ==  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group_obj ||
                          (*ap).tag ==  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_other)) {
                if (*ap).type_0 ==  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_default &&
                       flags &  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_mark_default!= 0 as libc::c_int {
                    prefix =
                        b"default:\x00" as *const u8 as *const libc::c_char
                } else { prefix = 0 as *const libc::c_char }
                r =
                    archive_mstring_get_mbs_l_safe(0 as *mut archive,
                                              &mut (*ap).name, &mut name,
                                              &mut len, sc);
                if r != 0 as libc::c_int {
                    free_safe(s as *mut libc::c_void);
                    return 0 as *mut libc::c_char
                }
                if count > 0 as libc::c_int {
                    let fresh19 = p;
                    p = p.offset(1);
                    *fresh19 = separator
                }
                if name.is_null() || flags & ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_style_extra_id!= 0 {
                    id = (*ap).id
                } else { id = -(1 as libc::c_int) }
                append_entry(&mut p, prefix, (*ap).type_0, (*ap).tag, flags,
                             name, (*ap).permset, id);
                count += 1
            }
        }
        ap = (*ap).next
    }
    /* Add terminating character */
    let fresh20 = p;
    p = p.offset(1);
    *fresh20 = '\u{0}' as i32 as libc::c_char;
    len = strlen_safe(s);
    if len as ssize_t > length - 1 as libc::c_int as libc::c_long {
        __archive_errx_safe(1 as libc::c_int,
                       b"Buffer overrun\x00" as *const u8 as
                           *const libc::c_char);
    }
    if !text_len.is_null() { *text_len = len as ssize_t }
    return s;
}
unsafe extern "C" fn append_id(mut p: *mut *mut libc::c_char,
                               mut id: libc::c_int) {
    if id < 0 as libc::c_int { id = 0 as libc::c_int }
    if id > 9 as libc::c_int { append_id(p, id / 10 as libc::c_int); }
    let fresh21 = *p;
    *p = (*p).offset(1);
    *fresh21 =
        (*::std::mem::transmute::<&[u8; 11],
                                  &[libc::c_char; 11]>(b"0123456789\x00"))[(id % 10 as libc::c_int) as usize];
}
unsafe fn append_entry(mut p: *mut *mut libc::c_char,
                                  mut prefix: *const libc::c_char,
                                  mut type_0: libc::c_int,
                                  mut tag: libc::c_int,
                                  mut flags: libc::c_int,
                                  mut name: *const libc::c_char,
                                  mut perm: libc::c_int,
                                  mut id: libc::c_int) {
    let mut i: libc::c_int = 0;
    if !prefix.is_null() {
        strcpy_safe(*p, prefix);
        *p = (*p).offset(strlen_safe(*p) as isize)
    }
    let mut current_block_20: u64;
    match tag {
        10002 => {
            name = 0 as *const libc::c_char;
            id = -(1 as libc::c_int);
            if type_0 &
                   (0x400 as libc::c_int | 0x800 as libc::c_int |
                        0x1000 as libc::c_int | 0x2000 as libc::c_int) !=
                   0 as libc::c_int {
                    strcpy_safe(*p, b"owner@\x00" as *const u8 as *const libc::c_char);
                current_block_20 = 14818589718467733107;
            } else { current_block_20 = 4317932568550761545; }
        }
        10001 => { current_block_20 = 4317932568550761545; }
        10004 => {
            name = 0 as *const libc::c_char;
            id = -(1 as libc::c_int);
            if type_0 &
                   (0x400 as libc::c_int | 0x800 as libc::c_int |
                        0x1000 as libc::c_int | 0x2000 as libc::c_int) !=
                   0 as libc::c_int {
                    strcpy_safe(*p, b"group@\x00" as *const u8 as *const libc::c_char);
                current_block_20 = 14818589718467733107;
            } else { current_block_20 = 8114179180390253173; }
        }
        10003 => { current_block_20 = 8114179180390253173; }
        10005 => {
            strcpy_safe(*p, b"mask\x00" as *const u8 as *const libc::c_char);
            name = 0 as *const libc::c_char;
            id = -(1 as libc::c_int);
            current_block_20 = 14818589718467733107;
        }
        10006 => {
            strcpy_safe(*p, b"other\x00" as *const u8 as *const libc::c_char);
            name = 0 as *const libc::c_char;
            id = -(1 as libc::c_int);
            current_block_20 = 14818589718467733107;
        }
        10107 => {
            strcpy_safe(*p, b"everyone@\x00" as *const u8 as *const libc::c_char);
            name = 0 as *const libc::c_char;
            id = -(1 as libc::c_int);
            current_block_20 = 14818589718467733107;
        }
        _ => { current_block_20 = 14818589718467733107; }
    }
    match current_block_20 {
        4317932568550761545 =>
        /* FALLTHROUGH */
        {
            strcpy_safe(*p, b"user\x00" as *const u8 as *const libc::c_char);
        }
        8114179180390253173 =>
        /* FALLTHROUGH */
        {
            strcpy_safe(*p, b"group\x00" as *const u8 as *const libc::c_char);
        }
        _ => { }
    }
    *p = (*p).offset(strlen_safe(*p) as isize);
    let fresh22 = *p;
    *p = (*p).offset(1);
    *fresh22 = ':' as i32 as libc::c_char;
    if type_0 & (0x100 as libc::c_int | 0x200 as libc::c_int) !=
           0 as libc::c_int || tag == 10001 as libc::c_int ||
           tag == 10003 as libc::c_int {
        if !name.is_null() {
            strcpy_safe(*p, name);
            *p = (*p).offset(strlen_safe(*p) as isize)
        } else if tag == 10001 as libc::c_int || tag == 10003 as libc::c_int {
            append_id(p, id);
            if type_0 &
                   (0x400 as libc::c_int | 0x800 as libc::c_int |
                        0x1000 as libc::c_int | 0x2000 as libc::c_int) ==
                   0 as libc::c_int {
                id = -(1 as libc::c_int)
            }
        }
        /* Solaris style has no second colon after other and mask */
        if flags & 0x4 as libc::c_int == 0 as libc::c_int ||
               tag != 10006 as libc::c_int && tag != 10005 as libc::c_int {
            let fresh23 = *p;
            *p = (*p).offset(1);
            *fresh23 = ':' as i32 as libc::c_char
        }
    }
    if type_0 & (0x100 as libc::c_int | 0x200 as libc::c_int) !=
           0 as libc::c_int {
        /* POSIX.1e ACL perms */
        let fresh24 = *p;
        *p = (*p).offset(1);
        *fresh24 =
            if perm & 0o444 as libc::c_int != 0 {
                'r' as i32
            } else { '-' as i32 } as libc::c_char;
        let fresh25 = *p;
        *p = (*p).offset(1);
        *fresh25 =
            if perm & 0o222 as libc::c_int != 0 {
                'w' as i32
            } else { '-' as i32 } as libc::c_char;
        let fresh26 = *p;
        *p = (*p).offset(1);
        *fresh26 =
            if perm & 0o111 as libc::c_int != 0 {
                'x' as i32
            } else { '-' as i32 } as libc::c_char
    } else {
        /* NFSv4 ACL perms */
        i = 0 as libc::c_int;
        while i < nfsv4_acl_perm_map_size {
            if perm & nfsv4_acl_perm_map[i as usize].perm != 0 {
                let fresh27 = *p;
                *p = (*p).offset(1);
                *fresh27 = nfsv4_acl_perm_map[i as usize].c
            } else if flags & 0x10 as libc::c_int == 0 as libc::c_int {
                let fresh28 = *p;
                *p = (*p).offset(1);
                *fresh28 = '-' as i32 as libc::c_char
            }
            i += 1
        }
        let fresh29 = *p;
        *p = (*p).offset(1);
        *fresh29 = ':' as i32 as libc::c_char;
        i = 0 as libc::c_int;
        while i < nfsv4_acl_flag_map_size {
            if perm & nfsv4_acl_flag_map[i as usize].perm != 0 {
                let fresh30 = *p;
                *p = (*p).offset(1);
                *fresh30 = nfsv4_acl_flag_map[i as usize].c
            } else if flags & 0x10 as libc::c_int == 0 as libc::c_int {
                let fresh31 = *p;
                *p = (*p).offset(1);
                *fresh31 = '-' as i32 as libc::c_char
            }
            i += 1
        }
        let fresh32 = *p;
        *p = (*p).offset(1);
        *fresh32 = ':' as i32 as libc::c_char;
        match type_0 {
            1024 => {
                strcpy_safe(*p, b"allow\x00" as *const u8 as *const libc::c_char);
            }
            2048 => {
                strcpy_safe(*p, b"deny\x00" as *const u8 as *const libc::c_char);
            }
            4096 => {
                strcpy_safe(*p, b"audit\x00" as *const u8 as *const libc::c_char);
            }
            8192 => {
                strcpy_safe(*p, b"alarm\x00" as *const u8 as *const libc::c_char);
            }
            _ => { }
        }
        *p = (*p).offset(strlen_safe(*p) as isize)
    }
    if id != -(1 as libc::c_int) {
        let fresh33 = *p;
        *p = (*p).offset(1);
        *fresh33 = ':' as i32 as libc::c_char;
        append_id(p, id);
    };
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
    let mut field: [archive_string_temporary_field_1; 6] =
        [archive_string_temporary_field_1{start: 0 as *const wchar_t,
                         end: 0 as *const wchar_t,}; 6];
    let mut name: archive_string_temporary_field_1 =
        archive_string_temporary_field_1{start: 0 as *const wchar_t,
                        end: 0 as *const wchar_t,};
    let mut s: *const wchar_t = 0 as *const wchar_t;
    let mut st: *const wchar_t = 0 as *const wchar_t;
    let mut numfields: libc::c_int = 0;
    let mut fields: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut sol: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut type_0: libc::c_int = 0;
    let mut types: libc::c_int = 0;
    let mut tag: libc::c_int = 0;
    let mut permset: libc::c_int = 0;
    let mut id: libc::c_int = 0;
    let mut len: size_t = 0;
    let mut sep: wchar_t = 0;
    ret = 0 as libc::c_int;
    types = 0 as libc::c_int;
    let mut current_block_6: u64;
    match want_type {
        768 => {
            want_type = 0x100 as libc::c_int;
            current_block_6 = 4235729007428639281;
        }
        256 | 512 => { current_block_6 = 4235729007428639281; }
        15360 => {
            numfields = 6 as libc::c_int;
            current_block_6 = 1856101646708284338;
        }
        _ => { return -(30 as libc::c_int) }
    }
    match current_block_6 {
        4235729007428639281 => { numfields = 5 as libc::c_int }
        _ => { }
    }
    /* Comment, skip entry */
    while !text.is_null() && *text != '\u{0}' as i32 {
        /*
		 * Parse the fields out of the next entry,
		 * advance 'text' to start of next entry.
		 */
        fields = 0 as libc::c_int;
        loop  {
            let mut start: *const wchar_t = 0 as *const wchar_t;
            let mut end: *const wchar_t = 0 as *const wchar_t;
            next_field_w(&mut text, &mut start, &mut end, &mut sep);
            if fields < numfields {
                field[fields as usize].start = start;
                field[fields as usize].end = end
            }
            fields += 1;
            if !(sep == ':' as i32) { break ; }
        }
        /* Set remaining fields to blank. */
        n = fields;
        while n < numfields {
            field[n as usize].end = 0 as *const wchar_t;
            field[n as usize].start = field[n as usize].end;
            n += 1
        }
        if !field[0 as libc::c_int as usize].start.is_null() &&
               *field[0 as libc::c_int as usize].start == '#' as i32 {
            continue ;
        }
        n = 0 as libc::c_int;
        sol = 0 as libc::c_int;
        id = -(1 as libc::c_int);
        permset = 0 as libc::c_int;
        name.end = 0 as *const wchar_t;
        name.start = name.end;
        if want_type != ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_nfs4 {
            /* POSIX.1e ACLs */
			/*
			 * Default keyword "default:user::rwx"
			 * if found, we have one more field
			 *
			 * We also support old Solaris extension:
			 * "defaultuser::rwx" is the default ACL corresponding
			 * to "user::rwx", etc. valid only for first field
			 */
            s = field[0 as libc::c_int as usize].start;
            len =
                field[0 as libc::c_int as
                          usize].end.offset_from(field[0 as libc::c_int as usize].start)
                    as libc::c_long as size_t;
            if *s == 'd' as i32 &&
                   (len == 1 as libc::c_int as libc::c_ulong ||
                        len >= 7 as libc::c_int as libc::c_ulong &&
                            wmemcmp_safe(s.offset(1 as libc::c_int as isize), wchar::wchz!("efault").as_ptr(),
                                    6 as libc::c_int as libc::c_ulong) ==
                                0 as libc::c_int) {
                type_0 =  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_default;
                if len > 7 as libc::c_int as libc::c_ulong {
                    field[0 as libc::c_int as usize].start =
                        field[0 as libc::c_int as
                                  usize].start.offset(7 as libc::c_int as
                                                          isize)
                } else { n = 1 as libc::c_int }
            } else { type_0 = want_type }
            /* Check for a numeric ID in field n+1 or n+3. */
            isint_w(field[(n + 1 as libc::c_int) as usize].start,
                    field[(n + 1 as libc::c_int) as usize].end, &mut id);
            /* Field n+3 is optional. */
            if id == -(1 as libc::c_int) && fields > n + 3 as libc::c_int {
                isint_w(field[(n + 3 as libc::c_int) as usize].start,
                        field[(n + 3 as libc::c_int) as usize].end, &mut id);
            }
            tag = 0 as libc::c_int;
            s = field[n as usize].start;
            st = field[n as usize].start.offset(1 as libc::c_int as isize);
            len =
                field[n as
                          usize].end.offset_from(field[n as usize].start)
                    as libc::c_long as size_t;
            match *s {
                117 => {
                    if len == 1 as libc::c_int as libc::c_ulong ||
                           len == 4 as libc::c_int as libc::c_ulong &&
                           wmemcmp_safe(st, wchar::wchz!("ser").as_ptr(),
                                       3 as libc::c_int as libc::c_ulong) ==
                                   0 as libc::c_int {
                        tag =  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user_obj
                    }
                }
                103 => {
                    if len == 1 as libc::c_int as libc::c_ulong ||
                           len == 5 as libc::c_int as libc::c_ulong &&
                           wmemcmp_safe(st, wchar::wchz!("roup").as_ptr(),
                                       4 as libc::c_int as libc::c_ulong) ==
                                   0 as libc::c_int {
                        tag =  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group_obj
                    }
                }
                111 => {
                    if len == 1 as libc::c_int as libc::c_ulong ||
                           len == 5 as libc::c_int as libc::c_ulong &&
                           wmemcmp_safe(st, wchar::wchz!("ther").as_ptr(),
                                       4 as libc::c_int as libc::c_ulong) ==
                                   0 as libc::c_int {
                        tag =  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_other
                    }
                }
                109 => {
                    if len == 1 as libc::c_int as libc::c_ulong ||
                           len == 4 as libc::c_int as libc::c_ulong &&
                           wmemcmp_safe(st, wchar::wchz!("ask").as_ptr(),
                                       3 as libc::c_int as libc::c_ulong) ==
                                   0 as libc::c_int {
                        tag =  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_mask
                    }
                }
                _ => { }
            }
            match tag {
                10006 | 10005 => {
                    if fields == n + 2 as libc::c_int &&
                           field[(n + 1 as libc::c_int) as usize].start <
                               field[(n + 1 as libc::c_int) as usize].end &&
                           ismode_w(field[(n + 1 as libc::c_int) as
                                              usize].start,
                                    field[(n + 1 as libc::c_int) as
                                              usize].end, &mut permset) != 0 {
                        /* This is Solaris-style "other:rwx" */
                        sol = 1 as libc::c_int
                    } else if fields == n + 3 as libc::c_int &&
                                  field[(n + 1 as libc::c_int) as usize].start
                                      <
                                      field[(n + 1 as libc::c_int) as
                                                usize].end {
                        /* Invalid mask or other field */
                        ret = -(20 as libc::c_int);
                        continue ;
                    }
                }
                10002 | 10004 => {
                    if id != -(1 as libc::c_int) ||
                           field[(n + 1 as libc::c_int) as usize].start <
                               field[(n + 1 as libc::c_int) as usize].end {
                        name = field[(n + 1 as libc::c_int) as usize];
                        if tag == 10002 as libc::c_int {
                            tag = 10001 as libc::c_int
                        } else { tag = 10003 as libc::c_int }
                    }
                }
                _ => {
                    /* Invalid tag, skip entry */
                    ret =  ARCHIVE_ACL_DEFINED_PARAM .archive_warn;
                    continue ;
                }
            }
            /*
			 * Without "default:" we expect mode in field 2
			 * Exception: Solaris other and mask fields
			 */
            if permset == 0 as libc::c_int &&
                   ismode_w(field[(n + 2 as libc::c_int - sol) as
                                      usize].start,
                            field[(n + 2 as libc::c_int - sol) as usize].end,
                            &mut permset) == 0 {
                /* Invalid mode, skip entry */
                ret =  ARCHIVE_ACL_DEFINED_PARAM .archive_warn;
                continue ;
            }
        } else {
            /* NFS4 ACLs */
            s = field[0 as libc::c_int as usize].start;
            len =
                field[0 as libc::c_int as
                          usize].end.offset_from(field[0 as
                                                                    libc::c_int
                                                                    as
                                                                    usize].start)
                    as libc::c_long as size_t;
            tag = 0 as libc::c_int;
            match len {
                4 => {
                    if wmemcmp_safe(s, wchar::wchz!("user").as_ptr(),
                               4 as libc::c_int as libc::c_ulong) ==
                           0 as libc::c_int {
                        tag =  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user
                    }
                }
                5 => {
                    if wmemcmp_safe(s, wchar::wchz!("group").as_ptr(),
                               5 as libc::c_int as libc::c_ulong) ==
                           0 as libc::c_int {
                        tag =  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group
                    }
                }
                6 => {
                    if wmemcmp_safe(s, wchar::wchz!("owner@").as_ptr(),
                               6 as libc::c_int as libc::c_ulong) ==
                           0 as libc::c_int {
                        tag =  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user_obj
                    } else if wmemcmp_safe(s, wchar::wchz!("group@").as_ptr(),
                                      len) == 0 as libc::c_int {
                        tag =  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group_obj
                    }
                }
                9 => {
                    if wmemcmp_safe(s, wchar::wchz!("everyone@").as_ptr(),
                               9 as libc::c_int as libc::c_ulong) ==
                           0 as libc::c_int {
                        tag =  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_everyone
                    }
                }
                _ => { }
            }
            if tag == 0 as libc::c_int {
                /* Invalid tag, skip entry */
                ret = ARCHIVE_ACL_DEFINED_PARAM .archive_warn;
                continue ;
            } else {
                if tag ==ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_user || tag ==ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_group
                   {
                    n = 1 as libc::c_int;
                    name = field[1 as libc::c_int as usize];
                    isint_w(name.start, name.end, &mut id);
                } else { n = 0 as libc::c_int }
                if is_nfs4_perms_w(field[(1 as libc::c_int + n) as
                                             usize].start,
                                   field[(1 as libc::c_int + n) as usize].end,
                                   &mut permset) == 0 {
                    /* Invalid NFSv4 perms, skip entry */
                    ret = ARCHIVE_ACL_DEFINED_PARAM .archive_warn;
                    continue ;
                } else if is_nfs4_flags_w(field[(2 as libc::c_int + n) as
                                                    usize].start,
                                          field[(2 as libc::c_int + n) as
                                                    usize].end, &mut permset)
                              == 0 {
                    /* Invalid NFSv4 flags, skip entry */
                    ret = ARCHIVE_ACL_DEFINED_PARAM .archive_warn;
                    continue ;
                } else {
                    s = field[(3 as libc::c_int + n) as usize].start;
                    len =
                        field[(3 as libc::c_int + n) as
                                  usize].end.offset_from(field[(3 as
                                                                             libc::c_int
                                                                             +
                                                                             n)
                                                                            as
                                                                            usize].start)
                            as libc::c_long as size_t;
                    type_0 = 0 as libc::c_int;
                    if len == 4 as libc::c_int as libc::c_ulong {
                        if wmemcmp_safe(s, wchar::wchz!("deny").as_ptr(),
                                   4 as libc::c_int as libc::c_ulong) ==
                               0 as libc::c_int {
                            type_0 = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_deny
                        }
                    } else if len == 5 as libc::c_int as libc::c_ulong {
                        if wmemcmp_safe(s, wchar::wchz!("allow").as_ptr(),
                                   5 as libc::c_int as libc::c_ulong) ==
                               0 as libc::c_int {
                            type_0 = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_allow
                        } else if wmemcmp_safe(s, wchar::wchz!("audit").as_ptr(),
                                          5 as libc::c_int as libc::c_ulong)
                                      == 0 as libc::c_int {
                            type_0 = ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_audit
                        } else if wmemcmp_safe(s, wchar::wchz!("alarm").as_ptr(),
                                          5 as libc::c_int as libc::c_ulong)
                                      == 0 as libc::c_int {
                            type_0 =ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_type_alram
                        }
                    }
                    if type_0 == 0 as libc::c_int {
                        /* Invalid entry type, skip entry */
                        ret = ARCHIVE_ACL_DEFINED_PARAM .archive_warn;
                        continue ;
                    } else {
                        isint_w(field[(4 as libc::c_int + n) as usize].start,
                                field[(4 as libc::c_int + n) as usize].end,
                                &mut id);
                    }
                }
            }
        }
        /* Add entry to the internal list. */
        r =
            archive_acl_add_entry_w_len(acl, type_0, permset, tag, id,
                                        name.start,
                                        name.end.offset_from(name.start)
                                            as libc::c_long as size_t);
        if r < ARCHIVE_ACL_DEFINED_PARAM .archive_warn { return r }
        if r !=ARCHIVE_ACL_DEFINED_PARAM .archive_ok{ ret = ARCHIVE_ACL_DEFINED_PARAM .archive_warn }
        types |= type_0
    }
    /* Reset ACL */
    archive_acl_reset(acl, types);
    return ret;
}
/*
 * Parse a string to a positive decimal integer.  Returns true if
 * the string is non-empty and consists only of decimal digits,
 * false otherwise.
 */
unsafe extern "C" fn isint_w(mut start: *const wchar_t,
                             mut end: *const wchar_t,
                             mut result: *mut libc::c_int) -> libc::c_int {
    let mut n: libc::c_int = 0 as libc::c_int;
    if start >= end { return 0 as libc::c_int }
    while start < end {
        if *start < '0' as i32 || *start > '9' as i32 {
            return 0 as libc::c_int
        }
        if n > 2147483647 as libc::c_int / 10 as libc::c_int ||
               n == 2147483647 as libc::c_int / 10 as libc::c_int &&
                   *start - '0' as i32 >
                       2147483647 as libc::c_int % 10 as libc::c_int {
            n = 2147483647 as libc::c_int
        } else { n *= 10 as libc::c_int; n += *start - '0' as i32 }
        start = start.offset(1)
    }
    *result = n;
    return 1 as libc::c_int;
}
/*
 * Parse a string as a mode field.  Returns true if
 * the string is non-empty and consists only of mode characters,
 * false otherwise.
 */
unsafe extern "C" fn ismode_w(mut start: *const wchar_t,
                              mut end: *const wchar_t,
                              mut permset: *mut libc::c_int) -> libc::c_int {
    let mut p: *const wchar_t = 0 as *const wchar_t;
    if start >= end { return 0 as libc::c_int }
    p = start;
    *permset = 0 as libc::c_int;
    while p < end {
        let fresh34 = p;
        p = p.offset(1);
        match *fresh34 {
            114 | 82 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_read}
            119 | 87 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write }
            120 | 88 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_execute }
            45 => { }
            _ => { return 0 as libc::c_int }
        }
    }
    return 1 as libc::c_int;
}
/*
 * Parse a string as a NFS4 ACL permission field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * permission characters, false otherwise
 */
unsafe extern "C" fn is_nfs4_perms_w(mut start: *const wchar_t,
                                     mut end: *const wchar_t,
                                     mut permset: *mut libc::c_int)
 -> libc::c_int {
    let mut p: *const wchar_t = start;
    while p < end {
        let fresh35 = p;
        p = p.offset(1);
        match *fresh35 {
            114 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_read_data }
            119 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write_data }
            120 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_execute }
            112 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_append_data }
            68 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_delete_child }
            100 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_delete}
            97 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_read_attributes}
            65 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write_attributes }
            82 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_read_named_attrs}
            87 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write_named_attrs}
            99 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_read_acl}
            67 => { *permset |=ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write_acl}
            111 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write_owner}
            115 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_synchronize}
            45 => { }
            _ => { return 0 as libc::c_int }
        }
    }
    return 1 as libc::c_int;
}
/*
 * Parse a string as a NFS4 ACL flags field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * flag characters, false otherwise
 */
unsafe extern "C" fn is_nfs4_flags_w(mut start: *const wchar_t,
                                     mut end: *const wchar_t,
                                     mut permset: *mut libc::c_int)
 -> libc::c_int {
    let mut p: *const wchar_t = start;
    while p < end {
        let fresh36 = p;
        p = p.offset(1);
        match *fresh36 {
            102 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_file_inherit}
            100 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_directory_inherit }
            105 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_inherit_only}
            110 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_no_propagate_inherit }
            83 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_successful_access }
            70 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_failed_access }
            73 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_inherited }
            45 => { }
            _ => { return 0 as libc::c_int }
        }
    }
    return 1 as libc::c_int;
}
/*
 * Match "[:whitespace:]*(.*)[:whitespace:]*[:,\n]".  *wp is updated
 * to point to just after the separator.  *start points to the first
 * character of the matched text and *end just after the last
 * character of the matched identifier.  In particular *end - *start
 * is the length of the field body, not including leading or trailing
 * whitespace.
 */
unsafe extern "C" fn next_field_w(mut wp: *mut *const wchar_t,
                                  mut start: *mut *const wchar_t,
                                  mut end: *mut *const wchar_t,
                                  mut sep: *mut wchar_t) {
    /* Skip leading whitespace to find start of field. */
    while **wp == ' ' as i32 || **wp == '\t' as i32 || **wp == '\n' as i32 {
        *wp = (*wp).offset(1)
    }
    *start = *wp;
    /* Scan for the separator. */
    while **wp != '\u{0}' as i32 && **wp != ',' as i32 && **wp != ':' as i32
              && **wp != '\n' as i32 && **wp != '#' as i32 {
        *wp = (*wp).offset(1)
    }
    *sep = **wp;
    /* Locate end of field, trim trailing whitespace if necessary */
    if *wp == *start {
        *end = *wp
    } else {
        *end = (*wp).offset(-(1 as libc::c_int as isize));
        while **end == ' ' as i32 || **end == '\t' as i32 ||
                  **end == '\n' as i32 {
            *end = (*end).offset(-1)
        }
        *end = (*end).offset(1)
    }
    /* Handle in-field comments */
    if *sep == '#' as i32 {
        while **wp != '\u{0}' as i32 && **wp != ',' as i32 &&
                  **wp != '\n' as i32 {
            *wp = (*wp).offset(1)
        }
        *sep = **wp
    }
    /* Adjust scanner location. */
    if **wp != '\u{0}' as i32 { *wp = (*wp).offset(1) };
}
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
/* E.g., access or default */
/* E.g., user/group/other/mask */
/* r/w/x bits */
/* uid/gid for user/group */
/* uname/gname */
/* See acl_next for details. */
/*
 * ACL text parser.
 */
/* wtext */
/* type */
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
    let mut field: [archive_string_temporary_field_2; 6] =
    [archive_string_temporary_field_2{start: 0 as *const libc::c_char,
                     end: 0 as *const libc::c_char,}; 6];
let mut name: archive_string_temporary_field_2 =
    archive_string_temporary_field_2{start: 0 as *const libc::c_char,
                    end: 0 as *const libc::c_char,};
let mut s: *const libc::c_char = 0 as *const libc::c_char;
let mut st: *const libc::c_char = 0 as *const libc::c_char;
let mut numfields: libc::c_int = 0;
let mut fields: libc::c_int = 0;
let mut n: libc::c_int = 0;
let mut r: libc::c_int = 0;
let mut sol: libc::c_int = 0;
let mut ret: libc::c_int = 0;
let mut type_0: libc::c_int = 0;
let mut types: libc::c_int = 0;
let mut tag: libc::c_int = 0;
let mut permset: libc::c_int = 0;
let mut id: libc::c_int = 0;
let mut len: size_t = 0;
let mut sep: libc::c_char = 0;
let mut current_block_4: u64;
match want_type {
    768 => {
        want_type = 0x100 as libc::c_int;
        current_block_4 = 5136372742794658517;
    }
    256 | 512 => { current_block_4 = 5136372742794658517; }
    15360 => {
        numfields = 6 as libc::c_int;
        current_block_4 = 13536709405535804910;
    }
    _ => { return -(30 as libc::c_int) }
}
match current_block_4 {
    5136372742794658517 => { numfields = 5 as libc::c_int }
    _ => { }
}
ret = 0 as libc::c_int;
types = 0 as libc::c_int;
/* Comment, skip entry */
while !text.is_null() && *text as libc::c_int != '\u{0}' as i32 {
    /*
     * Parse the fields out of the next entry,
     * advance 'text' to start of next entry.
     */
    fields = 0 as libc::c_int;
    loop  {
        let mut start: *const libc::c_char = 0 as *const libc::c_char;
        let mut end: *const libc::c_char = 0 as *const libc::c_char;
        next_field(&mut text, &mut start, &mut end, &mut sep);
        if fields < numfields {
            field[fields as usize].start = start;
            field[fields as usize].end = end
        }
        fields += 1;
        if !(sep as libc::c_int == ':' as i32) { break ; }
    }
    /* Set remaining fields to blank. */
    n = fields;
    while n < numfields {
        field[n as usize].end = 0 as *const libc::c_char;
        field[n as usize].start = field[n as usize].end;
        n += 1
    }
    if !field[0 as libc::c_int as usize].start.is_null() &&
           *field[0 as libc::c_int as usize].start as libc::c_int ==
               '#' as i32 {
        continue ;
    }
    n = 0 as libc::c_int;
    sol = 0 as libc::c_int;
    id = -(1 as libc::c_int);
    permset = 0 as libc::c_int;
    name.end = 0 as *const libc::c_char;
    name.start = name.end;
    if want_type !=
           0x400 as libc::c_int | 0x800 as libc::c_int |
               0x1000 as libc::c_int | 0x2000 as libc::c_int {
        /* POSIX.1e ACLs */
        /*
         * Default keyword "default:user::rwx"
         * if found, we have one more field
         *
         * We also support old Solaris extension:
         * "defaultuser::rwx" is the default ACL corresponding
         * to "user::rwx", etc. valid only for first field
         */
        s = field[0 as libc::c_int as usize].start;
        len =
            field[0 as libc::c_int as
                      usize].end.offset_from(field[0 as
                                                                libc::c_int
                                                                as
                                                                usize].start)
                as libc::c_long as size_t;
        if *s as libc::c_int == 'd' as i32 &&
               (len == 1 as libc::c_int as libc::c_ulong ||
                    len >= 7 as libc::c_int as libc::c_ulong &&
                        memcmp_safe(s.offset(1 as libc::c_int as isize) as
                                   *const libc::c_void,
                               b"efault\x00" as *const u8 as
                                   *const libc::c_char as
                                   *const libc::c_void,
                               6 as libc::c_int as libc::c_ulong) ==
                            0 as libc::c_int) {
            type_0 = 0x200 as libc::c_int;
            if len > 7 as libc::c_int as libc::c_ulong {
                field[0 as libc::c_int as usize].start =
                    field[0 as libc::c_int as
                              usize].start.offset(7 as libc::c_int as
                                                      isize)
            } else { n = 1 as libc::c_int }
        } else { type_0 = want_type }
        /* Check for a numeric ID in field n+1 or n+3. */
        isint(field[(n + 1 as libc::c_int) as usize].start,
              field[(n + 1 as libc::c_int) as usize].end, &mut id);
        /* Field n+3 is optional. */
        if id == -(1 as libc::c_int) && fields > n + 3 as libc::c_int {
            isint(field[(n + 3 as libc::c_int) as usize].start,
                  field[(n + 3 as libc::c_int) as usize].end, &mut id);
        }
        tag = 0 as libc::c_int;
        s = field[n as usize].start;
        st = field[n as usize].start.offset(1 as libc::c_int as isize);
        len =
            field[n as
                      usize].end.offset_from(field[n as
                                                                usize].start)
                as libc::c_long as size_t;
        if len == 0 as libc::c_int as libc::c_ulong {
            ret = -(20 as libc::c_int);
            continue ;
        } else {
            match *s as libc::c_int {
                117 => {
                    if len == 1 as libc::c_int as libc::c_ulong ||
                           len == 4 as libc::c_int as libc::c_ulong &&
                           memcmp_safe(st as *const libc::c_void,
                                      b"ser\x00" as *const u8 as
                                          *const libc::c_char as
                                          *const libc::c_void,
                                      3 as libc::c_int as libc::c_ulong)
                                   == 0 as libc::c_int {
                        tag = 10002 as libc::c_int
                    }
                }
                103 => {
                    if len == 1 as libc::c_int as libc::c_ulong ||
                           len == 5 as libc::c_int as libc::c_ulong &&
                           memcmp_safe(st as *const libc::c_void,
                                      b"roup\x00" as *const u8 as
                                          *const libc::c_char as
                                          *const libc::c_void,
                                      4 as libc::c_int as libc::c_ulong)
                                   == 0 as libc::c_int {
                        tag = 10004 as libc::c_int
                    }
                }
                111 => {
                    if len == 1 as libc::c_int as libc::c_ulong ||
                           len == 5 as libc::c_int as libc::c_ulong &&
                           memcmp_safe(st as *const libc::c_void,
                                      b"ther\x00" as *const u8 as
                                          *const libc::c_char as
                                          *const libc::c_void,
                                      4 as libc::c_int as libc::c_ulong)
                                   == 0 as libc::c_int {
                        tag = 10006 as libc::c_int
                    }
                }
                109 => {
                    if len == 1 as libc::c_int as libc::c_ulong ||
                           len == 4 as libc::c_int as libc::c_ulong &&
                           memcmp_safe(st as *const libc::c_void,
                                      b"ask\x00" as *const u8 as
                                          *const libc::c_char as
                                          *const libc::c_void,
                                      3 as libc::c_int as libc::c_ulong)
                                   == 0 as libc::c_int {
                        tag = 10005 as libc::c_int
                    }
                }
                _ => { }
            }
            match tag {
                10006 | 10005 => {
                    if fields == n + 2 as libc::c_int &&
                           field[(n + 1 as libc::c_int) as usize].start <
                               field[(n + 1 as libc::c_int) as usize].end
                           &&
                           ismode(field[(n + 1 as libc::c_int) as
                                            usize].start,
                                  field[(n + 1 as libc::c_int) as
                                            usize].end, &mut permset) != 0
                       {
                        /* This is Solaris-style "other:rwx" */
                        sol = 1 as libc::c_int
                    } else if fields == n + 3 as libc::c_int &&
                                  field[(n + 1 as libc::c_int) as
                                            usize].start <
                                      field[(n + 1 as libc::c_int) as
                                                usize].end {
                        /* Invalid mask or other field */
                        ret = -(20 as libc::c_int);
                        continue ;
                    }
                }
                10002 | 10004 => {
                    if id != -(1 as libc::c_int) ||
                           field[(n + 1 as libc::c_int) as usize].start <
                               field[(n + 1 as libc::c_int) as usize].end
                       {
                        name = field[(n + 1 as libc::c_int) as usize];
                        if tag == 10002 as libc::c_int {
                            tag = 10001 as libc::c_int
                        } else { tag = 10003 as libc::c_int }
                    }
                }
                _ => {
                    /* Invalid tag, skip entry */
                    ret = -(20 as libc::c_int);
                    continue ;
                }
            }
            /*
         * Without "default:" we expect mode in field 3
         * Exception: Solaris other and mask fields
         */
            if permset == 0 as libc::c_int &&
                   ismode(field[(n + 2 as libc::c_int - sol) as
                                    usize].start,
                          field[(n + 2 as libc::c_int - sol) as
                                    usize].end, &mut permset) == 0 {
                /* Invalid mode, skip entry */
                ret = -(20 as libc::c_int);
                continue ;
            }
        }
    } else {
        /* NFS4 ACLs */
        s = field[0 as libc::c_int as usize].start;
        len =
            field[0 as libc::c_int as
                      usize].end.offset_from(field[0 as libc::c_int as usize].start) as libc::c_long as size_t;
        tag = 0 as libc::c_int;
        match len {
            4 => {
                if memcmp_safe(s as *const libc::c_void,
                          b"user\x00" as *const u8 as *const libc::c_char
                              as *const libc::c_void,
                          4 as libc::c_int as libc::c_ulong) ==
                       0 as libc::c_int {
                    tag = 10001 as libc::c_int
                }
            }
            5 => {
                if memcmp_safe(s as *const libc::c_void,
                          b"group\x00" as *const u8 as *const libc::c_char
                              as *const libc::c_void,
                          5 as libc::c_int as libc::c_ulong) ==
                       0 as libc::c_int {
                    tag = 10003 as libc::c_int
                }
            }
            6 => {
                if memcmp_safe(s as *const libc::c_void,
                          b"owner@\x00" as *const u8 as
                              *const libc::c_char as *const libc::c_void,
                          6 as libc::c_int as libc::c_ulong) ==
                       0 as libc::c_int {
                    tag = 10002 as libc::c_int
                } else if memcmp_safe(s as *const libc::c_void,
                                 b"group@\x00" as *const u8 as
                                     *const libc::c_char as
                                     *const libc::c_void,
                                 6 as libc::c_int as libc::c_ulong) ==
                              0 as libc::c_int {
                    tag = 10004 as libc::c_int
                }
            }
            9 => {
                if memcmp_safe(s as *const libc::c_void,
                          b"everyone@\x00" as *const u8 as
                              *const libc::c_char as *const libc::c_void,
                          9 as libc::c_int as libc::c_ulong) ==
                       0 as libc::c_int {
                    tag = 10107 as libc::c_int
                }
            }
            _ => { }
        }
        if tag == 0 as libc::c_int {
            /* Invalid tag, skip entry */
            ret = -(20 as libc::c_int);
            continue ;
        } else {
            if tag == 10001 as libc::c_int || tag == 10003 as libc::c_int
               {
                n = 1 as libc::c_int;
                name = field[1 as libc::c_int as usize];
                isint(name.start, name.end, &mut id);
            } else { n = 0 as libc::c_int }
            if is_nfs4_perms(field[(1 as libc::c_int + n) as usize].start,
                             field[(1 as libc::c_int + n) as usize].end,
                             &mut permset) == 0 {
                /* Invalid NFSv4 perms, skip entry */
                ret = -(20 as libc::c_int);
                continue ;
            } else if is_nfs4_flags(field[(2 as libc::c_int + n) as
                                              usize].start,
                                    field[(2 as libc::c_int + n) as
                                              usize].end, &mut permset) ==
                          0 {
                /* Invalid NFSv4 flags, skip entry */
                ret = -(20 as libc::c_int);
                continue ;
            } else {
                s = field[(3 as libc::c_int + n) as usize].start;
                len =
                    field[(3 as libc::c_int + n) as
                              usize].end.offset_from(field[(3 as libc::c_int + n) as usize].start) as libc::c_long as size_t;
                type_0 = 0 as libc::c_int;
                if len == 4 as libc::c_int as libc::c_ulong {
                    if memcmp_safe(s as *const libc::c_void,
                              b"deny\x00" as *const u8 as
                                  *const libc::c_char as
                                  *const libc::c_void,
                              4 as libc::c_int as libc::c_ulong) ==
                           0 as libc::c_int {
                        type_0 = 0x800 as libc::c_int
                    }
                } else if len == 5 as libc::c_int as libc::c_ulong {
                    if memcmp_safe(s as *const libc::c_void,
                              b"allow\x00" as *const u8 as
                                  *const libc::c_char as
                                  *const libc::c_void,
                              5 as libc::c_int as libc::c_ulong) ==
                           0 as libc::c_int {
                        type_0 = 0x400 as libc::c_int
                    } else if memcmp_safe(s as *const libc::c_void,
                                     b"audit\x00" as *const u8 as
                                         *const libc::c_char as
                                         *const libc::c_void,
                                     5 as libc::c_int as libc::c_ulong) ==
                                  0 as libc::c_int {
                        type_0 = 0x1000 as libc::c_int
                    } else if memcmp_safe(s as *const libc::c_void,  
                                     b"alarm\x00" as *const u8 as
                                         *const libc::c_char as
                                         *const libc::c_void,
                                     5 as libc::c_int as libc::c_ulong) ==
                                  0 as libc::c_int {
                        type_0 = 0x2000 as libc::c_int
                    }
                }
                if type_0 == 0 as libc::c_int {
                    /* Invalid entry type, skip entry */
                    ret = -(20 as libc::c_int);
                    continue ;
                } else {
                    isint(field[(4 as libc::c_int + n) as usize].start,
                          field[(4 as libc::c_int + n) as usize].end,
                          &mut id);
                }
            }
        }
    }
    /* Add entry to the internal list. */
    r =
        archive_acl_add_entry_len_l(acl, type_0, permset, tag, id,
                                    name.start,
                                    name.end.offset_from(name.start)
                                        as libc::c_long as size_t, sc);
    if r < -(20 as libc::c_int) { return r }
    if r != 0 as libc::c_int { ret = -(20 as libc::c_int) }
    types |= type_0
}
/* Reset ACL */
archive_acl_reset(acl, types);
return ret;
}
/*
 * Parse a string to a positive decimal integer.  Returns true if
 * the string is non-empty and consists only of decimal digits,
 * false otherwise.
 */
unsafe extern "C" fn isint(mut start: *const libc::c_char,
                           mut end: *const libc::c_char,
                           mut result: *mut libc::c_int) -> libc::c_int {
    let mut n: libc::c_int = 0 as libc::c_int;
    if start >= end { return 0 as libc::c_int }
    while start < end {
        if (*start as libc::c_int) < '0' as i32 ||
               *start as libc::c_int > '9' as i32 {
            return 0 as libc::c_int
        }
        if n > 2147483647 as libc::c_int / 10 as libc::c_int ||
               n == 2147483647 as libc::c_int / 10 as libc::c_int &&
                   *start as libc::c_int - '0' as i32 >
                       2147483647 as libc::c_int % 10 as libc::c_int {
            n = 2147483647 as libc::c_int
        } else {
            n *= 10 as libc::c_int;
            n += *start as libc::c_int - '0' as i32
        }
        start = start.offset(1)
    }
    *result = n;
    return 1 as libc::c_int;
}
/*
 * Parse a string as a mode field.  Returns true if
 * the string is non-empty and consists only of mode characters,
 * false otherwise.
 */
unsafe extern "C" fn ismode(mut start: *const libc::c_char,
                            mut end: *const libc::c_char,
                            mut permset: *mut libc::c_int) -> libc::c_int {
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    if start >= end { return 0 as libc::c_int }
    p = start;
    *permset = 0 as libc::c_int;
    while p < end {
        let fresh37 = p;
        p = p.offset(1);
        match *fresh37 as libc::c_int {
            114 | 82 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_read}
            119 | 87 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write }
            120 | 88 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_execute }
            45 => { }
            _ => { return 0 as libc::c_int }
        }
    }
    return 1 as libc::c_int;
}
/*
 * Parse a string as a NFS4 ACL permission field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * permission characters, false otherwise
 */
unsafe extern "C" fn is_nfs4_perms(mut start: *const libc::c_char,
                                   mut end: *const libc::c_char,
                                   mut permset: *mut libc::c_int)
 -> libc::c_int {
    let mut p: *const libc::c_char = start;
    while p < end {
        let fresh38 = p;
        p = p.offset(1);
        match *fresh38 as libc::c_int {
            114 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_read_data }
            119 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write_data}
            120 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_execute }
            112 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_append_data}
            68 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_delete_child}
            100 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_delete }
            97 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_read_attributes }
            65 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write_attributes }
            82 => { *permset |=  ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_read_named_attrs }
            87 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write_named_attrs }
            99 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_read_acl}
            67 => { *permset |=ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write_acl }
            111 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_write_owner}
            115 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_synchronize }
            45 => { }
            _ => { return 0 as libc::c_int }
        }
    }
    return 1 as libc::c_int;
}
/*
 * Parse a string as a NFS4 ACL flags field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * flag characters, false otherwise
 */
unsafe extern "C" fn is_nfs4_flags(mut start: *const libc::c_char,
                                   mut end: *const libc::c_char,
                                   mut permset: *mut libc::c_int)
 -> libc::c_int {
    let mut p: *const libc::c_char = start;
    while p < end {
        let fresh39 = p;
        p = p.offset(1);
        match *fresh39 as libc::c_int {
            102 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_file_inherit }
            100 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_directory_inherit }
            105 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_inherit_only }
            110 => { *permset |=ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_no_propagate_inherit }
            83 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_successful_access }
            70 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_failed_access }
            73 => { *permset |= ARCHIVE_ACL_DEFINED_PARAM .archive_entry_acl_entry_inherited}
            45 => { }
            _ => { return 0 as libc::c_int }
        }
    }
    return 1 as libc::c_int;
}
/*
 * Match "[:whitespace:]*(.*)[:whitespace:]*[:,\n]".  *wp is updated
 * to point to just after the separator.  *start points to the first
 * character of the matched text and *end just after the last
 * character of the matched identifier.  In particular *end - *start
 * is the length of the field body, not including leading or trailing
 * whitespace.
 */
unsafe extern "C" fn next_field(mut p: *mut *const libc::c_char,
                                mut start: *mut *const libc::c_char,
                                mut end: *mut *const libc::c_char,
                                mut sep: *mut libc::c_char) {
    /* Skip leading whitespace to find start of field. */
    while **p as libc::c_int == ' ' as i32 ||
              **p as libc::c_int == '\t' as i32 ||
              **p as libc::c_int == '\n' as i32 {
        *p = (*p).offset(1)
    }
    *start = *p;
    /* Scan for the separator. */
    while **p as libc::c_int != '\u{0}' as i32 &&
              **p as libc::c_int != ',' as i32 &&
              **p as libc::c_int != ':' as i32 &&
              **p as libc::c_int != '\n' as i32 &&
              **p as libc::c_int != '#' as i32 {
        *p = (*p).offset(1)
    }
    *sep = **p;
    /* Locate end of field, trim trailing whitespace if necessary */
    if *p == *start {
        *end = *p
    } else {
        *end = (*p).offset(-(1 as libc::c_int as isize));
        while **end as libc::c_int == ' ' as i32 ||
                  **end as libc::c_int == '\t' as i32 ||
                  **end as libc::c_int == '\n' as i32 {
            *end = (*end).offset(-1)
        }
        *end = (*end).offset(1)
    }
    /* Handle in-field comments */
    if *sep as libc::c_int == '#' as i32 {
        while **p as libc::c_int != '\u{0}' as i32 &&
                  **p as libc::c_int != ',' as i32 &&
                  **p as libc::c_int != '\n' as i32 {
            *p = (*p).offset(1)
        }
        *sep = **p
    }
    /* Adjust scanner location. */
    if **p as libc::c_int != '\u{0}' as i32 { *p = (*p).offset(1) };
}
unsafe extern "C" fn run_static_initializers() {
    nfsv4_acl_perm_map_size =
        (::std::mem::size_of::<[nfsv4_acl_perm_map_struct; 14]>() as
             libc::c_ulong).wrapping_div(::std::mem::size_of::<nfsv4_acl_perm_map_struct>()
                                             as libc::c_ulong) as libc::c_int;
    nfsv4_acl_flag_map_size =
        (::std::mem::size_of::<[nfsv4_acl_perm_map_struct; 7]>() as
             libc::c_ulong).wrapping_div(::std::mem::size_of::<nfsv4_acl_perm_map_struct>()
                                             as libc::c_ulong) as libc::c_int
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];