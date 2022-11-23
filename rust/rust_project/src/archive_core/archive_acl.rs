use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

static mut nfsv4_acl_perm_map: [nfsv4_acl_perm_map_struct; 14] = [
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x8 as i32,
            c: 'r' as i32 as u8,
            wc: 'r' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x10 as i32,
            c: 'w' as i32 as u8,
            wc: 'w' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x1 as i32,
            c: 'x' as i32 as u8,
            wc: 'x' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x20 as i32,
            c: 'p' as i32 as u8,
            wc: 'p' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x800 as i32,
            c: 'd' as i32 as u8,
            wc: 'd' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x100 as i32,
            c: 'D' as i32 as u8,
            wc: 'D' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x200 as i32,
            c: 'a' as i32 as u8,
            wc: 'a' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x400 as i32,
            c: 'A' as i32 as u8,
            wc: 'A' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x40 as i32,
            c: 'R' as i32 as u8,
            wc: 'R' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x80 as i32,
            c: 'W' as i32 as u8,
            wc: 'W' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x1000 as i32,
            c: 'c' as i32 as u8,
            wc: 'c' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x2000 as i32,
            c: 'C' as i32 as u8,
            wc: 'C' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x4000 as i32,
            c: 'o' as i32 as u8,
            wc: 'o' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x8000 as i32,
            c: 's' as i32 as u8,
            wc: 's' as wchar_t,
        };
        init
    },
];
// Initialized in run_static_initializers
static mut nfsv4_acl_perm_map_size: i32 = 0;
static mut nfsv4_acl_flag_map: [nfsv4_acl_perm_map_struct; 7] = [
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x2000000 as i32,
            c: 'f' as i32 as u8,
            wc: 'f' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x4000000 as i32,
            c: 'd' as i32 as u8,
            wc: 'd' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x10000000 as i32,
            c: 'i' as i32 as u8,
            wc: 'i' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x8000000 as i32,
            c: 'n' as i32 as u8,
            wc: 'n' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x20000000 as i32,
            c: 'S' as i32 as u8,
            wc: 'S' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x40000000 as i32,
            c: 'F' as i32 as u8,
            wc: 'F' as wchar_t,
        };
        init
    },
    {
        let mut init = nfsv4_acl_perm_map_struct {
            perm: 0x1000000 as i32,
            c: 'I' as i32 as u8,
            wc: 'I' as wchar_t,
        };
        init
    },
];
// Initialized in run_static_initializers
static mut nfsv4_acl_flag_map_size: i32 = 0;

#[no_mangle]
pub unsafe extern "C" fn archive_acl_clear(mut acl: *mut archive_acl) {
    let safe_acl = unsafe { &mut *acl };
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    while !(safe_acl).acl_head.is_null() {
        ap = unsafe { (*(safe_acl.acl_head)).next };
        archive_mstring_clean_safe(unsafe { &mut (*(safe_acl.acl_head)).name });
        free_safe((safe_acl).acl_head as *mut ());
        (safe_acl).acl_head = ap
    }
    free_safe((safe_acl).acl_text_w as *mut ());
    (safe_acl).acl_text_w = 0 as *mut wchar_t;
    free_safe((safe_acl).acl_text as *mut ());
    (safe_acl).acl_text = 0 as *mut u8;
    (safe_acl).acl_p = 0 as *mut archive_acl_entry;
    (safe_acl).acl_types = 0 as i32;
    (safe_acl).acl_state = 0 as i32;
    /* Not counting. */
}

#[no_mangle]
pub unsafe extern "C" fn archive_acl_copy(mut dest: *mut archive_acl, mut src: *mut archive_acl) {
    let safe_dest = unsafe { &mut *dest };
    let safe_src = unsafe { &mut *src };
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut ap2: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    archive_acl_clear(dest);
    (safe_dest).mode = (safe_src).mode;
    ap = (safe_src).acl_head;
    while !ap.is_null() {
        ap2 = unsafe { acl_new_entry(safe_dest, (*ap).type_0, (*ap).permset, (*ap).tag, (*ap).id) };
        if !ap2.is_null() {
            unsafe { archive_mstring_copy_safe(&mut (*ap2).name, &mut (*ap).name) };
        }
        unsafe { ap = (*ap).next }
    }
}

#[no_mangle]
pub unsafe extern "C" fn archive_acl_add_entry(
    mut acl: *mut archive_acl,
    mut type_0: i32,
    mut permset: i32,
    mut tag: i32,
    mut id: i32,
    mut name: *const u8,
) -> i32 {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    if acl_special(acl, type_0, permset, tag) == 0 as i32 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
    }
    ap = acl_new_entry(acl, type_0, permset, tag, id);
    if ap.is_null() {
        /* XXX Error XXX */
        return ARCHIVE_ACL_DEFINED_PARAM.archvie_failed;
    }
    if !name.is_null() && *name as i32 != '\u{0}' as i32 {
        archive_mstring_copy_mbs_safe(&mut (*ap).name, name);
    } else {
        archive_mstring_clean_safe(&mut (*ap).name);
    }
    return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
}

#[no_mangle]
pub unsafe extern "C" fn archive_acl_add_entry_w_len(
    mut acl: *mut archive_acl,
    mut type_0: i32,
    mut permset: i32,
    mut tag: i32,
    mut id: i32,
    mut name: *const wchar_t,
    mut len: size_t,
) -> i32 {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    if acl_special(acl, type_0, permset, tag) == 0 as i32 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
    }
    ap = acl_new_entry(acl, type_0, permset, tag, id);
    if ap.is_null() {
        /* XXX Error XXX */
        return ARCHIVE_ACL_DEFINED_PARAM.archvie_failed;
    }
    if !name.is_null() && *name != '\u{0}' as wchar_t && len > 0 as i32 as u64 {
        archive_mstring_copy_wcs_len_safe(&mut (*ap).name, name, len);
    } else {
        archive_mstring_clean_safe(&mut (*ap).name);
    }
    return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
}
pub unsafe fn archive_acl_add_entry_len_l(
    mut acl: *mut archive_acl,
    mut type_0: i32,
    mut permset: i32,
    mut tag: i32,
    mut id: i32,
    mut name: *const u8,
    mut len: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut r: i32 = 0;
    if acl_special(acl, type_0, permset, tag) == 0 as i32 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
    }
    ap = acl_new_entry(acl, type_0, permset, tag, id);
    if ap.is_null() {
        /* XXX Error XXX */
        return ARCHIVE_ACL_DEFINED_PARAM.archvie_failed;
    }
    if !name.is_null() && *name as i32 != '\u{0}' as i32 && len > 0 as i32 as u64 {
        r = archive_mstring_copy_mbs_len_l_safe(&mut (*ap).name, name, len, sc)
    } else {
        r = 0 as i32;
        archive_mstring_clean_safe(&mut (*ap).name);
    }
    if r == 0 as i32 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
    } else if *__errno_location_safe() == ARCHIVE_ACL_DEFINED_PARAM.enomem as i32 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_fatal;
    } else {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
    };
}
/*
 * If this ACL entry is part of the standard POSIX permissions set,
 * store the permissions in the stat structure and return zero.
 */
fn acl_special(mut acl: *mut archive_acl, mut type_0: i32, mut permset: i32, mut tag: i32) -> i32 {
    let safe_acl = unsafe { &mut *acl };
    if type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
        && permset & !(0o7 as i32) == 0 as i32
    {
        match tag {
            10002 => {
                (safe_acl).mode &= !(0o700 as i32) as u32;
                (safe_acl).mode |= ((permset & 7 as i32) << 6 as i32) as u32;
                return 0 as i32;
            }
            10004 => {
                (safe_acl).mode &= !(0o70 as i32) as u32;
                (safe_acl).mode |= ((permset & 7 as i32) << 3 as i32) as u32;
                return 0 as i32;
            }
            10006 => {
                (safe_acl).mode &= !(0o7 as i32) as u32;
                (safe_acl).mode |= (permset & 7 as i32) as u32;
                return 0 as i32;
            }
            _ => {}
        }
    }
    return 1 as i32;
}
/*
 * Allocate and populate a new ACL entry with everything but the
 * name.
 */
unsafe fn acl_new_entry(
    mut acl: *mut archive_acl,
    mut type_0: i32,
    mut permset: i32,
    mut tag: i32,
    mut id: i32,
) -> *mut archive_acl_entry {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut aq: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    /* Type argument must be a valid NFS4 or POSIX.1e type.
     * The type must agree with anything already set and
     * the permset must be compatible. */
    if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 {
        if (*acl).acl_types & !ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 {
            return 0 as *mut archive_acl_entry;
        }
        if permset
            & !(ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_perms_nfs4
                | ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_inheritance_nfs4)
            != 0
        {
            return 0 as *mut archive_acl_entry;
        }
    } else if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0 {
        if (*acl).acl_types & !ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0 {
            return 0 as *mut archive_acl_entry;
        }
        if permset & !ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_perms_posix1e != 0 {
            return 0 as *mut archive_acl_entry;
        }
    } else {
        return 0 as *mut archive_acl_entry;
    }
    /* Verify the tag is valid and compatible with NFS4 or POSIX.1e. */
    match tag {
        10001 | 10002 | 10003 | 10004 => {}
        10005 | 10006 => {
            /* Tags valid only in POSIX.1e. */
            if type_0 & !ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0 {
                return 0 as *mut archive_acl_entry;
            }
        }
        10107 => {
            /* Tags valid only in NFS4. */
            if type_0 & !(ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4) != 0 {
                return 0 as *mut archive_acl_entry;
            }
        }
        _ => {
            /* No other values are valid. */
            return 0 as *mut archive_acl_entry;
        }
    }
    free_safe((*acl).acl_text_w as *mut ());
    (*acl).acl_text_w = 0 as *mut wchar_t;
    free_safe((*acl).acl_text as *mut ());
    (*acl).acl_text = 0 as *mut u8;
    /*
     * If there's a matching entry already in the list, overwrite it.
     * NFSv4 entries may be repeated and are not overwritten.
     *
     * TODO: compare names of no id is provided (needs more rework)
     */
    ap = (*acl).acl_head;
    aq = 0 as *mut archive_acl_entry;
    while !ap.is_null() {
        if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 == 0 as i32
            && (*ap).type_0 == type_0
            && (*ap).tag == tag
            && (*ap).id == id
        {
            if id != -(1 as i32)
                || tag != ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    && tag != ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
            {
                (*ap).permset = permset;
                return ap;
            }
        }
        aq = ap;
        ap = (*ap).next
    }
    /* Add a new entry to the end of the list. */
    ap = calloc(
        1 as i32 as u64,
        ::std::mem::size_of::<archive_acl_entry>() as u64,
    ) as *mut archive_acl_entry;
    if ap.is_null() {
        return 0 as *mut archive_acl_entry;
    }
    if aq.is_null() {
        (*acl).acl_head = ap
    } else {
        (*aq).next = ap
    }
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
pub unsafe extern "C" fn archive_acl_count(mut acl: *mut archive_acl, mut want_type: i32) -> i32 {
    let mut count: i32 = 0;
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    count = 0 as i32;
    ap = (*acl).acl_head;
    while !ap.is_null() {
        if (*ap).type_0 & want_type != 0 as i32 {
            count += 1
        }
        ap = (*ap).next
    }
    if count > 0 as i32
        && want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 as i32
    {
        count += 3 as i32
    }
    return count;
}
/*
 * Return a bitmask of stored ACL types in an ACL list
 */

#[no_mangle]
pub unsafe extern "C" fn archive_acl_types(mut acl: *mut archive_acl) -> i32 {
    return (*acl).acl_types;
}
/*
 * Prepare for reading entries from the ACL data.  Returns a count
 * of entries matching "want_type", or zero if there are no
 * non-extended ACL entries of that type.
 */

#[no_mangle]
pub unsafe extern "C" fn archive_acl_reset(mut acl: *mut archive_acl, mut want_type: i32) -> i32 {
    let safe_acl = unsafe { &mut *acl };
    let mut count: i32 = 0;
    let mut cutoff: i32 = 0;
    count = unsafe { archive_acl_count(safe_acl, want_type) };
    /*
     * If the only entries are the three standard ones,
     * then don't return any ACL data.  (In this case,
     * client can just use chmod(2) to set permissions.)
     */
    if want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 as i32 {
        cutoff = 3 as i32
    } else {
        cutoff = 0 as i32
    }
    if count > cutoff {
        (safe_acl).acl_state = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj as i32
    } else {
        (safe_acl).acl_state = 0 as i32
    }
    (safe_acl).acl_p = (safe_acl).acl_head;
    return count;
}
/*
 * Return the next ACL entry in the list.  Fake entries for the
 * standard permissions and include them in the returned list.
 */

#[no_mangle]
pub unsafe extern "C" fn archive_acl_next(
    mut a: *mut archive,
    mut acl: *mut archive_acl,
    mut want_type: i32,
    mut type_0: *mut i32,
    mut permset: *mut i32,
    mut tag: *mut i32,
    mut id: *mut i32,
    mut name: *mut *const u8,
) -> i32 {
    *name = 0 as *const u8;
    *id = -(1 as i32);
    /*
     * The acl_state is either zero (no entries available), -1
     * (reading from list), or an entry type (retrieve that type
     * from ae_stat.aest_mode).
     */
    if (*acl).acl_state == 0 as i32 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
    }
    /* The first three access entries are special. */
    if want_type & 0x100 as i32 != 0 as i32 {
        match (*acl).acl_state {
            10002 => {
                *permset = ((*acl).mode >> 6 as i32 & 7 as i32 as u32) as i32;
                *type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access;
                *tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj;
                (*acl).acl_state = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj;
                return 0 as i32;
            }
            10004 => {
                *permset = ((*acl).mode >> 3 as i32 & 7 as i32 as u32) as i32;
                *type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access;
                *tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj;
                (*acl).acl_state = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other;
                return 0 as i32;
            }
            10006 => {
                *permset = ((*acl).mode & 7 as i32 as u32) as i32;
                *type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access;
                *tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other;
                (*acl).acl_state = -(1 as i32);
                (*acl).acl_p = (*acl).acl_head;
                return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
            }
            _ => {}
        }
    }
    while !(*acl).acl_p.is_null() && (*(*acl).acl_p).type_0 & want_type == 0 as i32 {
        (*acl).acl_p = (*(*acl).acl_p).next
    }
    if (*acl).acl_p.is_null() {
        (*acl).acl_state = 0 as i32;
        *type_0 = 0 as i32;
        *permset = 0 as i32;
        *tag = 0 as i32;
        *id = -(1 as i32);
        *name = 0 as *const u8;
        return ARCHIVE_ACL_DEFINED_PARAM.archive_eof;
        /* End of ACL entries. */
    }
    *type_0 = (*(*acl).acl_p).type_0;
    *permset = (*(*acl).acl_p).permset;
    *tag = (*(*acl).acl_p).tag;
    *id = (*(*acl).acl_p).id;
    if archive_mstring_get_mbs_safe(a, &mut (*(*acl).acl_p).name, name) != 0 as i32 {
        if *__errno_location_safe() == ARCHIVE_ACL_DEFINED_PARAM.enomem {
            return ARCHIVE_ACL_DEFINED_PARAM.archive_fatal;
        }
        *name = 0 as *const u8
    }
    (*acl).acl_p = (*(*acl).acl_p).next;
    return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
}
/*
 * Determine what type of ACL do we want
 */
fn archive_acl_text_want_type(mut acl: *mut archive_acl, mut flags: i32) -> i32 {
    let safe_acl = unsafe { &mut *acl };
    let mut want_type: i32 = 0;
    /* Check if ACL is NFSv4 */
    if (safe_acl).acl_types & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 as i32 {
        /* NFSv4 should never mix with POSIX.1e */
        if (safe_acl).acl_types & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e
            != 0 as i32
        {
            return 0 as i32;
        } else {
            return ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4;
        }
    }
    /* Now deal with POSIX.1e ACLs */
    want_type = 0 as i32;
    if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 as i32 {
        want_type |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
    }
    if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default != 0 as i32 {
        want_type |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default
    }
    /* By default we want both access and default ACLs */
    if want_type == 0 as i32 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e;
    }
    return want_type;
}
/*
 * Calculate ACL text string length
 */
unsafe fn archive_acl_text_len(
    mut acl: *mut archive_acl,
    mut want_type: i32,
    mut flags: i32,
    mut wide: i32,
    mut a: *mut archive,
    mut sc: *mut archive_string_conv,
) -> ssize_t {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut name: *const u8 = 0 as *const u8;
    let mut wname: *const wchar_t = 0 as *const wchar_t;
    let mut count: i32 = 0;
    let mut idlen: i32 = 0;
    let mut tmp: i32 = 0;
    let mut r: i32 = 0;
    let mut length: ssize_t = 0;
    let mut len: size_t = 0;
    count = 0 as i32;
    length = 0 as i32 as ssize_t;
    ap = (*acl).acl_head;
    while !ap.is_null() {
        if !((*ap).type_0 & want_type == 0 as i32) {
            /*
             * Filemode-mapping ACL entries are stored exclusively in
             * ap->mode so they should not be in the list
             */
            if !((*ap).type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
                && ((*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                    || (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                    || (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other))
            {
                count += 1; /* "default:" */
                if want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default != 0 as i32
                    && (*ap).type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default
                        != 0 as i32
                {
                    length += 8 as i32 as i64
                } /* "owner@" */
                let mut current_block_10: u64; /* "group@" */
                match (*ap).tag {
                    10002 => {
                        if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 {
                            length += 6 as i32 as i64; /* "everyone@" */
                            current_block_10 = 2719512138335094285;
                        } else {
                            current_block_10 = 12183639489562779793;
                        }
                    }
                    10001 | 10005 => {
                        current_block_10 = 12183639489562779793;
                    }
                    10004 => {
                        if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 {
                            length += 6 as i32 as i64;
                            current_block_10 = 2719512138335094285;
                        } else {
                            current_block_10 = 11171774058386854943;
                        }
                    }
                    10003 | 10006 => {
                        current_block_10 = 11171774058386854943;
                    }
                    10107 => {
                        length += 9 as i32 as i64;
                        current_block_10 = 2719512138335094285;
                    }
                    _ => {
                        current_block_10 = 2719512138335094285;
                    }
                }
                match current_block_10 {
                    12183639489562779793 =>
                    /* FALLTHROUGH */
                    {
                        length += 4 as i32 as i64
                    }
                    11171774058386854943 =>
                    /* "user", "mask" */
                    /* FALLTHROUGH */
                    {
                        length += 5 as i32 as i64
                    }
                    _ => {}
                } /* "group", "other" */
                length += 1 as i32 as i64; /* colon after tag */
                if (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    || (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group as i32
                {
                    if wide != 0 {
                        r = archive_mstring_get_wcs_safe(a, &mut (*ap).name, &mut wname); /* 2nd colon empty user,group or other */
                        if r == 0 as i32 && !wname.is_null() {
                            length =
                                (length as u64).wrapping_add(wcslen(wname)) as ssize_t as ssize_t
                        } else if r < 0 as i32
                            && *__errno_location_safe() == ARCHIVE_ACL_DEFINED_PARAM.enomem
                        {
                            return 0 as i32 as ssize_t;
                        } else {
                            length = (length as u64).wrapping_add(
                                (::std::mem::size_of::<uid_t>() as u64)
                                    .wrapping_mul(3 as i32 as u64)
                                    .wrapping_add(1 as i32 as u64),
                            ) as ssize_t as ssize_t
                        }
                    } else {
                        r = archive_mstring_get_mbs_l_safe(
                            a,
                            &mut (*ap).name,
                            &mut name,
                            &mut len,
                            sc,
                        );
                        if r != 0 as i32 {
                            return 0 as i32 as ssize_t;
                        }
                        if len > 0 as i32 as u64 && !name.is_null() {
                            length = (length as u64).wrapping_add(len) as ssize_t as ssize_t
                        } else {
                            length = (length as u64).wrapping_add(
                                (::std::mem::size_of::<uid_t>() as u64)
                                    .wrapping_mul(3 as i32 as u64)
                                    .wrapping_add(1 as i32 as u64),
                            ) as ssize_t as ssize_t
                        }
                    }
                    length += 1 as i32 as i64
                    /* colon after user or group name */
                } else if want_type != ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 {
                    length += 1 as i32 as i64
                }
                if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_solaris != 0 as i32
                    && want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e
                        != 0 as i32
                    && ((*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other
                        || (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask)
                {
                    /* Solaris has no colon after other: and mask: */
                    length = length - 1 as i32 as i64
                } /* rwx */
                if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 {
                    /* rwxpdDaARWcCos:fdinSFI:deny */
                    length += 27 as i32 as i64;
                    if (*ap).type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_deny
                        == 0 as i32
                    {
                        length += 1 as i32 as i64
                    }
                    /* allow, alarm, audit */
                } else {
                    length += 3 as i32 as i64
                } /* colon */
                if ((*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    || (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group)
                    && flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_extra_id
                        != 0 as i32
                {
                    length += 1 as i32 as i64;
                    /* ID digit count */
                    idlen = 1 as i32;
                    tmp = (*ap).id;
                    while tmp > 9 as i32 {
                        tmp = tmp / 10 as i32;
                        idlen += 1
                    }
                    length += idlen as i64
                }
                length += 1
            }
        }
        ap = (*ap).next
        /* entry separator */
    }
    /* Add filemode-mapping access entries to the length */
    if want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 as i32 {
        if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_solaris != 0 as i32 {
            /* "user::rwx\ngroup::rwx\nother:rwx\n" */
            length += 31 as i32 as i64
        } else {
            /* "user::rwx\ngroup::rwx\nother::rwx\n" */
            length += 32 as i32 as i64
        }
    } else if count == 0 as i32 {
        return 0 as i32 as ssize_t;
    }
    /* The terminating character is included in count */
    return length;
}
/*
 * Generate a wide text version of the ACL. The flags parameter controls
 * the type and style of the generated ACL.
 */
#[no_mangle]
pub unsafe extern "C" fn archive_acl_to_text_w(
    mut acl: *mut archive_acl,
    mut text_len: *mut ssize_t,
    mut flags: i32,
    mut a: *mut archive,
) -> *mut wchar_t {
    let mut count: i32 = 0;
    let mut length: ssize_t = 0;
    let mut len: size_t = 0;
    let mut wname: *const wchar_t = 0 as *const wchar_t;
    let mut prefix: *const wchar_t = 0 as *const wchar_t;
    let mut separator: wchar_t = 0;
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut id: i32 = 0;
    let mut r: i32 = 0;
    let mut want_type: i32 = 0;
    let mut wp: *mut wchar_t = 0 as *mut wchar_t;
    let mut ws: *mut wchar_t = 0 as *mut wchar_t;
    want_type = archive_acl_text_want_type(acl, flags);
    /* Both NFSv4 and POSIX.1 types found */
    if want_type == 0 as i32 {
        return 0 as *mut wchar_t;
    }
    if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e {
        flags |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_mark_default
    }
    length = archive_acl_text_len(
        acl,
        want_type,
        flags,
        1 as i32,
        a,
        0 as *mut archive_string_conv,
    );
    if length == 0 as i32 as i64 {
        return 0 as *mut wchar_t;
    }
    if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_separator_comma != 0 {
        separator = ',' as wchar_t
    } else {
        separator = '\n' as wchar_t
    }
    /* Now, allocate the string and actually populate it. */
    ws = malloc_safe((length as u64).wrapping_mul(::std::mem::size_of::<wchar_t>() as u64))
        as *mut wchar_t;
    wp = ws;
    if wp.is_null() {
        if *__errno_location_safe() == ARCHIVE_ACL_DEFINED_PARAM.enomem {
            __archive_errx_safe(1 as i32, "No memory\x00");
        }
        return 0 as *mut wchar_t;
    }
    count = 0 as i32;
    if want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 as i32 {
        append_entry_w(
            &mut wp,
            0 as *const wchar_t,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj,
            flags,
            0 as *const wchar_t,
            ((*acl).mode & 0o700 as i32 as u32) as i32,
            -(1 as i32),
        );
        let fresh0 = wp;
        wp = wp.offset(1);
        *fresh0 = separator;
        append_entry_w(
            &mut wp,
            0 as *const wchar_t,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj,
            flags,
            0 as *const wchar_t,
            ((*acl).mode & 0o70 as i32 as u32) as i32,
            -(1 as i32),
        );
        let fresh1 = wp;
        wp = wp.offset(1);
        *fresh1 = separator;
        append_entry_w(
            &mut wp,
            0 as *const wchar_t,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other,
            flags,
            0 as *const wchar_t,
            ((*acl).mode & 0o7 as i32 as u32) as i32,
            -(1 as i32),
        );
        count += 3 as i32
    }
    ap = (*acl).acl_head;
    while !ap.is_null() {
        if !((*ap).type_0 & want_type == 0 as i32) {
            /*
             * Filemode-mapping ACL entries are stored exclusively in
             * ap->mode so they should not be in the list
             */
            if !((*ap).type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
                && ((*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                    || (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                    || (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other))
            {
                if (*ap).type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default
                    && flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_mark_default
                        != 0 as i32
                {
                    prefix = wchar::wchz!("default:").as_ptr();
                } else {
                    prefix = 0 as *const wchar_t
                }
                r = archive_mstring_get_wcs_safe(a, &mut (*ap).name, &mut wname);
                if r == 0 as i32 {
                    if count > 0 as i32 {
                        let fresh2 = wp;
                        wp = wp.offset(1);
                        *fresh2 = separator
                    }
                    if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_extra_id != 0 {
                        id = (*ap).id
                    } else {
                        id = -(1 as i32)
                    }
                    append_entry_w(
                        &mut wp,
                        prefix,
                        (*ap).type_0,
                        (*ap).tag,
                        flags,
                        wname,
                        (*ap).permset,
                        id,
                    );
                    count += 1
                } else if r < 0 as i32
                    && *__errno_location_safe() == ARCHIVE_ACL_DEFINED_PARAM.enomem
                {
                    free_safe(ws as *mut ());
                    return 0 as *mut wchar_t;
                }
            }
        }
        ap = (*ap).next
    }
    /* Add terminating character */
    let fresh3 = wp;
    wp = wp.offset(1);
    *fresh3 = '\u{0}' as wchar_t;
    len = wcslen(ws);
    if len as ssize_t > length - 1 as i32 as i64 {
        __archive_errx_safe(1 as i32, "Buffer overrun\x00");
    }
    if !text_len.is_null() {
        *text_len = len as ssize_t
    }
    return ws;
}
unsafe fn append_id_w(mut wp: *mut *mut wchar_t, mut id: i32) {
    if id < 0 as i32 {
        id = 0 as i32
    }
    if id > 9 as i32 {
        append_id_w(wp, id / 10 as i32);
    }
    let fresh4 = *wp;
    *wp = (*wp).offset(1);
    *fresh4 = wchar::wchz!("0123456789")[(id % 10 as i32) as usize];
}
pub unsafe fn append_entry_w(
    mut wp: *mut *mut wchar_t,
    mut prefix: *const wchar_t,
    mut type_0: i32,
    mut tag: i32,
    mut flags: i32,
    mut wname: *const wchar_t,
    mut perm: i32,
    mut id: i32,
) {
    let mut i: i32 = 0;
    if !prefix.is_null() {
        wcscpy_safe(*wp, prefix);
        *wp = (*wp).offset(wcslen(*wp) as isize)
    }
    let mut current_block_20: u64;
    match tag {
        10002 => {
            wname = 0 as *const wchar_t;
            id = -(1 as i32);
            if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 as i32 {
                wcscpy_safe(*wp, wchar::wchz!("owner@").as_ptr());
                current_block_20 = 14818589718467733107;
            } else {
                current_block_20 = 13059761959729012537;
            }
        }
        10001 => {
            current_block_20 = 13059761959729012537;
        }
        10004 => {
            wname = 0 as *const wchar_t;
            id = -(1 as i32);
            if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 as i32 {
                wcscpy_safe(*wp, wchar::wchz!("group@").as_ptr());
                current_block_20 = 14818589718467733107;
            } else {
                current_block_20 = 1203188319497562805;
            }
        }
        10003 => {
            current_block_20 = 1203188319497562805;
        }
        10005 => {
            wcscpy_safe(*wp, wchar::wchz!("mask").as_ptr());
            wname = 0 as *const wchar_t;
            id = -(1 as i32);
            current_block_20 = 14818589718467733107;
        }
        10006 => {
            wcscpy_safe(*wp, wchar::wchz!("other").as_ptr());
            wname = 0 as *const wchar_t;
            id = -(1 as i32);
            current_block_20 = 14818589718467733107;
        }
        10107 => {
            wcscpy_safe(*wp, wchar::wchz!("everyone@").as_ptr());
            wname = 0 as *const wchar_t;
            id = -(1 as i32);
            current_block_20 = 14818589718467733107;
        }
        _ => {
            current_block_20 = 14818589718467733107;
        }
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
        _ => {}
    }
    *wp = (*wp).offset(wcslen(*wp) as isize);
    let fresh5 = *wp;
    *wp = (*wp).offset(1);
    *fresh5 = ':' as wchar_t;
    if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0 as i32
        || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
        || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
    {
        if !wname.is_null() {
            wcscpy_safe(*wp, wname);
            *wp = (*wp).offset(wcslen(*wp) as isize)
        } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
            || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
        {
            append_id_w(wp, id);
            if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 == 0 as i32 {
                id = -(1 as i32)
            }
        }
        /* Solaris style has no second colon after other and mask */
        if (flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_solaris == 0 as i32)
            || tag != ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other
                && tag != ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask
        {
            let fresh6 = *wp;
            *wp = (*wp).offset(1);
            *fresh6 = ':' as wchar_t
        }
    }
    if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0 as i32 {
        /* POSIX.1e ACL perms */
        let fresh7 = *wp;
        *wp = (*wp).offset(1);
        *fresh7 = if perm & 0o444 as i32 != 0 {
            'r' as wchar_t
        } else {
            '-' as wchar_t
        };
        let fresh8 = *wp;
        *wp = (*wp).offset(1);
        *fresh8 = if perm & 0o222 as i32 != 0 {
            'w' as wchar_t
        } else {
            '-' as wchar_t
        };
        let fresh9 = *wp;
        *wp = (*wp).offset(1);
        *fresh9 = if perm & 0o111 as i32 != 0 {
            'x' as wchar_t
        } else {
            '-' as wchar_t
        }
    } else {
        /* NFSv4 ACL perms */
        i = 0 as i32;
        while i < nfsv4_acl_perm_map_size {
            if perm & nfsv4_acl_perm_map[i as usize].perm != 0 {
                let fresh10 = *wp;
                *wp = (*wp).offset(1);
                *fresh10 = nfsv4_acl_perm_map[i as usize].wc
            } else if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_compact == 0 as i32
            {
                let fresh11 = *wp;
                *wp = (*wp).offset(1);
                *fresh11 = '-' as wchar_t
            }
            i += 1
        }
        let fresh12 = *wp;
        *wp = (*wp).offset(1);
        *fresh12 = ':' as wchar_t;
        i = 0 as i32;
        while i < nfsv4_acl_flag_map_size {
            if perm & nfsv4_acl_flag_map[i as usize].perm != 0 {
                let fresh13 = *wp;
                *wp = (*wp).offset(1);
                *fresh13 = nfsv4_acl_flag_map[i as usize].wc
            } else if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_compact == 0 as i32
            {
                let fresh14 = *wp;
                *wp = (*wp).offset(1);
                *fresh14 = '-' as wchar_t
            }
            i += 1
        }
        let fresh15 = *wp;
        *wp = (*wp).offset(1);
        *fresh15 = ':' as wchar_t;
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
            _ => {}
        }
        *wp = (*wp).offset(wcslen_safe(*wp) as isize)
    }
    if id != -(1 as i32) {
        let fresh16 = *wp;
        *wp = (*wp).offset(1);
        *fresh16 = ':' as wchar_t;
        append_id_w(wp, id);
    };
}
/*
 * Generate a text version of the ACL. The flags parameter controls
 * the type and style of the generated ACL.
 */

#[no_mangle]
pub unsafe extern "C" fn archive_acl_to_text_l(
    mut acl: *mut archive_acl,
    mut text_len: *mut ssize_t,
    mut flags: i32,
    mut sc: *mut archive_string_conv,
) -> *mut u8 {
    let mut count: i32 = 0;
    let mut length: ssize_t = 0;
    let mut len: size_t = 0;
    let mut name: *const u8 = 0 as *const u8;
    let mut prefix: *const u8 = 0 as *const u8;
    let mut separator: u8 = 0;
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut id: i32 = 0;
    let mut r: i32 = 0;
    let mut want_type: i32 = 0;
    let mut p: *mut u8 = 0 as *mut u8;
    let mut s: *mut u8 = 0 as *mut u8;
    want_type = archive_acl_text_want_type(acl, flags);
    /* Both NFSv4 and POSIX.1 types found */
    if want_type == 0 as i32 {
        return 0 as *mut u8;
    }
    if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e {
        flags |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_mark_default
    }
    length = archive_acl_text_len(acl, want_type, flags, 0 as i32, 0 as *mut archive, sc);
    if length == 0 as i32 as i64 {
        return 0 as *mut u8;
    }
    if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_separator_comma != 0 {
        separator = ',' as i32 as u8
    } else {
        separator = '\n' as i32 as u8
    }
    /* Now, allocate the string and actually populate it. */
    s = malloc_safe((length as u64).wrapping_mul(::std::mem::size_of::<u8>() as u64)) as *mut u8;
    p = s;
    if p.is_null() {
        if *__errno_location_safe() == ARCHIVE_ACL_DEFINED_PARAM.enomem {
            __archive_errx_safe(1 as i32, "No memory\x00");
        }
        return 0 as *mut u8;
    }
    count = 0 as i32;
    if want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 as i32 {
        append_entry(
            &mut p,
            0 as *const u8,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj,
            flags,
            0 as *const u8,
            ((*acl).mode & 0o700 as i32 as u32) as i32,
            -(1 as i32),
        );
        let fresh17 = p;
        p = p.offset(1);
        *fresh17 = separator;
        append_entry(
            &mut p,
            0 as *const u8,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj,
            flags,
            0 as *const u8,
            ((*acl).mode & 0o70 as i32 as u32) as i32,
            -(1 as i32),
        );
        let fresh18 = p;
        p = p.offset(1);
        *fresh18 = separator;
        append_entry(
            &mut p,
            0 as *const u8,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
            ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other,
            flags,
            0 as *const u8,
            ((*acl).mode & 0o7 as i32 as u32) as i32,
            -(1 as i32),
        );
        count += 3 as i32
    }
    ap = (*acl).acl_head;
    while !ap.is_null() {
        if !((*ap).type_0 & want_type == 0 as i32) {
            /*
             * Filemode-mapping ACL entries are stored exclusively in
             * ap->mode so they should not be in the list
             */
            if !((*ap).type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
                && ((*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                    || (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                    || (*ap).tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other))
            {
                if (*ap).type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default
                    && flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_mark_default
                        != 0 as i32
                {
                    prefix = b"default:\x00" as *const u8
                } else {
                    prefix = 0 as *const u8
                }
                r = archive_mstring_get_mbs_l_safe(
                    0 as *mut archive,
                    &mut (*ap).name,
                    &mut name,
                    &mut len,
                    sc,
                );
                if r != 0 as i32 {
                    free_safe(s as *mut ());
                    return 0 as *mut u8;
                }
                if count > 0 as i32 {
                    let fresh19 = p;
                    p = p.offset(1);
                    *fresh19 = separator
                }
                if name.is_null()
                    || flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_extra_id != 0
                {
                    id = (*ap).id
                } else {
                    id = -(1 as i32)
                }
                append_entry(
                    &mut p,
                    prefix,
                    (*ap).type_0,
                    (*ap).tag,
                    flags,
                    name,
                    (*ap).permset,
                    id,
                );
                count += 1
            }
        }
        ap = (*ap).next
    }
    /* Add terminating character */
    let fresh20 = p;
    p = p.offset(1);
    *fresh20 = '\u{0}' as i32 as u8;
    len = strlen_safe(s);
    if len as ssize_t > length - 1 as i32 as i64 {
        __archive_errx_safe(1 as i32, "Buffer overrun\x00");
    }
    if !text_len.is_null() {
        *text_len = len as ssize_t
    }
    return s;
}
unsafe extern "C" fn append_id(mut p: *mut *mut u8, mut id: i32) {
    if id < 0 as i32 {
        id = 0 as i32
    }
    if id > 9 as i32 {
        append_id(p, id / 10 as i32);
    }
    let fresh21 = *p;
    *p = (*p).offset(1);
    *fresh21 = (*::std::mem::transmute::<&[u8; 11], &[u8; 11]>(b"0123456789\x00"))
        [(id % 10 as i32) as usize];
}
unsafe fn append_entry(
    mut p: *mut *mut u8,
    mut prefix: *const u8,
    mut type_0: i32,
    mut tag: i32,
    mut flags: i32,
    mut name: *const u8,
    mut perm: i32,
    mut id: i32,
) {
    let mut i: i32 = 0;
    if !prefix.is_null() {
        strcpy_safe(*p, prefix);
        *p = (*p).offset(strlen_safe(*p) as isize)
    }
    let mut current_block_20: u64;
    match tag {
        10002 => {
            name = 0 as *const u8;
            id = -(1 as i32);
            if type_0 & (0x400 as i32 | 0x800 as i32 | 0x1000 as i32 | 0x2000 as i32) != 0 as i32 {
                strcpy_safe(*p, b"owner@\x00" as *const u8);
                current_block_20 = 14818589718467733107;
            } else {
                current_block_20 = 4317932568550761545;
            }
        }
        10001 => {
            current_block_20 = 4317932568550761545;
        }
        10004 => {
            name = 0 as *const u8;
            id = -(1 as i32);
            if type_0 & (0x400 as i32 | 0x800 as i32 | 0x1000 as i32 | 0x2000 as i32) != 0 as i32 {
                strcpy_safe(*p, b"group@\x00" as *const u8);
                current_block_20 = 14818589718467733107;
            } else {
                current_block_20 = 8114179180390253173;
            }
        }
        10003 => {
            current_block_20 = 8114179180390253173;
        }
        10005 => {
            strcpy_safe(*p, b"mask\x00" as *const u8);
            name = 0 as *const u8;
            id = -(1 as i32);
            current_block_20 = 14818589718467733107;
        }
        10006 => {
            strcpy_safe(*p, b"other\x00" as *const u8);
            name = 0 as *const u8;
            id = -(1 as i32);
            current_block_20 = 14818589718467733107;
        }
        10107 => {
            strcpy_safe(*p, b"everyone@\x00" as *const u8);
            name = 0 as *const u8;
            id = -(1 as i32);
            current_block_20 = 14818589718467733107;
        }
        _ => {
            current_block_20 = 14818589718467733107;
        }
    }
    match current_block_20 {
        4317932568550761545 =>
        /* FALLTHROUGH */
        {
            strcpy_safe(*p, b"user\x00" as *const u8);
        }
        8114179180390253173 =>
        /* FALLTHROUGH */
        {
            strcpy_safe(*p, b"group\x00" as *const u8);
        }
        _ => {}
    }
    *p = (*p).offset(strlen_safe(*p) as isize);
    let fresh22 = *p;
    *p = (*p).offset(1);
    *fresh22 = ':' as i32 as u8;
    if type_0 & (0x100 as i32 | 0x200 as i32) != 0 as i32
        || tag == 10001 as i32
        || tag == 10003 as i32
    {
        if !name.is_null() {
            strcpy_safe(*p, name);
            *p = (*p).offset(strlen_safe(*p) as isize)
        } else if tag == 10001 as i32 || tag == 10003 as i32 {
            append_id(p, id);
            if type_0 & (0x400 as i32 | 0x800 as i32 | 0x1000 as i32 | 0x2000 as i32) == 0 as i32 {
                id = -(1 as i32)
            }
        }
        /* Solaris style has no second colon after other and mask */
        if flags & 0x4 as i32 == 0 as i32 || tag != 10006 as i32 && tag != 10005 as i32 {
            let fresh23 = *p;
            *p = (*p).offset(1);
            *fresh23 = ':' as i32 as u8
        }
    }
    if type_0 & (0x100 as i32 | 0x200 as i32) != 0 as i32 {
        /* POSIX.1e ACL perms */
        let fresh24 = *p;
        *p = (*p).offset(1);
        *fresh24 = if perm & 0o444 as i32 != 0 {
            'r' as i32
        } else {
            '-' as i32
        } as u8;
        let fresh25 = *p;
        *p = (*p).offset(1);
        *fresh25 = if perm & 0o222 as i32 != 0 {
            'w' as i32
        } else {
            '-' as i32
        } as u8;
        let fresh26 = *p;
        *p = (*p).offset(1);
        *fresh26 = if perm & 0o111 as i32 != 0 {
            'x' as i32
        } else {
            '-' as i32
        } as u8
    } else {
        /* NFSv4 ACL perms */
        i = 0 as i32;
        while i < nfsv4_acl_perm_map_size {
            if perm & nfsv4_acl_perm_map[i as usize].perm != 0 {
                let fresh27 = *p;
                *p = (*p).offset(1);
                *fresh27 = nfsv4_acl_perm_map[i as usize].c
            } else if flags & 0x10 as i32 == 0 as i32 {
                let fresh28 = *p;
                *p = (*p).offset(1);
                *fresh28 = '-' as i32 as u8
            }
            i += 1
        }
        let fresh29 = *p;
        *p = (*p).offset(1);
        *fresh29 = ':' as i32 as u8;
        i = 0 as i32;
        while i < nfsv4_acl_flag_map_size {
            if perm & nfsv4_acl_flag_map[i as usize].perm != 0 {
                let fresh30 = *p;
                *p = (*p).offset(1);
                *fresh30 = nfsv4_acl_flag_map[i as usize].c
            } else if flags & 0x10 as i32 == 0 as i32 {
                let fresh31 = *p;
                *p = (*p).offset(1);
                *fresh31 = '-' as i32 as u8
            }
            i += 1
        }
        let fresh32 = *p;
        *p = (*p).offset(1);
        *fresh32 = ':' as i32 as u8;
        match type_0 {
            1024 => {
                strcpy_safe(*p, b"allow\x00" as *const u8);
            }
            2048 => {
                strcpy_safe(*p, b"deny\x00" as *const u8);
            }
            4096 => {
                strcpy_safe(*p, b"audit\x00" as *const u8);
            }
            8192 => {
                strcpy_safe(*p, b"alarm\x00" as *const u8);
            }
            _ => {}
        }
        *p = (*p).offset(strlen_safe(*p) as isize)
    }
    if id != -(1 as i32) {
        let fresh33 = *p;
        *p = (*p).offset(1);
        *fresh33 = ':' as i32 as u8;
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
pub unsafe extern "C" fn archive_acl_from_text_w(
    mut acl: *mut archive_acl,
    mut text: *const wchar_t,
    mut want_type: i32,
) -> i32 {
    let mut field: [archive_string_temporary_field_1; 6] = [archive_string_temporary_field_1 {
        start: 0 as *const wchar_t,
        end: 0 as *const wchar_t,
    }; 6];
    let mut name: archive_string_temporary_field_1 = archive_string_temporary_field_1 {
        start: 0 as *const wchar_t,
        end: 0 as *const wchar_t,
    };
    let mut s: *const wchar_t = 0 as *const wchar_t;
    let mut st: *const wchar_t = 0 as *const wchar_t;
    let mut numfields: i32 = 0;
    let mut fields: i32 = 0;
    let mut n: i32 = 0;
    let mut r: i32 = 0;
    let mut sol: i32 = 0;
    let mut ret: i32 = 0;
    let mut type_0: i32 = 0;
    let mut types: i32 = 0;
    let mut tag: i32 = 0;
    let mut permset: i32 = 0;
    let mut id: i32 = 0;
    let mut len: size_t = 0;
    let mut sep: wchar_t = 0;
    ret = 0 as i32;
    types = 0 as i32;
    let mut current_block_6: u64;
    match want_type {
        768 => {
            want_type = 0x100 as i32;
            current_block_6 = 4235729007428639281;
        }
        256 | 512 => {
            current_block_6 = 4235729007428639281;
        }
        15360 => {
            numfields = 6 as i32;
            current_block_6 = 1856101646708284338;
        }
        _ => return -(30 as i32),
    }
    match current_block_6 {
        4235729007428639281 => numfields = 5 as i32,
        _ => {}
    }
    /* Comment, skip entry */
    while !text.is_null() && *text != '\u{0}' as wchar_t {
        /*
         * Parse the fields out of the next entry,
         * advance 'text' to start of next entry.
         */
        fields = 0 as i32;
        loop {
            let mut start: *const wchar_t = 0 as *const wchar_t;
            let mut end: *const wchar_t = 0 as *const wchar_t;
            next_field_w(&mut text, &mut start, &mut end, &mut sep);
            if fields < numfields {
                field[fields as usize].start = start;
                field[fields as usize].end = end
            }
            fields += 1;
            if !(sep == ':' as wchar_t) {
                break;
            }
        }
        /* Set remaining fields to blank. */
        n = fields;
        while n < numfields {
            field[n as usize].end = 0 as *const wchar_t;
            field[n as usize].start = field[n as usize].end;
            n += 1
        }
        if !field[0 as i32 as usize].start.is_null()
            && *field[0 as i32 as usize].start == '#' as wchar_t
        {
            continue;
        }
        n = 0 as i32;
        sol = 0 as i32;
        id = -(1 as i32);
        permset = 0 as i32;
        name.end = 0 as *const wchar_t;
        name.start = name.end;
        if want_type != ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 {
            /* POSIX.1e ACLs */
            /*
             * Default keyword "default:user::rwx"
             * if found, we have one more field
             *
             * We also support old Solaris extension:
             * "defaultuser::rwx" is the default ACL corresponding
             * to "user::rwx", etc. valid only for first field
             */
            s = field[0 as i32 as usize].start;
            len = field[0 as i32 as usize]
                .end
                .offset_from(field[0 as i32 as usize].start) as i64 as size_t;
            if *s == 'd' as wchar_t
                && (len == 1 as i32 as u64
                    || len >= 7 as i32 as u64
                        && wmemcmp_safe(
                            s.offset(1 as i32 as isize),
                            wchar::wchz!("efault").as_ptr(),
                            6 as i32 as u64,
                        ) == 0 as i32)
            {
                type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default;
                if len > 7 as i32 as u64 {
                    field[0 as i32 as usize].start =
                        field[0 as i32 as usize].start.offset(7 as i32 as isize)
                } else {
                    n = 1 as i32
                }
            } else {
                type_0 = want_type
            }
            /* Check for a numeric ID in field n+1 or n+3. */
            isint_w(
                field[(n + 1 as i32) as usize].start,
                field[(n + 1 as i32) as usize].end,
                &mut id,
            );
            /* Field n+3 is optional. */
            if id == -(1 as i32) && fields > n + 3 as i32 {
                isint_w(
                    field[(n + 3 as i32) as usize].start,
                    field[(n + 3 as i32) as usize].end,
                    &mut id,
                );
            }
            tag = 0 as i32;
            s = field[n as usize].start;
            st = field[n as usize].start.offset(1 as i32 as isize);
            len = field[n as usize].end.offset_from(field[n as usize].start) as i64 as size_t;
            match *s {
                117 => {
                    if len == 1 as i32 as u64
                        || len == 4 as i32 as u64
                            && wmemcmp_safe(st, wchar::wchz!("ser").as_ptr(), 3 as i32 as u64)
                                == 0 as i32
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                    }
                }
                103 => {
                    if len == 1 as i32 as u64
                        || len == 5 as i32 as u64
                            && wmemcmp_safe(st, wchar::wchz!("roup").as_ptr(), 4 as i32 as u64)
                                == 0 as i32
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                    }
                }
                111 => {
                    if len == 1 as i32 as u64
                        || len == 5 as i32 as u64
                            && wmemcmp_safe(st, wchar::wchz!("ther").as_ptr(), 4 as i32 as u64)
                                == 0 as i32
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other
                    }
                }
                109 => {
                    if len == 1 as i32 as u64
                        || len == 4 as i32 as u64
                            && wmemcmp_safe(st, wchar::wchz!("ask").as_ptr(), 3 as i32 as u64)
                                == 0 as i32
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask
                    }
                }
                _ => {}
            }
            match tag {
                10006 | 10005 => {
                    if fields == n + 2 as i32
                        && field[(n + 1 as i32) as usize].start < field[(n + 1 as i32) as usize].end
                        && ismode_w(
                            field[(n + 1 as i32) as usize].start,
                            field[(n + 1 as i32) as usize].end,
                            &mut permset,
                        ) != 0
                    {
                        /* This is Solaris-style "other:rwx" */
                        sol = 1 as i32
                    } else if fields == n + 3 as i32
                        && field[(n + 1 as i32) as usize].start < field[(n + 1 as i32) as usize].end
                    {
                        /* Invalid mask or other field */
                        ret = -(20 as i32);
                        continue;
                    }
                }
                10002 | 10004 => {
                    if id != -(1 as i32)
                        || field[(n + 1 as i32) as usize].start < field[(n + 1 as i32) as usize].end
                    {
                        name = field[(n + 1 as i32) as usize];
                        if tag == 10002 as i32 {
                            tag = 10001 as i32
                        } else {
                            tag = 10003 as i32
                        }
                    }
                }
                _ => {
                    /* Invalid tag, skip entry */
                    ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                    continue;
                }
            }
            /*
             * Without "default:" we expect mode in field 2
             * Exception: Solaris other and mask fields
             */
            if permset == 0 as i32
                && ismode_w(
                    field[(n + 2 as i32 - sol) as usize].start,
                    field[(n + 2 as i32 - sol) as usize].end,
                    &mut permset,
                ) == 0
            {
                /* Invalid mode, skip entry */
                ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                continue;
            }
        } else {
            /* NFS4 ACLs */
            s = field[0 as i32 as usize].start;
            len = field[0 as i32 as usize]
                .end
                .offset_from(field[0 as i32 as usize].start) as i64 as size_t;
            tag = 0 as i32;
            match len {
                4 => {
                    if wmemcmp_safe(s, wchar::wchz!("user").as_ptr(), 4 as i32 as u64) == 0 as i32 {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    }
                }
                5 => {
                    if wmemcmp_safe(s, wchar::wchz!("group").as_ptr(), 5 as i32 as u64) == 0 as i32
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
                    }
                }
                6 => {
                    if wmemcmp_safe(s, wchar::wchz!("owner@").as_ptr(), 6 as i32 as u64) == 0 as i32
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                    } else if wmemcmp_safe(s, wchar::wchz!("group@").as_ptr(), len) == 0 as i32 {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                    }
                }
                9 => {
                    if wmemcmp_safe(s, wchar::wchz!("everyone@").as_ptr(), 9 as i32 as u64)
                        == 0 as i32
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_everyone
                    }
                }
                _ => {}
            }
            if tag == 0 as i32 {
                /* Invalid tag, skip entry */
                ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                continue;
            } else {
                if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
                {
                    n = 1 as i32;
                    name = field[1 as i32 as usize];
                    isint_w(name.start, name.end, &mut id);
                } else {
                    n = 0 as i32
                }
                if is_nfs4_perms_w(
                    field[(1 as i32 + n) as usize].start,
                    field[(1 as i32 + n) as usize].end,
                    &mut permset,
                ) == 0
                    || is_nfs4_flags_w(
                        field[(2 as i32 + n) as usize].start,
                        field[(2 as i32 + n) as usize].end,
                        &mut permset,
                    ) == 0
                {
                    /* Invalid NFSv4 perms, skip entry */
                    ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                    continue;
                } else {
                    s = field[(3 as i32 + n) as usize].start;
                    len = field[(3 as i32 + n) as usize]
                        .end
                        .offset_from(field[(3 as i32 + n) as usize].start)
                        as i64 as size_t;
                    type_0 = 0 as i32;
                    if len == 4 as i32 as u64 {
                        if wmemcmp_safe(s, wchar::wchz!("deny").as_ptr(), 4 as i32 as u64)
                            == 0 as i32
                        {
                            type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_deny
                        }
                    } else if len == 5 as i32 as u64 {
                        if wmemcmp_safe(s, wchar::wchz!("allow").as_ptr(), 5 as i32 as u64)
                            == 0 as i32
                        {
                            type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_allow
                        } else if wmemcmp_safe(s, wchar::wchz!("audit").as_ptr(), 5 as i32 as u64)
                            == 0 as i32
                        {
                            type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_audit
                        } else if wmemcmp_safe(s, wchar::wchz!("alarm").as_ptr(), 5 as i32 as u64)
                            == 0 as i32
                        {
                            type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_alram
                        }
                    }
                    if type_0 == 0 as i32 {
                        /* Invalid entry type, skip entry */
                        ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                        continue;
                    } else {
                        isint_w(
                            field[(4 as i32 + n) as usize].start,
                            field[(4 as i32 + n) as usize].end,
                            &mut id,
                        );
                    }
                }
            }
        }
        /* Add entry to the internal list. */
        r = archive_acl_add_entry_w_len(
            acl,
            type_0,
            permset,
            tag,
            id,
            name.start,
            name.end.offset_from(name.start) as i64 as size_t,
        );
        if r < ARCHIVE_ACL_DEFINED_PARAM.archive_warn {
            return r;
        }
        if r != ARCHIVE_ACL_DEFINED_PARAM.archive_ok {
            ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn
        }
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
unsafe extern "C" fn isint_w(
    mut start: *const wchar_t,
    mut end: *const wchar_t,
    mut result: *mut i32,
) -> i32 {
    let mut n: i32 = 0 as i32;
    if start >= end {
        return 0 as i32;
    }
    while start < end {
        if *start < '0' as wchar_t || *start > '9' as wchar_t {
            return 0 as i32;
        }
        if n > 2147483647 as i32 / 10 as i32
            || n == 2147483647 as i32 / 10 as i32
                && *start - '0' as wchar_t > 2147483647 as wchar_t % 10 as wchar_t
        {
            n = 2147483647 as i32
        } else {
            n *= 10 as i32;
            n += *start as i32 - '0' as i32
        }
        start = start.offset(1)
    }
    *result = n;
    return 1 as i32;
}
/*
 * Parse a string as a mode field.  Returns true if
 * the string is non-empty and consists only of mode characters,
 * false otherwise.
 */
unsafe extern "C" fn ismode_w(
    mut start: *const wchar_t,
    mut end: *const wchar_t,
    mut permset: *mut i32,
) -> i32 {
    let mut p: *const wchar_t = 0 as *const wchar_t;
    if start >= end {
        return 0 as i32;
    }
    p = start;
    *permset = 0 as i32;
    while p < end {
        let fresh34 = p;
        p = p.offset(1);
        match *fresh34 {
            114 | 82 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read,
            119 | 87 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write,
            120 | 88 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_execute,
            45 => {}
            _ => return 0 as i32,
        }
    }
    return 1 as i32;
}
/*
 * Parse a string as a NFS4 ACL permission field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * permission characters, false otherwise
 */
unsafe extern "C" fn is_nfs4_perms_w(
    mut start: *const wchar_t,
    mut end: *const wchar_t,
    mut permset: *mut i32,
) -> i32 {
    let mut p: *const wchar_t = start;
    while p < end {
        let fresh35 = p;
        p = p.offset(1);
        match *fresh35 {
            114 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_data,
            119 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_data,
            120 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_execute,
            112 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_append_data,
            68 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_delete_child,
            100 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_delete,
            97 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_attributes,
            65 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_attributes,
            82 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_named_attrs,
            87 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_named_attrs,
            99 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_acl,
            67 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_acl,
            111 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_owner,
            115 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_synchronize,
            45 => {}
            _ => return 0 as i32,
        }
    }
    return 1 as i32;
}
/*
 * Parse a string as a NFS4 ACL flags field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * flag characters, false otherwise
 */
unsafe extern "C" fn is_nfs4_flags_w(
    mut start: *const wchar_t,
    mut end: *const wchar_t,
    mut permset: *mut i32,
) -> i32 {
    let mut p: *const wchar_t = start;
    while p < end {
        let fresh36 = p;
        p = p.offset(1);
        match *fresh36 {
            102 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_file_inherit,
            100 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_directory_inherit,
            105 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_inherit_only,
            110 => {
                *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_no_propagate_inherit
            }
            83 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_successful_access,
            70 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_failed_access,
            73 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_inherited,
            45 => {}
            _ => return 0 as i32,
        }
    }
    return 1 as i32;
}
/*
 * Match "[:whitespace:]*(.*)[:whitespace:]*[:,\n]".  *wp is updated
 * to point to just after the separator.  *start points to the first
 * character of the matched text and *end just after the last
 * character of the matched identifier.  In particular *end - *start
 * is the length of the field body, not including leading or trailing
 * whitespace.
 */
unsafe extern "C" fn next_field_w(
    mut wp: *mut *const wchar_t,
    mut start: *mut *const wchar_t,
    mut end: *mut *const wchar_t,
    mut sep: *mut wchar_t,
) {
    /* Skip leading whitespace to find start of field. */
    while **wp == ' ' as wchar_t || **wp == '\t' as wchar_t || **wp == '\n' as wchar_t {
        *wp = (*wp).offset(1)
    }
    *start = *wp;
    /* Scan for the separator. */
    while **wp != '\u{0}' as wchar_t
        && **wp != ',' as wchar_t
        && **wp != ':' as wchar_t
        && **wp != '\n' as wchar_t
        && **wp != '#' as wchar_t
    {
        *wp = (*wp).offset(1)
    }
    *sep = **wp;
    /* Locate end of field, trim trailing whitespace if necessary */
    if *wp == *start {
        *end = *wp
    } else {
        *end = (*wp).offset(-(1 as i32 as isize));
        while **end == ' ' as wchar_t || **end == '\t' as wchar_t || **end == '\n' as wchar_t {
            *end = (*end).offset(-1)
        }
        *end = (*end).offset(1)
    }
    /* Handle in-field comments */
    if *sep == '#' as wchar_t {
        while **wp != '\u{0}' as wchar_t && **wp != ',' as wchar_t && **wp != '\n' as wchar_t {
            *wp = (*wp).offset(1)
        }
        *sep = **wp
    }
    /* Adjust scanner location. */
    if **wp != '\u{0}' as wchar_t {
        *wp = (*wp).offset(1)
    };
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
pub unsafe extern "C" fn archive_acl_from_text_l(
    mut acl: *mut archive_acl,
    mut text: *const u8,
    mut want_type: i32,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut field: [archive_string_temporary_field_2; 6] = [archive_string_temporary_field_2 {
        start: 0 as *const u8,
        end: 0 as *const u8,
    }; 6];
    let mut name: archive_string_temporary_field_2 = archive_string_temporary_field_2 {
        start: 0 as *const u8,
        end: 0 as *const u8,
    };
    let mut s: *const u8 = 0 as *const u8;
    let mut st: *const u8 = 0 as *const u8;
    let mut numfields: i32 = 0;
    let mut fields: i32 = 0;
    let mut n: i32 = 0;
    let mut r: i32 = 0;
    let mut sol: i32 = 0;
    let mut ret: i32 = 0;
    let mut type_0: i32 = 0;
    let mut types: i32 = 0;
    let mut tag: i32 = 0;
    let mut permset: i32 = 0;
    let mut id: i32 = 0;
    let mut len: size_t = 0;
    let mut sep: u8 = 0;
    let mut current_block_4: u64;
    match want_type {
        768 => {
            want_type = 0x100 as i32;
            current_block_4 = 5136372742794658517;
        }
        256 | 512 => {
            current_block_4 = 5136372742794658517;
        }
        15360 => {
            numfields = 6 as i32;
            current_block_4 = 13536709405535804910;
        }
        _ => return -(30 as i32),
    }
    match current_block_4 {
        5136372742794658517 => numfields = 5 as i32,
        _ => {}
    }
    ret = 0 as i32;
    types = 0 as i32;
    /* Comment, skip entry */
    while !text.is_null() && *text as i32 != '\u{0}' as i32 {
        /*
         * Parse the fields out of the next entry,
         * advance 'text' to start of next entry.
         */
        fields = 0 as i32;
        loop {
            let mut start: *const u8 = 0 as *const u8;
            let mut end: *const u8 = 0 as *const u8;
            next_field(&mut text, &mut start, &mut end, &mut sep);
            if fields < numfields {
                field[fields as usize].start = start;
                field[fields as usize].end = end
            }
            fields += 1;
            if !(sep as i32 == ':' as i32) {
                break;
            }
        }
        /* Set remaining fields to blank. */
        n = fields;
        while n < numfields {
            field[n as usize].end = 0 as *const u8;
            field[n as usize].start = field[n as usize].end;
            n += 1
        }
        if !field[0 as i32 as usize].start.is_null()
            && *field[0 as i32 as usize].start as i32 == '#' as i32
        {
            continue;
        }
        n = 0 as i32;
        sol = 0 as i32;
        id = -(1 as i32);
        permset = 0 as i32;
        name.end = 0 as *const u8;
        name.start = name.end;
        if want_type != 0x400 as i32 | 0x800 as i32 | 0x1000 as i32 | 0x2000 as i32 {
            /* POSIX.1e ACLs */
            /*
             * Default keyword "default:user::rwx"
             * if found, we have one more field
             *
             * We also support old Solaris extension:
             * "defaultuser::rwx" is the default ACL corresponding
             * to "user::rwx", etc. valid only for first field
             */
            s = field[0 as i32 as usize].start;
            len = field[0 as i32 as usize]
                .end
                .offset_from(field[0 as i32 as usize].start) as i64 as size_t;
            if *s as i32 == 'd' as i32
                && (len == 1 as i32 as u64
                    || len >= 7 as i32 as u64
                        && memcmp_safe(
                            s.offset(1 as i32 as isize) as *const (),
                            b"efault\x00" as *const u8 as *const (),
                            6 as i32 as u64,
                        ) == 0 as i32)
            {
                type_0 = 0x200 as i32;
                if len > 7 as i32 as u64 {
                    field[0 as i32 as usize].start =
                        field[0 as i32 as usize].start.offset(7 as i32 as isize)
                } else {
                    n = 1 as i32
                }
            } else {
                type_0 = want_type
            }
            /* Check for a numeric ID in field n+1 or n+3. */
            isint(
                field[(n + 1 as i32) as usize].start,
                field[(n + 1 as i32) as usize].end,
                &mut id,
            );
            /* Field n+3 is optional. */
            if id == -(1 as i32) && fields > n + 3 as i32 {
                isint(
                    field[(n + 3 as i32) as usize].start,
                    field[(n + 3 as i32) as usize].end,
                    &mut id,
                );
            }
            tag = 0 as i32;
            s = field[n as usize].start;
            st = field[n as usize].start.offset(1 as i32 as isize);
            len = field[n as usize].end.offset_from(field[n as usize].start) as i64 as size_t;
            if len == 0 as i32 as u64 {
                ret = -(20 as i32);
                continue;
            } else {
                match *s as i32 {
                    117 => {
                        if len == 1 as i32 as u64
                            || len == 4 as i32 as u64
                                && memcmp_safe(
                                    st as *const (),
                                    b"ser\x00" as *const u8 as *const (),
                                    3 as i32 as u64,
                                ) == 0 as i32
                        {
                            tag = 10002 as i32
                        }
                    }
                    103 => {
                        if len == 1 as i32 as u64
                            || len == 5 as i32 as u64
                                && memcmp_safe(
                                    st as *const (),
                                    b"roup\x00" as *const u8 as *const (),
                                    4 as i32 as u64,
                                ) == 0 as i32
                        {
                            tag = 10004 as i32
                        }
                    }
                    111 => {
                        if len == 1 as i32 as u64
                            || len == 5 as i32 as u64
                                && memcmp_safe(
                                    st as *const (),
                                    b"ther\x00" as *const u8 as *const (),
                                    4 as i32 as u64,
                                ) == 0 as i32
                        {
                            tag = 10006 as i32
                        }
                    }
                    109 => {
                        if len == 1 as i32 as u64
                            || len == 4 as i32 as u64
                                && memcmp_safe(
                                    st as *const (),
                                    b"ask\x00" as *const u8 as *const (),
                                    3 as i32 as u64,
                                ) == 0 as i32
                        {
                            tag = 10005 as i32
                        }
                    }
                    _ => {}
                }
                match tag {
                    10006 | 10005 => {
                        if fields == n + 2 as i32
                            && field[(n + 1 as i32) as usize].start
                                < field[(n + 1 as i32) as usize].end
                            && ismode(
                                field[(n + 1 as i32) as usize].start,
                                field[(n + 1 as i32) as usize].end,
                                &mut permset,
                            ) != 0
                        {
                            /* This is Solaris-style "other:rwx" */
                            sol = 1 as i32
                        } else if fields == n + 3 as i32
                            && field[(n + 1 as i32) as usize].start
                                < field[(n + 1 as i32) as usize].end
                        {
                            /* Invalid mask or other field */
                            ret = -(20 as i32);
                            continue;
                        }
                    }
                    10002 | 10004 => {
                        if id != -(1 as i32)
                            || field[(n + 1 as i32) as usize].start
                                < field[(n + 1 as i32) as usize].end
                        {
                            name = field[(n + 1 as i32) as usize];
                            if tag == 10002 as i32 {
                                tag = 10001 as i32
                            } else {
                                tag = 10003 as i32
                            }
                        }
                    }
                    _ => {
                        /* Invalid tag, skip entry */
                        ret = -(20 as i32);
                        continue;
                    }
                }
                /*
                 * Without "default:" we expect mode in field 3
                 * Exception: Solaris other and mask fields
                 */
                if permset == 0 as i32
                    && ismode(
                        field[(n + 2 as i32 - sol) as usize].start,
                        field[(n + 2 as i32 - sol) as usize].end,
                        &mut permset,
                    ) == 0
                {
                    /* Invalid mode, skip entry */
                    ret = -(20 as i32);
                    continue;
                }
            }
        } else {
            /* NFS4 ACLs */
            s = field[0 as i32 as usize].start;
            len = field[0 as i32 as usize]
                .end
                .offset_from(field[0 as i32 as usize].start) as i64 as size_t;
            tag = 0 as i32;
            match len {
                4 => {
                    if memcmp_safe(
                        s as *const (),
                        b"user\x00" as *const u8 as *const (),
                        4 as i32 as u64,
                    ) == 0 as i32
                    {
                        tag = 10001 as i32
                    }
                }
                5 => {
                    if memcmp_safe(
                        s as *const (),
                        b"group\x00" as *const u8 as *const (),
                        5 as i32 as u64,
                    ) == 0 as i32
                    {
                        tag = 10003 as i32
                    }
                }
                6 => {
                    if memcmp_safe(
                        s as *const (),
                        b"owner@\x00" as *const u8 as *const (),
                        6 as i32 as u64,
                    ) == 0 as i32
                    {
                        tag = 10002 as i32
                    } else if memcmp_safe(
                        s as *const (),
                        b"group@\x00" as *const u8 as *const (),
                        6 as i32 as u64,
                    ) == 0 as i32
                    {
                        tag = 10004 as i32
                    }
                }
                9 => {
                    if memcmp_safe(
                        s as *const (),
                        b"everyone@\x00" as *const u8 as *const (),
                        9 as i32 as u64,
                    ) == 0 as i32
                    {
                        tag = 10107 as i32
                    }
                }
                _ => {}
            }
            if tag == 0 as i32 {
                /* Invalid tag, skip entry */
                ret = -(20 as i32);
                continue;
            } else {
                if tag == 10001 as i32 || tag == 10003 as i32 {
                    n = 1 as i32;
                    name = field[1 as i32 as usize];
                    isint(name.start, name.end, &mut id);
                } else {
                    n = 0 as i32
                }
                if is_nfs4_perms(
                    field[(1 as i32 + n) as usize].start,
                    field[(1 as i32 + n) as usize].end,
                    &mut permset,
                ) == 0
                    || is_nfs4_flags(
                        field[(2 as i32 + n) as usize].start,
                        field[(2 as i32 + n) as usize].end,
                        &mut permset,
                    ) == 0
                {
                    /* Invalid NFSv4 flags, skip entry */
                    ret = -(20 as i32);
                    continue;
                } else {
                    s = field[(3 as i32 + n) as usize].start;
                    len = field[(3 as i32 + n) as usize]
                        .end
                        .offset_from(field[(3 as i32 + n) as usize].start)
                        as i64 as size_t;
                    type_0 = 0 as i32;
                    if len == 4 as i32 as u64 {
                        if memcmp_safe(
                            s as *const (),
                            b"deny\x00" as *const u8 as *const (),
                            4 as i32 as u64,
                        ) == 0 as i32
                        {
                            type_0 = 0x800 as i32
                        }
                    } else if len == 5 as i32 as u64 {
                        if memcmp_safe(
                            s as *const (),
                            b"allow\x00" as *const u8 as *const (),
                            5 as i32 as u64,
                        ) == 0 as i32
                        {
                            type_0 = 0x400 as i32
                        } else if memcmp_safe(
                            s as *const (),
                            b"audit\x00" as *const u8 as *const (),
                            5 as i32 as u64,
                        ) == 0 as i32
                        {
                            type_0 = 0x1000 as i32
                        } else if memcmp_safe(
                            s as *const (),
                            b"alarm\x00" as *const u8 as *const (),
                            5 as i32 as u64,
                        ) == 0 as i32
                        {
                            type_0 = 0x2000 as i32
                        }
                    }
                    if type_0 == 0 as i32 {
                        /* Invalid entry type, skip entry */
                        ret = -(20 as i32);
                        continue;
                    } else {
                        isint(
                            field[(4 as i32 + n) as usize].start,
                            field[(4 as i32 + n) as usize].end,
                            &mut id,
                        );
                    }
                }
            }
        }
        /* Add entry to the internal list. */
        r = archive_acl_add_entry_len_l(
            acl,
            type_0,
            permset,
            tag,
            id,
            name.start,
            name.end.offset_from(name.start) as i64 as size_t,
            sc,
        );
        if r < -(20 as i32) {
            return r;
        }
        if r != 0 as i32 {
            ret = -(20 as i32)
        }
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
unsafe extern "C" fn isint(mut start: *const u8, mut end: *const u8, mut result: *mut i32) -> i32 {
    let mut n: i32 = 0 as i32;
    if start >= end {
        return 0 as i32;
    }
    while start < end {
        if (*start as i32) < '0' as i32 || *start as i32 > '9' as i32 {
            return 0 as i32;
        }
        if n > 2147483647 as i32 / 10 as i32
            || n == 2147483647 as i32 / 10 as i32
                && *start as i32 - '0' as i32 > 2147483647 as i32 % 10 as i32
        {
            n = 2147483647 as i32
        } else {
            n *= 10 as i32;
            n += *start as i32 - '0' as i32
        }
        start = start.offset(1)
    }
    *result = n;
    return 1 as i32;
}
/*
 * Parse a string as a mode field.  Returns true if
 * the string is non-empty and consists only of mode characters,
 * false otherwise.
 */
unsafe extern "C" fn ismode(
    mut start: *const u8,
    mut end: *const u8,
    mut permset: *mut i32,
) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    if start >= end {
        return 0 as i32;
    }
    p = start;
    *permset = 0 as i32;
    while p < end {
        let fresh37 = p;
        p = p.offset(1);
        match *fresh37 as i32 {
            114 | 82 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read,
            119 | 87 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write,
            120 | 88 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_execute,
            45 => {}
            _ => return 0 as i32,
        }
    }
    return 1 as i32;
}
/*
 * Parse a string as a NFS4 ACL permission field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * permission characters, false otherwise
 */
unsafe extern "C" fn is_nfs4_perms(
    mut start: *const u8,
    mut end: *const u8,
    mut permset: *mut i32,
) -> i32 {
    let mut p: *const u8 = start;
    while p < end {
        let fresh38 = p;
        p = p.offset(1);
        match *fresh38 as i32 {
            114 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_data,
            119 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_data,
            120 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_execute,
            112 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_append_data,
            68 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_delete_child,
            100 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_delete,
            97 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_attributes,
            65 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_attributes,
            82 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_named_attrs,
            87 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_named_attrs,
            99 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_acl,
            67 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_acl,
            111 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_owner,
            115 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_synchronize,
            45 => {}
            _ => return 0 as i32,
        }
    }
    return 1 as i32;
}
/*
 * Parse a string as a NFS4 ACL flags field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * flag characters, false otherwise
 */
unsafe extern "C" fn is_nfs4_flags(
    mut start: *const u8,
    mut end: *const u8,
    mut permset: *mut i32,
) -> i32 {
    let mut p: *const u8 = start;
    while p < end {
        let fresh39 = p;
        p = p.offset(1);
        match *fresh39 as i32 {
            102 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_file_inherit,
            100 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_directory_inherit,
            105 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_inherit_only,
            110 => {
                *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_no_propagate_inherit
            }
            83 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_successful_access,
            70 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_failed_access,
            73 => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_inherited,
            45 => {}
            _ => return 0 as i32,
        }
    }
    return 1 as i32;
}
/*
 * Match "[:whitespace:]*(.*)[:whitespace:]*[:,\n]".  *wp is updated
 * to point to just after the separator.  *start points to the first
 * character of the matched text and *end just after the last
 * character of the matched identifier.  In particular *end - *start
 * is the length of the field body, not including leading or trailing
 * whitespace.
 */
unsafe extern "C" fn next_field(
    mut p: *mut *const u8,
    mut start: *mut *const u8,
    mut end: *mut *const u8,
    mut sep: *mut u8,
) {
    /* Skip leading whitespace to find start of field. */
    while **p as i32 == ' ' as i32 || **p as i32 == '\t' as i32 || **p as i32 == '\n' as i32 {
        *p = (*p).offset(1)
    }
    *start = *p;
    /* Scan for the separator. */
    while **p as i32 != '\u{0}' as i32
        && **p as i32 != ',' as i32
        && **p as i32 != ':' as i32
        && **p as i32 != '\n' as i32
        && **p as i32 != '#' as i32
    {
        *p = (*p).offset(1)
    }
    *sep = **p;
    /* Locate end of field, trim trailing whitespace if necessary */
    if *p == *start {
        *end = *p
    } else {
        *end = (*p).offset(-(1 as i32 as isize));
        while **end as i32 == ' ' as i32
            || **end as i32 == '\t' as i32
            || **end as i32 == '\n' as i32
        {
            *end = (*end).offset(-1)
        }
        *end = (*end).offset(1)
    }
    /* Handle in-field comments */
    if *sep as i32 == '#' as i32 {
        while **p as i32 != '\u{0}' as i32 && **p as i32 != ',' as i32 && **p as i32 != '\n' as i32
        {
            *p = (*p).offset(1)
        }
        *sep = **p
    }
    /* Adjust scanner location. */
    if **p as i32 != '\u{0}' as i32 {
        *p = (*p).offset(1)
    };
}
unsafe extern "C" fn run_static_initializers() {
    nfsv4_acl_perm_map_size = (::std::mem::size_of::<[nfsv4_acl_perm_map_struct; 14]>() as u64)
        .wrapping_div(::std::mem::size_of::<nfsv4_acl_perm_map_struct>() as u64)
        as i32;
    nfsv4_acl_flag_map_size = (::std::mem::size_of::<[nfsv4_acl_perm_map_struct; 7]>() as u64)
        .wrapping_div(::std::mem::size_of::<nfsv4_acl_perm_map_struct>() as u64)
        as i32
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
