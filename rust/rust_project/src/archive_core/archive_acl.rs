use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;
use std::mem::size_of;

#[no_mangle]
pub fn archive_acl_clear(acl: *mut archive_acl) {
    let safe_acl = unsafe { &mut *acl };
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    while !(safe_acl).acl_head.is_null() {
        ap = unsafe { (*(safe_acl.acl_head)).next };
        unsafe { archive_mstring_clean_safe(&mut (*(safe_acl.acl_head)).name) };
        unsafe { free_safe((safe_acl).acl_head as *mut ()) };
        (safe_acl).acl_head = ap
    }
    unsafe { free_safe((safe_acl).acl_text_w as *mut ()) };
    (safe_acl).acl_text_w = 0 as *mut wchar_t;
    unsafe { free_safe((safe_acl).acl_text as *mut ()) };
    (safe_acl).acl_text = 0 as *mut u8;
    (safe_acl).acl_p = 0 as *mut archive_acl_entry;
    (safe_acl).acl_types = 0;
    (safe_acl).acl_state = 0;
    /* Not counting. */
}

#[no_mangle]
pub fn archive_acl_copy(dest: *mut archive_acl, src: *mut archive_acl) {
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
pub fn archive_acl_add_entry(
    acl: *mut archive_acl,
    type_0: i32,
    permset: i32,
    tag: i32,
    id: i32,
    name: *const u8,
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
    unsafe {
        if !name.is_null() && *name as i32 != '\u{0}' as i32 {
            archive_mstring_copy_mbs_safe(&mut (*ap).name, name);
        } else {
            archive_mstring_clean_safe(&mut (*ap).name);
        }
    }
    return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
}

#[no_mangle]
pub fn archive_acl_add_entry_w_len(
    acl: *mut archive_acl,
    type_0: i32,
    permset: i32,
    tag: i32,
    id: i32,
    name: *const wchar_t,
    len: size_t,
) -> i32 {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    if acl_special(acl, type_0, permset, tag) == 0 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
    }
    ap = acl_new_entry(acl, type_0, permset, tag, id);
    if ap.is_null() {
        /* XXX Error XXX */
        return ARCHIVE_ACL_DEFINED_PARAM.archvie_failed;
    }
    unsafe {
        if !name.is_null() && *name != '\u{0}' as wchar_t && len > 0 as u64 {
            archive_mstring_copy_wcs_len_safe(&mut (*ap).name, name, len);
        } else {
            archive_mstring_clean_safe(&mut (*ap).name);
        }
    }
    return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
}
pub fn archive_acl_add_entry_len_l(
    acl: *mut archive_acl,
    type_0: i32,
    permset: i32,
    tag: i32,
    id: i32,
    name: *const u8,
    len: size_t,
    sc: *mut archive_string_conv,
) -> i32 {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut r: i32;
    if acl_special(acl, type_0, permset, tag) == 0 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
    }
    ap = acl_new_entry(acl, type_0, permset, tag, id);
    if ap.is_null() {
        /* XXX Error XXX */
        return ARCHIVE_ACL_DEFINED_PARAM.archvie_failed;
    }
    unsafe {
        if !name.is_null() && *name as i32 != '\u{0}' as i32 && len > 0 as u64 {
            r = archive_mstring_copy_mbs_len_l_safe(&mut (*ap).name, name, len, sc)
        } else {
            r = 0;
            archive_mstring_clean_safe(&mut (*ap).name);
        }
    }
    if r == 0 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
    } else if unsafe { *__errno_location_safe() } == ARCHIVE_ACL_DEFINED_PARAM.enomem as i32 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_fatal;
    } else {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
    };
}
/*
 * If this ACL entry is part of the standard POSIX permissions set,
 * store the permissions in the stat structure and return zero.
 */
fn acl_special(acl: *mut archive_acl, type_0: i32, permset: i32, tag: i32) -> i32 {
    let safe_acl = unsafe { &mut *acl };
    if type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
        && permset & !(0o7 as i32) == 0
    {
        if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj {
            (safe_acl).mode &= !(0o700 as i32) as u32;
            (safe_acl).mode |= ((permset & 7) << 6) as u32;
            return 0;
        } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj {
            (safe_acl).mode &= !(0o70 as i32) as u32;
            (safe_acl).mode |= ((permset & 7) << 3) as u32;
            return 0;
        } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other {
            (safe_acl).mode &= !(0o7 as i32) as u32;
            (safe_acl).mode |= (permset & 7) as u32;
            return 0;
        }
    }
    return 1;
}
/*
 * Allocate and populate a new ACL entry with everything but the
 * name.
 */
fn acl_new_entry(
    acl: *mut archive_acl,
    type_0: i32,
    permset: i32,
    tag: i32,
    id: i32,
) -> *mut archive_acl_entry {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut aq: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    /* Type argument must be a valid NFS4 or POSIX.1e type.
     * The type must agree with anything already set and
     * the permset must be compatible. */
    let safe_acl = unsafe { &mut *acl };
    if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 {
        if safe_acl.acl_types & !ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 {
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
        if safe_acl.acl_types & !ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0 {
            return 0 as *mut archive_acl_entry;
        }
        if permset & !ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_perms_posix1e != 0 {
            return 0 as *mut archive_acl_entry;
        }
    } else {
        return 0 as *mut archive_acl_entry;
    }
    /* Verify the tag is valid and compatible with NFS4 or POSIX.1e. */
    if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
        || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
        || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
        || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
    {
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask
        || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other
    {
        if type_0 & !ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0 {
            return 0 as *mut archive_acl_entry;
        }
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_everyone {
        if type_0 & !(ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4) != 0 {
            return 0 as *mut archive_acl_entry;
        }
    } else {
        return 0 as *mut archive_acl_entry;
    }
    unsafe { free_safe((*acl).acl_text_w as *mut ()) };
    safe_acl.acl_text_w = 0 as *mut wchar_t;
    unsafe { free_safe((*acl).acl_text as *mut ()) };
    safe_acl.acl_text = 0 as *mut u8;
    /*
     * If there's a matching entry already in the list, overwrite it.
     * NFSv4 entries may be repeated and are not overwritten.
     *
     * TODO: compare names of no id is provided (needs more rework)
     */
    ap = safe_acl.acl_head;
    aq = 0 as *mut archive_acl_entry;
    while !ap.is_null() {
        unsafe {
            if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 == 0 as i32
                && (*ap).type_0 == type_0
                && (*ap).tag == tag
                && (*ap).id == id
            {
                if id != -1
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
    }
    /* Add a new entry to the end of the list. */
    ap = unsafe {
        calloc(1 as u64, size_of::<archive_acl_entry>() as u64) as *mut archive_acl_entry
    };
    if ap.is_null() {
        return 0 as *mut archive_acl_entry;
    }
    unsafe {
        if aq.is_null() {
            safe_acl.acl_head = ap
        } else {
            (*aq).next = ap
        }
        (*ap).type_0 = type_0;
        (*ap).tag = tag;
        (*ap).id = id;
        (*ap).permset = permset;
        (*acl).acl_types |= type_0;
    }
    return ap;
}
/*
 * Return a count of entries matching "want_type".
 */

#[no_mangle]
pub fn archive_acl_count(acl: *mut archive_acl, want_type: i32) -> i32 {
    let mut count: i32 = 0;
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;

    unsafe {
        ap = (*acl).acl_head;
        while !ap.is_null() {
            if (*ap).type_0 & want_type != 0 {
                count += 1
            }
            ap = (*ap).next
        }
    }
    if count > 0 && want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 {
        count += 3
    }
    return count;
}
/*
 * Return a bitmask of stored ACL types in an ACL list
 */

#[no_mangle]
pub fn archive_acl_types(acl: *mut archive_acl) -> i32 {
    let safe_acl = unsafe { &mut *acl };
    return safe_acl.acl_types;
}
/*
 * Prepare for reading entries from the ACL data.  Returns a count
 * of entries matching "want_type", or zero if there are no
 * non-extended ACL entries of that type.
 */

#[no_mangle]
pub fn archive_acl_reset(acl: *mut archive_acl, want_type: i32) -> i32 {
    let safe_acl = unsafe { &mut *acl };
    let mut count: i32;
    let mut cutoff: i32;
    count = archive_acl_count(safe_acl, want_type);
    /*
     * If the only entries are the three standard ones,
     * then don't return any ACL data.  (In this case,
     * client can just use chmod(2) to set permissions.)
     */
    if want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 {
        cutoff = 3
    } else {
        cutoff = 0
    }
    if count > cutoff {
        (safe_acl).acl_state = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
    } else {
        (safe_acl).acl_state = 0
    }
    (safe_acl).acl_p = (safe_acl).acl_head;
    return count;
}
/*
 * Return the next ACL entry in the list.  Fake entries for the
 * standard permissions and include them in the returned list.
 */

#[no_mangle]
pub fn archive_acl_next(
    a: *mut archive,
    acl: *mut archive_acl,
    want_type: i32,
    type_0: *mut i32,
    permset: *mut i32,
    tag: *mut i32,
    id: *mut i32,
    name: *mut *const u8,
) -> i32 {
    unsafe {
        *name = 0 as *const u8;
        *id = -1;
    }
    /*
     * The acl_state is either zero (no entries available), -1
     * (reading from list), or an entry type (retrieve that type
     * from ae_stat.aest_mode).
     */
    let safe_acl = unsafe { &mut *acl };
    if safe_acl.acl_state == 0 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
    }
    /* The first three access entries are special. */
    unsafe {
        if want_type & 0x100 as i32 != 0 {
            if safe_acl.acl_state == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj {
                *permset = ((*acl).mode >> 6 as i32 & 7 as u32) as i32;
                *type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access;
                *tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj;
                (*acl).acl_state = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj;
                return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
            } else if safe_acl.acl_state == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj {
                *permset = ((*acl).mode >> 3 as i32 & 7 as u32) as i32;
                *type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access;
                *tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj;
                (*acl).acl_state = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other;
                return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
            } else if safe_acl.acl_state == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other {
                *permset = ((*acl).mode & 7 as u32) as i32;
                *type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access;
                *tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other;
                (*acl).acl_state = -(1 as i32);
                (*acl).acl_p = (*acl).acl_head;
                return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
            }
        }
        while !(*acl).acl_p.is_null() && (*(*acl).acl_p).type_0 & want_type == 0 as i32 {
            (*acl).acl_p = (*(*acl).acl_p).next
        }
        if (*acl).acl_p.is_null() {
            (*acl).acl_state = 0;
            *type_0 = 0;
            *permset = 0;
            *tag = 0;
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
    }
    return ARCHIVE_ACL_DEFINED_PARAM.archive_ok;
}
/*
 * Determine what type of ACL do we want
 */
fn archive_acl_text_want_type(acl: *mut archive_acl, flags: i32) -> i32 {
    let safe_acl = unsafe { &mut *acl };
    let mut want_type: i32;
    /* Check if ACL is NFSv4 */
    if (safe_acl).acl_types & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 as i32 {
        /* NFSv4 should never mix with POSIX.1e */
        if (safe_acl).acl_types & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0 {
            return 0;
        } else {
            return ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4;
        }
    }
    /* Now deal with POSIX.1e ACLs */
    want_type = 0;
    if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 as i32 {
        want_type |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
    }
    if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default != 0 as i32 {
        want_type |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default
    }
    /* By default we want both access and default ACLs */
    if want_type == 0 {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e;
    }
    return want_type;
}
/*
 * Calculate ACL text string length
 */
fn archive_acl_text_len(
    acl: *mut archive_acl,
    want_type: i32,
    flags: i32,
    wide: i32,
    a: *mut archive,
    sc: *mut archive_string_conv,
) -> ssize_t {
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut name: *const u8 = 0 as *const u8;
    let mut wname: *const wchar_t = 0 as *const wchar_t;
    let mut count: i32;
    let mut idlen: i32;
    let mut tmp: i32;
    let mut r: i32;
    let mut length: ssize_t;
    let mut len: size_t = 0;
    count = 0;
    length = 0;
    let safe_acl = unsafe { &mut *acl };
    let mut safe_ap = unsafe { &mut *ap };
    ap = safe_acl.acl_head;
    while !ap.is_null() {
        safe_ap = unsafe { &mut *ap };
        if !(safe_ap.type_0 & want_type == 0) {
            /*
             * Filemode-mapping ACL entries are stored exclusively in
             * ap->mode so they should not be in the list
             */
            if !(safe_ap.type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
                && (safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                    || safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                    || safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other))
            {
                count += 1; /* "default:" */
                if want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default != 0
                    && safe_ap.type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default
                        != 0
                {
                    length += 8
                } /* "owner@" */

                if safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj {
                    if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 {
                        length += 6; /* "everyone@" */
                    } else {
                        length += 4;
                    }
                } else if safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    || safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask
                {
                    length += 4;
                } else if safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj {
                    if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 {
                        length += 6;
                    } else {
                        length += 5;
                    }
                } else if safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
                    || safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other
                {
                    length += 5;
                } else if safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_everyone {
                    length += 9;
                }

                /* "group", "other" */
                length += 1; /* colon after tag */
                if safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    || safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group as i32
                {
                    if wide != 0 {
                        let errno_location: i32 = unsafe { *__errno_location_safe() };
                        r = unsafe {
                            archive_mstring_get_wcs_safe(a, &mut safe_ap.name, &mut wname)
                        }; /* 2nd colon empty user,group or other */
                        if r == 0 && !wname.is_null() {
                            length =
                                (length as u64).wrapping_add(unsafe { wcslen(wname) }) as ssize_t
                        } else if r < 0 && errno_location == ARCHIVE_ACL_DEFINED_PARAM.enomem {
                            return 0;
                        } else {
                            length = (length as u64).wrapping_add(
                                (size_of::<uid_t>() as u64).wrapping_mul(3).wrapping_add(1),
                            ) as ssize_t
                        }
                    } else {
                        r = unsafe {
                            archive_mstring_get_mbs_l_safe(
                                a,
                                &mut safe_ap.name,
                                &mut name,
                                &mut len,
                                sc,
                            )
                        };
                        if r != 0 {
                            return 0;
                        }
                        if len > 0 as i32 as u64 && !name.is_null() {
                            length = (length as u64).wrapping_add(len) as ssize_t
                        } else {
                            length = (length as u64).wrapping_add(
                                (size_of::<uid_t>() as u64).wrapping_mul(3).wrapping_add(1),
                            ) as ssize_t
                        }
                    }
                    length += 1
                    /* colon after user or group name */
                } else if want_type != ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 {
                    length += 1
                }
                if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_solaris != 0 as i32
                    && want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0
                    && (safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other
                        || safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask)
                {
                    /* Solaris has no colon after other: and mask: */
                    length = length - 1
                } /* rwx */
                if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 {
                    /* rwxpdDaARWcCos:fdinSFI:deny */
                    length += 27;
                    if safe_ap.type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_deny == 0 {
                        length += 1
                    }
                    /* allow, alarm, audit */
                } else {
                    length += 3
                } /* colon */
                if (safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    || safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group)
                    && flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_extra_id != 0
                {
                    length += 1;
                    /* ID digit count */
                    idlen = 1;
                    tmp = safe_ap.id;
                    while tmp > 9 {
                        tmp = tmp / 10;
                        idlen += 1
                    }
                    length += idlen as i64
                }
                length += 1
            }
        }
        ap = safe_ap.next
        /* entry separator */
    }
    /* Add filemode-mapping access entries to the length */
    if want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 {
        if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_solaris != 0 {
            /* "user::rwx\ngroup::rwx\nother:rwx\n" */
            length += 31
        } else {
            /* "user::rwx\ngroup::rwx\nother::rwx\n" */
            length += 32
        }
    } else if count == 0 {
        return 0 as ssize_t;
    }
    /* The terminating character is included in count */
    return length;
}
/*
 * Generate a wide text version of the ACL. The flags parameter controls
 * the type and style of the generated ACL.
 */
#[no_mangle]
pub fn archive_acl_to_text_w(
    acl: *mut archive_acl,
    text_len: *mut ssize_t,
    mut flags: i32,
    a: *mut archive,
) -> *mut wchar_t {
    let mut count: i32;
    let mut length: ssize_t;
    let mut len: size_t;
    let mut wname: *const wchar_t = 0 as *const wchar_t;
    let mut prefix: *const wchar_t = 0 as *const wchar_t;
    let mut separator: wchar_t = 0;
    let mut ap: *mut archive_acl_entry = 0 as *mut archive_acl_entry;
    let mut id: i32;
    let mut r: i32;
    let mut want_type: i32;
    let mut wp: *mut wchar_t = 0 as *mut wchar_t;
    let mut ws: *mut wchar_t = 0 as *mut wchar_t;
    want_type = archive_acl_text_want_type(acl, flags);
    /* Both NFSv4 and POSIX.1 types found */
    if want_type == 0 {
        return 0 as *mut wchar_t;
    }
    if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e {
        flags |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_mark_default
    }
    length = archive_acl_text_len(acl, want_type, flags, 1, a, 0 as *mut archive_string_conv);
    if length == 0 {
        return 0 as *mut wchar_t;
    }
    if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_separator_comma != 0 {
        separator = ',' as wchar_t
    } else {
        separator = '\n' as wchar_t
    }
    /* Now, allocate the string and actually populate it. */
    ws = unsafe { malloc_safe((length as u64).wrapping_mul(size_of::<wchar_t>() as u64)) }
        as *mut wchar_t;
    wp = ws;
    let errno_location: i32 = unsafe { *__errno_location_safe() };
    if wp.is_null() {
        if errno_location == ARCHIVE_ACL_DEFINED_PARAM.enomem {
            unsafe { __archive_errx_safe(1 as i32, "No memory\x00") };
        }
        return 0 as *mut wchar_t;
    }
    count = 0 as i32;
    if want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 as i32 {
        unsafe {
            append_entry_w(
                &mut wp,
                0 as *const wchar_t,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj,
                flags,
                0 as *const wchar_t,
                ((*acl).mode & 0o700 as u32) as i32,
                -1,
            )
        };
        let fresh0 = wp;
        wp = unsafe { wp.offset(1) };
        unsafe { *fresh0 = separator };
        unsafe {
            append_entry_w(
                &mut wp,
                0 as *const wchar_t,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj,
                flags,
                0 as *const wchar_t,
                ((*acl).mode & 0o70 as u32) as i32,
                -1,
            )
        };
        let fresh1 = wp;
        unsafe {
            wp = wp.offset(1);
            *fresh1 = separator;
            append_entry_w(
                &mut wp,
                0 as *const wchar_t,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other,
                flags,
                0 as *const wchar_t,
                ((*acl).mode & 0o7 as u32) as i32,
                -1,
            )
        };
        count += 3
    }
    let safe_acl = unsafe { &mut *acl };
    ap = safe_acl.acl_head;
    while !ap.is_null() {
        let mut safe_ap = unsafe { &mut *ap };
        if !(safe_ap.type_0 & want_type == 0 as i32) {
            /*
             * Filemode-mapping ACL entries are stored exclusively in
             * ap->mode so they should not be in the list
             */
            if !(safe_ap.type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
                && (safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                    || safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                    || safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other))
            {
                if safe_ap.type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default
                    && flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_mark_default
                        != 0 as i32
                {
                    prefix = wchar::wchz!("default:").as_ptr();
                } else {
                    prefix = 0 as *const wchar_t
                }
                r = unsafe { archive_mstring_get_wcs_safe(a, &mut safe_ap.name, &mut wname) };
                if r == 0 {
                    if count > 0 {
                        let fresh2 = wp;
                        unsafe {
                            wp = wp.offset(1);
                            *fresh2 = separator
                        }
                    }
                    if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_extra_id != 0 {
                        id = safe_ap.id
                    } else {
                        id = -1
                    }
                    append_entry_w(
                        &mut wp,
                        prefix,
                        safe_ap.type_0,
                        safe_ap.tag,
                        flags,
                        wname,
                        safe_ap.permset,
                        id,
                    );
                    count += 1
                } else if r < 0 && errno_location == ARCHIVE_ACL_DEFINED_PARAM.enomem {
                    unsafe { free_safe(ws as *mut ()) };
                    return 0 as *mut wchar_t;
                }
            }
        }
        ap = safe_ap.next
    }
    /* Add terminating character */
    let fresh3 = wp;
    unsafe {
        wp = wp.offset(1);
        *fresh3 = '\u{0}' as wchar_t;
        len = wcslen(ws);
        if len as ssize_t > length - 1 {
            __archive_errx_safe(1 as i32, "Buffer overrun\x00");
        }
        if !text_len.is_null() {
            *text_len = len as ssize_t
        }
    }
    return ws;
}
fn append_id_w(mut wp: *mut *mut wchar_t, mut id: i32) {
    if id < 0 {
        id = 0
    }
    if id > 9 {
        append_id_w(wp, id / 10);
    }
    unsafe {
        let fresh4 = *wp;
        *wp = (*wp).offset(1);
        *fresh4 = wchar::wchz!("0123456789")[(id % 10) as usize]
    };
}
pub fn append_entry_w(
    wp: *mut *mut wchar_t,
    prefix: *const wchar_t,
    type_0: i32,
    tag: i32,
    flags: i32,
    mut wname: *const wchar_t,
    perm: i32,
    mut id: i32,
) {
    let mut i: i32 = 0;
    if !prefix.is_null() {
        unsafe {
            wcscpy_safe(*wp, prefix);
            *wp = (*wp).offset(wcslen(*wp) as isize)
        }
    }
    if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj {
        wname = 0 as *const wchar_t;
        id = -1;
        if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 as i32 {
            unsafe { wcscpy_safe(*wp, wchar::wchz!("owner@").as_ptr()) };
        } else {
            unsafe { wcscpy_safe(*wp, wchar::wchz!("user").as_ptr()) };
        }
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user {
        unsafe { wcscpy_safe(*wp, wchar::wchz!("user").as_ptr()) };
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj {
        wname = 0 as *const wchar_t;
        id = -(1 as i32);
        if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 as i32 {
            unsafe { wcscpy_safe(*wp, wchar::wchz!("group@").as_ptr()) };
        } else {
            unsafe { wcscpy_safe(*wp, wchar::wchz!("group").as_ptr()) };
        }
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group {
        unsafe { wcscpy_safe(*wp, wchar::wchz!("group").as_ptr()) };
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask {
        unsafe { wcscpy_safe(*wp, wchar::wchz!("mask").as_ptr()) };
        wname = 0 as *const wchar_t;
        id = -1;
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other {
        unsafe { wcscpy_safe(*wp, wchar::wchz!("other").as_ptr()) };
        wname = 0 as *const wchar_t;
        id = -1;
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_everyone {
        unsafe { wcscpy_safe(*wp, wchar::wchz!("everyone@").as_ptr()) };
        wname = 0 as *const wchar_t;
        id = -1;
    }

    unsafe {
        *wp = (*wp).offset(wcslen(*wp) as isize);
        let fresh5 = *wp;
        *wp = (*wp).offset(1);
        *fresh5 = ':' as wchar_t;
    }
    if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0 as i32
        || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
        || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
    {
        if !wname.is_null() {
            unsafe {
                wcscpy_safe(*wp, wname);
                *wp = (*wp).offset(wcslen(*wp) as isize)
            }
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
            unsafe {
                let fresh6 = *wp;
                *wp = (*wp).offset(1);
                *fresh6 = ':' as wchar_t
            }
        }
    }
    if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0 as i32 {
        /* POSIX.1e ACL perms */
        unsafe {
            let fresh7 = *wp;
            *wp = (*wp).offset(1);
            *fresh7 = if perm & 0o444 as i32 != 0 {
                'r' as wchar_t
            } else {
                '-' as wchar_t
            };
        }
        unsafe {
            let fresh8 = *wp;
            *wp = (*wp).offset(1);
            *fresh8 = if perm & 0o222 as i32 != 0 {
                'w' as wchar_t
            } else {
                '-' as wchar_t
            }
        };
        unsafe {
            let fresh9 = *wp;
            *wp = (*wp).offset(1);
            *fresh9 = if perm & 0o111 as i32 != 0 {
                'x' as wchar_t
            } else {
                '-' as wchar_t
            }
        }
    } else {
        /* NFSv4 ACL perms */
        i = 0 as i32;
        unsafe {
            while i < nfsv4_acl_perm_map_size {
                if perm & nfsv4_acl_perm_map[i as usize].perm != 0 {
                    let fresh10 = *wp;
                    *wp = (*wp).offset(1);
                    *fresh10 = nfsv4_acl_perm_map[i as usize].wc
                } else if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_compact
                    == 0 as i32
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
        }
        i = 0 as i32;
        unsafe {
            while i < nfsv4_acl_flag_map_size {
                if perm & nfsv4_acl_flag_map[i as usize].perm != 0 {
                    let fresh13 = *wp;
                    *wp = (*wp).offset(1);
                    *fresh13 = nfsv4_acl_flag_map[i as usize].wc
                } else if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_compact
                    == 0 as i32
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
            if type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_allow {
                wcscpy_safe(*wp, wchar::wchz!("allow").as_ptr());
            } else if type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_deny {
                wcscpy_safe(*wp, wchar::wchz!("deny").as_ptr());
            } else if type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_audit {
                wcscpy_safe(*wp, wchar::wchz!("audit").as_ptr());
            } else if type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_alram {
                wcscpy_safe(*wp, wchar::wchz!("alarm").as_ptr());
            }

            *wp = (*wp).offset(wcslen_safe(*wp) as isize)
        }
    }
    if id != -1 {
        unsafe {
            let fresh16 = *wp;
            *wp = (*wp).offset(1);
            *fresh16 = ':' as wchar_t;
            append_id_w(wp, id);
        }
    };
}
/*
 * Generate a text version of the ACL. The flags parameter controls
 * the type and style of the generated ACL.
 */

#[no_mangle]
pub fn archive_acl_to_text_l(
    mut acl: *mut archive_acl,
    text_len: *mut ssize_t,
    mut flags: i32,
    sc: *mut archive_string_conv,
) -> *mut u8 {
    let mut count: i32;
    let mut length: ssize_t;
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
    if length == 0 as i64 {
        return 0 as *mut u8;
    }
    if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_separator_comma != 0 {
        separator = ',' as u8
    } else {
        separator = '\n' as u8
    }
    /* Now, allocate the string and actually populate it. */
    s = unsafe { malloc_safe((length as u64).wrapping_mul(size_of::<u8>() as u64)) } as *mut u8;
    p = s;
    if p.is_null() {
        unsafe {
            if *__errno_location_safe() == ARCHIVE_ACL_DEFINED_PARAM.enomem {
                __archive_errx_safe(1 as i32, "No memory\x00");
            }
        }
        return 0 as *mut u8;
    }
    count = 0;
    if want_type & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access != 0 as i32 {
        unsafe {
            append_entry(
                &mut p,
                0 as *const u8,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj,
                flags,
                0 as *const u8,
                ((*acl).mode & 0o700 as u32) as i32,
                -1,
            )
        };
        let fresh17 = p;
        unsafe {
            p = p.offset(1);
            *fresh17 = separator;
            append_entry(
                &mut p,
                0 as *const u8,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj,
                flags,
                0 as *const u8,
                ((*acl).mode & 0o70 as u32) as i32,
                -1,
            )
        };
        let fresh18 = p;
        unsafe {
            p = p.offset(1);
            *fresh18 = separator;
            append_entry(
                &mut p,
                0 as *const u8,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access,
                ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other,
                flags,
                0 as *const u8,
                ((*acl).mode & 0o7 as u32) as i32,
                -1,
            )
        };
        count += 3
    }
    let safe_acl = unsafe { &mut *acl };
    ap = safe_acl.acl_head;
    while !ap.is_null() {
        let mut safe_ap = unsafe { &mut *ap };
        if !(safe_ap.type_0 & want_type == 0) {
            /*
             * Filemode-mapping ACL entries are stored exclusively in
             * ap->mode so they should not be in the list
             */
            if !(safe_ap.type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
                && (safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                    || safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                    || safe_ap.tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other))
            {
                if safe_ap.type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default
                    && flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_mark_default
                        != 0 as i32
                {
                    prefix = b"default:\x00" as *const u8
                } else {
                    prefix = 0 as *const u8
                }
                r = unsafe {
                    archive_mstring_get_mbs_l_safe(
                        0 as *mut archive,
                        &mut safe_ap.name,
                        &mut name,
                        &mut len,
                        sc,
                    )
                };
                if r != 0 {
                    unsafe { free_safe(s as *mut ()) };
                    return 0 as *mut u8;
                }
                if count > 0 {
                    let fresh19 = p;
                    unsafe {
                        p = p.offset(1);
                        *fresh19 = separator
                    }
                }
                if name.is_null()
                    || flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_extra_id != 0
                {
                    id = safe_ap.id
                } else {
                    id = -(1 as i32)
                }

                append_entry(
                    &mut p,
                    prefix,
                    safe_ap.type_0,
                    safe_ap.tag,
                    flags,
                    name,
                    safe_ap.permset,
                    id,
                );
                count += 1
            }
        }
        ap = safe_ap.next
    }
    /* Add terminating character */
    let fresh20 = p;
    unsafe {
        p = p.offset(1);
        *fresh20 = '\u{0}' as u8;
        len = strlen_safe(s);
        if len as ssize_t > length - 1 {
            __archive_errx_safe(1 as i32, "Buffer overrun\x00");
        }
        if !text_len.is_null() {
            *text_len = len as ssize_t
        }
    }
    return s;
}
unsafe fn append_id(mut p: *mut *mut u8, mut id: i32) {
    if id < 0 {
        id = 0
    }
    if id > 9 {
        append_id(p, id / 10);
    }
    let fresh21 = *p;
    *p = (*p).offset(1);
    *fresh21 =
        (*::std::mem::transmute::<&[u8; 11], &[u8; 11]>(b"0123456789\x00"))[(id % 10) as usize];
}
fn append_entry(
    p: *mut *mut u8,
    prefix: *const u8,
    type_0: i32,
    tag: i32,
    flags: i32,
    mut name: *const u8,
    perm: i32,
    mut id: i32,
) {
    let mut i: i32 = 0;
    if !prefix.is_null() {
        unsafe {
            strcpy_safe(*p, prefix);
            *p = (*p).offset(strlen_safe(*p) as isize)
        }
    }
    if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj {
        name = 0 as *const u8;
        id = -1;
        if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 {
            unsafe { strcpy_safe(*p, b"owner@\x00" as *const u8) };
        } else {
            unsafe { strcpy_safe(*p, b"user\x00" as *const u8) };
        }
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user {
        unsafe { strcpy_safe(*p, b"user\x00" as *const u8) };
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj {
        name = 0 as *const u8;
        id = -1;
        if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 != 0 {
            unsafe { strcpy_safe(*p, b"group@\x00" as *const u8) };
        } else {
            unsafe { strcpy_safe(*p, b"group\x00" as *const u8) };
        }
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group {
        unsafe { strcpy_safe(*p, b"group\x00" as *const u8) };
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask {
        unsafe { strcpy_safe(*p, b"mask\x00" as *const u8) };
        name = 0 as *const u8;
        id = -1;
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other {
        unsafe { strcpy_safe(*p, b"other\x00" as *const u8) };
        name = 0 as *const u8;
        id = -1;
    } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_everyone {
        unsafe { strcpy_safe(*p, b"everyone@\x00" as *const u8) };
        name = 0 as *const u8;
        id = -1;
    }

    unsafe {
        *p = (*p).offset(strlen_safe(*p) as isize);
        let fresh22 = *p;
        *p = (*p).offset(1);
        *fresh22 = ':' as i32 as u8
    };
    if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0
        || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
        || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
    {
        if !name.is_null() {
            unsafe {
                strcpy_safe(*p, name);
                *p = (*p).offset(strlen_safe(*p) as isize)
            }
        } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
            || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
        {
            unsafe { append_id(p, id) };
            if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 == 0 {
                id = -(1 as i32)
            }
        }
        /* Solaris style has no second colon after other and mask */
        if flags & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_style_solaris == 0
            || tag != ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other
                && tag != ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask
        {
            unsafe {
                let fresh23 = *p;
                *p = (*p).offset(1);
                *fresh23 = ':' as u8
            }
        }
    }
    if type_0 & ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e != 0 {
        /* POSIX.1e ACL perms */
        unsafe {
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
        }
    } else {
        /* NFSv4 ACL perms */
        i = 0;
        unsafe {
            while i < nfsv4_acl_perm_map_size {
                if perm & nfsv4_acl_perm_map[i as usize].perm != 0 {
                    let fresh27 = *p;
                    *p = (*p).offset(1);
                    *fresh27 = nfsv4_acl_perm_map[i as usize].c
                } else if flags & 0x10 as i32 == 0 {
                    let fresh28 = *p;
                    *p = (*p).offset(1);
                    *fresh28 = '-' as u8
                }
                i += 1
            }
            let fresh29 = *p;
            *p = (*p).offset(1);
            *fresh29 = ':' as u8;
            i = 0 as i32;
            while i < nfsv4_acl_flag_map_size {
                if perm & nfsv4_acl_flag_map[i as usize].perm != 0 {
                    let fresh30 = *p;
                    *p = (*p).offset(1);
                    *fresh30 = nfsv4_acl_flag_map[i as usize].c
                } else if flags & 0x10 as i32 == 0 {
                    let fresh31 = *p;
                    *p = (*p).offset(1);
                    *fresh31 = '-' as u8
                }
                i += 1
            }
            let fresh32 = *p;
            *p = (*p).offset(1);
            *fresh32 = ':' as u8
        };
        if type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_allow {
            unsafe { strcpy_safe(*p, b"allow\x00" as *const u8) };
        } else if type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_deny {
            unsafe { strcpy_safe(*p, b"deny\x00" as *const u8) };
        } else if type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_audit {
            unsafe { strcpy_safe(*p, b"audit\x00" as *const u8) };
        } else if type_0 == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_alram {
            unsafe { strcpy_safe(*p, b"alarm\x00" as *const u8) };
        }

        unsafe { *p = (*p).offset(strlen_safe(*p) as isize) }
    }
    if id != -1 {
        unsafe {
            let fresh33 = *p;
            *p = (*p).offset(1);
            *fresh33 = ':' as u8;
            append_id(p, id)
        };
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
pub fn archive_acl_from_text_w(
    acl: *mut archive_acl,
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

    let mut fields: i32;
    let mut n: i32;
    let mut r: i32;
    let mut sol: i32;
    let mut ret: i32;
    let mut type_0: i32;
    let mut types: i32;
    let mut tag: i32;
    let mut permset: i32;
    let mut id: i32;
    let mut len: size_t;
    let mut sep: wchar_t = 0;
    let mut s_char: wchar_t;

    ret = 0;
    types = 0;
    if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e {
        want_type = 0x100 as i32;
        numfields = 5;
    } else if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
        || want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default
    {
        numfields = 5;
    } else if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 {
        numfields = 6;
    } else {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_fatal;
    }

    /* Comment, skip entry */
    while !text.is_null() && unsafe { *text } != '\u{0}' as wchar_t {
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
            && unsafe { *field[0 as usize].start } == '#' as wchar_t
        {
            continue;
        }
        n = 0;
        sol = 0;
        id = -1;
        permset = 0;
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
            s = field[0 as usize].start;
            unsafe { len = field[0 as usize].end.offset_from(field[0 as usize].start) as size_t };
            unsafe {
                if *s == 'd' as wchar_t
                    && (len == 1 as u64
                        || len >= 7 as u64
                            && wmemcmp_safe(
                                s.offset(1 as isize),
                                wchar::wchz!("efault").as_ptr(),
                                6 as u64,
                            ) == 0 as i32)
                {
                    type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default;
                    if len > 7 as u64 {
                        field[0 as usize].start = field[0 as usize].start.offset(7 as isize)
                    } else {
                        n = 1
                    }
                } else {
                    type_0 = want_type
                }
            }
            /* Check for a numeric ID in field n+1 or n+3. */

            isint_w(
                field[(n + 1) as usize].start,
                field[(n + 1) as usize].end,
                &mut id,
            );
            /* Field n+3 is optional. */
            if id == -1 && fields > n + 3 as i32 {
                isint_w(
                    field[(n + 3) as usize].start,
                    field[(n + 3) as usize].end,
                    &mut id,
                );
            }
            tag = 0;
            s = field[n as usize].start;
            unsafe { st = field[n as usize].start.offset(1 as isize) };
            len = unsafe { field[n as usize].end.offset_from(field[n as usize].start) } as size_t;
            s_char = unsafe { *s as wchar_t };
            if s_char == 'u' as wchar_t {
                if len == 1
                    || len == 4 && unsafe { wmemcmp_safe(st, wchar::wchz!("ser").as_ptr(), 3) } == 0
                {
                    tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                }
            } else if s_char == 'g' as wchar_t {
                if len == 1
                    || len == 5
                        && unsafe { wmemcmp_safe(st, wchar::wchz!("roup").as_ptr(), 4) } == 0
                {
                    tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                }
            } else if s_char == 'o' as wchar_t {
                if len == 1
                    || len == 5
                        && unsafe { wmemcmp_safe(st, wchar::wchz!("ther").as_ptr(), 4) } == 0
                {
                    tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other
                }
            } else if s_char == 'm' as wchar_t {
                if len == 1
                    || len == 4 && unsafe { wmemcmp_safe(st, wchar::wchz!("ask").as_ptr(), 3) } == 0
                {
                    tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask
                }
            } else {
            }
            if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other
                || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask
            {
                if fields == n + 2
                    && field[(n + 1) as usize].start < field[(n + 1) as usize].end
                    && ismode_w(
                        field[(n + 1) as usize].start,
                        field[(n + 1) as usize].end,
                        &mut permset,
                    ) != 0
                {
                    /* This is Solaris-style "other:rwx" */
                    sol = 1
                } else if fields == n + 3
                    && field[(n + 1) as usize].start < field[(n + 1) as usize].end
                {
                    /* Invalid mask or other field */
                    ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                    continue;
                }
            } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
            {
                if id != -1 || field[(n + 1) as usize].start < field[(n + 1) as usize].end {
                    name = field[(n + 1) as usize];
                    if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    } else {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
                    }
                }
            } else {
                /* Invalid tag, skip entry */
                ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                continue;
            }

            /*
             * Without "default:" we expect mode in field 2
             * Exception: Solaris other and mask fields
             */
            if permset == 0
                && ismode_w(
                    field[(n + 2 - sol) as usize].start,
                    field[(n + 2 - sol) as usize].end,
                    &mut permset,
                ) == 0
            {
                /* Invalid mode, skip entry */
                ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                continue;
            }
        } else {
            /* NFS4 ACLs */
            s = field[0 as usize].start;
            unsafe { len = field[0 as usize].end.offset_from(field[0 as usize].start) as size_t };
            tag = 0;
            match len {
                4 => {
                    if unsafe { wmemcmp_safe(s, wchar::wchz!("user").as_ptr(), 4 as u64) } == 0 {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    }
                }
                5 => {
                    if unsafe { wmemcmp_safe(s, wchar::wchz!("group").as_ptr(), 5 as u64) } == 0 {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
                    }
                }
                6 => {
                    if unsafe { wmemcmp_safe(s, wchar::wchz!("owner@").as_ptr(), 6 as u64) } == 0 {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                    } else if unsafe { wmemcmp_safe(s, wchar::wchz!("group@").as_ptr(), len) } == 0
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                    }
                }
                9 => {
                    if unsafe { wmemcmp_safe(s, wchar::wchz!("everyone@").as_ptr(), 9 as u64) } == 0
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_everyone
                    }
                }
                _ => {}
            }
            if tag == 0 {
                /* Invalid tag, skip entry */
                ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                continue;
            } else {
                if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
                {
                    n = 1;
                    name = field[1 as usize];
                    isint_w(name.start, name.end, &mut id);
                } else {
                    n = 0
                }
                if is_nfs4_perms_w(
                    field[(1 + n) as usize].start,
                    field[(1 + n) as usize].end,
                    &mut permset,
                ) == 0
                    || is_nfs4_flags_w(
                        field[(2 + n) as usize].start,
                        field[(2 + n) as usize].end,
                        &mut permset,
                    ) == 0
                {
                    /* Invalid NFSv4 perms, skip entry */
                    ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                    continue;
                } else {
                    s = field[(3 + n) as usize].start;
                    len = unsafe {
                        field[(3 + n) as usize]
                            .end
                            .offset_from(field[(3 as i32 + n) as usize].start)
                    } as size_t;
                    type_0 = 0 as i32;
                    if len == 4 as u64 {
                        if unsafe { wmemcmp_safe(s, wchar::wchz!("deny").as_ptr(), 4 as u64) } == 0
                        {
                            type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_deny
                        }
                    } else if len == 5 as u64 {
                        if unsafe { wmemcmp_safe(s, wchar::wchz!("allow").as_ptr(), 5 as u64) } == 0
                        {
                            type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_allow
                        } else if unsafe {
                            wmemcmp_safe(s, wchar::wchz!("audit").as_ptr(), 5 as u64)
                        } == 0
                        {
                            type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_audit
                        } else if unsafe {
                            wmemcmp_safe(s, wchar::wchz!("alarm").as_ptr(), 5 as u64)
                        } == 0
                        {
                            type_0 = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_alram
                        }
                    }
                    if type_0 == 0 {
                        /* Invalid entry type, skip entry */
                        ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                        continue;
                    } else {
                        isint_w(
                            field[(4 + n) as usize].start,
                            field[(4 + n) as usize].end,
                            &mut id,
                        );
                    }
                }
            }
        }
        /* Add entry to the internal list. */
        r = unsafe {
            archive_acl_add_entry_w_len(
                acl,
                type_0,
                permset,
                tag,
                id,
                name.start,
                name.end.offset_from(name.start) as i64 as size_t,
            )
        };
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
fn isint_w(mut start: *const wchar_t, end: *const wchar_t, result: *mut i32) -> i32 {
    let mut n: i32 = 0;
    if start >= end {
        return 0;
    }
    while start < end {
        if unsafe { *start } < '0' as wchar_t || unsafe { *start } > '9' as wchar_t {
            return 0;
        }
        if n > INT_MAX / 10
            || n == INT_MAX / 10
                && unsafe { *start } - '0' as wchar_t > INT_MAX as wchar_t % 10 as wchar_t
        {
            n = INT_MAX
        } else {
            n *= 10;
            n += unsafe { *start } as i32 - '0' as i32
        }
        start = unsafe { start.offset(1) }
    }
    unsafe {
        *result = n;
    }
    return 1;
}
/*
 * Parse a string as a mode field.  Returns true if
 * the string is non-empty and consists only of mode characters,
 * false otherwise.
 */
fn ismode_w(start: *const wchar_t, end: *const wchar_t, permset: *mut i32) -> i32 {
    let mut p: *const wchar_t = 0 as *const wchar_t;
    if start >= end {
        return 0;
    }
    p = start;
    unsafe { *permset = 0 };
    while p < end {
        let p_char = unsafe { *p };
        p = unsafe { p.offset(1) };
        if p_char == 'r' as wchar_t || p_char == 'R' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read };
        } else if p_char == 'w' as wchar_t || p_char == 'W' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write };
        } else if p_char == 'x' as wchar_t || p_char == 'X' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_execute };
        } else if p_char == '-' as wchar_t {
        } else {
            return 0;
        }
    }
    return 1;
}
/*
 * Parse a string as a NFS4 ACL permission field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * permission characters, false otherwise
 */
fn is_nfs4_perms_w(start: *const wchar_t, end: *const wchar_t, permset: *mut i32) -> i32 {
    let mut p: *const wchar_t = start;
    while p < end {
        let p_char = unsafe { *p };
        unsafe { p = p.offset(1) };
        if p_char == 'r' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_data };
        } else if p_char == 'w' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_data };
        } else if p_char == 'x' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_execute };
        } else if p_char == 'p' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_append_data };
        } else if p_char == 'D' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_delete_child };
        } else if p_char == 'd' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_delete };
        } else if p_char == 'a' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_attributes };
        } else if p_char == 'A' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_attributes };
        } else if p_char == 'R' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_named_attrs };
        } else if p_char == 'W' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_named_attrs };
        } else if p_char == 'c' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_acl };
        } else if p_char == 'C' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_acl };
        } else if p_char == 'o' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_owner };
        } else if p_char == 's' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_synchronize };
        } else if p_char == '-' as wchar_t {
        } else {
            return 0;
        }
    }
    return 1 as i32;
}
/*
 * Parse a string as a NFS4 ACL flags field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * flag characters, false otherwise
 */
fn is_nfs4_flags_w(start: *const wchar_t, end: *const wchar_t, permset: *mut i32) -> i32 {
    let mut p: *const wchar_t = start;
    while p < end {
        let p_char = unsafe { *p };
        unsafe { p = p.offset(1) };
        if p_char == 'f' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_file_inherit };
        } else if p_char == 'd' as wchar_t {
            unsafe {
                *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_directory_inherit
            };
        } else if p_char == 'i' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_inherit_only };
        } else if p_char == 'n' as wchar_t {
            unsafe {
                *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_no_propagate_inherit
            };
        } else if p_char == 'S' as wchar_t {
            unsafe {
                *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_successful_access
            };
        } else if p_char == 'F' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_failed_access };
        } else if p_char == 'I' as wchar_t {
            unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_inherited };
        } else if p_char == '-' as wchar_t {
        } else {
            return 0;
        }
    }
    return 1;
}
/*
 * Match "[:whitespace:]*(.*)[:whitespace:]*[:,\n]".  *wp is updated
 * to point to just after the separator.  *start points to the first
 * character of the matched text and *end just after the last
 * character of the matched identifier.  In particular *end - *start
 * is the length of the field body, not including leading or trailing
 * whitespace.
 */
fn next_field_w(
    wp: *mut *const wchar_t,
    start: *mut *const wchar_t,
    end: *mut *const wchar_t,
    sep: *mut wchar_t,
) {
    /* Skip leading whitespace to find start of field. */
    unsafe {
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
pub fn archive_acl_from_text_l(
    acl: *mut archive_acl,
    mut text: *const u8,
    mut want_type: i32,
    sc: *mut archive_string_conv,
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
    if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_posix1e {
        want_type = 0x100 as i32;
        numfields = 5;
    } else if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_access
        || want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_default
    {
        numfields = 5;
    } else if want_type == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_type_nfs4 {
        numfields = 6;
    } else {
        return ARCHIVE_ACL_DEFINED_PARAM.archive_fatal;
    }

    ret = 0;
    types = 0;
    /* Comment, skip entry */
    while !text.is_null() && unsafe { *text } as i32 != '\u{0}' as i32 {
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
        if !field[0 as usize].start.is_null()
            && unsafe { *field[0 as usize].start } as i32 == '#' as i32
        {
            continue;
        }
        n = 0;
        sol = 0;
        id = -1;
        permset = 0;
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
            s = field[0 as usize].start;
            unsafe { len = field[0 as usize].end.offset_from(field[0 as usize].start) as size_t };
            if unsafe { *s } as i32 == 'd' as i32
                && (len == 1 as u64
                    || len >= 7 as u64
                        && unsafe {
                            memcmp_safe(
                                s.offset(1 as isize) as *const (),
                                b"efault\x00" as *const u8 as *const (),
                                6 as u64,
                            )
                        } == 0 as i32)
            {
                type_0 = 0x200 as i32;
                if len > 7 as u64 {
                    field[0 as usize].start = unsafe { field[0 as usize].start.offset(7 as isize) }
                } else {
                    n = 1 as i32
                }
            } else {
                type_0 = want_type
            }
            /* Check for a numeric ID in field n+1 or n+3. */

            isint(
                field[(n + 1) as usize].start,
                field[(n + 1) as usize].end,
                &mut id,
            );
            /* Field n+3 is optional. */
            if id == -1 && fields > n + 3 {
                isint(
                    field[(n + 3) as usize].start,
                    field[(n + 3) as usize].end,
                    &mut id,
                );
            }
            tag = 0;
            s = field[n as usize].start;
            st = unsafe { field[n as usize].start.offset(1 as isize) };
            len = unsafe { field[n as usize].end.offset_from(field[n as usize].start) } as size_t;
            if len == 0 as u64 {
                ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                continue;
            } else {
                let s_char = unsafe { *s as char };
                match s_char {
                    'u' => {
                        if len == 1 as u64
                            || len == 4 as u64
                                && unsafe {
                                    memcmp_safe(
                                        st as *const (),
                                        b"ser\x00" as *const u8 as *const (),
                                        3 as u64,
                                    )
                                } == 0
                        {
                            tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                        }
                    }
                    'g' => {
                        if len == 1 as u64
                            || len == 5 as u64
                                && unsafe {
                                    memcmp_safe(
                                        st as *const (),
                                        b"roup\x00" as *const u8 as *const (),
                                        4 as u64,
                                    )
                                } == 0
                        {
                            tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                        }
                    }
                    'o' => {
                        if len == 1 as u64
                            || len == 5 as u64
                                && unsafe {
                                    memcmp_safe(
                                        st as *const (),
                                        b"ther\x00" as *const u8 as *const (),
                                        4 as u64,
                                    )
                                } == 0
                        {
                            tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other
                        }
                    }
                    'm' => {
                        if len == 1 as u64
                            || len == 4 as u64
                                && unsafe {
                                    memcmp_safe(
                                        st as *const (),
                                        b"ask\x00" as *const u8 as *const (),
                                        3 as u64,
                                    )
                                } == 0
                        {
                            tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask
                        }
                    }
                    _ => {}
                }
                if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_other
                    || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_mask
                {
                    if fields == n + 2
                        && field[(n + 1) as usize].start < field[(n + 1) as usize].end
                        && ismode(
                            field[(n + 1) as usize].start,
                            field[(n + 1) as usize].end,
                            &mut permset,
                        ) != 0
                    {
                        /* This is Solaris-style "other:rwx" */
                        sol = 1
                    } else if fields == n + 3
                        && field[(n + 1) as usize].start < field[(n + 1) as usize].end
                    {
                        /* Invalid mask or other field */
                        ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                        continue;
                    }
                } else if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                    || tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                {
                    if id != -(1 as i32)
                        || field[(n + 1) as usize].start < field[(n + 1) as usize].end
                    {
                        name = field[(n + 1) as usize];
                        if tag == ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj {
                            tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                        } else {
                            tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
                        }
                    }
                } else {
                    ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                    continue;
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
                    ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                    continue;
                }
            }
        } else {
            /* NFS4 ACLs */
            s = field[0 as usize].start;
            len = unsafe { field[0 as usize].end.offset_from(field[0 as usize].start) } as size_t;
            tag = 0 as i32;
            match len {
                4 => {
                    if unsafe {
                        memcmp_safe(
                            s as *const (),
                            b"user\x00" as *const u8 as *const (),
                            4 as u64,
                        )
                    } == 0
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user
                    }
                }
                5 => {
                    if unsafe {
                        memcmp_safe(
                            s as *const (),
                            b"group\x00" as *const u8 as *const (),
                            5 as i32 as u64,
                        )
                    } == 0
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group
                    }
                }
                6 => {
                    if unsafe {
                        memcmp_safe(
                            s as *const (),
                            b"owner@\x00" as *const u8 as *const (),
                            6 as u64,
                        )
                    } == 0
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_user_obj
                    } else if unsafe {
                        memcmp_safe(
                            s as *const (),
                            b"group@\x00" as *const u8 as *const (),
                            6 as u64,
                        )
                    } == 0
                    {
                        tag = ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_group_obj
                    }
                }
                9 => {
                    if unsafe {
                        memcmp_safe(
                            s as *const (),
                            b"everyone@\x00" as *const u8 as *const (),
                            9 as u64,
                        )
                    } == 0
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
                    n = 1;
                    name = field[1 as usize];
                    isint(name.start, name.end, &mut id);
                } else {
                    n = 0
                }
                unsafe {
                    if is_nfs4_perms(
                        field[(1 + n) as usize].start,
                        field[(1 + n) as usize].end,
                        &mut permset,
                    ) == 0
                        || is_nfs4_flags(
                            field[(2 + n) as usize].start,
                            field[(2 + n) as usize].end,
                            &mut permset,
                        ) == 0
                    {
                        /* Invalid NFSv4 flags, skip entry */
                        ret = ARCHIVE_ACL_DEFINED_PARAM.archive_warn;
                        continue;
                    } else {
                        s = field[(3 + n) as usize].start;
                        len = field[(3 + n) as usize]
                            .end
                            .offset_from(field[(3 as i32 + n) as usize].start)
                            as size_t;
                        type_0 = 0;
                        if len == 4 as u64 {
                            if memcmp_safe(
                                s as *const (),
                                b"deny\x00" as *const u8 as *const (),
                                4 as u64,
                            ) == 0
                            {
                                type_0 = 0x800 as i32
                            }
                        } else if len == 5 as u64 {
                            if memcmp_safe(
                                s as *const (),
                                b"allow\x00" as *const u8 as *const (),
                                5 as u64,
                            ) == 0
                            {
                                type_0 = 0x400 as i32
                            } else if memcmp_safe(
                                s as *const (),
                                b"audit\x00" as *const u8 as *const (),
                                5 as u64,
                            ) == 0
                            {
                                type_0 = 0x1000 as i32
                            } else if memcmp_safe(
                                s as *const (),
                                b"alarm\x00" as *const u8 as *const (),
                                5 as u64,
                            ) == 0
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
        }
        /* Add entry to the internal list. */
        r = archive_acl_add_entry_len_l(
            acl,
            type_0,
            permset,
            tag,
            id,
            name.start,
            unsafe { name.end.offset_from(name.start) } as size_t,
            sc,
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
fn isint(mut start: *const u8, end: *const u8, result: *mut i32) -> i32 {
    let mut n: i32 = 0;
    if start >= end {
        return 0;
    }
    while start < end {
        if (unsafe { *start } as i32) < '0' as i32 || unsafe { *start } as i32 > '9' as i32 {
            return 0;
        }
        if n > INT_MAX / 10
            || n == INT_MAX / 10 as i32
                && unsafe { *start } as i32 - '0' as i32 > INT_MAX as i32 % 10 as i32
        {
            n = INT_MAX as i32
        } else {
            n *= 10 as i32;
            n += unsafe { *start } as i32 - '0' as i32
        }
        start = unsafe { start.offset(1) }
    }
    unsafe { *result = n };
    return 1 as i32;
}
/*
 * Parse a string as a mode field.  Returns true if
 * the string is non-empty and consists only of mode characters,
 * false otherwise.
 */
fn ismode(start: *const u8, end: *const u8, permset: *mut i32) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    if start >= end {
        return 0;
    }
    p = start;
    unsafe {
        *permset = 0 as i32;
    }
    while p < end {
        let p_char = unsafe { *p as char };
        p = unsafe { p.offset(1) };
        match p_char {
            'r' | 'R' => unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read },
            'w' | 'W' => unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write },
            'x' | 'X' => unsafe { *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_execute },
            '-' => {}
            _ => return 0,
        }
    }
    return 1;
}
/*
 * Parse a string as a NFS4 ACL permission field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * permission characters, false otherwise
 */
fn is_nfs4_perms(start: *const u8, end: *const u8, permset: *mut i32) -> i32 {
    let mut p: *const u8 = start;
    while p < end {
        let p_char = unsafe { *p as char };
        unsafe {
            p = p.offset(1);
            match p_char {
                'r' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_data,
                'w' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_data,
                'x' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_execute,
                'p' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_append_data,
                'D' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_delete_child,
                'd' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_delete,
                'a' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_attributes,
                'A' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_attributes,
                'R' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_named_attrs,
                'W' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_named_attrs,
                'c' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_read_acl,
                'C' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_acl,
                'o' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_write_owner,
                's' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_synchronize,
                '-' => {}
                _ => return 0,
            }
        }
    }
    return 1;
}
/*
 * Parse a string as a NFS4 ACL flags field.
 * Returns true if the string is non-empty and consists only of NFS4 ACL
 * flag characters, false otherwise
 */
fn is_nfs4_flags(start: *const u8, end: *const u8, permset: *mut i32) -> i32 {
    let mut p: *const u8 = start;
    while p < end {
        unsafe {
            let p_char = *p as char;
            p = p.offset(1);
            match p_char {
                'f' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_file_inherit,
                'd' => {
                    *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_directory_inherit
                }
                'i' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_inherit_only,
                'n' => {
                    *permset |=
                        ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_no_propagate_inherit
                }
                'S' => {
                    *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_successful_access
                }
                'F' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_failed_access,
                'I' => *permset |= ARCHIVE_ACL_DEFINED_PARAM.archive_entry_acl_entry_inherited,
                '-' => {}
                _ => return 0,
            }
        }
    }
    return 1;
}
/*
 * Match "[:whitespace:]*(.*)[:whitespace:]*[:,\n]".  *wp is updated
 * to point to just after the separator.  *start points to the first
 * character of the matched text and *end just after the last
 * character of the matched identifier.  In particular *end - *start
 * is the length of the field body, not including leading or trailing
 * whitespace.
 */
fn next_field(p: *mut *const u8, start: *mut *const u8, end: *mut *const u8, sep: *mut u8) {
    /* Skip leading whitespace to find start of field. */
    unsafe {
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
            while **p as i32 != '\u{0}' as i32
                && **p as i32 != ',' as i32
                && **p as i32 != '\n' as i32
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
}

static nfsv4_acl_perm_map: [nfsv4_acl_perm_map_struct; 14] = [
    nfsv4_acl_perm_map_struct {
        perm: 0x8,
        c: 'r' as u8,
        wc: 'r' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x10,
        c: 'w' as u8,
        wc: 'w' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x1,
        c: 'x' as u8,
        wc: 'x' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x20,
        c: 'p' as u8,
        wc: 'p' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x800,
        c: 'd' as u8,
        wc: 'd' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x100,
        c: 'D' as u8,
        wc: 'D' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x200,
        c: 'a' as u8,
        wc: 'a' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x400,
        c: 'A' as u8,
        wc: 'A' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x40,
        c: 'R' as u8,
        wc: 'R' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x80,
        c: 'W' as u8,
        wc: 'W' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x1000,
        c: 'c' as u8,
        wc: 'c' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x2000,
        c: 'C' as u8,
        wc: 'C' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x4000,
        c: 'o' as u8,
        wc: 'o' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x8000,
        c: 's' as u8,
        wc: 's' as wchar_t,
    },
];
// Initialized in run_static_initializers
static mut nfsv4_acl_perm_map_size: i32 =
    (size_of::<[nfsv4_acl_perm_map_struct; 14]>() / size_of::<nfsv4_acl_perm_map_struct>()) as i32;
static nfsv4_acl_flag_map: [nfsv4_acl_perm_map_struct; 7] = [
    nfsv4_acl_perm_map_struct {
        perm: 0x2000000,
        c: 'f' as u8,
        wc: 'f' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x4000000,
        c: 'd' as u8,
        wc: 'd' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x10000000,
        c: 'i' as u8,
        wc: 'i' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x8000000,
        c: 'n' as u8,
        wc: 'n' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x20000000,
        c: 'S' as u8,
        wc: 'S' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x40000000,
        c: 'F' as u8,
        wc: 'F' as wchar_t,
    },
    nfsv4_acl_perm_map_struct {
        perm: 0x1000000,
        c: 'I' as u8,
        wc: 'I' as wchar_t,
    },
];
// Initialized in run_static_initializers
static mut nfsv4_acl_flag_map_size: i32 =
    (size_of::<[nfsv4_acl_perm_map_struct; 7]>() / size_of::<nfsv4_acl_perm_map_struct>()) as i32;
