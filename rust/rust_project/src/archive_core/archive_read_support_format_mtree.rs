use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;
use std::mem::size_of;

fn get_time_t_max() -> int64_t {
    /* ISO C allows time_t to be a floating-point type,
    but POSIX requires an integer type.  The following
    should work on any system that follows the POSIX
    conventions. */
    match () {
        #[cfg(HAVE_TIME_T_MAX)]
        _ => {
            return ARCHIVE_MTREE_DEFINED_PARAM.time_t_max;
        }
        #[cfg(not(HAVE_TIME_T_MAX))]
        _ => {
            if (0) < -1 as time_t {
                /* Time_t is unsigned */
                return !(0);
            } else if size_of::<time_t>() as u64 == size_of::<int64_t>() as u64 {
                return ARCHIVE_MTREE_DEFINED_PARAM.int64_max as time_t;
            } else {
                return ARCHIVE_MTREE_DEFINED_PARAM.int32_max as time_t;
            };
        }
    }
}
fn get_time_t_min() -> int64_t {
    match () {
        #[cfg(HAVE_TIME_T_MIN)]
        _ => {
            return ARCHIVE_MTREE_DEFINED_PARAM.time_t_min;
        }
        #[cfg(not(HAVE_TIME_T_MIN))]
        _ => {
            if (0) < -1 as time_t {
                /* Time_t is signed. */
                /* Assume it's the same as int64_t or int32_t */
                /* Time_t is unsigned */
                return 0;
            } else if size_of::<time_t>() as u64 == size_of::<int64_t>() as u64 {
                return ARCHIVE_MTREE_DEFINED_PARAM.int64_min as time_t;
            } else {
                return ARCHIVE_MTREE_DEFINED_PARAM.int32_min as time_t;
            };
        }
    }
}

fn mtree_strnlen(p: *const u8, maxlen: size_t) -> size_t {
    match () {
        #[cfg(HAVE_STRLEN)]
        _ => {
            return unsafe { strnlen_safe(p, maxlen) };
        }
        #[cfg(not(HAVE_STRLEN))]
        _ => {
            let i: size_t = 0;
            i = 0;
            while i <= maxlen {
                if unsafe { *p.offset(i as isize) as size_t == 0 } {
                    break;
                }
                i += 1
            }
            if i > maxlen {
                return -1 as size_t;
            }
            return i;
        }
    }
}
fn archive_read_format_mtree_options(a: *mut archive_read, key: *const u8, val: *const u8) -> i32 {
    let mut mtree: *mut mtree = 0 as *mut mtree;
    mtree = unsafe { (*(*a).format).data as *mut mtree };
    let mtree_safe = unsafe { &mut *mtree };
    if unsafe { strcmp_safe(key, b"checkfs\x00" as *const u8) } == 0 {
        /* Time_t is signed. */
        /* Allows to read information missing from the mtree from the file system */
        if val.is_null() || unsafe { *val.offset(0) as i32 == 0 } {
            mtree_safe.checkfs = 0
        } else {
            mtree_safe.checkfs = 1
        }
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    }
    /* Note: The "warn" return is just to inform the options
     * supervisor that we didn't handle it.  It will generate
     * a suitable error if no one used this option. */
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
}

fn free_options(mut head: *mut mtree_option) {
    let mut next: *mut mtree_option = 0 as *mut mtree_option;
    while !head.is_null() {
        let head_safe = unsafe { &mut *head };
        next = head_safe.next;
        unsafe { free_safe(head_safe.value as *mut ()) };
        unsafe { free_safe(head as *mut ()) };
        head = next
    }
}
fn mtree_cmp_node(n1: *const archive_rb_node, n2: *const archive_rb_node) -> i32 {
    let e1: *const mtree_entry = n1 as *const mtree_entry;
    let e2: *const mtree_entry = n2 as *const mtree_entry;
    unsafe { return strcmp_safe((*e1).name, (*e2).name) };
}
fn mtree_cmp_key(n: *const archive_rb_node, key: *const ()) -> i32 {
    let e: *const mtree_entry = n as *const mtree_entry;
    let e_safe = unsafe { &*e };
    return unsafe { strcmp_safe(e_safe.name, key as *const u8) };
}
#[no_mangle]
pub fn archive_read_support_format_mtree(_a: *mut archive) -> i32 {
    static rb_ops: archive_rb_tree_ops = unsafe {
        {
            let init = archive_rb_tree_ops {
                rbto_compare_nodes: Some(mtree_cmp_node),
                rbto_compare_key: Some(mtree_cmp_key),
            };
            init
        }
    };
    let a: *mut archive_read = _a as *mut archive_read;
    let mut mtree: *mut mtree = 0 as *mut mtree;
    let mut r: i32 = 0;
    let magic_test: i32 = unsafe {
        __archive_check_magic_safe(
            _a,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_read_magic,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_state_new,
            b"archive_read_support_format_mtree\x00" as *const u8,
        )
    };
    if magic_test == ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    mtree = unsafe { calloc_safe(1, size_of::<mtree>() as u64) } as *mut mtree;
    let a_safe = unsafe { &mut *a };
    if mtree.is_null() {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.enomem,
            b"Can\'t allocate mtree data\x00" as *const u8
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    let mtree_safe = unsafe { &mut *mtree };
    mtree_safe.checkfs = 0;
    mtree_safe.fd = -1;
    unsafe {
        __archive_rb_tree_init_safe(&mut mtree_safe.rbtree, &rb_ops);
    }
    r = unsafe {
        __archive_read_register_format_safe(
            a,
            mtree as *mut (),
            b"mtree\x00" as *const u8,
            Some(mtree_bid),
            Some(archive_read_format_mtree_options),
            Some(read_header),
            Some(read_data),
            Some(skip),
            None,
            Some(cleanup),
            None,
            None,
        )
    };
    if r != ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
        unsafe { free_safe(mtree as *mut ()) };
    }
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
fn cleanup(a: *mut archive_read) -> i32 {
    let mut mtree: *mut mtree = 0 as *mut mtree;
    let mut p: *mut mtree_entry = 0 as *mut mtree_entry;
    let mut q: *mut mtree_entry = 0 as *mut mtree_entry;
    let a_safe;
    let mtree_safe;
    unsafe {
        a_safe = &mut (*(*a).format);
    }
    mtree = a_safe.data as *mut mtree;
    unsafe {
        mtree_safe = &mut *mtree;
    }
    p = mtree_safe.entries;
    while !p.is_null() {
        let p_safe = unsafe { &mut *p };
        q = p_safe.next;
        unsafe { free_safe(p_safe.name as *mut ()) };
        free_options(p_safe.options);
        unsafe { free_safe(p as *mut ()) };
        p = q
    }
    unsafe {
        archive_string_free_safe(&mut mtree_safe.line);
        archive_string_free_safe(&mut mtree_safe.current_dir);
        archive_string_free_safe(&mut mtree_safe.contents_name);
        archive_entry_linkresolver_free_safe(mtree_safe.resolver);
        free_safe(mtree_safe.buff as *mut ());
        free_safe(mtree as *mut ())
    };
    a_safe.data = 0 as *mut ();
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
fn get_line_size(mut b: *const u8, avail: ssize_t, nlsize: *mut ssize_t) -> ssize_t {
    let mut len: ssize_t = 0;
    len = 0;
    while len < avail {
        let b_safe = unsafe { &*b };
        let nlsize_safe = unsafe { &mut *nlsize };
        match *b_safe as char {
            '\0' => {
                /* Non-ascii character or control character. */
                if !nlsize.is_null() {
                    *nlsize_safe = 0
                }
                return -1 as ssize_t;
            }
            '\r' => {
                if unsafe { avail - len > 1 && *b.offset(1) == '\n' as u8 } {
                    if !nlsize.is_null() {
                        *nlsize_safe = 2
                    }
                    return len + 2;
                }
                if !nlsize.is_null() {
                    *nlsize_safe = 1
                }
                return len + 1;
            }
            '\n' => {
                /* FALL THROUGH */
                if !nlsize.is_null() {
                    *nlsize_safe = 1
                }
                return len + 1;
            }
            _ => {
                b = unsafe { b.offset(1) };
                len += 1;
            }
        }
    }
    let nlsize_safe = unsafe { &mut *nlsize };
    if !nlsize.is_null() {
        *nlsize_safe = 0
    }
    return avail;
}
/*
 *  <---------------- ravail --------------------->
 *  <-- diff ------> <---  avail ----------------->
 *                   <---- len ----------->
 * | Previous lines | line being parsed  nl extra |
 *                  ^
 *                  b
 *
 */
fn next_line(
    a: *mut archive_read,
    b: *mut *const u8,
    avail: *mut ssize_t,
    ravail: *mut ssize_t,
    nl: *mut ssize_t,
) -> ssize_t {
    let mut len: ssize_t = 0;
    let mut quit: i32 = 0;
    quit = 0;
    let avail_safe = unsafe { &mut *avail };
    let nl_safe = unsafe { &mut *nl };
    let b_safe = unsafe { &mut *b };
    if *avail_safe == 0 {
        *nl_safe = 0;
        len = 0
    } else {
        len = get_line_size(*b_safe, *avail_safe, nl)
    }
    /*
     * Read bytes more while it does not reach the end of line.
     */
    while *nl_safe == 0 && len == *avail_safe && quit == 0 {
        let ravail_safe = unsafe { &mut *ravail };
        let diff: ssize_t = *ravail_safe - *avail_safe;
        let mut nbytes_req: size_t = (*ravail_safe + 1023 & !(1023 as u32) as i64) as size_t;
        let mut tested: ssize_t = 0;
        /*
         * Place an arbitrary limit on the line length.
         * mtree is almost free-form input and without line length limits,
         * it can consume a lot of memory.
         */
        if len >= ARCHIVE_MTREE_DEFINED_PARAM.max_line_len {
            return -1 as ssize_t;
        }
        /* Increase reading bytes if it is not enough to at least
         * new two lines. */
        if nbytes_req < (*ravail_safe as size_t).wrapping_add(160) {
            nbytes_req <<= 1
        }
        *b_safe = unsafe { __archive_read_ahead_safe(a, nbytes_req, avail) } as *const u8;
        if b_safe.is_null() {
            if ravail_safe >= avail_safe {
                return 0;
            }
            /* Reading bytes reaches the end of file. */
            *b_safe =
                unsafe { __archive_read_ahead_safe(a, *avail_safe as size_t, avail) } as *const u8; /* Skip some bytes we already determined. */
            quit = 1
        }
        *ravail_safe = *avail_safe;
        *b_safe = unsafe { (*b).offset(diff as isize) };
        *avail_safe -= diff;
        tested = len;
        len = unsafe { get_line_size((*b).offset(len as isize), *avail_safe - len, nl) };
        if len >= 0 {
            len += tested
        }
    }
    return len;
}
/*
 * Compare characters with a mtree keyword.
 * Returns the length of a mtree keyword if matched.
 * Returns 0 if not matched.
 */
fn bid_keycmp(mut p: *const u8, mut key: *const u8, mut len: ssize_t) -> i32 {
    let mut match_len: i32 = 0;
    let mut key_safe;
    let mut p_safe;
    while unsafe { len > 0 && *p != 0 && *key != 0 } {
        unsafe {
            p_safe = &*p;
            key_safe = &*key;
        }
        if *p_safe as i32 == *key_safe as i32 {
            len -= 1;
            unsafe {
                p = p.offset(1);
                key = key.offset(1);
            }
            match_len += 1
        } else {
            return 0;
        }
        /* Not match */
    } /* Not match */
    if unsafe { *key != '\u{0}' as u8 } {
        return 0;
    }
    /* A following character should be specified characters */
    if unsafe {
        *p.offset(0) == '=' as u8
            || *p.offset(0) == ' ' as u8
            || *p.offset(0) == '\t' as u8
            || *p.offset(0) == '\n' as u8
            || *p.offset(0) == '\r' as u8
            || *p.offset(0) == '\\' as u8
                && (*p.offset(1) == '\n' as u8 || *p.offset(1) == '\r' as u8)
    } {
        return match_len;
    }
    return 0;
    /* Not match */
}
/*
 * Test whether the characters 'p' has is mtree keyword.
 * Returns the length of a detected keyword.
 * Returns 0 if any keywords were not found.
 */
fn bid_keyword(p: *const u8, len: ssize_t) -> i32 {
    static mut keys_c: [*const u8; 4] = [
        b"content\x00" as *const u8,
        b"contents\x00" as *const u8,
        b"cksum\x00" as *const u8,
        0 as *const u8,
    ];
    static mut keys_df: [*const u8; 3] = [
        b"device\x00" as *const u8,
        b"flags\x00" as *const u8,
        0 as *const u8,
    ];
    static mut keys_g: [*const u8; 3] = [
        b"gid\x00" as *const u8,
        b"gname\x00" as *const u8,
        0 as *const u8,
    ];
    static mut keys_il: [*const u8; 4] = [
        b"ignore\x00" as *const u8,
        b"inode\x00" as *const u8,
        b"link\x00" as *const u8,
        0 as *const u8,
    ];
    static mut keys_m: [*const u8; 4] = [
        b"md5\x00" as *const u8,
        b"md5digest\x00" as *const u8,
        b"mode\x00" as *const u8,
        0 as *const u8,
    ];
    static mut keys_no: [*const u8; 4] = [
        b"nlink\x00" as *const u8,
        b"nochange\x00" as *const u8,
        b"optional\x00" as *const u8,
        0 as *const u8,
    ];
    static mut keys_r: [*const u8; 4] = [
        b"resdevice\x00" as *const u8,
        b"rmd160\x00" as *const u8,
        b"rmd160digest\x00" as *const u8,
        0 as *const u8,
    ];
    static mut keys_s: [*const u8; 10] = [
        b"sha1\x00" as *const u8,
        b"sha1digest\x00" as *const u8,
        b"sha256\x00" as *const u8,
        b"sha256digest\x00" as *const u8,
        b"sha384\x00" as *const u8,
        b"sha384digest\x00" as *const u8,
        b"sha512\x00" as *const u8,
        b"sha512digest\x00" as *const u8,
        b"size\x00" as *const u8,
        0 as *const u8,
    ];
    static mut keys_t: [*const u8; 4] = [
        b"tags\x00" as *const u8,
        b"time\x00" as *const u8,
        b"type\x00" as *const u8,
        0 as *const u8,
    ];
    static mut keys_u: [*const u8; 3] = [
        b"uid\x00" as *const u8,
        b"uname\x00" as *const u8,
        0 as *const u8,
    ];
    let mut keys: *const *const u8 = 0 as *const *const u8;
    let mut i: i32 = 0;
    unsafe {
        match *p as char {
            'c' => {
                keys = keys_c.as_ptr()
                /* Unknown key */
            }
            'd' | 'f' => keys = keys_df.as_ptr(),
            'g' => keys = keys_g.as_ptr(),
            'i' | 'l' => keys = keys_il.as_ptr(),
            'm' => keys = keys_m.as_ptr(),
            'n' | 'o' => keys = keys_no.as_ptr(),
            'r' => keys = keys_r.as_ptr(),
            's' => keys = keys_s.as_ptr(),
            't' => keys = keys_t.as_ptr(),
            'u' => keys = keys_u.as_ptr(),
            _ => return 0,
        }
    }
    i = 0;
    while unsafe { !(*keys.offset(i as isize)).is_null() } {
        let l: i32 = unsafe { bid_keycmp(p, *keys.offset(i as isize), len) };
        if l > 0 {
            return l;
        }
        i += 1
    }
    return 0;
    /* Unknown key */
}
/*
 * Test whether there is a set of mtree keywords.
 * Returns the number of keyword.
 * Returns -1 if we got incorrect sequence.
 * This function expects a set of "<space characters>keyword=value".
 * When "unset" is specified, expects a set of "<space characters>keyword".
 */
fn bid_keyword_list(mut p: *const u8, mut len: ssize_t, unset: i32, last_is_path: i32) -> i32 {
    let mut l: i32 = 0;
    let mut keycnt: i32 = 0;
    let mut p_safe = unsafe { &*p };
    while len > 0 && *p_safe != 0 {
        let mut blank: i32 = 0;
        /* Test whether there are blank characters in the line. */
        p_safe = unsafe { &*p };
        while len > 0 && (*p_safe == ' ' as u8 || *p_safe == '\t' as u8) {
            p = unsafe { p.offset(1) };
            len -= 1;
            blank = 1;
            p_safe = unsafe { &*p };
        }
        if *p_safe == '\n' as u8 || *p_safe == '\r' as u8 {
            break;
        }
        if unsafe {
            *p.offset(0) == '\\' as u8 && (*p.offset(1) == '\n' as u8 || *p.offset(1) == '\r' as u8)
        } {
            break;
        }
        if blank == 0 && last_is_path == 0 {
            /* No blank character. */
            return -1;
        }
        if last_is_path != 0 && len == 0 {
            return keycnt;
        }
        if unset != 0 {
            l = bid_keycmp(p, b"all\x00" as *const u8, len);
            if l > 0 {
                return 1;
            }
        }
        /* Test whether there is a correct key in the line. */
        l = bid_keyword(p, len); /* Unknown keyword was found. */
        if l == 0 {
            return -1;
        }
        p = unsafe { p.offset(l as isize) };
        len -= l as i64;
        keycnt += 1;
        /* Skip value */
        p_safe = unsafe { &*p };
        if *p_safe == '=' as u8 {
            let mut value: i32 = 0;
            p = unsafe { p.offset(1) };
            len -= 1;
            while unsafe { len > 0 && *p != ' ' as u8 && *p != '\t' as u8 } {
                p = unsafe { p.offset(1) };
                len -= 1;
                value = 1
            }
            /* A keyword should have a its value unless
             * "/unset" operation. */
            if unset == 0 && value == 0 {
                return -1;
            }
        }
    }
    return keycnt;
}
fn bid_entry(p: *const u8, len: ssize_t, nl: ssize_t, last_is_path: *mut i32) -> i32 {
    let mut f: i32 = 0;
    static safe_char: [u8; 256] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut ll: ssize_t = 0;
    let mut pp: *const u8 = p;
    let pp_end: *const u8 = unsafe { pp.offset(len as isize) };
    let last_is_path_safe = unsafe { &mut *last_is_path };
    *last_is_path_safe = 0;
    /*
     * Skip the path-name which is quoted.
     */
    while pp < pp_end {
        if unsafe { safe_char[*(pp as *const u8) as usize] == 0 } {
            let pp_safe = unsafe { &*pp };
            if *pp_safe != ' ' as u8
                && *pp_safe != '\t' as u8
                && *pp_safe != '\r' as u8
                && *pp_safe != '\n' as u8
            {
                f = 0
            }
            break;
        } else {
            f = 1;
            pp = unsafe { pp.offset(1) }
        }
    }
    ll = unsafe { pp_end.offset_from(pp) as i64 };
    /* If a path-name was not found at the first, try to check
     * a mtree format(a.k.a form D) ``NetBSD's mtree -D'' creates,
     * which places the path-name at the last. */
    if f == 0 {
        let mut pb: *const u8 = unsafe { p.offset(len as isize).offset(-(nl as isize)) };
        let mut name_len: i32 = 0;
        let mut slash: i32 = 0;
        /* The form D accepts only a single line for an entry. */
        unsafe {
            if pb.offset(-2) >= p
                && *pb.offset(-1) == '\\' as u8
                && (*pb.offset(-2) == ' ' as u8 || *pb.offset(-2) == '\t' as u8)
            {
                return -1;
            }
            if pb.offset(-1) >= p && *pb.offset(-1) == '\\' as u8 {
                return -1;
            }
        }
        slash = 0;
        loop {
            pb = unsafe { pb.offset(-1) };
            let pb_safe = unsafe { &*pb };
            if !(p <= pb && *pb_safe != ' ' as u8 && *pb_safe != '\t' as u8) {
                break;
            }
            if unsafe { safe_char[*(pb as *const u8) as usize] == 0 } {
                return -1;
            }
            name_len += 1;
            /* The pathname should have a slash in this
             * format. */
            if *pb_safe == '/' as u8 {
                slash = 1
            }
        }
        if name_len == 0 || slash == 0 {
            return -1;
        }
        /* If '/' is placed at the first in this field, this is not
         * a valid filename. */
        if unsafe { *pb.offset(1) == '/' as u8 } {
            return -1;
        }
        ll = len - nl - name_len as i64;
        pp = p;
        *last_is_path_safe = 1
    }
    return bid_keyword_list(pp, ll, 0, *last_is_path_safe);
}
fn mtree_bid(a: *mut archive_read, best_bid: i32) -> i32 {
    let signature: *const u8 = b"#mtree\x00" as *const u8;
    let mut p: *const u8 = 0 as *const u8;
    /* UNUSED */
    /* Now let's look at the actual header and see if it matches. */
    p = unsafe { __archive_read_ahead_safe(a, strlen_safe(signature), 0 as *mut ssize_t) }
        as *const u8;
    if p.is_null() {
        return -1;
    }
    if unsafe {
        memcmp_safe(
            p as *const (),
            signature as *const (),
            strlen_safe(signature),
        )
    } == 0
    {
        return 8 * unsafe { strlen_safe(signature) } as i32;
    }
    /*
     * There is not a mtree signature. Let's try to detect mtree format.
     */
    return detect_form(a, 0 as *mut i32); /* The archive is generated by `NetBSD mtree -D'
                                          	* (In this source we call it `form D') . */
}
fn detect_form(a: *mut archive_read, is_form_d: *mut i32) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let mut avail: ssize_t = 0;
    let mut ravail: ssize_t = 0;
    let mut detected_bytes: ssize_t = 0;
    let mut len: ssize_t = 0;
    let mut nl: ssize_t = 0;
    let mut entry_cnt: i32 = 0;
    let mut multiline: i32 = 0;
    let mut form_D: i32 = 0;
    let is_form_d_safe = unsafe { &mut *is_form_d };
    if !is_form_d.is_null() {
        *is_form_d_safe = 0
    }
    p = unsafe { __archive_read_ahead_safe(a, 1, &mut avail) } as *const u8;
    if p.is_null() {
        return -1;
    }
    ravail = avail;
    loop {
        len = next_line(a, &mut p, &mut avail, &mut ravail, &mut nl);
        /* The terminal character of the line should be
         * a new line character, '\r\n' or '\n'. */
        if len <= 0 || nl == 0 {
            break;
        }
        if multiline == 0 {
            /* Leading whitespace is never significant,
             * ignore it. */
            let mut p_safe = unsafe { &*p };
            while len > 0 && (*p_safe == ' ' as u8 || *p_safe == '\t' as u8) {
                unsafe {
                    p = p.offset(1);
                    p_safe = &*p;
                }
                avail -= 1;
                len -= 1
            }
            /* Skip comment or empty line. */
            if unsafe {
                *p.offset(0) == '#' as u8
                    || *p.offset(0) == '\n' as u8
                    || *p.offset(0) == '\r' as u8
            } {
                p = unsafe { p.offset(len as isize) };
                avail -= len
            } else {
                if unsafe { *p.offset(0) != '/' as u8 } {
                    let mut last_is_path: i32 = 0;
                    let mut keywords: i32 = 0;
                    keywords = bid_entry(p, len, nl, &mut last_is_path);
                    if !(keywords >= 0) {
                        break;
                    }
                    detected_bytes += len;
                    if form_D == 0 {
                        if last_is_path != 0 {
                            form_D = 1
                        } else if keywords > 0 {
                            /* This line is not `form D'. */
                            form_D = -1
                        }
                    } else if form_D == 1 {
                        if last_is_path == 0 && keywords > 0 {
                            break;
                        }
                    }
                    if unsafe {
                        last_is_path == 0 && *p.offset((len - nl - 1) as isize) == '\\' as u8
                    } {
                        /* This line continues. */
                        multiline = 1
                    } else {
                        /* We've got plenty of correct lines
                         * to assume that this file is a mtree
                         * format. */
                        entry_cnt += 1;
                        if entry_cnt >= ARCHIVE_MTREE_DEFINED_PARAM.max_bid_entry {
                            break;
                        }
                    }
                } else if len > 4 && unsafe { strncmp_safe(p, b"/set\x00" as *const u8, 4) } == 0 {
                    if unsafe { bid_keyword_list(p.offset(4), len - 4, 0, 0) <= 0 } {
                        break;
                    }
                    /* This line continues. */
                    if unsafe { *p.offset((len - nl - 1) as isize) == '\\' as u8 } {
                        multiline = 2
                    }
                } else {
                    if !(len > 6 && unsafe { strncmp_safe(p, b"/unset\x00" as *const u8, 6) } == 0)
                    {
                        break;
                    }
                    unsafe {
                        if bid_keyword_list(p.offset(6), len - 6, 1, 0) <= 0 {
                            break;
                        }
                        /* This line continues. */
                        if *p.offset((len - nl - 1) as isize) == '\\' as u8 {
                            multiline = 2
                        }
                    }
                }
                /* Test next line. */
                p = unsafe { p.offset(len as isize) };
                avail -= len
            }
        } else {
            /* A continuance line; the terminal
             * character of previous line was '\' character. */
            if bid_keyword_list(p, len, 0, 0) <= 0 {
                break;
            }
            if multiline == 1 {
                detected_bytes += len
            }
            if unsafe { *p.offset((len - nl - 1) as isize) != '\\' as u8 } {
                if multiline == 1 && {
                    entry_cnt += 1;
                    (entry_cnt) >= ARCHIVE_MTREE_DEFINED_PARAM.max_bid_entry
                } {
                    break;
                }
                multiline = 0
            }
            p = unsafe { p.offset(len as isize) };
            avail -= len
        }
    }
    if entry_cnt >= ARCHIVE_MTREE_DEFINED_PARAM.max_bid_entry || entry_cnt > 0 && len == 0 {
        if !is_form_d.is_null() {
            if form_D == 1 {
                *is_form_d_safe = 1
            }
        }
        return 32;
    }
    return 0;
}
/*
 * The extended mtree format permits multiple lines specifying
 * attributes for each file.  For those entries, only the last line
 * is actually used.  Practically speaking, that means we have
 * to read the entire mtree file into memory up front.
 *
 * The parsing is done in two steps.  First, it is decided if a line
 * changes the global defaults and if it is, processed accordingly.
 * Otherwise, the options of the line are merged with the current
 * global options.
 */
fn add_option(
    a: *mut archive_read,
    global: *mut *mut mtree_option,
    value: *const u8,
    len: size_t,
) -> i32 {
    let mut opt: *mut mtree_option = 0 as *mut mtree_option;
    opt = unsafe { malloc_safe(size_of::<mtree_option>() as u64) } as *mut mtree_option;
    if opt.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            *__errno_location(),
            b"Can\'t allocate memory\x00" as *const u8
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    let opt_safe = unsafe { &mut *opt };
    opt_safe.value = unsafe { malloc_safe(len.wrapping_add(1)) } as *mut u8;
    if opt_safe.value.is_null() {
        unsafe { free_safe(opt as *mut ()) };
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            *__errno_location(),
            b"Can\'t allocate memory\x00" as *const u8
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    unsafe { memcpy_safe(opt_safe.value as *mut (), value as *const (), len) };
    unsafe { *(*opt).value.offset(len as isize) = '\u{0}' as u8 };
    let global_safe = unsafe { &mut *global };
    opt_safe.next = *global_safe;
    *global_safe = opt;
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
fn remove_option(global: *mut *mut mtree_option, value: *const u8, len: size_t) {
    let mut iter: *mut mtree_option = 0 as *mut mtree_option;
    let mut last: *mut mtree_option = 0 as *mut mtree_option;
    last = 0 as *mut mtree_option;
    let global_safe = unsafe { &mut *global };
    let mut iter_safe = unsafe { &*iter };
    iter = *global_safe;
    while !iter.is_null() {
        iter_safe = unsafe { &*iter };
        if unsafe {
            strncmp_safe((*iter).value, value, len) == 0
                && (*(*iter).value.offset(len as isize) == '\u{0}' as u8
                    || *(*iter).value.offset(len as isize) == '=' as u8)
        } {
            break;
        }
        last = iter;
        iter = iter_safe.next
    }
    if iter.is_null() {
        return;
    }
    iter_safe = unsafe { &*iter };
    let last_safe = unsafe { &mut *last };
    if last.is_null() {
        *global_safe = iter_safe.next
    } else {
        last_safe.next = iter_safe.next
    }
    unsafe {
        free_safe(iter_safe.value as *mut ());
        free_safe(iter as *mut ())
    };
}
fn process_global_set(
    a: *mut archive_read,
    global: *mut *mut mtree_option,
    mut line: *const u8,
) -> i32 {
    let mut next: *const u8 = 0 as *const u8;
    let mut eq: *const u8 = 0 as *const u8;
    let mut len: size_t = 0;
    let mut r: i32 = 0;
    line = unsafe { line.offset(4) };
    loop {
        next = unsafe { line.offset(strspn(line, b" \t\r\n\x00" as *const u8) as isize) };
        let next_safe = unsafe { &*next };
        if *next_safe == '\u{0}' as u8 {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
        line = next;
        next = unsafe { line.offset(strcspn(line, b" \t\r\n\x00" as *const u8) as isize) };
        eq = unsafe { strchr_safe(line, '=' as i32) };
        unsafe {
            if eq > next {
                len = next.offset_from(line) as size_t
            } else {
                len = eq.offset_from(line) as size_t
            }
        }
        remove_option(global, line, len);
        unsafe {
            r = add_option(a, global, line, next.offset_from(line) as size_t);
        }
        if r != ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
            return r;
        }
        line = next
    }
}
fn process_global_unset(
    a: *mut archive_read,
    global: *mut *mut mtree_option,
    mut line: *const u8,
) -> i32 {
    let mut next: *const u8 = 0 as *const u8;
    let mut len: size_t = 0;
    let a_safe;
    unsafe {
        line = line.offset(6);
        a_safe = &mut *a;
    }
    if !unsafe { strchr_safe(line, '=' as i32) }.is_null() {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_misc,
            b"/unset shall not contain `=\'\x00" as *const u8
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    loop {
        let next_safe;
        unsafe {
            next = line.offset(strspn(line, b" \t\r\n\x00" as *const u8) as isize);
            next_safe = &*next;
        }
        if *next_safe == '\u{0}' as u8 {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
        line = next;
        len = unsafe { strcspn_safe(line, b" \t\r\n\x00" as *const u8) };
        let global_safe = unsafe { &mut *global };
        if len == 3 && unsafe { strncmp_safe(line, b"all\x00" as *const u8, 3) } == 0 {
            free_options(*global_safe);
            *global_safe = 0 as *mut mtree_option
        } else {
            remove_option(global, line, len);
        }
        line = unsafe { line.offset(len as isize) }
    }
}
fn process_add_entry(
    a: *mut archive_read,
    mtree: *mut mtree,
    global: *mut *mut mtree_option,
    mut line: *const u8,
    mut line_len: ssize_t,
    last_entry: *mut *mut mtree_entry,
    is_form_d: i32,
) -> i32 {
    let mut entry: *mut mtree_entry = 0 as *mut mtree_entry;
    let mut iter: *mut mtree_option = 0 as *mut mtree_option;
    let mut next: *const u8 = 0 as *const u8;
    let mut eq: *const u8 = 0 as *const u8;
    let mut name: *const u8 = 0 as *const u8;
    let mut end: *const u8 = 0 as *const u8;
    let mut name_len: size_t = 0;
    let mut len: size_t = 0;
    let mut r: i32 = 0;
    let mut i: i32 = 0;
    entry = unsafe { malloc_safe(size_of::<mtree_entry>() as u64) } as *mut mtree_entry;
    if entry.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            *__errno_location(),
            b"Can\'t allocate memory\x00" as *const u8
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    let entry_safe = unsafe { &mut *entry };
    entry_safe.next = 0 as *mut mtree_entry;
    entry_safe.options = 0 as *mut mtree_option;
    entry_safe.name = 0 as *mut u8;
    entry_safe.used = 0;
    entry_safe.full = 0;
    /* Add this entry to list. */
    let last_entry_safe = unsafe { &mut *last_entry };
    let mtree_safe = unsafe { &mut *mtree };
    if (*last_entry_safe).is_null() {
        mtree_safe.entries = entry
    } else {
        unsafe { (**last_entry).next = entry }
    }
    *last_entry_safe = entry;
    if is_form_d != 0 {
        /* Filename is last item on line. */
        /* Adjust line_len to trim trailing whitespace */
        while line_len > 0 {
            let last_character: u8 = unsafe { *line.offset((line_len - 1) as isize) };
            if !(last_character == '\r' as u8
                || last_character == '\n' as u8
                || last_character == '\t' as u8
                || last_character == ' ' as u8)
            {
                break;
            }
            line_len -= 1
        }
        /* Name starts after the last whitespace separator */
        name = line;
        i = 0;
        while (i as i64) < line_len {
            unsafe {
                if *line.offset(i as isize) == '\r' as u8
                    || *line.offset(i as isize) == '\n' as u8
                    || *line.offset(i as isize) == '\t' as u8
                    || *line.offset(i as isize) == ' ' as u8
                {
                    name = line.offset(i as isize).offset(1)
                }
            }
            i += 1
        }
        name_len = unsafe { line.offset(line_len as isize).offset_from(name) as size_t };
        end = name
    } else {
        /* Filename is first item on line */
        name_len = unsafe { strcspn_safe(line, b" \t\r\n\x00" as *const u8) };
        name = line;
        unsafe {
            line = line.offset(name_len as isize);
            end = line.offset(line_len as isize)
        }
    }
    /* name/name_len is the name within the line. */
    /* line..end brackets the entire line except the name */
    entry_safe.name = unsafe { malloc_safe(name_len.wrapping_add(1)) } as *mut u8;
    if entry_safe.name.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            *__errno_location(),
            b"Can\'t allocate memory\x00" as *const u8
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    unsafe { memcpy_safe(entry_safe.name as *mut (), name as *const (), name_len) };
    unsafe {
        *(*entry).name.offset(name_len as isize) = '\u{0}' as u8;
    }
    parse_escapes(entry_safe.name, entry);
    entry_safe.next_dup = 0 as *mut mtree_entry;
    if entry_safe.full != 0 {
        if unsafe {
            __archive_rb_tree_insert_node_safe(&mut mtree_safe.rbtree, &mut entry_safe.rbnode)
        } == 0
        {
            let mut alt: *mut mtree_entry = 0 as *mut mtree_entry;
            alt = unsafe {
                __archive_rb_tree_find_node_safe(
                    &mut mtree_safe.rbtree,
                    entry_safe.name as *const (),
                )
            } as *mut mtree_entry;
            let mut alt_safe = unsafe { &mut *alt };
            while !alt_safe.next_dup.is_null() {
                alt_safe = unsafe { &mut *alt };
                alt = alt_safe.next_dup
            }
            alt_safe = unsafe { &mut *alt };
            alt_safe.next_dup = entry
        }
    }
    iter = unsafe { *global };
    while !iter.is_null() {
        let iter_safe = unsafe { &mut *iter };
        r = add_option(a, &mut entry_safe.options, iter_safe.value, unsafe {
            strlen_safe(iter_safe.value)
        });
        if r != ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
            return r;
        }
        iter = iter_safe.next
    }
    loop {
        let next_safe;
        unsafe {
            next = line.offset(strspn(line, b" \t\r\n\x00" as *const u8) as isize);
            next_safe = &*next;
        }
        if *next_safe == '\u{0}' as u8 {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
        if next >= end {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
        line = next;
        next = unsafe { line.offset(strcspn(line, b" \t\r\n\x00" as *const u8) as isize) };
        eq = unsafe { strchr_safe(line, '=' as i32) };
        unsafe {
            if eq.is_null() || eq > next {
                len = next.offset_from(line) as size_t
            } else {
                len = eq.offset_from(line) as size_t
            }
        }
        remove_option(&mut entry_safe.options, line, len);
        unsafe {
            r = add_option(
                a,
                &mut (*entry).options,
                line,
                next.offset_from(line) as size_t,
            );
        }
        if r != ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
            return r;
        }
        line = next
    }
}
fn read_mtree(a: *mut archive_read, mtree: *mut mtree) -> i32 {
    let mut len: ssize_t = 0;
    let mut counter: uintmax_t = 0;
    let mut p: *mut u8 = 0 as *mut u8;
    let mut s: *mut u8 = 0 as *mut u8;
    let mut global: *mut mtree_option = 0 as *mut mtree_option;
    let mut last_entry: *mut mtree_entry = 0 as *mut mtree_entry;
    let mut r: i32 = 0;
    let mut is_form_d: i32 = 0;
    let mtree_safe = unsafe { &mut *mtree };
    mtree_safe.archive_format = ARCHIVE_MTREE_DEFINED_PARAM.archive_format_mtree;
    mtree_safe.archive_format_name = b"mtree\x00" as *const u8;
    global = 0 as *mut mtree_option;
    last_entry = 0 as *mut mtree_entry;
    detect_form(a, &mut is_form_d);
    counter = 1;
    loop {
        r = ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        len = readline(a, mtree, &mut p, 65536);
        if len == 0 {
            mtree_safe.this_entry = mtree_safe.entries;
            free_options(global);
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
        if len < 0 {
            free_options(global);
            return len as i32;
        }
        /* Leading whitespace is never significant, ignore it. */
        let mut p_safe = unsafe { &mut *p };
        while *p_safe == ' ' as u8 || *p_safe == '\t' as u8 {
            p = unsafe { p.offset(1) };
            len -= 1;
            p_safe = unsafe { &mut *p };
        }
        /* Skip content lines and blank lines. */
        if !(*p_safe == '#' as u8) {
            if !(*p_safe == '\r' as u8 || *p_safe == '\n' as u8 || *p_safe == '\u{0}' as u8) {
                /* Non-printable characters are not allowed */
                s = p;
                unsafe {
                    while s < p.offset(len as isize).offset(-1) {
                        if unsafe { isprint(*s as i32) } == 0 {
                            r = ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
                            break;
                        } else {
                            s = s.offset(1)
                        }
                    }
                }
                if r != ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
                    break;
                }
                if *p_safe != '/' as u8 {
                    r = process_add_entry(a, mtree, &mut global, p, len, &mut last_entry, is_form_d)
                } else if len > 4 && unsafe { strncmp_safe(p, b"/set\x00" as *const u8, 4) } == 0 {
                    if unsafe { *p.offset(4) != ' ' as u8 && *p.offset(4) != '\t' as u8 } {
                        break;
                    }
                    r = process_global_set(a, &mut global, p)
                } else {
                    if !(len > 6 && unsafe { strncmp_safe(p, b"/unset\x00" as *const u8, 6) } == 0)
                    {
                        break;
                    }
                    if unsafe { *p.offset(6) != ' ' as u8 && *p.offset(6) != '\t' as u8 } {
                        break;
                    }
                    r = process_global_unset(a, &mut global, p)
                }
                if r != ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
                    free_options(global);
                    return r;
                }
            }
        }
        counter = counter.wrapping_add(1)
    }
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
        b"Can\'t parse line %ju\x00" as *const u8,
        counter
    );
    free_options(global);
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
}
/*
 * Read in the entire mtree file into memory on the first request.
 * Then use the next unused file to satisfy each header request.
 */
fn read_header(a: *mut archive_read, entry: *mut archive_entry) -> i32 {
    let mut mtree: *mut mtree = 0 as *mut mtree;
    let mut p: *mut u8 = 0 as *mut u8;
    let mut r: i32 = 0;
    let mut use_next: i32 = 0;
    let mut mtree_safe;
    unsafe {
        mtree = (*(*a).format).data as *mut mtree;
        mtree_safe = &mut *mtree;
    }
    if mtree_safe.fd >= 0 {
        unsafe { close_safe((*mtree_safe).fd) };
        (*mtree_safe).fd = -1
    }
    if mtree_safe.entries.is_null() {
        mtree_safe.resolver = unsafe { archive_entry_linkresolver_new_safe() };
        if mtree_safe.resolver.is_null() {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
        }
        unsafe {
            archive_entry_linkresolver_set_strategy_safe(
                mtree_safe.resolver,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_format_mtree,
            )
        };
        r = read_mtree(a, mtree);
        if r != ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
            return r;
        }
    }
    let a_safe = unsafe { &mut *a };
    a_safe.archive.archive_format = mtree_safe.archive_format;
    a_safe.archive.archive_format_name = mtree_safe.archive_format_name;
    loop {
        if mtree_safe.this_entry.is_null() {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_eof;
        }
        unsafe {
            if strcmp((*(*mtree).this_entry).name, b"..\x00" as *const u8) == 0 {
                (*(*mtree).this_entry).used = 1;
                if (*mtree).current_dir.length > 0 {
                    /* Roll back current path. */
                    p = (*mtree)
                        .current_dir
                        .s
                        .offset((*mtree).current_dir.length as isize)
                        .offset(-1);
                    while p >= (*mtree).current_dir.s && *p != '/' as u8 {
                        p = p.offset(-1)
                    }
                    if p >= (*mtree).current_dir.s {
                        p = p.offset(-1)
                    }
                    (*mtree).current_dir.length =
                        (p.offset_from((*mtree).current_dir.s) as i64 + 1) as size_t
                }
            }
        }
        let m_entry_safe = unsafe { &mut (*(*mtree).this_entry) };
        if m_entry_safe.used == 0 {
            use_next = 0;
            r = parse_file(a, entry, mtree, mtree_safe.this_entry, &mut use_next);
            if use_next == 0 {
                return r;
            }
        }
        mtree_safe.this_entry = m_entry_safe.next
    }
}
/*
 * A single file can have multiple lines contribute specifications.
 * Parse as many lines as necessary, then pull additional information
 * from a backing file on disk as necessary.
 */

fn parse_file(
    a: *mut archive_read,
    mut entry: *mut archive_entry,
    mtree: *mut mtree,
    mentry: *mut mtree_entry,
    use_next: *mut i32,
) -> i32 {
    let mut path: *const u8 = 0 as *const u8;
    let mut st_storage: stat = unsafe { std::mem::zeroed() };
    let mut st: *mut stat = 0 as *mut stat;
    let mut mp: *mut mtree_entry = 0 as *mut mtree_entry;
    let mut sparse_entry: *mut archive_entry = 0 as *mut archive_entry;
    let mut r: i32 = ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    let mut r1: i32 = 0;
    let mut parsed_kws: i32 = 0;
    let mentry_safe = unsafe { &mut *mentry };
    mentry_safe.used = 1;
    /* Initialize reasonable defaults. */
    unsafe {
        archive_entry_set_filetype_safe(entry, ARCHIVE_MTREE_DEFINED_PARAM.ae_ifreg as mode_t);
        archive_entry_set_size_safe(entry, 0);
    }
    let mtree_safe = unsafe { &mut *mtree };
    mtree_safe.contents_name.length = 0;
    /* Parse options from this line. */
    parsed_kws = 0;
    r = parse_line(a, entry, mtree, mentry, &mut parsed_kws);
    if mentry_safe.full != 0 {
        unsafe { archive_entry_copy_pathname_safe(entry, mentry_safe.name) };
        /*
         * "Full" entries are allowed to have multiple lines
         * and those lines aren't required to be adjacent.  We
         * don't support multiple lines for "relative" entries
         * nor do we make any attempt to merge data from
         * separate "relative" and "full" entries.  (Merging
         * "relative" and "full" entries would require dealing
         * with pathname canonicalization, which is a very
         * tricky subject.)
         */
        mp = unsafe {
            __archive_rb_tree_find_node_safe(&mut mtree_safe.rbtree, mentry_safe.name as *const ())
        } as *mut mtree_entry;
        let mut mp_safe;
        while !mp.is_null() {
            mp_safe = unsafe { &mut *mp };
            if mp_safe.full != 0 && mp_safe.used == 0 {
                /* Later lines override earlier ones. */
                mp_safe.used = 1;
                r1 = parse_line(a, entry, mtree, mp, &mut parsed_kws);
                if r1 < r {
                    r = r1
                }
            }
            mp = mp_safe.next_dup
        }
    } else {
        /*
         * Relative entries require us to construct
         * the full path and possibly update the
         * current directory.
         */
        let n: size_t = mtree_safe.current_dir.length;
        if n > 0 {
            unsafe {
                archive_strcat_safe(
                    &mut mtree_safe.current_dir,
                    b"/\x00" as *const u8 as *const (),
                )
            };
        }
        unsafe { archive_strcat_safe(&mut mtree_safe.current_dir, mentry_safe.name as *const ()) };
        unsafe { archive_entry_copy_pathname_safe(entry, mtree_safe.current_dir.s) };
        if unsafe { archive_entry_filetype_safe(entry) }
            != ARCHIVE_MTREE_DEFINED_PARAM.ae_ifdir as mode_t
        {
            mtree_safe.current_dir.length = n
        }
    }
    if mtree_safe.checkfs != 0 {
        /*
         * Try to open and stat the file to get the real size
         * and other file info.  It would be nice to avoid
         * this here so that getting a listing of an mtree
         * wouldn't require opening every referenced contents
         * file.  But then we wouldn't know the actual
         * contents size, so I don't see a really viable way
         * around this.  (Also, we may want to someday pull
         * other unspecified info from the contents file on
         * disk.)
         */
        mtree_safe.fd = -1;
        if mtree_safe.contents_name.length > 0 {
            path = mtree_safe.contents_name.s
        } else {
            path = unsafe { archive_entry_pathname_safe(entry) }
        }
        if unsafe { archive_entry_filetype_safe(entry) }
            == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifreg as mode_t
            || unsafe { archive_entry_filetype_safe(entry) }
                == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifdir as mode_t
        {
            mtree_safe.fd = unsafe {
                open_safe(
                    path,
                    ARCHIVE_MTREE_DEFINED_PARAM.o_rdonly
                        | ARCHIVE_MTREE_DEFINED_PARAM.o_binary
                        | ARCHIVE_MTREE_DEFINED_PARAM.o_cloexec,
                )
            };
            unsafe { __archive_ensure_cloexec_flag_safe(mtree_safe.fd) };

            if unsafe {
                (*mtree).fd == -1
                    && (*__errno_location() != ARCHIVE_MTREE_DEFINED_PARAM.enoent
                        || (*mtree).contents_name.length > 0)
            } {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    *__errno_location(),
                    b"Can\'t open %s\x00" as *const u8,
                    path
                );
                r = ARCHIVE_MTREE_DEFINED_PARAM.archive_warn
            }
        }
        st = &mut st_storage;
        if mtree_safe.fd >= 0 {
            if unsafe { fstat_safe(mtree_safe.fd, st) } == -1 {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    *__errno_location(),
                    b"Could not fstat %s\x00" as *const u8,
                    path
                );
                r = ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
                /* If we can't stat it, don't keep it open. */
                unsafe { close_safe(mtree_safe.fd) };
                mtree_safe.fd = -1;
                st = 0 as *mut stat
            }
        } else if unsafe { lstat_safe(path, st) } == -1 {
            st = 0 as *mut stat
        }
        /*
         * Check for a mismatch between the type in the specification
         * and the type of the contents object on disk.
         */
        let st_safe = unsafe { &mut *st };
        if !st.is_null() {
            let mut conditions: bool = st_safe.st_mode & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as u32
                == ARCHIVE_MTREE_DEFINED_PARAM.s_ifreg as u32
                && unsafe { archive_entry_filetype_safe(entry) }
                    == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifreg as mode_t;
            match () {
                #[cfg(S_IFLNK)]
                _ => {
                    conditions = conditions
                        || st_safe.st_mode & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as u32
                            == ARCHIVE_MTREE_DEFINED_PARAM.s_iflnk as u32
                            && unsafe { archive_entry_filetype_safe(entry) }
                                == ARCHIVE_MTREE_DEFINED_PARAM.ae_iflnk as mode_t;
                }
                #[cfg(not(S_IFLNK))]
                _ => {}
            }
            match () {
                #[cfg(S_IFSOCK)]
                _ => {
                    conditions = conditions
                        || st_safe.st_mode & ARCHIVE_MTREE_DEFINED_PARAM.s_ifsock as u32
                            == ARCHIVE_MTREE_DEFINED_PARAM.s_ifsock as u32
                            && unsafe { archive_entry_filetype_safe(entry) }
                                == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifsock as mode_t;
                }
                #[cfg(not(S_IFSOCK))]
                _ => {}
            }
            match () {
                #[cfg(S_IFCHR)]
                _ => {
                    conditions = conditions
                        || st_safe.st_mode & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as u32
                            == ARCHIVE_MTREE_DEFINED_PARAM.s_ifchr as u32
                            && unsafe { archive_entry_filetype_safe(entry) }
                                == ARCHIVE_MTREE_DEFINED_PARAM.s_ifchr as mode_t;
                }
                #[cfg(not(S_IFCHR))]
                _ => {}
            }
            match () {
                #[cfg(S_IFBLK)]
                _ => {
                    conditions = conditions
                        || st_safe.st_mode & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as u32
                            == ARCHIVE_MTREE_DEFINED_PARAM.s_ifblk as u32
                            && unsafe { archive_entry_filetype_safe(entry) }
                                == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifblk as mode_t;
                }
                #[cfg(not(S_IFBLK))]
                _ => {}
            }
            conditions = conditions
                || st_safe.st_mode & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as u32
                    == ARCHIVE_MTREE_DEFINED_PARAM.s_ifdir as u32
                    && unsafe { archive_entry_filetype_safe(entry) }
                        == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifdir as mode_t;
            match () {
                #[cfg(S_IFIFO)]
                _ => {
                    conditions = conditions
                        || st_safe.st_mode & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as u32
                            == ARCHIVE_MTREE_DEFINED_PARAM.s_ififo as u32
                            && unsafe { archive_entry_filetype_safe(entry) }
                                == ARCHIVE_MTREE_DEFINED_PARAM.ae_ififo as mode_t;
                }
                #[cfg(not(S_IFIFO))]
                _ => {}
            }
            if conditions {
            } else {
                /* Types don't match; bail out gracefully. */
                if mtree_safe.fd >= 0 {
                    unsafe { close_safe(mtree_safe.fd) };
                }
                mtree_safe.fd = -1;
                if parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_optional != 0 {
                    /* It's not an error for an optional
                     * entry to not match disk. */
                    unsafe { *use_next = 1 }
                } else if r == ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_misc,
                        b"mtree specification has different type for %s\x00" as *const u8
                            as *const u8,
                        archive_entry_pathname(entry)
                    );
                    r = ARCHIVE_MTREE_DEFINED_PARAM.archive_warn
                }
                return r;
            }
        }
        /*
         * If there is a contents file on disk, pick some of the
         * metadata from that file.  For most of these, we only
         * set it from the contents if it wasn't already parsed
         * from the specification.
         */
        if !st.is_null() {
            if (parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_device == 0
                || parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange != 0)
                && (unsafe { archive_entry_filetype_safe(entry) }
                    == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifchr as mode_t
                    || unsafe { archive_entry_filetype_safe(entry) }
                        == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifblk as mode_t)
            {
                unsafe { archive_entry_set_rdev_safe(entry, st_safe.st_rdev) };
            }
            if parsed_kws
                & (ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_gid
                    | ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_gname)
                == 0
                || parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange != 0
            {
                unsafe { archive_entry_set_gid_safe(entry, st_safe.st_gid as la_int64_t) };
            }
            if parsed_kws
                & (ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_uid
                    | ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_uname)
                == 0
                || parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange != 0
            {
                unsafe { archive_entry_set_uid_safe(entry, st_safe.st_uid as la_int64_t) };
            }
            if parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_mtime == 0
                || parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange != 0
            {
                match () {
                    #[cfg(HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC)]
                    _ => {
                        archive_entry_set_mtime_safe(
                            entry,
                            st_safe.st_mtime,
                            st_safe.st_mtimespec.tv_nsec,
                        );
                    }
                    #[cfg(all(
                        not(HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC),
                        HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC
                    ))]
                    _ => {
                        unsafe {
                            archive_entry_set_mtime_safe(
                                entry,
                                st_safe.st_mtime,
                                st_safe.st_mtime_nsec,
                            )
                        };
                    }
                    #[cfg(all(
                        not(any(
                            HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC,
                            HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC
                        )),
                        HAVE_STRUCT_STAT_ST_MTIME_N
                    ))]
                    _ => {
                        unsafe {
                            archive_entry_set_mtime_safe(
                                entry,
                                st_safe.st_mtime,
                                st_safe.st_mtime_n,
                            )
                        };
                    }
                    #[cfg(all(
                        not(any(
                            HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC,
                            HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC,
                            HAVE_STRUCT_STAT_ST_MTIME_N
                        )),
                        HAVE_STRUCT_STAT_ST_UMTIME
                    ))]
                    _ => {
                        archive_entry_set_mtime_safe(
                            entry,
                            st_safe.st_mtime,
                            st_safe.st_umtime * 1000,
                        );
                    }
                    #[cfg(all(
                        not(any(
                            HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC,
                            HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC,
                            HAVE_STRUCT_STAT_ST_MTIME_N,
                            HAVE_STRUCT_STAT_ST_UMTIME
                        )),
                        HAVE_STRUCT_STAT_ST_MTIME_USEC
                    ))]
                    _ => {
                        archive_entry_set_mtime_safe(
                            entry,
                            st_safe.st_mtime,
                            st_safe.st_mtime_usec * 1000,
                        );
                    }
                    #[cfg(not(any(
                        HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC,
                        HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC,
                        HAVE_STRUCT_STAT_ST_MTIME_N,
                        HAVE_STRUCT_STAT_ST_UMTIME,
                        HAVE_STRUCT_STAT_ST_MTIME_USEC
                    )))]
                    _ => {
                        archive_entry_set_mtime_safe(entry, st_safe.st_mtime, 0);
                    }
                }
            }
            if parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nlink == 0
                || parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange != 0
            {
                unsafe { archive_entry_set_nlink_safe(entry, st_safe.st_nlink as u32) };
            }
            if parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_perm == 0
                || parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange != 0
            {
                unsafe { archive_entry_set_perm_safe(entry, st_safe.st_mode) };
            }
            if parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_size == 0
                || parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange != 0
            {
                unsafe { archive_entry_set_size_safe(entry, st_safe.st_size) };
            }
            unsafe {
                archive_entry_set_ino_safe(entry, st_safe.st_ino as la_int64_t);
                archive_entry_set_dev_safe(entry, st_safe.st_dev);
                archive_entry_linkify_safe(mtree_safe.resolver, &mut entry, &mut sparse_entry);
            }
        } else if parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_optional != 0 {
            /*
             * Couldn't open the entry, stat it or the on-disk type
             * didn't match.  If this entry is optional, just
             * ignore it and read the next header entry.
             */
            unsafe {
                *use_next = 1;
            }
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
    }
    mtree_safe.cur_size = unsafe { archive_entry_size_safe(entry) };
    mtree_safe.offset = 0;
    return r;
}
/*
 * Each line contains a sequence of keywords.
 */
fn parse_line(
    a: *mut archive_read,
    entry: *mut archive_entry,
    mtree: *mut mtree,
    mp: *mut mtree_entry,
    parsed_kws: *mut i32,
) -> i32 {
    let mut iter: *mut mtree_option = 0 as *mut mtree_option;
    let mut r: i32 = ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    let mut r1: i32 = 0;
    let parsed_kws_safe;
    let a_safe;
    unsafe {
        iter = (*mp).options;
        parsed_kws_safe = &mut *parsed_kws;
        a_safe = &mut *a;
    }
    while !iter.is_null() {
        r1 = parse_keyword(a, mtree, entry, iter, parsed_kws);
        if r1 < r {
            r = r1
        }
        iter = unsafe { (*iter).next }
    }
    if r == ARCHIVE_MTREE_DEFINED_PARAM.archive_ok
        && *parsed_kws_safe & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_type == 0
    {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
            b"Missing type keyword in mtree specification\x00" as *const u8
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
    }
    return r;
}
/*
 * Device entries have one of the following forms:
 *  - raw dev_t
 *  - format,major,minor[,subdevice]
 * When parsing succeeded, `pdev' will contain the appropriate dev_t value.
 */
/* strsep() is not in C90, but strcspn() is. */
/* Taken from http://unixpapa.com/incnote/string.html */
fn la_strsep(sp: *mut *mut u8, sep: *const u8) -> *mut u8 {
    let mut p: *mut u8 = 0 as *mut u8;
    let mut s: *mut u8 = 0 as *mut u8;
    if unsafe { sp.is_null() || (*sp).is_null() || **sp == '\u{0}' as u8 } {
        return 0 as *mut u8;
    }
    let sp_safe = unsafe { &mut *sp };
    s = *sp_safe;
    unsafe {
        p = s.offset(strcspn(s, sep) as isize);
        if *p != '\u{0}' as u8 {
            let fresh0 = p;
            p = p.offset(1);
            *fresh0 = '\u{0}' as u8
        }
    }
    *sp_safe = p;
    return s;
}
fn parse_device(pdev: *mut dev_t, a: *mut archive, mut val: *mut u8) -> i32 {
    let mut numbers: [u64; 3] = [0; 3];
    let mut p: *mut u8 = 0 as *mut u8;
    let mut dev: *mut u8 = 0 as *mut u8;
    let mut argc: i32 = 0;
    let mut pack: Option<pack_t> = None;
    let mut result: dev_t = 0;
    let mut error: *const u8 = 0 as *const u8;
    unsafe { memset_safe(pdev as *mut (), 0, size_of::<dev_t>() as u64) };
    dev = unsafe { strchr_safe(val, ',' as i32) };
    if !dev.is_null() {
        /*
         * Device's major/minor are given in a specified format.
         * Decode and pack it accordingly.
         */
        let fresh1 = dev;
        unsafe {
            dev = dev.offset(1);
            *fresh1 = '\u{0}' as u8;
        }
        pack = unsafe { pack_find_safe(val) };
        if pack.is_none() {
            archive_set_error_safe!(
                a,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                b"Unknown format `%s\'\x00" as *const u8,
                val
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
        }
        argc = 0;
        loop {
            p = la_strsep(&mut dev, b",\x00" as *const u8);
            if p.is_null() {
                break;
            }
            let p_safe = unsafe { &mut *p };
            if *p_safe == '\u{0}' as u8 {
                archive_set_error_safe!(
                    a,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                    b"Missing number\x00" as *const u8
                );
                return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
            }
            if argc >= 3 {
                archive_set_error_safe!(
                    a,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                    b"Too many arguments\x00" as *const u8
                );
                return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
            }
            let fresh2 = argc;
            argc = argc + 1;
            numbers[fresh2 as usize] = mtree_atol(&mut p, 0) as u64
        }
        if argc < 2 {
            archive_set_error_safe!(
                a,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                b"Not enough arguments\x00" as *const u8
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
        }
        unsafe {
            result = Some(pack.expect("non-null function pointer"))
                .expect("non-null function pointer")(
                argc, numbers.as_mut_ptr(), &mut error
            );
        }
        if !error.is_null() {
            archive_set_error_safe!(
                a,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                b"%s\x00" as *const u8,
                error
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
        }
    } else {
        /* file system raw value. */
        result = mtree_atol(&mut val, 0) as dev_t
    }
    unsafe {
        *pdev = result;
    }
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
fn parse_hex_nibble(c: u8) -> i32 {
    if c >= '0' as u8 && c <= '9' as u8 {
        return c as i32 - '0' as i32;
    }
    if c >= 'a' as u8 && c <= 'f' as u8 {
        return 10 + c as i32 - 'a' as i32;
    }
    return -1;
}
fn parse_digest(
    a: *mut archive_read,
    entry: *mut archive_entry,
    digest: *const u8,
    type_0: i32,
) -> i32 {
    let mut digest_buf: [u8; 64] = [0; 64];
    let mut high: i32 = 0;
    let mut low: i32 = 0;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut len: size_t = 0;
    let a_safe = unsafe { &mut *a };
    if type_0 == ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_md5 {
        len = size_of::<[u8; 16]>() as u64
    } else if type_0 == ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_rmd160
        || type_0 == ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha1
    {
        len = size_of::<[u8; 20]>() as u64
    } else if type_0 == ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha256 {
        len = size_of::<[u8; 32]>() as u64
    } else if type_0 == ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha384 {
        len = size_of::<[u8; 48]>() as u64
    } else if type_0 == ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha512 {
        len = size_of::<[u8; 64]>() as u64
    } else {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_programmer,
            b"Internal error: Unknown digest type\x00" as *const u8
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    if len > size_of::<[u8; 64]>() as u64 {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_programmer,
            b"Internal error: Digest storage too large\x00" as *const u8
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    len = (len as u64).wrapping_mul(2) as size_t;
    if mtree_strnlen(digest, len.wrapping_add(1)) != len {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
            b"incorrect digest length, ignoring\x00" as *const u8
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
    }
    i = 0;
    j = 0;
    while i < len {
        unsafe {
            high = parse_hex_nibble(*digest.offset(i as isize));
            low = parse_hex_nibble(*digest.offset(i.wrapping_add(1) as isize));
        }
        if high == -1 || low == -1 {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                b"invalid digest data, ignoring\x00" as *const u8
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
        }
        digest_buf[j as usize] = (high << 4 | low) as u8;
        i = (i as u64).wrapping_add(2) as size_t;
        j = j.wrapping_add(1)
    }
    return unsafe { archive_entry_set_digest_safe(entry, type_0, digest_buf.as_mut_ptr()) };
}
/*
 * Parse a single keyword and its value.
 */
fn parse_keyword(
    a: *mut archive_read,
    mtree: *mut mtree,
    entry: *mut archive_entry,
    opt: *mut mtree_option,
    parsed_kws: *mut i32,
) -> i32 {
    let mut val: *mut u8 = 0 as *mut u8;
    let mut key: *mut u8 = 0 as *mut u8;
    key = unsafe { (*opt).value };
    let key_safe = unsafe { &mut *key };
    if *key_safe == '\u{0}' as u8 {
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    }
    let parsed_kws_safe = unsafe { &mut *parsed_kws };
    if unsafe { strcmp_safe(key, b"nochange\x00" as *const u8) } == 0 {
        *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange;
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    }
    if unsafe { strcmp_safe(key, b"optional\x00" as *const u8) } == 0 {
        *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_optional;
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    }
    if unsafe { strcmp_safe(key, b"ignore\x00" as *const u8) } == 0 {
        /*
         * The mtree processing is not recursive, so
         * recursion will only happen for explicitly listed
         * entries.
         */
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    }
    val = unsafe { strchr_safe(key, '=' as i32) };
    if val.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
            b"Malformed attribute \"%s\" (%d)\x00" as *const u8,
            key,
            *key.offset(0) as i32
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
    }
    let val_safe;
    let mtree_safe;
    unsafe {
        val_safe = &mut *val;
        mtree_safe = &mut *mtree;
    }
    *val_safe = '\u{0}' as u8;
    val = unsafe { val.offset(1) };
    let mut current_block: u64;
    match unsafe { *key.offset(0) as char } {
        'c' => {
            if unsafe { strcmp_safe(key, b"content\x00" as *const u8) } == 0
                || unsafe { strcmp_safe(key, b"contents\x00" as *const u8) } == 0
            {
                parse_escapes(val, 0 as *mut mtree_entry);
                mtree_safe.contents_name.length = 0;
                unsafe {
                    archive_strncat_safe(
                        &mut mtree_safe.contents_name,
                        val as *const (),
                        (if val.is_null() { 0 } else { strlen_safe(val) }),
                    )
                };
                current_block = 1;
            } else if unsafe { strcmp_safe(key, b"cksum\x00" as *const u8) } == 0 {
                current_block = 1;
            } else {
                current_block = 100;
            }
        }
        'd' => {
            current_block = 100;
        }
        'f' => {
            current_block = 102;
        }
        'g' => {
            current_block = 103;
        }
        'i' => {
            current_block = 105;
        }
        'l' => {
            current_block = 108;
        }
        'm' => {
            current_block = 109;
        }
        'n' => {
            current_block = 110;
        }
        'r' => {
            current_block = 114;
        }
        's' => {
            current_block = 115;
        }
        't' => {
            current_block = 116;
        }
        'u' => {
            current_block = 117;
        }
        _ => {
            current_block = 0;
        }
    }
    let a_safe = unsafe { &mut *a };
    match current_block {
        100 => {
            if unsafe { strcmp_safe(key, b"device\x00" as *const u8) } == 0 {
                /* stat(2) st_rdev field, e.g. the major/minor IDs
                 * of a char/block special file */
                let mut r: i32 = 0;
                let mut dev: dev_t = 0;
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_device;
                r = parse_device(&mut dev, &mut a_safe.archive, val);
                if r == ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
                    unsafe { archive_entry_set_rdev_safe(entry, dev) };
                }
                return r;
            }
            current_block = 102;
        }
        _ => {}
    }
    match current_block {
        102 => {
            if unsafe { strcmp_safe(key, b"flags\x00" as *const u8) } == 0 {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_fflags;
                unsafe { archive_entry_copy_fflags_text_safe(entry, val) };
                current_block = 1;
            } else {
                current_block = 103;
            }
        }
        _ => {}
    }
    match current_block {
        103 => {
            if unsafe { strcmp_safe(key, b"gid\x00" as *const u8) } == 0 {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_gid;
                unsafe { archive_entry_set_gid_safe(entry, mtree_atol(&mut val, 10)) };
                current_block = 1;
            } else if unsafe { strcmp_safe(key, b"gname\x00" as *const u8) } == 0 {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_gname;
                unsafe { archive_entry_copy_gname_safe(entry, val) };
                current_block = 1;
            } else {
                current_block = 105;
            }
        }
        _ => {}
    }
    match current_block {
        105 => {
            if unsafe { strcmp_safe(key, b"inode\x00" as *const u8) } == 0 {
                unsafe { archive_entry_set_ino_safe(entry, mtree_atol(&mut val, 10)) };
                current_block = 1;
            } else {
                current_block = 108;
            }
        }
        _ => {}
    }
    match current_block {
        108 => {
            if unsafe { strcmp_safe(key, b"link\x00" as *const u8) } == 0 {
                unsafe { archive_entry_copy_symlink_safe(entry, val) };
                current_block = 1;
            } else {
                current_block = 109;
            }
        }
        _ => {}
    }
    match current_block {
        109 => {
            if unsafe { strcmp_safe(key, b"md5\x00" as *const u8) } == 0
                || unsafe { strcmp_safe(key, b"md5digest\x00" as *const u8) } == 0
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_md5,
                );
            }
            if unsafe { strcmp_safe(key, b"mode\x00" as *const u8) } == 0 {
                if unsafe { *val.offset(0) >= '0' as u8 && *val.offset(0) <= '7' as u8 } {
                    *parsed_kws_safe |= 0x40;
                    unsafe {
                        archive_entry_set_perm_safe(entry, mtree_atol(&mut val, 8) as mode_t)
                    };
                } else {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                        b"Symbolic or non-octal mode \"%s\" unsupported\x00" as *const u8
                            as *const u8,
                        val
                    );
                    return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
                }
                current_block = 1;
            } else {
                current_block = 110;
            }
        }
        _ => {}
    }
    match current_block {
        110 => {
            if unsafe { strcmp_safe(key, b"nlink\x00" as *const u8) } == 0 {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nlink;
                unsafe { archive_entry_set_nlink_safe(entry, mtree_atol(&mut val, 10) as u32) };
                current_block = 1;
            } else {
                current_block = 114;
            }
        }
        _ => {}
    }
    match current_block {
        114 => {
            if unsafe { strcmp_safe(key, b"resdevice\x00" as *const u8) } == 0 {
                /* stat(2) st_dev field, e.g. the device ID where the
                 * inode resides */
                let mut r_0: i32 = 0;
                let mut dev_0: dev_t = 0;
                r_0 = parse_device(&mut dev_0, &mut a_safe.archive, val);
                if r_0 == 0 {
                    unsafe { archive_entry_set_dev_safe(entry, dev_0) };
                }
                return r_0;
            }
            if unsafe { strcmp_safe(key, b"rmd160\x00" as *const u8) } == 0
                || unsafe { strcmp_safe(key, b"rmd160digest\x00" as *const u8) } == 0
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_rmd160,
                );
            }
            current_block = 115;
        }
        _ => {}
    }
    match current_block {
        115 => {
            if unsafe { strcmp_safe(key, b"sha1\x00" as *const u8) } == 0
                || unsafe { strcmp_safe(key, b"sha1digest\x00" as *const u8) } == 0
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha1,
                );
            }
            if unsafe { strcmp_safe(key, b"sha256\x00" as *const u8) } == 0
                || unsafe { strcmp_safe(key, b"sha256digest\x00" as *const u8) } == 0
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha256,
                );
            }
            if unsafe { strcmp_safe(key, b"sha384\x00" as *const u8) } == 0
                || unsafe { strcmp_safe(key, b"sha384digest\x00" as *const u8) } == 0
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha384,
                );
            }
            if unsafe { strcmp_safe(key, b"sha512\x00" as *const u8) } == 0
                || unsafe { strcmp_safe(key, b"sha512digest\x00" as *const u8) } == 0
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha512,
                );
            }
            if unsafe { strcmp_safe(key, b"size\x00" as *const u8) } == 0 {
                unsafe { archive_entry_set_size_safe(entry, mtree_atol(&mut val, 10)) };
                current_block = 1;
            } else {
                current_block = 116;
            }
        }
        _ => {}
    }
    match current_block {
        116 => {
            if unsafe { strcmp_safe(key, b"tags\x00" as *const u8) } == 0 {
                current_block = 1;
            } else if unsafe { strcmp_safe(key, b"time\x00" as *const u8) } == 0 {
                let mut m: int64_t = 0;
                let my_time_t_max: int64_t = get_time_t_max();
                let my_time_t_min: int64_t = get_time_t_min();
                let mut ns: i64 = 0;
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_mtime;
                unsafe {
                    m = mtree_atol(&mut val, 10);
                }
                /* Replicate an old mtree bug:
                 * 123456789.1 represents 123456789
                 * seconds and 1 nanosecond. */
                if *val_safe == '.' as u8 {
                    unsafe {
                        val = val.offset(1);
                    }
                    ns = mtree_atol(&mut val, 10);
                    if ns < 0 {
                        ns = 0
                    } else if ns > 999999999 {
                        ns = 999999999
                    }
                }
                if m > my_time_t_max {
                    m = my_time_t_max
                } else if m < my_time_t_min {
                    m = my_time_t_min
                }
                unsafe { archive_entry_set_mtime_safe(entry, m, ns) };
                current_block = 1;
            } else if unsafe { strcmp_safe(key, b"type\x00" as *const u8) } == 0 {
                let mut current_block_110: u64;
                match unsafe { *val.offset(0) as i32 } {
                    98 => {
                        if unsafe { strcmp_safe(val, b"block\x00" as *const u8) } == 0 {
                            unsafe {
                                archive_entry_set_filetype_safe(
                                    entry,
                                    ARCHIVE_MTREE_DEFINED_PARAM.ae_ifblk as mode_t,
                                )
                            };
                            current_block_110 = 1;
                        } else {
                            current_block_110 = 99;
                        }
                    }
                    99 => {
                        current_block_110 = 99;
                    }
                    100 => {
                        current_block_110 = 100;
                    }
                    102 => {
                        current_block_110 = 102;
                    }
                    108 => {
                        current_block_110 = 108;
                    }
                    _ => {
                        current_block_110 = 0;
                    }
                }
                match current_block_110 {
                    99 => {
                        if unsafe { strcmp_safe(val, b"char\x00" as *const u8) } == 0 {
                            unsafe {
                                archive_entry_set_filetype_safe(
                                    entry,
                                    ARCHIVE_MTREE_DEFINED_PARAM.ae_ifchr as mode_t,
                                )
                            };
                            current_block_110 = 1;
                        } else {
                            current_block_110 = 100;
                        }
                    }
                    _ => {}
                }
                match current_block_110 {
                    100 => {
                        if unsafe { strcmp_safe(val, b"dir\x00" as *const u8) } == 0 {
                            unsafe {
                                archive_entry_set_filetype_safe(
                                    entry,
                                    ARCHIVE_MTREE_DEFINED_PARAM.ae_ifdir as mode_t,
                                )
                            };
                            current_block_110 = 1;
                        } else {
                            current_block_110 = 102;
                        }
                    }
                    _ => {}
                }
                match current_block_110 {
                    102 => {
                        if unsafe { strcmp_safe(val, b"fifo\x00" as *const u8) } == 0 {
                            unsafe {
                                archive_entry_set_filetype_safe(
                                    entry,
                                    ARCHIVE_MTREE_DEFINED_PARAM.ae_ififo as mode_t,
                                )
                            };
                            current_block_110 = 1;
                        } else if unsafe { strcmp_safe(val, b"file\x00" as *const u8) } == 0 {
                            unsafe {
                                archive_entry_set_filetype_safe(
                                    entry,
                                    ARCHIVE_MTREE_DEFINED_PARAM.ae_ifreg as mode_t,
                                )
                            };
                            current_block_110 = 1;
                        } else {
                            current_block_110 = 108;
                        }
                    }
                    _ => {}
                }
                match current_block_110 {
                    108 => {
                        if unsafe { strcmp_safe(val, b"link\x00" as *const u8) } == 0 {
                            unsafe {
                                archive_entry_set_filetype_safe(
                                    entry,
                                    ARCHIVE_MTREE_DEFINED_PARAM.ae_iflnk as mode_t,
                                )
                            };
                            current_block_110 = 1;
                        } else {
                            current_block_110 = 0;
                        }
                    }
                    _ => {}
                }
                match current_block_110 {
                    1 => {}
                    _ => {
                        archive_set_error_safe!(
                            &mut (*a).archive as *mut archive,
                            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                            b"Unrecognized file type \"%s\"; assuming \"file\"\x00" as *const u8
                                as *const u8,
                            val
                        );
                        unsafe {
                            archive_entry_set_filetype_safe(
                                entry,
                                ARCHIVE_MTREE_DEFINED_PARAM.ae_ifreg as mode_t,
                            )
                        };
                        return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
                    }
                }
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_type;
                current_block = 1;
            } else {
                current_block = 117;
            }
        }
        _ => {}
    }
    match current_block {
        117 => {
            if unsafe { strcmp_safe(key, b"uid\x00" as *const u8) } == 0 {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_uid;
                unsafe { archive_entry_set_uid_safe(entry, mtree_atol(&mut val, 10)) };
                current_block = 1;
            } else if unsafe { strcmp_safe(key, b"uname\x00" as *const u8) } == 0 {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_uname;
                unsafe { archive_entry_copy_uname_safe(entry, val) };
                current_block = 1;
            } else {
                current_block = 0;
            }
        }
        _ => {}
    }
    match current_block {
        1 =>
            /*
         * Comma delimited list of tags.
         * Ignore the tags for now, but the interface
         * should be extended to allow inclusion/exclusion.
         */
            {}
        _ => {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                b"Unrecognized key %s=%s\x00" as *const u8,
                key,
                val
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
        }
    }
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}

fn read_data(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let mut bytes_to_read: size_t = 0;
    let mut bytes_read: ssize_t = 0;
    let mut mtree: *mut mtree = 0 as *mut mtree;
    let mtree_safe;
    let buff_safe;
    let offset_safe;
    let size_safe;
    let a_safe;
    unsafe {
        mtree = (*(*a).format).data as *mut mtree;
        mtree_safe = &mut *mtree;
        buff_safe = &mut *buff;
        offset_safe = &mut *offset;
        size_safe = &mut *size;
        a_safe = &mut *a;
    }
    if mtree_safe.fd < 0 {
        *buff_safe = 0 as *const ();
        *offset_safe = 0;
        *size_safe = 0;
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_eof;
    }
    if mtree_safe.buff.is_null() {
        mtree_safe.buffsize = 64;
        mtree_safe.buff = unsafe { malloc_safe(mtree_safe.buffsize) } as *mut u8;
        if mtree_safe.buff.is_null() {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_MTREE_DEFINED_PARAM.enomem,
                b"Can\'t allocate memory\x00" as *const u8
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
        }
    }
    *buff_safe = mtree_safe.buff as *const ();
    *offset_safe = mtree_safe.offset;
    if mtree_safe.buffsize as int64_t > mtree_safe.cur_size - mtree_safe.offset {
        bytes_to_read = (mtree_safe.cur_size - mtree_safe.offset) as size_t
    } else {
        bytes_to_read = mtree_safe.buffsize
    }
    bytes_read = unsafe { read_safe(mtree_safe.fd, mtree_safe.buff as *mut (), bytes_to_read) };
    if bytes_read < 0 {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            *__errno_location(),
            b"Can\'t read\x00" as *const u8
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
    }
    if bytes_read == 0 {
        *size_safe = 0;
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_eof;
    }
    mtree_safe.offset += bytes_read;
    *size_safe = bytes_read as size_t;
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
/* Skip does nothing except possibly close the contents file. */
fn skip(a: *mut archive_read) -> i32 {
    let mut mtree: *mut mtree = 0 as *mut mtree;
    let mtree_safe;
    unsafe {
        mtree = (*(*a).format).data as *mut mtree;
        mtree_safe = &mut *mtree;
    }
    if mtree_safe.fd >= 0 {
        unsafe { close_safe(mtree_safe.fd) };
        mtree_safe.fd = -1
    }
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
/*
 * Since parsing backslash sequences always makes strings shorter,
 * we can always do this conversion in-place.
 */
fn parse_escapes(mut src: *mut u8, mentry: *mut mtree_entry) {
    let mut dest: *mut u8 = src;
    let mut c: u8 = 0;
    let mentry_safe = unsafe { &mut *mentry };
    if !mentry.is_null() && unsafe { strcmp_safe(src, b".\x00" as *const u8) } == 0 {
        mentry_safe.full = 1
    }
    while unsafe { *src != '\u{0}' as u8 } {
        let fresh3 = src;
        unsafe {
            src = src.offset(1);
            c = *fresh3;
        }
        if c == '/' as u8 && !mentry.is_null() {
            mentry_safe.full = 1
        }
        if c == '\\' as u8 {
            let current_block_30: u64;
            match unsafe { *src.offset(0) as i32 } {
                48 => {
                    if unsafe {
                        (*src.offset(1) as i32) < '0' as i32 || *src.offset(1) as i32 > '7' as i32
                    } {
                        c = 0;
                        src = unsafe { src.offset(1) };
                        current_block_30 = 10;
                    } else {
                        current_block_30 = 9;
                    }
                }
                49 | 50 | 51 => {
                    current_block_30 = 9;
                }
                97 => {
                    c = '\u{7}' as u8;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 10;
                }
                98 => {
                    c = '\u{8}' as u8;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 10;
                }
                102 => {
                    c = '\u{c}' as u8;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 10;
                }
                110 => {
                    c = '\n' as u8;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 10;
                }
                114 => {
                    c = '\r' as u8;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 10;
                }
                115 => {
                    c = ' ' as u8;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 10;
                }
                116 => {
                    c = '\t' as u8;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 10;
                }
                118 => {
                    c = '\u{b}' as u8;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 10;
                }
                92 => {
                    c = '\\' as u8;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 10;
                }
                _ => {
                    current_block_30 = 10;
                }
            }
            match current_block_30 {
                9 =>
                /* FALLTHROUGH */
                unsafe {
                    if *src.offset(1) >= '0' as u8
                        && *src.offset(1) <= '7' as u8
                        && *src.offset(2) >= '0' as u8
                        && *src.offset(2) <= '7' as u8
                    {
                        c = ((*src.offset(0) as i32 - '0' as i32) << 6) as u8;
                        c = (c as i32 | (*src.offset(1) as i32 - '0' as i32) << 3) as u8;
                        c = (c as i32 | *src.offset(2) as i32 - '0' as i32) as u8;
                        src = src.offset(3)
                    }
                },
                _ => {}
            }
        }
        let fresh4 = dest;
        unsafe {
            dest = dest.offset(1);
            *fresh4 = c
        }
    }
    unsafe {
        *dest = '\u{0}' as u8;
    }
}
/* Parse a hex digit. */
fn parsedigit(c: u8) -> i32 {
    if c >= '0' as u8 && c <= '9' as u8 {
        return c as i32 - '0' as i32;
    } else if c >= 'a' as u8 && c <= 'f' as u8 {
        return c as i32 - 'a' as i32;
    } else if c >= 'A' as u8 && c <= 'F' as u8 {
        return c as i32 - 'A' as i32;
    } else {
        return -1;
    };
}
/*
 * Note that this implementation does not (and should not!) obey
 * locale settings; you cannot simply substitute strtol here, since
 * it does obey locale.
 */
fn mtree_atol(p: *mut *mut u8, mut base: i32) -> int64_t {
    let mut l: int64_t = 0;
    let mut limit: int64_t = 0;
    let mut digit: i32 = 0;
    let mut last_digit_limit: i32 = 0;
    let p_safe = unsafe { &mut *p };
    if base == 0 {
        unsafe {
            if **p != '0' as u8 {
                base = 10
            } else if *(*p).offset(1) == 'x' as u8 || *(*p).offset(1) == 'X' as u8 {
                *p_safe = (*p).offset(2);
                base = 16
            } else {
                base = 8
            }
        }
    }
    if unsafe { **p == '-' as u8 } {
        limit = ARCHIVE_MTREE_DEFINED_PARAM.int64_min / base as i64;
        last_digit_limit = -(ARCHIVE_MTREE_DEFINED_PARAM.int64_min % base as i64) as i32;
        *p_safe = unsafe { (*p).offset(1) };
        l = 0;
        digit = unsafe { parsedigit(**p) };
        while digit >= 0 && digit < base {
            if l < limit || l == limit && digit >= last_digit_limit {
                return ARCHIVE_MTREE_DEFINED_PARAM.int64_min;
            }
            l = l * base as i64 - digit as i64;
            *p_safe = unsafe { (*p).offset(1) };
            digit = unsafe { parsedigit(**p) }
        }
        return l;
    } else {
        limit = ARCHIVE_MTREE_DEFINED_PARAM.int64_max / base as i64;
        last_digit_limit = (ARCHIVE_MTREE_DEFINED_PARAM.int64_max % base as i64) as i32;
        l = 0;
        digit = unsafe { parsedigit(**p) };
        while digit >= 0 && digit < base {
            if l > limit || l == limit && digit > last_digit_limit {
                return ARCHIVE_MTREE_DEFINED_PARAM.int64_max;
            }
            l = l * base as i64 + digit as i64;
            *p_safe = unsafe { (*p).offset(1) };
            digit = unsafe { parsedigit(**p) }
        }
        return l;
    };
}
/*
 * Returns length of line (including trailing newline)
 * or negative on error.  'start' argument is updated to
 * point to first character of line.
 */
fn readline(
    a: *mut archive_read,
    mtree: *mut mtree,
    start: *mut *mut u8,
    limit: ssize_t,
) -> ssize_t {
    let mut bytes_read: ssize_t = 0;
    let mut total_size: ssize_t = 0;
    let mut find_off: ssize_t = 0;
    let mut t: *const () = 0 as *const ();
    let mut nl: *mut () = 0 as *mut ();
    let mut u: *mut u8 = 0 as *mut u8;
    loop
    /* Accumulate line in a line buffer. */
    /* Read some more. */
    {
        t = unsafe { __archive_read_ahead_safe(a, 1, &mut bytes_read) };
        if t == 0 as *mut () {
            return 0;
        }
        if bytes_read < 0 {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        nl = unsafe { memchr_safe(t, '\n' as i32, bytes_read as u64) };
        /* If we found '\n', trim the read to end exactly there. */
        if !nl.is_null() {
            unsafe { bytes_read = (nl as *const u8).offset_from(t as *const u8) as i64 + 1 }
        }
        let a_safe = unsafe { &mut *a };
        let mtree_safe = unsafe { &mut *mtree };
        if total_size + bytes_read + 1 > limit {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                b"Line too long\x00" as *const u8
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        if unsafe {
            archive_string_ensure_safe(
                &mut mtree_safe.line,
                (total_size + bytes_read + 1) as size_t,
            )
        }
        .is_null()
        {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_MTREE_DEFINED_PARAM.enomem,
                b"Can\'t allocate working buffer\x00" as *const u8
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        /* Append new bytes to string. */
        unsafe {
            memcpy_safe(
                (*mtree).line.s.offset(total_size as isize) as *mut (),
                t,
                bytes_read as u64,
            );
        }
        unsafe { __archive_read_consume_safe(a, bytes_read) };
        total_size += bytes_read;
        unsafe {
            *(*mtree).line.s.offset(total_size as isize) = '\u{0}' as u8;
            u = (*mtree).line.s.offset(find_off as isize);
            while *u != 0 {
                if *u.offset(0) == '\n' as u8 {
                    /* Ends with unescaped newline. */
                    *start = (*mtree).line.s;
                    return total_size;
                } else {
                    if *u.offset(0) == '#' as u8 {
                        /* Ends with comment sequence #...\n */
                        if nl.is_null() {
                            break;
                        }
                    } else if *u.offset(0) == '\\' as u8 {
                        if *u.offset(1) == '\n' as u8 {
                            /* Trim escaped newline. */
                            total_size -= 2;
                            *(*mtree).line.s.offset(total_size as isize) = '\u{0}' as u8;
                            break;
                        } else if *u.offset(1) != '\u{0}' as u8 {
                            /* Skip the two-char escape sequence */
                            u = u.offset(1)
                        }
                    }
                    u = u.offset(1)
                }
            }
            find_off = u.offset_from((*mtree).line.s) as i64
        }
    }
}

#[no_mangle]
pub fn archive_test_parse_keyword(
    _a: *mut archive,
    entry: *mut archive_entry,
    parsed_kws: *mut i32,
) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut mtree: *mut mtree = 0 as *mut mtree;
    mtree = unsafe { calloc_safe(1, size_of::<mtree>() as u64) } as *mut mtree;
    let mut mtree_option: *mut mtree_option = 0 as *mut mtree_option;
    mtree_option = unsafe { calloc_safe(1, size_of::<mtree_option>() as u64) } as *mut mtree_option;
    let mut mtree_entry: *mut mtree_entry = 0 as *mut mtree_entry;
    mtree_entry = unsafe { calloc_safe(1, size_of::<mtree_entry>() as u64) } as *mut mtree_entry;
    unsafe {
        (*(mtree_option)).value = b"optional" as *const u8 as *mut u8;
    }
    parse_keyword(a, mtree, entry, mtree_option, parsed_kws);
}

#[no_mangle]
pub fn archive_test_process_global_unset(_a: *mut archive, line: *const u8) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut mtree_option: *mut mtree_option = 0 as *mut mtree_option;
    mtree_option = unsafe { calloc_safe(1, size_of::<mtree_option>() as u64) } as *mut mtree_option;
    let mtree_option2: *mut *mut mtree_option = mtree_option as *mut *mut mtree_option;
    process_global_unset(a, mtree_option2, line);
}

#[no_mangle]
pub fn archive_test_la_strsep(sp: *mut *mut u8, sep: *const u8) {
    la_strsep(sp, sep);
}

#[no_mangle]
pub fn archive_test_parse_digest(
    _a: *mut archive_read,
    entry: *mut archive_entry,
    digest: *const u8,
    type_0: i32,
) {
    let a: *mut archive_read = _a as *mut archive_read;
    parse_digest(a, entry, digest, type_0);
}

#[no_mangle]
pub fn archive_test_archive_read_support_format_mtree() {
    let mut archive_read: *mut archive_read = 0 as *mut archive_read;
    archive_read = unsafe { calloc_safe(1, size_of::<archive_read>() as u64) } as *mut archive_read;
    unsafe {
        (*archive_read).archive.magic = ARCHIVE_AR_DEFINED_PARAM.archive_read_magic;
    }
    unsafe {
        (*archive_read).archive.state = ARCHIVE_AR_DEFINED_PARAM.archive_state_new;
    }
    archive_read_support_format_mtree(unsafe { &mut (*archive_read).archive } as *mut archive);
}

#[no_mangle]
pub fn archive_test_read_header(_a: *mut archive, entry: *mut archive_entry) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut mtree: *mut mtree = 0 as *mut mtree;
    mtree = unsafe { calloc_safe(1, size_of::<mtree>() as u64) } as *mut mtree;
    unsafe {
        (*mtree).fd = 1;
    }
    unsafe {
        (*(*a).format).data = mtree as *mut ();
    }
    read_header(a, entry);
}

#[no_mangle]
fn archive_test_parse_device(a: *mut archive) {
    let pdevp: [dev_t; 4] = [1, 2, 3, 4];
    let pdev: *mut dev_t = &pdevp as *const [dev_t; 4] as *mut [dev_t; 4] as *mut dev_t;
    let valp: [u8; 5] = ['1' as u8, '2' as u8, ',' as u8, '3' as u8, '4' as u8];
    let val: *mut u8 = &valp as *const [u8; 5] as *mut [u8; 5] as *mut u8;
    parse_device(pdev, a, val);
    let valp2: [u8; 9] = [
        '1' as u8, '2' as u8, ',' as u8, '3' as u8, '8' as u8, '6' as u8, 'b' as u8, 's' as u8,
        'd' as u8,
    ];
    let val2: *mut u8 = &valp2 as *const [u8; 9] as *mut [u8; 9] as *mut u8;
    parse_device(pdev, a, val2);
}

#[no_mangle]
fn archive_test_archive_read_format_mtree_options(_a: *mut archive) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut mtree: *mut mtree = 0 as *mut mtree;
    mtree = unsafe { calloc_safe(1, size_of::<mtree>() as u64) } as *mut mtree;
    unsafe { (*(*a).format).data = mtree as *mut () };
    archive_read_format_mtree_options(a, b"checkfs\x00" as *const u8, b"None\x00" as *const u8);
}

#[no_mangle]
fn archive_test_bid_keyword() {
    bid_keyword(b"rsd\x00" as *const u8, 3);
}

#[no_mangle]
fn archive_test_bid_keyword_list() {
    bid_keyword_list(b"12345\x00" as *const u8, 5, 1, 0);
}

#[no_mangle]
fn archive_test_mtree_atol() {
    let p1: [u8; 3] = ['0' as u8, 'x' as u8, 'x' as u8];
    let p2: *mut u8 = &p1 as *const [u8; 3] as *mut [u8; 3] as *mut u8;
    let p: *mut *mut u8 = unsafe { &p2 as *const *mut u8 as *mut *mut u8 };
    mtree_atol(p, 0);
}
