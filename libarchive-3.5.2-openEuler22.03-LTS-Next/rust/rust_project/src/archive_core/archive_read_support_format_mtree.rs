use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_struct::struct_transfer::* ;
use rust_ffi::ffi_method::method_call::*;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mtree {
    pub line: archive_string,
    pub buffsize: size_t,
    pub buff: *mut libc::c_char,
    pub offset: int64_t,
    pub fd: libc::c_int,
    pub archive_format: libc::c_int,
    pub archive_format_name: *const libc::c_char,
    pub entries: *mut mtree_entry,
    pub this_entry: *mut mtree_entry,
    pub entry_rbtree: archive_rb_tree,
    pub current_dir: archive_string,
    pub contents_name: archive_string,
    pub resolver: *mut archive_entry_linkresolver,
    pub rbtree: archive_rb_tree,
    pub cur_size: int64_t,
    pub checkfs: libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mtree_entry {
    pub rbnode: archive_rb_node,
    pub next_dup: *mut mtree_entry,
    pub next: *mut mtree_entry,
    pub options: *mut mtree_option,
    pub name: *mut libc::c_char,
    pub full: libc::c_char,
    pub used: libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mtree_option {
    pub next: *mut mtree_option,
    pub value: *mut libc::c_char,
}

extern "C" fn get_time_t_max() -> int64_t {
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
            if (0 as libc::c_int as time_t) < -(1 as libc::c_int) as time_t {
                /* Time_t is unsigned */
                return !(0 as libc::c_int as time_t);
            } else if ::std::mem::size_of::<time_t>() as libc::c_ulong
                == ::std::mem::size_of::<int64_t>() as libc::c_ulong
            {
                return ARCHIVE_MTREE_DEFINED_PARAM.int64_max as time_t;
            } else {
                return ARCHIVE_MTREE_DEFINED_PARAM.int32_max as time_t;
            };
        }
    }
}
extern "C" fn get_time_t_min() -> int64_t {
    match () {
        #[cfg(HAVE_TIME_T_MIN)]
        _ => {
            return ARCHIVE_MTREE_DEFINED_PARAM.time_t_min;
        }
        #[cfg(not(HAVE_TIME_T_MIN))]
        _ => {
            if (0 as libc::c_int as time_t) < -(1 as libc::c_int) as time_t {
                /* Time_t is signed. */
                /* Assume it's the same as int64_t or int32_t */
                /* Time_t is unsigned */
                return 0 as libc::c_int as time_t;
            } else if ::std::mem::size_of::<time_t>() as libc::c_ulong
                == ::std::mem::size_of::<int64_t>() as libc::c_ulong
            {
                return ARCHIVE_MTREE_DEFINED_PARAM.int64_min as time_t;
            } else {
                return ARCHIVE_MTREE_DEFINED_PARAM.int32_min as time_t;
            };
        }
    }
}

extern "C" fn mtree_strnlen(mut p: *const libc::c_char, mut maxlen: size_t) -> size_t {
    match () {
        #[cfg(HAVE_STRLEN)]
        _ => {
            return strnlen_safe(p, maxlen);
        }
        #[cfg(not(HAVE_STRLEN))]
        _ => {
            let mut i: size_t = 0;
            i = 0 as libc::c_int as size_t;
            while i <= maxlen {
                if unsafe {
                    *p.offset(i as isize) as libc::c_int as size_t == 0 as libc::c_int as size_t
                } {
                    break;
                }
                i += 1
            }
            if i > maxlen {
                return -(1 as libc::c_int) as size_t;
            }
            return i;
        }
    }
}
extern "C" fn archive_read_format_mtree_options(
    mut a: *mut archive_read,
    mut key: *const libc::c_char,
    mut val: *const libc::c_char,
) -> libc::c_int {
    let mut mtree: *mut mtree = 0 as *mut mtree;
    mtree = unsafe { (*(*a).format).data as *mut mtree };
    let mtree_safe = unsafe { &mut *mtree };
    if strcmp_safe(key, b"checkfs\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        /* Time_t is signed. */
        /* Allows to read information missing from the mtree from the file system */
        if val.is_null()
            || unsafe { *val.offset(0 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int }
        {
            mtree_safe.checkfs = 0 as libc::c_int as libc::c_char
        } else {
            mtree_safe.checkfs = 1 as libc::c_int as libc::c_char
        }
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    }
    /* Note: The "warn" return is just to inform the options
     * supervisor that we didn't handle it.  It will generate
     * a suitable error if no one used this option. */
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
}

extern "C" fn free_options(mut head: *mut mtree_option) {
    let mut next: *mut mtree_option = 0 as *mut mtree_option;
    while !head.is_null() {
        let head_safe = unsafe { &mut *head };
        next = head_safe.next;
        free_safe(head_safe.value as *mut libc::c_void);
        free_safe(head as *mut libc::c_void);
        head = next
    }
}
extern "C" fn mtree_cmp_node(
    mut n1: *const archive_rb_node,
    mut n2: *const archive_rb_node,
) -> libc::c_int {
    let mut e1: *const mtree_entry = n1 as *const mtree_entry;
    let mut e2: *const mtree_entry = n2 as *const mtree_entry;
    unsafe { return strcmp_safe((*e1).name, (*e2).name) };
}
extern "C" fn mtree_cmp_key(
    mut n: *const archive_rb_node,
    mut key: *const libc::c_void,
) -> libc::c_int {
    let mut e: *const mtree_entry = n as *const mtree_entry;
    let e_safe = unsafe { &*e };
    return strcmp_safe(e_safe.name, key as *const libc::c_char);
}
#[no_mangle]
pub extern "C" fn archive_read_support_format_mtree(mut _a: *mut archive) -> libc::c_int {
    static mut rb_ops: archive_rb_tree_ops = unsafe {
        {
            let mut init = archive_rb_tree_ops {
                rbto_compare_nodes: Some(
                    mtree_cmp_node
                        as unsafe extern "C" fn(
                            _: *const archive_rb_node,
                            _: *const archive_rb_node,
                        ) -> libc::c_int,
                ),
                rbto_compare_key: Some(
                    mtree_cmp_key
                        as unsafe extern "C" fn(
                            _: *const archive_rb_node,
                            _: *const libc::c_void,
                        ) -> libc::c_int,
                ),
            };
            init
        }
    };
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut mtree: *mut mtree = 0 as *mut mtree;
    let mut r: libc::c_int = 0;
    let mut magic_test: libc::c_int = __archive_check_magic_safe(
        _a,
        0xdeb0c5 as libc::c_uint,
        1 as libc::c_uint,
        b"archive_read_support_format_mtree\x00" as *const u8 as *const libc::c_char,
    );
    if magic_test == -(30 as libc::c_int) {
        return -(30 as libc::c_int);
    }
    mtree = calloc_safe(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<mtree>() as libc::c_ulong,
    ) as *mut mtree;
    let a_safe = unsafe { &mut *a };
    if mtree.is_null() {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.enomem,
            b"Can\'t allocate mtree data\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    let mtree_safe = unsafe { &mut *mtree };
    mtree_safe.checkfs = 0 as libc::c_int as libc::c_char;
    mtree_safe.fd = -(1 as libc::c_int);
    unsafe {
        __archive_rb_tree_init_safe(&mut mtree_safe.rbtree, &rb_ops);
    }
    r = __archive_read_register_format_safe(
        a,
        mtree as *mut libc::c_void,
        b"mtree\x00" as *const u8 as *const libc::c_char,
        Some(mtree_bid as extern "C" fn(_: *mut archive_read, _: libc::c_int) -> libc::c_int),
        Some(
            archive_read_format_mtree_options
                as extern "C" fn(
                    _: *mut archive_read,
                    _: *const libc::c_char,
                    _: *const libc::c_char,
                ) -> libc::c_int,
        ),
        Some(
            read_header
                as extern "C" fn(_: *mut archive_read, _: *mut archive_entry) -> libc::c_int,
        ),
        Some(
            read_data
                as extern "C" fn(
                    _: *mut archive_read,
                    _: *mut *const libc::c_void,
                    _: *mut size_t,
                    _: *mut int64_t,
                ) -> libc::c_int,
        ),
        Some(skip as extern "C" fn(_: *mut archive_read) -> libc::c_int),
        None,
        Some(cleanup as extern "C" fn(_: *mut archive_read) -> libc::c_int),
        None,
        None,
    );
    if r != ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
        free_safe(mtree as *mut libc::c_void);
    }
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
extern "C" fn cleanup(mut a: *mut archive_read) -> libc::c_int {
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
        free_safe(p_safe.name as *mut libc::c_void);
        free_options(p_safe.options);
        free_safe(p as *mut libc::c_void);
        p = q
    }
    archive_string_free_safe(&mut mtree_safe.line);
    archive_string_free_safe(&mut mtree_safe.current_dir);
    archive_string_free_safe(&mut mtree_safe.contents_name);
    archive_entry_linkresolver_free_safe(mtree_safe.resolver);
    free_safe(mtree_safe.buff as *mut libc::c_void);
    free_safe(mtree as *mut libc::c_void);
    a_safe.data = 0 as *mut libc::c_void;
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
extern "C" fn get_line_size(
    mut b: *const libc::c_char,
    mut avail: ssize_t,
    mut nlsize: *mut ssize_t,
) -> ssize_t {
    let mut len: ssize_t = 0;
    len = 0 as libc::c_int as ssize_t;
    while len < avail {
        loop {
            let b_safe = unsafe { &*b };
            let nlsize_safe = unsafe { &mut *nlsize };
            match *b_safe as libc::c_int {
                0 => {
                    /* Non-ascii character or control character. */
                    if !nlsize.is_null() {
                        *nlsize_safe = 0 as libc::c_int as ssize_t
                    }
                    return -(1 as libc::c_int) as ssize_t;
                }
                13 => {
                    if unsafe {
                        avail - len > 1 as libc::c_int as libc::c_long
                            && *b.offset(1 as libc::c_int as isize) as libc::c_int == '\n' as i32
                    } {
                        if !nlsize.is_null() {
                            *nlsize_safe = 2 as libc::c_int as ssize_t
                        }
                        return len + 2 as libc::c_int as libc::c_long;
                    }
                }
                10 => {}
                _ => {
                    b = unsafe { b.offset(1) };
                    len += 1;
                    break;
                    // break;
                }
            }
            /* FALL THROUGH */
            if !nlsize.is_null() {
                *nlsize_safe = 1 as libc::c_int as ssize_t
            }
            return len + 1 as libc::c_int as libc::c_long;
        }
    }
    let nlsize_safe = unsafe { &mut *nlsize };
    if !nlsize.is_null() {
        *nlsize_safe = 0 as libc::c_int as ssize_t
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
extern "C" fn next_line(
    mut a: *mut archive_read,
    mut b: *mut *const libc::c_char,
    mut avail: *mut ssize_t,
    mut ravail: *mut ssize_t,
    mut nl: *mut ssize_t,
) -> ssize_t {
    let mut len: ssize_t = 0;
    let mut quit: libc::c_int = 0;
    quit = 0 as libc::c_int;
    let avail_safe = unsafe { &mut *avail };
    let nl_safe = unsafe { &mut *nl };
    let b_safe = unsafe { &mut *b };
    if *avail_safe == 0 as libc::c_int as libc::c_long {
        *nl_safe = 0 as libc::c_int as ssize_t;
        len = 0 as libc::c_int as ssize_t
    } else {
        len = get_line_size(*b_safe, *avail_safe, nl)
    }
    /*
     * Read bytes more while it does not reach the end of line.
     */
    while *nl_safe == 0 as libc::c_int as libc::c_long && len == *avail_safe && quit == 0 {
        let ravail_safe = unsafe { &mut *ravail };
        let mut diff: ssize_t = *ravail_safe - *avail_safe;
        let mut nbytes_req: size_t = (*ravail_safe + 1023 as libc::c_int as libc::c_long
            & !(1023 as libc::c_uint) as libc::c_long)
            as size_t;
        let mut tested: ssize_t = 0;
        /*
         * Place an arbitrary limit on the line length.
         * mtree is almost free-form input and without line length limits,
         * it can consume a lot of memory.
         */
        if len >= ARCHIVE_MTREE_DEFINED_PARAM.max_line_len {
            return -(1 as libc::c_int) as ssize_t;
        }
        /* Increase reading bytes if it is not enough to at least
         * new two lines. */
        if nbytes_req < (*ravail_safe as size_t).wrapping_add(160 as libc::c_int as libc::c_ulong) {
            nbytes_req <<= 1 as libc::c_int
        }
        *b_safe = __archive_read_ahead_safe(a, nbytes_req, avail) as *const libc::c_char;
        if b_safe.is_null() {
            if ravail_safe >= avail_safe {
                return 0 as libc::c_int as ssize_t;
            }
            /* Reading bytes reaches the end of file. */
            *b_safe =
                __archive_read_ahead_safe(a, *avail_safe as size_t, avail) as *const libc::c_char; /* Skip some bytes we already determined. */
            quit = 1 as libc::c_int
        }
        *ravail_safe = *avail_safe;
        *b_safe = unsafe { (*b).offset(diff as isize) };
        *avail_safe -= diff;
        tested = len;
        len = unsafe { get_line_size((*b).offset(len as isize), *avail_safe - len, nl) };
        if len >= 0 as libc::c_int as libc::c_long {
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
extern "C" fn bid_keycmp(
    mut p: *const libc::c_char,
    mut key: *const libc::c_char,
    mut len: ssize_t,
) -> libc::c_int {
    let mut match_len: libc::c_int = 0 as libc::c_int;
    let mut key_safe;
    let mut p_safe;
    while unsafe {
        len > 0 as libc::c_int as libc::c_long && *p as libc::c_int != 0 && *key as libc::c_int != 0
    } {
        unsafe {
            p_safe = &*p;
            key_safe = &*key;
        }
        if *p_safe as libc::c_int == *key_safe as libc::c_int {
            len -= 1;
            unsafe {
                p = p.offset(1);
                key = key.offset(1);
            }
            match_len += 1
        } else {
            return 0 as libc::c_int;
        }
        /* Not match */
    } /* Not match */
    if unsafe { *key as libc::c_int != '\u{0}' as i32 } {
        return 0 as libc::c_int;
    }
    /* A following character should be specified characters */
    if unsafe {
        *p.offset(0 as libc::c_int as isize) as libc::c_int == '=' as i32
            || *p.offset(0 as libc::c_int as isize) as libc::c_int == ' ' as i32
            || *p.offset(0 as libc::c_int as isize) as libc::c_int == '\t' as i32
            || *p.offset(0 as libc::c_int as isize) as libc::c_int == '\n' as i32
            || *p.offset(0 as libc::c_int as isize) as libc::c_int == '\r' as i32
            || *p.offset(0 as libc::c_int as isize) as libc::c_int == '\\' as i32
                && (*p.offset(1 as libc::c_int as isize) as libc::c_int == '\n' as i32
                    || *p.offset(1 as libc::c_int as isize) as libc::c_int == '\r' as i32)
    } {
        return match_len;
    }
    return 0 as libc::c_int;
    /* Not match */
}
/*
 * Test whether the characters 'p' has is mtree keyword.
 * Returns the length of a detected keyword.
 * Returns 0 if any keywords were not found.
 */
extern "C" fn bid_keyword(mut p: *const libc::c_char, mut len: ssize_t) -> libc::c_int {
    static mut keys_c: [*const libc::c_char; 4] = [
        b"content\x00" as *const u8 as *const libc::c_char,
        b"contents\x00" as *const u8 as *const libc::c_char,
        b"cksum\x00" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    static mut keys_df: [*const libc::c_char; 3] = [
        b"device\x00" as *const u8 as *const libc::c_char,
        b"flags\x00" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    static mut keys_g: [*const libc::c_char; 3] = [
        b"gid\x00" as *const u8 as *const libc::c_char,
        b"gname\x00" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    static mut keys_il: [*const libc::c_char; 4] = [
        b"ignore\x00" as *const u8 as *const libc::c_char,
        b"inode\x00" as *const u8 as *const libc::c_char,
        b"link\x00" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    static mut keys_m: [*const libc::c_char; 4] = [
        b"md5\x00" as *const u8 as *const libc::c_char,
        b"md5digest\x00" as *const u8 as *const libc::c_char,
        b"mode\x00" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    static mut keys_no: [*const libc::c_char; 4] = [
        b"nlink\x00" as *const u8 as *const libc::c_char,
        b"nochange\x00" as *const u8 as *const libc::c_char,
        b"optional\x00" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    static mut keys_r: [*const libc::c_char; 4] = [
        b"resdevice\x00" as *const u8 as *const libc::c_char,
        b"rmd160\x00" as *const u8 as *const libc::c_char,
        b"rmd160digest\x00" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    static mut keys_s: [*const libc::c_char; 10] = [
        b"sha1\x00" as *const u8 as *const libc::c_char,
        b"sha1digest\x00" as *const u8 as *const libc::c_char,
        b"sha256\x00" as *const u8 as *const libc::c_char,
        b"sha256digest\x00" as *const u8 as *const libc::c_char,
        b"sha384\x00" as *const u8 as *const libc::c_char,
        b"sha384digest\x00" as *const u8 as *const libc::c_char,
        b"sha512\x00" as *const u8 as *const libc::c_char,
        b"sha512digest\x00" as *const u8 as *const libc::c_char,
        b"size\x00" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    static mut keys_t: [*const libc::c_char; 4] = [
        b"tags\x00" as *const u8 as *const libc::c_char,
        b"time\x00" as *const u8 as *const libc::c_char,
        b"type\x00" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    static mut keys_u: [*const libc::c_char; 3] = [
        b"uid\x00" as *const u8 as *const libc::c_char,
        b"uname\x00" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    let mut keys: *const *const libc::c_char = 0 as *const *const libc::c_char;
    let mut i: libc::c_int = 0;
    unsafe {
        match *p as libc::c_int {
            99 => {
                keys = keys_c.as_ptr()
                /* Unknown key */
            }
            100 | 102 => keys = keys_df.as_ptr(),
            103 => keys = keys_g.as_ptr(),
            105 | 108 => keys = keys_il.as_ptr(),
            109 => keys = keys_m.as_ptr(),
            110 | 111 => keys = keys_no.as_ptr(),
            114 => keys = keys_r.as_ptr(),
            115 => keys = keys_s.as_ptr(),
            116 => keys = keys_t.as_ptr(),
            117 => keys = keys_u.as_ptr(),
            _ => return 0 as libc::c_int,
        }
    }
    i = 0 as libc::c_int;
    while unsafe { !(*keys.offset(i as isize)).is_null() } {
        let mut l: libc::c_int = unsafe { bid_keycmp(p, *keys.offset(i as isize), len) };
        if l > 0 as libc::c_int {
            return l;
        }
        i += 1
    }
    return 0 as libc::c_int;
    /* Unknown key */
}
/*
 * Test whether there is a set of mtree keywords.
 * Returns the number of keyword.
 * Returns -1 if we got incorrect sequence.
 * This function expects a set of "<space characters>keyword=value".
 * When "unset" is specified, expects a set of "<space characters>keyword".
 */
extern "C" fn bid_keyword_list(
    mut p: *const libc::c_char,
    mut len: ssize_t,
    mut unset: libc::c_int,
    mut last_is_path: libc::c_int,
) -> libc::c_int {
    let mut l: libc::c_int = 0;
    let mut keycnt: libc::c_int = 0 as libc::c_int;
    let mut p_safe = unsafe { &*p };
    while len > 0 as libc::c_int as libc::c_long && *p_safe as libc::c_int != 0 {
        let mut blank: libc::c_int = 0 as libc::c_int;
        /* Test whether there are blank characters in the line. */
        p_safe = unsafe { &*p };
        while len > 0 as libc::c_int as libc::c_long
            && (*p_safe as libc::c_int == ' ' as i32 || *p_safe as libc::c_int == '\t' as i32)
        {
            p = unsafe { p.offset(1) };
            len -= 1;
            blank = 1 as libc::c_int;
            p_safe = unsafe { &*p };
        }
        if *p_safe as libc::c_int == '\n' as i32 || *p_safe as libc::c_int == '\r' as i32 {
            break;
        }
        if unsafe {
            *p.offset(0 as libc::c_int as isize) as libc::c_int == '\\' as i32
                && (*p.offset(1 as libc::c_int as isize) as libc::c_int == '\n' as i32
                    || *p.offset(1 as libc::c_int as isize) as libc::c_int == '\r' as i32)
        } {
            break;
        }
        if blank == 0 && last_is_path == 0 {
            /* No blank character. */
            return -(1 as libc::c_int);
        }
        if last_is_path != 0 && len == 0 as libc::c_int as libc::c_long {
            return keycnt;
        }
        if unset != 0 {
            l = bid_keycmp(p, b"all\x00" as *const u8 as *const libc::c_char, len);
            if l > 0 as libc::c_int {
                return 1 as libc::c_int;
            }
        }
        /* Test whether there is a correct key in the line. */
        l = bid_keyword(p, len); /* Unknown keyword was found. */
        if l == 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        p = unsafe { p.offset(l as isize) };
        len -= l as libc::c_long;
        keycnt += 1;
        /* Skip value */
        p_safe = unsafe { &*p };
        if *p_safe as libc::c_int == '=' as i32 {
            let mut value: libc::c_int = 0 as libc::c_int;
            p = unsafe { p.offset(1) };
            len -= 1;
            while unsafe {
                len > 0 as libc::c_int as libc::c_long
                    && *p as libc::c_int != ' ' as i32
                    && *p as libc::c_int != '\t' as i32
            } {
                p = unsafe { p.offset(1) };
                len -= 1;
                value = 1 as libc::c_int
            }
            /* A keyword should have a its value unless
             * "/unset" operation. */
            if unset == 0 && value == 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
        }
    }
    return keycnt;
}
extern "C" fn bid_entry(
    mut p: *const libc::c_char,
    mut len: ssize_t,
    mut nl: ssize_t,
    mut last_is_path: *mut libc::c_int,
) -> libc::c_int {
    let mut f: libc::c_int = 0 as libc::c_int;
    static mut safe_char: [libc::c_uchar; 256] = [
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        1 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
        0 as libc::c_int as libc::c_uchar,
    ];
    let mut ll: ssize_t = 0;
    let mut pp: *const libc::c_char = p;
    let pp_end: *const libc::c_char = unsafe { pp.offset(len as isize) };
    let last_is_path_safe = unsafe { &mut *last_is_path };
    *last_is_path_safe = 0 as libc::c_int;
    /*
     * Skip the path-name which is quoted.
     */
    while pp < pp_end {
        if unsafe { safe_char[*(pp as *const libc::c_uchar) as usize] == 0 } {
            let mut pp_safe = unsafe { &*pp };
            if *pp_safe as libc::c_int != ' ' as i32
                && *pp_safe as libc::c_int != '\t' as i32
                && *pp_safe as libc::c_int != '\r' as i32
                && *pp_safe as libc::c_int != '\n' as i32
            {
                f = 0 as libc::c_int
            }
            break;
        } else {
            f = 1 as libc::c_int;
            pp = unsafe { pp.offset(1) }
        }
    }
    ll = unsafe { pp_end.offset_from(pp) as libc::c_long };
    /* If a path-name was not found at the first, try to check
     * a mtree format(a.k.a form D) ``NetBSD's mtree -D'' creates,
     * which places the path-name at the last. */
    if f == 0 as libc::c_int {
        let mut pb: *const libc::c_char = unsafe { p.offset(len as isize).offset(-(nl as isize)) };
        let mut name_len: libc::c_int = 0 as libc::c_int;
        let mut slash: libc::c_int = 0;
        /* The form D accepts only a single line for an entry. */
        unsafe {
            if pb.offset(-(2 as libc::c_int as isize)) >= p
                && *pb.offset(-(1 as libc::c_int) as isize) as libc::c_int == '\\' as i32
                && (*pb.offset(-(2 as libc::c_int) as isize) as libc::c_int == ' ' as i32
                    || *pb.offset(-(2 as libc::c_int) as isize) as libc::c_int == '\t' as i32)
            {
                return -(1 as libc::c_int);
            }
            if pb.offset(-(1 as libc::c_int as isize)) >= p
                && *pb.offset(-(1 as libc::c_int) as isize) as libc::c_int == '\\' as i32
            {
                return -(1 as libc::c_int);
            }
        }
        slash = 0 as libc::c_int;
        loop {
            pb = unsafe { pb.offset(-1) };
            let mut pb_safe = unsafe { &*pb };
            if !(p <= pb
                && *pb_safe as libc::c_int != ' ' as i32
                && *pb_safe as libc::c_int != '\t' as i32)
            {
                break;
            }
            if unsafe { safe_char[*(pb as *const libc::c_uchar) as usize] == 0 } {
                return -(1 as libc::c_int);
            }
            name_len += 1;
            /* The pathname should have a slash in this
             * format. */
            if *pb_safe as libc::c_int == '/' as i32 {
                slash = 1 as libc::c_int
            }
        }
        if name_len == 0 as libc::c_int || slash == 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        /* If '/' is placed at the first in this field, this is not
         * a valid filename. */
        if unsafe { *pb.offset(1 as libc::c_int as isize) as libc::c_int == '/' as i32 } {
            return -(1 as libc::c_int);
        }
        ll = len - nl - name_len as libc::c_long;
        pp = p;
        *last_is_path_safe = 1 as libc::c_int
    }
    return bid_keyword_list(pp, ll, 0 as libc::c_int, *last_is_path_safe);
}
extern "C" fn mtree_bid(mut a: *mut archive_read, mut best_bid: libc::c_int) -> libc::c_int {
    let mut signature: *const libc::c_char = b"#mtree\x00" as *const u8 as *const libc::c_char;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    /* UNUSED */
    /* Now let's look at the actual header and see if it matches. */
    p = __archive_read_ahead_safe(a, strlen_safe(signature), 0 as *mut ssize_t)
        as *const libc::c_char;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    if memcmp_safe(
        p as *const libc::c_void,
        signature as *const libc::c_void,
        strlen_safe(signature),
    ) == 0 as libc::c_int
    {
        return 8 as libc::c_int * strlen_safe(signature) as libc::c_int;
    }
    /*
     * There is not a mtree signature. Let's try to detect mtree format.
     */
    return detect_form(a, 0 as *mut libc::c_int); /* The archive is generated by `NetBSD mtree -D'
                                                  	* (In this source we call it `form D') . */
}
extern "C" fn detect_form(
    mut a: *mut archive_read,
    mut is_form_d: *mut libc::c_int,
) -> libc::c_int {
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut avail: ssize_t = 0;
    let mut ravail: ssize_t = 0;
    let mut detected_bytes: ssize_t = 0 as libc::c_int as ssize_t;
    let mut len: ssize_t = 0;
    let mut nl: ssize_t = 0;
    let mut entry_cnt: libc::c_int = 0 as libc::c_int;
    let mut multiline: libc::c_int = 0 as libc::c_int;
    let mut form_D: libc::c_int = 0 as libc::c_int;
    let is_form_d_safe = unsafe { &mut *is_form_d };
    if !is_form_d.is_null() {
        *is_form_d_safe = 0 as libc::c_int
    }
    p = __archive_read_ahead_safe(a, 1 as libc::c_int as size_t, &mut avail) as *const libc::c_char;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    ravail = avail;
    loop {
        len = next_line(a, &mut p, &mut avail, &mut ravail, &mut nl);
        /* The terminal character of the line should be
         * a new line character, '\r\n' or '\n'. */
        if len <= 0 as libc::c_int as libc::c_long || nl == 0 as libc::c_int as libc::c_long {
            break;
        }
        if multiline == 0 {
            /* Leading whitespace is never significant,
             * ignore it. */
            let mut p_safe = unsafe { &*p };
            while len > 0 as libc::c_int as libc::c_long
                && (*p_safe as libc::c_int == ' ' as i32 || *p_safe as libc::c_int == '\t' as i32)
            {
                unsafe {
                    p = p.offset(1);
                    p_safe = &*p;
                }
                avail -= 1;
                len -= 1
            }
            /* Skip comment or empty line. */
            if unsafe {
                *p.offset(0 as libc::c_int as isize) as libc::c_int == '#' as i32
                    || *p.offset(0 as libc::c_int as isize) as libc::c_int == '\n' as i32
                    || *p.offset(0 as libc::c_int as isize) as libc::c_int == '\r' as i32
            } {
                p = unsafe { p.offset(len as isize) };
                avail -= len
            } else {
                if unsafe { *p.offset(0 as libc::c_int as isize) as libc::c_int != '/' as i32 } {
                    let mut last_is_path: libc::c_int = 0;
                    let mut keywords: libc::c_int = 0;
                    keywords = bid_entry(p, len, nl, &mut last_is_path);
                    if !(keywords >= 0 as libc::c_int) {
                        break;
                    }
                    detected_bytes += len;
                    if form_D == 0 as libc::c_int {
                        if last_is_path != 0 {
                            form_D = 1 as libc::c_int
                        } else if keywords > 0 as libc::c_int {
                            /* This line is not `form D'. */
                            form_D = -(1 as libc::c_int)
                        }
                    } else if form_D == 1 as libc::c_int {
                        if last_is_path == 0 && keywords > 0 as libc::c_int {
                            break;
                        }
                    }
                    if unsafe {
                        last_is_path == 0
                            && *p.offset((len - nl - 1 as libc::c_int as libc::c_long) as isize)
                                as libc::c_int
                                == '\\' as i32
                    } {
                        /* This line continues. */
                        multiline = 1 as libc::c_int
                    } else {
                        /* We've got plenty of correct lines
                         * to assume that this file is a mtree
                         * format. */
                        entry_cnt += 1;
                        if entry_cnt >= ARCHIVE_MTREE_DEFINED_PARAM.max_bid_entry {
                            break;
                        }
                    }
                } else if len > 4 as libc::c_int as libc::c_long
                    && strncmp_safe(
                        p,
                        b"/set\x00" as *const u8 as *const libc::c_char,
                        4 as libc::c_int as libc::c_ulong,
                    ) == 0 as libc::c_int
                {
                    if unsafe {
                        bid_keyword_list(
                            p.offset(4 as libc::c_int as isize),
                            len - 4 as libc::c_int as libc::c_long,
                            0 as libc::c_int,
                            0 as libc::c_int,
                        ) <= 0 as libc::c_int
                    } {
                        break;
                    }
                    /* This line continues. */
                    if unsafe {
                        *p.offset((len - nl - 1 as libc::c_int as libc::c_long) as isize)
                            as libc::c_int
                            == '\\' as i32
                    } {
                        multiline = 2 as libc::c_int
                    }
                } else {
                    if !(len > 6 as libc::c_int as libc::c_long
                        && strncmp_safe(
                            p,
                            b"/unset\x00" as *const u8 as *const libc::c_char,
                            6 as libc::c_int as libc::c_ulong,
                        ) == 0 as libc::c_int)
                    {
                        break;
                    }
                    unsafe {
                        if bid_keyword_list(
                            p.offset(6 as libc::c_int as isize),
                            len - 6 as libc::c_int as libc::c_long,
                            1 as libc::c_int,
                            0 as libc::c_int,
                        ) <= 0 as libc::c_int
                        {
                            break;
                        }
                        /* This line continues. */
                        if *p.offset((len - nl - 1 as libc::c_int as libc::c_long) as isize)
                            as libc::c_int
                            == '\\' as i32
                        {
                            multiline = 2 as libc::c_int
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
            if bid_keyword_list(p, len, 0 as libc::c_int, 0 as libc::c_int) <= 0 as libc::c_int {
                break;
            }
            if multiline == 1 as libc::c_int {
                detected_bytes += len
            }
            if unsafe {
                *p.offset((len - nl - 1 as libc::c_int as libc::c_long) as isize) as libc::c_int
                    != '\\' as i32
            } {
                if multiline == 1 as libc::c_int && {
                    entry_cnt += 1;
                    (entry_cnt) >= ARCHIVE_MTREE_DEFINED_PARAM.max_bid_entry
                } {
                    break;
                }
                multiline = 0 as libc::c_int
            }
            p = unsafe { p.offset(len as isize) };
            avail -= len
        }
    }
    if entry_cnt >= ARCHIVE_MTREE_DEFINED_PARAM.max_bid_entry
        || entry_cnt > 0 as libc::c_int && len == 0 as libc::c_int as libc::c_long
    {
        if !is_form_d.is_null() {
            if form_D == 1 as libc::c_int {
                *is_form_d_safe = 1 as libc::c_int
            }
        }
        return 32 as libc::c_int;
    }
    return 0 as libc::c_int;
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
extern "C" fn add_option(
    mut a: *mut archive_read,
    mut global: *mut *mut mtree_option,
    mut value: *const libc::c_char,
    mut len: size_t,
) -> libc::c_int {
    let mut opt: *mut mtree_option = 0 as *mut mtree_option;
    opt = malloc_safe(::std::mem::size_of::<mtree_option>() as libc::c_ulong) as *mut mtree_option;
    if opt.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            *__errno_location(),
            b"Can\'t allocate memory\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    let opt_safe = unsafe { &mut *opt };
    opt_safe.value =
        malloc_safe(len.wrapping_add(1 as libc::c_int as libc::c_ulong)) as *mut libc::c_char;
    if opt_safe.value.is_null() {
        free_safe(opt as *mut libc::c_void);
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            *__errno_location(),
            b"Can\'t allocate memory\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    memcpy_safe(
        opt_safe.value as *mut libc::c_void,
        value as *const libc::c_void,
        len,
    );
    unsafe { *(*opt).value.offset(len as isize) = '\u{0}' as i32 as libc::c_char };
    let global_safe = unsafe { &mut *global };
    opt_safe.next = *global_safe;
    *global_safe = opt;
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
extern "C" fn remove_option(
    mut global: *mut *mut mtree_option,
    mut value: *const libc::c_char,
    mut len: size_t,
) {
    let mut iter: *mut mtree_option = 0 as *mut mtree_option;
    let mut last: *mut mtree_option = 0 as *mut mtree_option;
    last = 0 as *mut mtree_option;
    let global_safe = unsafe { &mut *global };
    let mut iter_safe = unsafe { &*iter };
    iter = *global_safe;
    while !iter.is_null() {
        iter_safe = unsafe { &*iter };
        if unsafe {
            strncmp_safe((*iter).value, value, len) == 0 as libc::c_int
                && (*(*iter).value.offset(len as isize) as libc::c_int == '\u{0}' as i32
                    || *(*iter).value.offset(len as isize) as libc::c_int == '=' as i32)
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
    free_safe(iter_safe.value as *mut libc::c_void);
    free_safe(iter as *mut libc::c_void);
}
extern "C" fn process_global_set(
    mut a: *mut archive_read,
    mut global: *mut *mut mtree_option,
    mut line: *const libc::c_char,
) -> libc::c_int {
    let mut next: *const libc::c_char = 0 as *const libc::c_char;
    let mut eq: *const libc::c_char = 0 as *const libc::c_char;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    line = unsafe { line.offset(4 as libc::c_int as isize) };
    loop {
        next = unsafe {
            line.offset(strspn(line, b" \t\r\n\x00" as *const u8 as *const libc::c_char) as isize)
        };
        let next_safe = unsafe { &*next };
        if *next_safe as libc::c_int == '\u{0}' as i32 {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
        line = next;
        next = unsafe {
            line.offset(strcspn(line, b" \t\r\n\x00" as *const u8 as *const libc::c_char) as isize)
        };
        eq = strchr_safe(line, '=' as i32);
        unsafe {
            if eq > next {
                len = next.offset_from(line) as libc::c_long as size_t
            } else {
                len = eq.offset_from(line) as libc::c_long as size_t
            }
        }
        remove_option(global, line, len);
        unsafe {
            r = add_option(
                a,
                global,
                line,
                next.offset_from(line) as libc::c_long as size_t,
            );
        }
        if r != ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
            return r;
        }
        line = next
    }
}
extern "C" fn process_global_unset(
    mut a: *mut archive_read,
    mut global: *mut *mut mtree_option,
    mut line: *const libc::c_char,
) -> libc::c_int {
    let mut next: *const libc::c_char = 0 as *const libc::c_char;
    let mut len: size_t = 0;
    let a_safe;
    unsafe {
        line = line.offset(6 as libc::c_int as isize);
        a_safe = &mut *a;
    }
    if !strchr_safe(line, '=' as i32).is_null() {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_misc,
            b"/unset shall not contain `=\'\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    loop {
        let mut next_safe;
        unsafe {
            next = line
                .offset(strspn(line, b" \t\r\n\x00" as *const u8 as *const libc::c_char) as isize);
            next_safe = &*next;
        }
        if *next_safe as libc::c_int == '\u{0}' as i32 {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
        line = next;
        len = strcspn_safe(line, b" \t\r\n\x00" as *const u8 as *const libc::c_char);
        let global_safe = unsafe { &mut *global };
        if len == 3 as libc::c_int as libc::c_ulong
            && strncmp_safe(
                line,
                b"all\x00" as *const u8 as *const libc::c_char,
                3 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
        {
            free_options(*global_safe);
            *global_safe = 0 as *mut mtree_option
        } else {
            remove_option(global, line, len);
        }
        line = unsafe { line.offset(len as isize) }
    }
}
extern "C" fn process_add_entry(
    mut a: *mut archive_read,
    mut mtree: *mut mtree,
    mut global: *mut *mut mtree_option,
    mut line: *const libc::c_char,
    mut line_len: ssize_t,
    mut last_entry: *mut *mut mtree_entry,
    mut is_form_d: libc::c_int,
) -> libc::c_int {
    let mut entry: *mut mtree_entry = 0 as *mut mtree_entry;
    let mut iter: *mut mtree_option = 0 as *mut mtree_option;
    let mut next: *const libc::c_char = 0 as *const libc::c_char;
    let mut eq: *const libc::c_char = 0 as *const libc::c_char;
    let mut name: *const libc::c_char = 0 as *const libc::c_char;
    let mut end: *const libc::c_char = 0 as *const libc::c_char;
    let mut name_len: size_t = 0;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    entry = malloc_safe(::std::mem::size_of::<mtree_entry>() as libc::c_ulong) as *mut mtree_entry;
    if entry.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            *__errno_location(),
            b"Can\'t allocate memory\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    let entry_safe = unsafe { &mut *entry };
    entry_safe.next = 0 as *mut mtree_entry;
    entry_safe.options = 0 as *mut mtree_option;
    entry_safe.name = 0 as *mut libc::c_char;
    entry_safe.used = 0 as libc::c_int as libc::c_char;
    entry_safe.full = 0 as libc::c_int as libc::c_char;
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
        while line_len > 0 as libc::c_int as libc::c_long {
            let mut last_character: libc::c_char =
                unsafe { *line.offset((line_len - 1 as libc::c_int as libc::c_long) as isize) };
            if !(last_character as libc::c_int == '\r' as i32
                || last_character as libc::c_int == '\n' as i32
                || last_character as libc::c_int == '\t' as i32
                || last_character as libc::c_int == ' ' as i32)
            {
                break;
            }
            line_len -= 1
        }
        /* Name starts after the last whitespace separator */
        name = line;
        i = 0 as libc::c_int;
        while (i as libc::c_long) < line_len {
            unsafe {
                if *line.offset(i as isize) as libc::c_int == '\r' as i32
                    || *line.offset(i as isize) as libc::c_int == '\n' as i32
                    || *line.offset(i as isize) as libc::c_int == '\t' as i32
                    || *line.offset(i as isize) as libc::c_int == ' ' as i32
                {
                    name = line.offset(i as isize).offset(1 as libc::c_int as isize)
                }
            }
            i += 1
        }
        name_len =
            unsafe { line.offset(line_len as isize).offset_from(name) as libc::c_long as size_t };
        end = name
    } else {
        /* Filename is first item on line */
        name_len = strcspn_safe(line, b" \t\r\n\x00" as *const u8 as *const libc::c_char);
        name = line;
        unsafe {
            line = line.offset(name_len as isize);
            end = line.offset(line_len as isize)
        }
    }
    /* name/name_len is the name within the line. */
    /* line..end brackets the entire line except the name */
    entry_safe.name =
        malloc_safe(name_len.wrapping_add(1 as libc::c_int as libc::c_ulong)) as *mut libc::c_char;
    if entry_safe.name.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            *__errno_location(),
            b"Can\'t allocate memory\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    memcpy_safe(
        entry_safe.name as *mut libc::c_void,
        name as *const libc::c_void,
        name_len,
    );
    unsafe {
        *(*entry).name.offset(name_len as isize) = '\u{0}' as i32 as libc::c_char;
    }
    parse_escapes(entry_safe.name, entry);
    entry_safe.next_dup = 0 as *mut mtree_entry;
    if entry_safe.full != 0 {
        if __archive_rb_tree_insert_node_safe(&mut mtree_safe.rbtree, &mut entry_safe.rbnode) == 0 {
            let mut alt: *mut mtree_entry = 0 as *mut mtree_entry;
            alt = __archive_rb_tree_find_node_safe(
                &mut mtree_safe.rbtree,
                entry_safe.name as *const libc::c_void,
            ) as *mut mtree_entry;
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
        r = add_option(
            a,
            &mut entry_safe.options,
            iter_safe.value,
            strlen_safe(iter_safe.value),
        );
        if r != ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
            return r;
        }
        iter = iter_safe.next
    }
    loop {
        let next_safe;
        unsafe {
            next = line
                .offset(strspn(line, b" \t\r\n\x00" as *const u8 as *const libc::c_char) as isize);
            next_safe = &*next;
        }
        if *next_safe as libc::c_int == '\u{0}' as i32 {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
        if next >= end {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
        line = next;
        next = unsafe {
            line.offset(strcspn(line, b" \t\r\n\x00" as *const u8 as *const libc::c_char) as isize)
        };
        eq = strchr_safe(line, '=' as i32);
        unsafe {
            if eq.is_null() || eq > next {
                len = next.offset_from(line) as libc::c_long as size_t
            } else {
                len = eq.offset_from(line) as libc::c_long as size_t
            }
        }
        remove_option(&mut entry_safe.options, line, len);
        unsafe {
            r = add_option(
                a,
                &mut (*entry).options,
                line,
                next.offset_from(line) as libc::c_long as size_t,
            );
        }
        if r != ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
            return r;
        }
        line = next
    }
}
extern "C" fn read_mtree(mut a: *mut archive_read, mut mtree: *mut mtree) -> libc::c_int {
    let mut len: ssize_t = 0;
    let mut counter: uintmax_t = 0;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut global: *mut mtree_option = 0 as *mut mtree_option;
    let mut last_entry: *mut mtree_entry = 0 as *mut mtree_entry;
    let mut r: libc::c_int = 0;
    let mut is_form_d: libc::c_int = 0;
    let mtree_safe = unsafe { &mut *mtree };
    mtree_safe.archive_format = ARCHIVE_MTREE_DEFINED_PARAM.archive_format_mtree;
    mtree_safe.archive_format_name = b"mtree\x00" as *const u8 as *const libc::c_char;
    global = 0 as *mut mtree_option;
    last_entry = 0 as *mut mtree_entry;
    detect_form(a, &mut is_form_d);
    counter = 1 as libc::c_int as uintmax_t;
    loop {
        r = ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        len = readline(a, mtree, &mut p, 65536 as libc::c_int as ssize_t);
        if len == 0 as libc::c_int as libc::c_long {
            mtree_safe.this_entry = mtree_safe.entries;
            free_options(global);
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
        if len < 0 as libc::c_int as libc::c_long {
            free_options(global);
            return len as libc::c_int;
        }
        /* Leading whitespace is never significant, ignore it. */
        let mut p_safe = unsafe { &mut *p };
        while *p_safe as libc::c_int == ' ' as i32 || *p_safe as libc::c_int == '\t' as i32 {
            p = unsafe { p.offset(1) };
            len -= 1;
            p_safe = unsafe { &mut *p };
        }
        /* Skip content lines and blank lines. */
        if !(*p_safe as libc::c_int == '#' as i32) {
            if !(*p_safe as libc::c_int == '\r' as i32
                || *p_safe as libc::c_int == '\n' as i32
                || *p_safe as libc::c_int == '\u{0}' as i32)
            {
                /* Non-printable characters are not allowed */
                s = p;
                unsafe {
                    while s < p.offset(len as isize).offset(-(1 as libc::c_int as isize)) {
                        if *(*__ctype_b_loc()).offset(*s as libc::c_uchar as libc::c_int as isize)
                            as libc::c_int
                            & _ISprint_m as libc::c_int as libc::c_ushort as libc::c_int
                            == 0
                        {
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
                if *p_safe as libc::c_int != '/' as i32 {
                    r = process_add_entry(a, mtree, &mut global, p, len, &mut last_entry, is_form_d)
                } else if len > 4 as libc::c_int as libc::c_long
                    && strncmp_safe(
                        p,
                        b"/set\x00" as *const u8 as *const libc::c_char,
                        4 as libc::c_int as libc::c_ulong,
                    ) == 0 as libc::c_int
                {
                    if unsafe {
                        *p.offset(4 as libc::c_int as isize) as libc::c_int != ' ' as i32
                            && *p.offset(4 as libc::c_int as isize) as libc::c_int != '\t' as i32
                    } {
                        break;
                    }
                    r = process_global_set(a, &mut global, p)
                } else {
                    if !(len > 6 as libc::c_int as libc::c_long
                        && strncmp_safe(
                            p,
                            b"/unset\x00" as *const u8 as *const libc::c_char,
                            6 as libc::c_int as libc::c_ulong,
                        ) == 0 as libc::c_int)
                    {
                        break;
                    }
                    if unsafe {
                        *p.offset(6 as libc::c_int as isize) as libc::c_int != ' ' as i32
                            && *p.offset(6 as libc::c_int as isize) as libc::c_int != '\t' as i32
                    } {
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
        b"Can\'t parse line %ju\x00" as *const u8 as *const libc::c_char,
        counter
    );
    free_options(global);
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
}
/*
 * Read in the entire mtree file into memory on the first request.
 * Then use the next unused file to satisfy each header request.
 */
extern "C" fn read_header(mut a: *mut archive_read, mut entry: *mut archive_entry) -> libc::c_int {
    let mut mtree: *mut mtree = 0 as *mut mtree;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut use_next: libc::c_int = 0;
    let mtree_safe;
    unsafe {
        mtree = (*(*a).format).data as *mut mtree;
        mtree_safe = &mut *mtree;
    }
    if mtree_safe.fd >= 0 as libc::c_int {
        close_safe((*mtree_safe).fd);
        (*mtree_safe).fd = -(1 as libc::c_int)
    }
    if mtree_safe.entries.is_null() {
        mtree_safe.resolver = archive_entry_linkresolver_new_safe();
        if mtree_safe.resolver.is_null() {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
        }
        archive_entry_linkresolver_set_strategy_safe(
            mtree_safe.resolver,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_format_mtree,
        );
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
            if strcmp(
                (*(*mtree).this_entry).name,
                b"..\x00" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
            {
                (*(*mtree).this_entry).used = 1 as libc::c_int as libc::c_char;
                if (*mtree).current_dir.length > 0 as libc::c_int as libc::c_ulong {
                    /* Roll back current path. */
                    p = (*mtree)
                        .current_dir
                        .s
                        .offset((*mtree).current_dir.length as isize)
                        .offset(-(1 as libc::c_int as isize));
                    while p >= (*mtree).current_dir.s && *p as libc::c_int != '/' as i32 {
                        p = p.offset(-1)
                    }
                    if p >= (*mtree).current_dir.s {
                        p = p.offset(-1)
                    }
                    (*mtree).current_dir.length =
                        (p.offset_from((*mtree).current_dir.s) as libc::c_long
                            + 1 as libc::c_int as libc::c_long) as size_t
                }
            }
        }
        let m_entry_safe = unsafe { &mut (*(*mtree).this_entry) };
        if m_entry_safe.used == 0 {
            use_next = 0 as libc::c_int;
            r = parse_file(a, entry, mtree, mtree_safe.this_entry, &mut use_next);
            if use_next == 0 as libc::c_int {
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

extern "C" fn parse_file(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
    mut mtree: *mut mtree,
    mut mentry: *mut mtree_entry,
    mut use_next: *mut libc::c_int,
) -> libc::c_int {
    let mut path: *const libc::c_char = 0 as *const libc::c_char;
    let mut st_storage: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_mtim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_ctim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        __glibc_reserved: [0; 3],
    };
    let mut st: *mut stat = 0 as *mut stat;
    let mut mp: *mut mtree_entry = 0 as *mut mtree_entry;
    let mut sparse_entry: *mut archive_entry = 0 as *mut archive_entry;
    let mut r: libc::c_int = ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    let mut r1: libc::c_int = 0;
    let mut parsed_kws: libc::c_int = 0;
    let mentry_safe = unsafe { &mut *mentry };
    mentry_safe.used = 1 as libc::c_int as libc::c_char;
    /* Initialize reasonable defaults. */
    archive_entry_set_filetype_safe(
        entry,
        ARCHIVE_MTREE_DEFINED_PARAM.ae_ifreg as mode_t,
    );
    archive_entry_set_size_safe(entry, 0 as libc::c_int as la_int64_t);
    let mtree_safe = unsafe { &mut *mtree };
    mtree_safe.contents_name.length = 0 as libc::c_int as size_t;
    /* Parse options from this line. */
    parsed_kws = 0 as libc::c_int;
    r = parse_line(a, entry, mtree, mentry, &mut parsed_kws);
    if mentry_safe.full != 0 {
        archive_entry_copy_pathname_safe(entry, mentry_safe.name);
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
        mp = __archive_rb_tree_find_node_safe(
            &mut mtree_safe.rbtree,
            mentry_safe.name as *const libc::c_void,
        ) as *mut mtree_entry;
        let mut mp_safe;
        while !mp.is_null() {
            mp_safe = unsafe { &mut *mp };
            if mp_safe.full as libc::c_int != 0 && mp_safe.used == 0 {
                /* Later lines override earlier ones. */
                mp_safe.used = 1 as libc::c_int as libc::c_char;
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
        let mut n: size_t = mtree_safe.current_dir.length;
        if n > 0 as libc::c_int as libc::c_ulong {
            archive_strcat_safe(
                &mut mtree_safe.current_dir,
                b"/\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
            );
        }
        archive_strcat_safe(
            &mut mtree_safe.current_dir,
            mentry_safe.name as *const libc::c_void,
        );
        archive_entry_copy_pathname_safe(entry, mtree_safe.current_dir.s);
        if archive_entry_filetype_safe(entry)
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
        mtree_safe.fd = -(1 as libc::c_int);
        if mtree_safe.contents_name.length > 0 as libc::c_int as libc::c_ulong {
            path = mtree_safe.contents_name.s
        } else {
            path = archive_entry_pathname_safe(entry)
        }
        if archive_entry_filetype_safe(entry)
            == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifreg as mode_t
            || archive_entry_filetype_safe(entry)
                == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifdir as mode_t
        {
            mtree_safe.fd = open_safe(
                path,
                ARCHIVE_MTREE_DEFINED_PARAM.o_rdonly
                    | ARCHIVE_MTREE_DEFINED_PARAM.o_binary
                    | ARCHIVE_MTREE_DEFINED_PARAM.o_cloexec,
            );
            __archive_ensure_cloexec_flag_safe(mtree_safe.fd);

            if unsafe {
                (*mtree).fd == -(1 as libc::c_int)
                    && (*__errno_location() != ARCHIVE_MTREE_DEFINED_PARAM.enoent
                        || (*mtree).contents_name.length > 0 as libc::c_int as libc::c_ulong)
            } {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    *__errno_location(),
                    b"Can\'t open %s\x00" as *const u8 as *const libc::c_char,
                    path
                );
                r = ARCHIVE_MTREE_DEFINED_PARAM.archive_warn
            }
        }
        st = &mut st_storage;
        if mtree_safe.fd >= 0 as libc::c_int {
            if fstat_safe(mtree_safe.fd, st) == -(1 as libc::c_int) {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    *__errno_location(),
                    b"Could not fstat %s\x00" as *const u8 as *const libc::c_char,
                    path
                );
                r = ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
                /* If we can't stat it, don't keep it open. */
                close_safe(mtree_safe.fd);
                mtree_safe.fd = -(1 as libc::c_int);
                st = 0 as *mut stat
            }
        } else if lstat_safe(path, st) == -(1 as libc::c_int) {
            st = 0 as *mut stat
        }
        /*
         * Check for a mismatch between the type in the specification
         * and the type of the contents object on disk.
         */
        let st_safe = unsafe { &mut *st };
        if !st.is_null() {
            let mut conditions: bool = st_safe.st_mode
                & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as libc::c_uint
                == ARCHIVE_MTREE_DEFINED_PARAM.s_ifreg as libc::c_uint
                && archive_entry_filetype_safe(entry)
                    == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifreg as mode_t
                || st_safe.st_mode
                    & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as libc::c_uint
                    == ARCHIVE_MTREE_DEFINED_PARAM.s_ifdir as libc::c_uint
                    && archive_entry_filetype_safe(entry)
                        == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifdir as mode_t;
            match () {
                #[cfg(S_IFLNK)]
                _ => {
                    conditions = conditions
                        || st_safe.st_mode
                            & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as libc::c_uint
                            == ARCHIVE_MTREE_DEFINED_PARAM.s_iflnk as libc::c_uint
                            && archive_entry_filetype_safe(entry)
                                == ARCHIVE_MTREE_DEFINED_PARAM.ae_iflnk as mode_t;
                }
                #[cfg(not(S_IFLNK))]
                _ => {}
            }
            match () {
                #[cfg(S_IFSOCK)]
                _ => {
                    conditions = conditions
                        || st_safe.st_mode
                            & ARCHIVE_MTREE_DEFINED_PARAM.s_ifsock as libc::c_uint
                            == ARCHIVE_MTREE_DEFINED_PARAM.s_ifsock as libc::c_uint
                            && archive_entry_filetype_safe(entry)
                                == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifsock as mode_t;
                }
                #[cfg(not(S_IFSOCK))]
                _ => {}
            }
            match () {
                #[cfg(S_IFCHR)]
                _ => {
                    conditions = conditions
                        || st_safe.st_mode
                            & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as libc::c_uint
                            == ARCHIVE_MTREE_DEFINED_PARAM.s_ifchr as libc::c_uint
                            && archive_entry_filetype_safe(entry)
                                == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifsock as mode_t;
                }
                #[cfg(not(S_IFCHR))]
                _ => {}
            }
            match () {
                #[cfg(S_IFBLK)]
                _ => {
                    conditions = conditions
                        || st_safe.st_mode
                            & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as libc::c_uint
                            == ARCHIVE_MTREE_DEFINED_PARAM.s_ifblk as libc::c_uint
                            && archive_entry_filetype_safe(entry)
                                == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifblk as mode_t;
                }
                #[cfg(not(S_IFBLK))]
                _ => {}
            }
            match () {
                #[cfg(S_IFIFO)]
                _ => {
                    conditions = conditions
                        || st_safe.st_mode
                            & ARCHIVE_MTREE_DEFINED_PARAM.s_ifmt as libc::c_uint
                            == ARCHIVE_MTREE_DEFINED_PARAM.s_ififo as libc::c_uint
                            && archive_entry_filetype_safe(entry)
                                == ARCHIVE_MTREE_DEFINED_PARAM.ae_ififo as mode_t;
                }
                #[cfg(not(S_IFIFO))]
                _ => {}
            }
            if conditions {
            } else {
                /* Types don't match; bail out gracefully. */
                if mtree_safe.fd >= 0 as libc::c_int {
                    close_safe(mtree_safe.fd);
                }
                mtree_safe.fd = -(1 as libc::c_int);
                if parsed_kws
                    & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_optional
                    != 0
                {
                    /* It's not an error for an optional
                     * entry to not match disk. */
                    unsafe { *use_next = 1 as libc::c_int }
                } else if r == ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_misc,
                        b"mtree specification has different type for %s\x00" as *const u8
                            as *const libc::c_char,
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
            if (parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_device
                == 0 as libc::c_int
                || parsed_kws
                    & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange
                    != 0 as libc::c_int)
                && (archive_entry_filetype_safe(entry)
                    == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifchr as mode_t
                    || archive_entry_filetype_safe(entry)
                        == ARCHIVE_MTREE_DEFINED_PARAM.ae_ifblk as mode_t)
            {
                archive_entry_set_rdev_safe(entry, st_safe.st_rdev);
            }
            if parsed_kws
                & (ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_gid
                    | ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_gname)
                == 0 as libc::c_int
                || parsed_kws
                    & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange
                    != 0 as libc::c_int
            {
                archive_entry_set_gid_safe(entry, st_safe.st_gid as la_int64_t);
            }
            if parsed_kws
                & (ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_uid
                    | ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_uname)
                == 0 as libc::c_int
                || parsed_kws
                    & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange
                    != 0 as libc::c_int
            {
                archive_entry_set_uid_safe(entry, st_safe.st_uid as la_int64_t);
            }
            if parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_mtime
                == 0 as libc::c_int
                || parsed_kws
                    & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange
                    != 0 as libc::c_int
            {
                match () {
                    #[cfg(HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC)]
                    _ => {
                        archive_entry_set_mtime_safe(
                            entry,
                            st_safe.st_mtim.tv_sec,
                            st_safe.st_mtimespec.tv_nsec,
                        );
                    }
                    #[cfg(HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC)]
                    _ => {
                        archive_entry_set_mtime_safe(
                            entry,
                            st_safe.st_mtim.tv_sec,
                            st_safe.st_mtim.tv_nsec,
                        );
                    }
                    #[cfg(HAVE_STRUCT_STAT_ST_MTIME_N)]
                    _ => {
                        archive_entry_set_mtime_safe(
                            entry,
                            st_safe.st_mtim.tv_sec,
                            st_safe.st_mtime_n,
                        );
                    }
                    #[cfg(HAVE_STRUCT_STAT_ST_UMTIME)]
                    _ => {
                        archive_entry_set_mtime_safe(
                            entry,
                            st_safe.st_mtim.tv_sec,
                            st_safe.st_umtime * 1000 as libc::c_long,
                        );
                    }
                    #[cfg(HAVE_STRUCT_STAT_ST_MTIME_USEC)]
                    _ => {
                        archive_entry_set_mtime_safe(
                            entry,
                            st_safe.st_mtim.tv_sec,
                            st_safe.st_mtime_usec * 1000 as libc::c_long,
                        );
                    }
                    _ => {
                        archive_entry_set_mtime_safe(
                            entry,
                            st_safe.st_mtim.tv_sec,
                            0 as libc::c_long,
                        );
                    }
                }
            }
            if parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nlink
                == 0 as libc::c_int
                || parsed_kws
                    & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange
                    != 0 as libc::c_int
            {
                archive_entry_set_nlink_safe(entry, st_safe.st_nlink as libc::c_uint);
            }
            if parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_perm
                == 0 as libc::c_int
                || parsed_kws
                    & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange
                    != 0 as libc::c_int
            {
                archive_entry_set_perm_safe(entry, st_safe.st_mode);
            }
            if parsed_kws & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_size
                == 0 as libc::c_int
                || parsed_kws
                    & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange
                    != 0 as libc::c_int
            {
                archive_entry_set_size_safe(entry, st_safe.st_size);
            }
            archive_entry_set_ino_safe(entry, st_safe.st_ino as la_int64_t);
            archive_entry_set_dev_safe(entry, st_safe.st_dev);
            archive_entry_linkify_safe(mtree_safe.resolver, &mut entry, &mut sparse_entry);
        } else if parsed_kws
            & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_optional
            != 0
        {
            /*
             * Couldn't open the entry, stat it or the on-disk type
             * didn't match.  If this entry is optional, just
             * ignore it and read the next header entry.
             */
            unsafe {
                *use_next = 1 as libc::c_int;
            }
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
        }
    }
    mtree_safe.cur_size = archive_entry_size_safe(entry);
    mtree_safe.offset = 0 as libc::c_int as int64_t;
    return r;
}
/*
 * Each line contains a sequence of keywords.
 */
extern "C" fn parse_line(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
    mut mtree: *mut mtree,
    mut mp: *mut mtree_entry,
    mut parsed_kws: *mut libc::c_int,
) -> libc::c_int {
    let mut iter: *mut mtree_option = 0 as *mut mtree_option;
    let mut r: libc::c_int = ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    let mut r1: libc::c_int = 0;
    let mut parsed_kws_safe;
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
        && *parsed_kws_safe & ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_type
            == 0 as libc::c_int
    {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
            b"Missing type keyword in mtree specification\x00" as *const u8 as *const libc::c_char
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
extern "C" fn la_strsep(
    mut sp: *mut *mut libc::c_char,
    mut sep: *const libc::c_char,
) -> *mut libc::c_char {
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    if unsafe { sp.is_null() || (*sp).is_null() || **sp as libc::c_int == '\u{0}' as i32 } {
        return 0 as *mut libc::c_char;
    }
    let mut sp_safe = unsafe { &mut *sp };
    s = *sp_safe;
    unsafe {
        p = s.offset(strcspn(s, sep) as isize);
        if *p as libc::c_int != '\u{0}' as i32 {
            let fresh0 = p;
            p = p.offset(1);
            *fresh0 = '\u{0}' as i32 as libc::c_char
        }
    }
    *sp_safe = p;
    return s;
}
extern "C" fn parse_device(
    mut pdev: *mut dev_t,
    mut a: *mut archive,
    mut val: *mut libc::c_char,
) -> libc::c_int {
    let mut numbers: [libc::c_ulong; 3] = [0; 3];
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut dev: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut argc: libc::c_int = 0;
    let mut pack: Option<pack_t> = None;
    let mut result: dev_t = 0;
    let mut error: *const libc::c_char = 0 as *const libc::c_char;
    memset_safe(
        pdev as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<dev_t>() as libc::c_ulong,
    );
    dev = strchr_safe(val, ',' as i32);
    if !dev.is_null() {
        /*
         * Device's major/minor are given in a specified format.
         * Decode and pack it accordingly.
         */
        let fresh1 = dev;
        unsafe {
            dev = dev.offset(1);
            *fresh1 = '\u{0}' as i32 as libc::c_char;
        }
        pack = pack_find_safe(val);
        if pack.is_none() {
            archive_set_error_safe!(
                a,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                b"Unknown format `%s\'\x00" as *const u8 as *const libc::c_char,
                val
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
        }
        argc = 0 as libc::c_int;
        loop {
            p = la_strsep(&mut dev, b",\x00" as *const u8 as *const libc::c_char);
            if p.is_null() {
                break;
            }
            let p_safe = unsafe { &mut *p };
            if *p_safe as libc::c_int == '\u{0}' as i32 {
                archive_set_error_safe!(
                    a,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                    b"Missing number\x00" as *const u8 as *const libc::c_char
                );
                return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
            }
            if argc >= 3 as libc::c_int {
                archive_set_error_safe!(
                    a,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                    b"Too many arguments\x00" as *const u8 as *const libc::c_char
                );
                return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
            }
            let fresh2 = argc;
            argc = argc + 1;
            numbers[fresh2 as usize] = mtree_atol(&mut p, 0 as libc::c_int) as libc::c_ulong
        }
        if argc < 2 as libc::c_int {
            archive_set_error_safe!(
                a,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                b"Not enough arguments\x00" as *const u8 as *const libc::c_char
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
                b"%s\x00" as *const u8 as *const libc::c_char,
                error
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
        }
    } else {
        /* file system raw value. */
        result = mtree_atol(&mut val, 0 as libc::c_int) as dev_t
    }
    unsafe {
        *pdev = result;
    }
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
extern "C" fn parse_hex_nibble(mut c: libc::c_char) -> libc::c_int {
    if c as libc::c_int >= '0' as i32 && c as libc::c_int <= '9' as i32 {
        return c as libc::c_int - '0' as i32;
    }
    if c as libc::c_int >= 'a' as i32 && c as libc::c_int <= 'f' as i32 {
        return 10 as libc::c_int + c as libc::c_int - 'a' as i32;
    }
    return -(1 as libc::c_int);
}
extern "C" fn parse_digest(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
    mut digest: *const libc::c_char,
    mut type_0: libc::c_int,
) -> libc::c_int {
    let mut digest_buf: [libc::c_uchar; 64] = [0; 64];
    let mut high: libc::c_int = 0;
    let mut low: libc::c_int = 0;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut len: size_t = 0;
    let a_safe = unsafe { &mut *a };
    match type_0 {
        1 => len = ::std::mem::size_of::<[libc::c_uchar; 16]>() as libc::c_ulong,
        2 => len = ::std::mem::size_of::<[libc::c_uchar; 20]>() as libc::c_ulong,
        3 => len = ::std::mem::size_of::<[libc::c_uchar; 20]>() as libc::c_ulong,
        4 => len = ::std::mem::size_of::<[libc::c_uchar; 32]>() as libc::c_ulong,
        5 => len = ::std::mem::size_of::<[libc::c_uchar; 48]>() as libc::c_ulong,
        6 => len = ::std::mem::size_of::<[libc::c_uchar; 64]>() as libc::c_ulong,
        _ => {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_programmer,
                b"Internal error: Unknown digest type\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
        }
    }
    if len > ::std::mem::size_of::<[libc::c_uchar; 64]>() as libc::c_ulong {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_programmer,
            b"Internal error: Digest storage too large\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
    }
    len =
        (len as libc::c_ulong).wrapping_mul(2 as libc::c_int as libc::c_ulong) as size_t as size_t;
    if mtree_strnlen(digest, len.wrapping_add(1 as libc::c_int as libc::c_ulong)) != len {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
            b"incorrect digest length, ignoring\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
    }
    i = 0 as libc::c_int as size_t;
    j = 0 as libc::c_int as size_t;
    while i < len {
        unsafe {
            high = parse_hex_nibble(*digest.offset(i as isize));
            low = parse_hex_nibble(
                *digest.offset(i.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize),
            );
        }
        if high == -(1 as libc::c_int) || low == -(1 as libc::c_int) {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                b"invalid digest data, ignoring\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
        }
        digest_buf[j as usize] = (high << 4 as libc::c_int | low) as libc::c_uchar;
        i = (i as libc::c_ulong).wrapping_add(2 as libc::c_int as libc::c_ulong) as size_t
            as size_t;
        j = j.wrapping_add(1)
    }
    return archive_entry_set_digest_safe(entry, type_0, digest_buf.as_mut_ptr());
}
/*
 * Parse a single keyword and its value.
 */
extern "C" fn parse_keyword(
    mut a: *mut archive_read,
    mut mtree: *mut mtree,
    mut entry: *mut archive_entry,
    mut opt: *mut mtree_option,
    mut parsed_kws: *mut libc::c_int,
) -> libc::c_int {
    let mut val: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut key: *mut libc::c_char = 0 as *mut libc::c_char;
    key = unsafe { (*opt).value };
    let key_safe = unsafe { &mut *key };
    if *key_safe as libc::c_int == '\u{0}' as i32 {
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    }
    let parsed_kws_safe = unsafe { &mut *parsed_kws };
    if strcmp_safe(key, b"nochange\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nochange;
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    }
    if strcmp_safe(key, b"optional\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_optional;
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    }
    if strcmp_safe(key, b"ignore\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        /*
         * The mtree processing is not recursive, so
         * recursion will only happen for explicitly listed
         * entries.
         */
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
    }
    val = strchr_safe(key, '=' as i32);
    if val.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
            b"Malformed attribute \"%s\" (%d)\x00" as *const u8 as *const libc::c_char,
            key,
            *key.offset(0 as libc::c_int as isize) as libc::c_int
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
    }
    let val_safe;
    let mtree_safe;
    unsafe {
        val_safe = &mut *val;
        mtree_safe = &mut *mtree;
    }
    *val_safe = '\u{0}' as i32 as libc::c_char;
    val = unsafe { val.offset(1) };
    let mut current_block_120: u64;
    match unsafe { *key.offset(0 as libc::c_int as isize) as libc::c_int } {
        99 => {
            if strcmp_safe(key, b"content\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
                || strcmp_safe(key, b"contents\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
            {
                parse_escapes(val, 0 as *mut mtree_entry);
                mtree_safe.contents_name.length = 0 as libc::c_int as size_t;
                archive_strncat_safe(
                    &mut mtree_safe.contents_name,
                    val as *const libc::c_void,
                    (if val.is_null() {
                        0 as libc::c_int as libc::c_ulong
                    } else {
                        strlen_safe(val)
                    }),
                );
                current_block_120 = 14133002253412689704;
            } else if strcmp_safe(key, b"cksum\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                current_block_120 = 14133002253412689704;
            } else {
                current_block_120 = 15612923873456120061;
            }
        }
        100 => {
            current_block_120 = 15612923873456120061;
        }
        102 => {
            current_block_120 = 2516300604401959109;
        }
        103 => {
            current_block_120 = 6285744289709947169;
        }
        105 => {
            current_block_120 = 8078319602943683960;
        }
        108 => {
            current_block_120 = 14398214535289615461;
        }
        109 => {
            current_block_120 = 2086966976840294615;
        }
        110 => {
            current_block_120 = 2945138788423298433;
        }
        114 => {
            current_block_120 = 3583232612309986830;
        }
        115 => {
            current_block_120 = 6521175633009022335;
        }
        116 => {
            current_block_120 = 13294178446195614068;
        }
        117 => {
            current_block_120 = 534366734980114256;
        }
        _ => {
            current_block_120 = 2983046246157475477;
        }
    }
    let a_safe = unsafe { &mut *a };
    match current_block_120 {
        15612923873456120061 => {
            if strcmp_safe(key, b"device\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                /* stat(2) st_rdev field, e.g. the major/minor IDs
                 * of a char/block special file */
                let mut r: libc::c_int = 0;
                let mut dev: dev_t = 0;
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_device;
                r = parse_device(&mut dev, &mut a_safe.archive, val);
                if r == ARCHIVE_MTREE_DEFINED_PARAM.archive_ok {
                    archive_entry_set_rdev_safe(entry, dev);
                }
                return r;
            }
            current_block_120 = 2516300604401959109;
        }
        _ => {}
    }
    match current_block_120 {
        2516300604401959109 => {
            if strcmp_safe(key, b"flags\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_fflags;
                archive_entry_copy_fflags_text_safe(entry, val);
                current_block_120 = 14133002253412689704;
            } else {
                current_block_120 = 6285744289709947169;
            }
        }
        _ => {}
    }
    match current_block_120 {
        6285744289709947169 => {
            if strcmp_safe(key, b"gid\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_gid;
                archive_entry_set_gid_safe(entry, mtree_atol(&mut val, 10 as libc::c_int));
                current_block_120 = 14133002253412689704;
            } else if strcmp_safe(key, b"gname\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_gname;
                archive_entry_copy_gname_safe(entry, val);
                current_block_120 = 14133002253412689704;
            } else {
                current_block_120 = 8078319602943683960;
            }
        }
        _ => {}
    }
    match current_block_120 {
        8078319602943683960 => {
            if strcmp_safe(key, b"inode\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                archive_entry_set_ino_safe(entry, mtree_atol(&mut val, 10 as libc::c_int));
                current_block_120 = 14133002253412689704;
            } else {
                current_block_120 = 14398214535289615461;
            }
        }
        _ => {}
    }
    match current_block_120 {
        14398214535289615461 => {
            if strcmp_safe(key, b"link\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            {
                archive_entry_copy_symlink_safe(entry, val);
                current_block_120 = 14133002253412689704;
            } else {
                current_block_120 = 2086966976840294615;
            }
        }
        _ => {}
    }
    match current_block_120 {
        2086966976840294615 => {
            if strcmp_safe(key, b"md5\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int
                || strcmp_safe(key, b"md5digest\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_md5,
                );
            }
            if strcmp_safe(key, b"mode\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            {
                if unsafe {
                    *val.offset(0 as libc::c_int as isize) as libc::c_int >= '0' as i32
                        && *val.offset(0 as libc::c_int as isize) as libc::c_int <= '7' as i32
                } {
                    *parsed_kws_safe |= 0x40 as libc::c_int;
                    archive_entry_set_perm_safe(
                        entry,
                        mtree_atol(&mut val, 8 as libc::c_int) as mode_t,
                    );
                } else {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                        b"Symbolic or non-octal mode \"%s\" unsupported\x00" as *const u8
                            as *const libc::c_char,
                        val
                    );
                    return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
                }
                current_block_120 = 14133002253412689704;
            } else {
                current_block_120 = 2945138788423298433;
            }
        }
        _ => {}
    }
    match current_block_120 {
        2945138788423298433 => {
            if strcmp_safe(key, b"nlink\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_nlink;
                archive_entry_set_nlink_safe(
                    entry,
                    mtree_atol(&mut val, 10 as libc::c_int) as libc::c_uint,
                );
                current_block_120 = 14133002253412689704;
            } else {
                current_block_120 = 3583232612309986830;
            }
        }
        _ => {}
    }
    match current_block_120 {
        3583232612309986830 => {
            if strcmp_safe(key, b"resdevice\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                /* stat(2) st_dev field, e.g. the device ID where the
                 * inode resides */
                let mut r_0: libc::c_int = 0;
                let mut dev_0: dev_t = 0;
                r_0 = parse_device(&mut dev_0, &mut a_safe.archive, val);
                if r_0 == 0 as libc::c_int {
                    archive_entry_set_dev_safe(entry, dev_0);
                }
                return r_0;
            }
            if strcmp_safe(key, b"rmd160\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
                || strcmp_safe(key, b"rmd160digest\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_rmd160,
                );
            }
            current_block_120 = 6521175633009022335;
        }
        _ => {}
    }
    match current_block_120 {
        6521175633009022335 => {
            if strcmp_safe(key, b"sha1\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int
                || strcmp_safe(key, b"sha1digest\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha1,
                );
            }
            if strcmp_safe(key, b"sha256\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
                || strcmp_safe(key, b"sha256digest\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha256,
                );
            }
            if strcmp_safe(key, b"sha384\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
                || strcmp_safe(key, b"sha384digest\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha384,
                );
            }
            if strcmp_safe(key, b"sha512\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
                || strcmp_safe(key, b"sha512digest\x00" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
            {
                return parse_digest(
                    a,
                    entry,
                    val,
                    ARCHIVE_MTREE_DEFINED_PARAM.archive_entry_digest_sha512,
                );
            }
            if strcmp_safe(key, b"size\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            {
                archive_entry_set_size_safe(entry, mtree_atol(&mut val, 10 as libc::c_int));
                current_block_120 = 14133002253412689704;
            } else {
                current_block_120 = 13294178446195614068;
            }
        }
        _ => {}
    }
    match current_block_120 {
        13294178446195614068 => {
            if strcmp_safe(key, b"tags\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            {
                current_block_120 = 14133002253412689704;
            } else if strcmp_safe(key, b"time\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                let mut m: int64_t = 0;
                let mut my_time_t_max: int64_t = get_time_t_max();
                let mut my_time_t_min: int64_t = get_time_t_min();
                let mut ns: libc::c_long = 0 as libc::c_int as libc::c_long;
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_mtime;
                unsafe {
                    m = mtree_atol(&mut val, 10 as libc::c_int);
                }
                /* Replicate an old mtree bug:
                 * 123456789.1 represents 123456789
                 * seconds and 1 nanosecond. */
                if *val_safe as libc::c_int == '.' as i32 {
                    unsafe {
                        val = val.offset(1);
                    }
                    ns = mtree_atol(&mut val, 10 as libc::c_int);
                    if ns < 0 as libc::c_int as libc::c_long {
                        ns = 0 as libc::c_int as libc::c_long
                    } else if ns > 999999999 as libc::c_int as libc::c_long {
                        ns = 999999999 as libc::c_int as libc::c_long
                    }
                }
                if m > my_time_t_max {
                    m = my_time_t_max
                } else if m < my_time_t_min {
                    m = my_time_t_min
                }
                archive_entry_set_mtime_safe(entry, m, ns);
                current_block_120 = 14133002253412689704;
            } else if strcmp_safe(key, b"type\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                let mut current_block_110: u64;
                match unsafe { *val.offset(0 as libc::c_int as isize) as libc::c_int } {
                    98 => {
                        if strcmp_safe(val, b"block\x00" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                        {
                            archive_entry_set_filetype_safe(
                                entry,
                                ARCHIVE_MTREE_DEFINED_PARAM.ae_ifblk as mode_t,
                            );
                            current_block_110 = 14579489411542934868;
                        } else {
                            current_block_110 = 9913677422114762036;
                        }
                    }
                    99 => {
                        current_block_110 = 9913677422114762036;
                    }
                    100 => {
                        current_block_110 = 16822926593281005087;
                    }
                    102 => {
                        current_block_110 = 1613355923386801241;
                    }
                    108 => {
                        current_block_110 = 1673727746689388553;
                    }
                    _ => {
                        current_block_110 = 11264357029779558864;
                    }
                }
                match current_block_110 {
                    9913677422114762036 => {
                        if strcmp_safe(val, b"char\x00" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                        {
                            archive_entry_set_filetype_safe(
                                entry,
                                ARCHIVE_MTREE_DEFINED_PARAM.ae_ifchr as mode_t,
                            );
                            current_block_110 = 14579489411542934868;
                        } else {
                            current_block_110 = 16822926593281005087;
                        }
                    }
                    _ => {}
                }
                match current_block_110 {
                    16822926593281005087 => {
                        if strcmp_safe(val, b"dir\x00" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                        {
                            archive_entry_set_filetype_safe(
                                entry,
                                ARCHIVE_MTREE_DEFINED_PARAM.ae_ifdir as mode_t,
                            );
                            current_block_110 = 14579489411542934868;
                        } else {
                            current_block_110 = 1613355923386801241;
                        }
                    }
                    _ => {}
                }
                match current_block_110 {
                    1613355923386801241 => {
                        if strcmp_safe(val, b"fifo\x00" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                        {
                            archive_entry_set_filetype_safe(
                                entry,
                                ARCHIVE_MTREE_DEFINED_PARAM.ae_ififo as mode_t,
                            );
                            current_block_110 = 14579489411542934868;
                        } else if strcmp_safe(val, b"file\x00" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                        {
                            archive_entry_set_filetype_safe(
                                entry,
                                ARCHIVE_MTREE_DEFINED_PARAM.ae_ifreg as mode_t,
                            );
                            current_block_110 = 14579489411542934868;
                        } else {
                            current_block_110 = 1673727746689388553;
                        }
                    }
                    _ => {}
                }
                match current_block_110 {
                    1673727746689388553 => {
                        if strcmp_safe(val, b"link\x00" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                        {
                            archive_entry_set_filetype_safe(
                                entry,
                                ARCHIVE_MTREE_DEFINED_PARAM.ae_iflnk as mode_t,
                            );
                            current_block_110 = 14579489411542934868;
                        } else {
                            current_block_110 = 11264357029779558864;
                        }
                    }
                    _ => {}
                }
                match current_block_110 {
                    14579489411542934868 => {}
                    _ => {
                        archive_set_error_safe!(
                            &mut (*a).archive as *mut archive,
                            ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                            b"Unrecognized file type \"%s\"; assuming \"file\"\x00" as *const u8
                                as *const libc::c_char,
                            val
                        );
                        archive_entry_set_filetype_safe(
                            entry,
                            ARCHIVE_MTREE_DEFINED_PARAM.ae_ifreg as mode_t,
                        );
                        return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
                    }
                }
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_type;
                current_block_120 = 14133002253412689704;
            } else {
                current_block_120 = 534366734980114256;
            }
        }
        _ => {}
    }
    match current_block_120 {
        534366734980114256 => {
            if strcmp_safe(key, b"uid\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_uid;
                archive_entry_set_uid_safe(entry, mtree_atol(&mut val, 10 as libc::c_int));
                current_block_120 = 14133002253412689704;
            } else if strcmp_safe(key, b"uname\x00" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                *parsed_kws_safe |= ARCHIVE_MTREE_DEFINED_PARAM.mtree_has_uname;
                archive_entry_copy_uname_safe(entry, val);
                current_block_120 = 14133002253412689704;
            } else {
                current_block_120 = 2983046246157475477;
            }
        }
        _ => {}
    }
    match current_block_120 {
        14133002253412689704 =>
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
                b"Unrecognized key %s=%s\x00" as *const u8 as *const libc::c_char,
                key,
                val
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
        }
    }
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}

extern "C" fn read_data(
    mut a: *mut archive_read,
    mut buff: *mut *const libc::c_void,
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) -> libc::c_int {
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
    if mtree_safe.fd < 0 as libc::c_int {
        *buff_safe = 0 as *const libc::c_void;
        *offset_safe = 0 as libc::c_int as int64_t;
        *size_safe = 0 as libc::c_int as size_t;
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_eof;
    }
    if mtree_safe.buff.is_null() {
        mtree_safe.buffsize = (64 as libc::c_int * 1024 as libc::c_int) as size_t;
        mtree_safe.buff = malloc_safe(mtree_safe.buffsize) as *mut libc::c_char;
        if mtree_safe.buff.is_null() {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_MTREE_DEFINED_PARAM.enomem,
                b"Can\'t allocate memory\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal;
        }
    }
    *buff_safe = mtree_safe.buff as *const libc::c_void;
    *offset_safe = mtree_safe.offset;
    if mtree_safe.buffsize as int64_t > mtree_safe.cur_size - mtree_safe.offset {
        bytes_to_read = (mtree_safe.cur_size - mtree_safe.offset) as size_t
    } else {
        bytes_to_read = mtree_safe.buffsize
    }
    bytes_read = read_safe(
        mtree_safe.fd,
        mtree_safe.buff as *mut libc::c_void,
        bytes_to_read,
    );
    if bytes_read < 0 as libc::c_int as libc::c_long {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            *__errno_location(),
            b"Can\'t read\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_warn;
    }
    if bytes_read == 0 as libc::c_int as libc::c_long {
        *size_safe = 0 as libc::c_int as size_t;
        return ARCHIVE_MTREE_DEFINED_PARAM.archive_eof;
    }
    mtree_safe.offset += bytes_read;
    *size_safe = bytes_read as size_t;
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
/* Skip does nothing except possibly close the contents file. */
extern "C" fn skip(mut a: *mut archive_read) -> libc::c_int {
    let mut mtree: *mut mtree = 0 as *mut mtree;
    let mtree_safe;
    unsafe {
        mtree = (*(*a).format).data as *mut mtree;
        mtree_safe = &mut *mtree;
    }
    if mtree_safe.fd >= 0 as libc::c_int {
        close_safe(mtree_safe.fd);
        mtree_safe.fd = -(1 as libc::c_int)
    }
    return ARCHIVE_MTREE_DEFINED_PARAM.archive_ok;
}
/*
 * Since parsing backslash sequences always makes strings shorter,
 * we can always do this conversion in-place.
 */
extern "C" fn parse_escapes(mut src: *mut libc::c_char, mut mentry: *mut mtree_entry) {
    let mut dest: *mut libc::c_char = src;
    let mut c: libc::c_char = 0;
    let mentry_safe = unsafe { &mut *mentry };
    if !mentry.is_null()
        && strcmp_safe(src, b".\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        mentry_safe.full = 1 as libc::c_int as libc::c_char
    }
    while unsafe { *src as libc::c_int != '\u{0}' as i32 } {
        let fresh3 = src;
        unsafe {
            src = src.offset(1);
            c = *fresh3;
        }
        if c as libc::c_int == '/' as i32 && !mentry.is_null() {
            mentry_safe.full = 1 as libc::c_int as libc::c_char
        }
        if c as libc::c_int == '\\' as i32 {
            let mut current_block_30: u64;
            match unsafe { *src.offset(0 as libc::c_int as isize) as libc::c_int } {
                48 => {
                    if unsafe {
                        (*src.offset(1 as libc::c_int as isize) as libc::c_int) < '0' as i32
                            || *src.offset(1 as libc::c_int as isize) as libc::c_int > '7' as i32
                    } {
                        c = 0 as libc::c_int as libc::c_char;
                        src = unsafe { src.offset(1) };
                        current_block_30 = 3934796541983872331;
                    } else {
                        current_block_30 = 16439418194823959314;
                    }
                }
                49 | 50 | 51 => {
                    current_block_30 = 16439418194823959314;
                }
                97 => {
                    c = '\u{7}' as i32 as libc::c_char;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 3934796541983872331;
                }
                98 => {
                    c = '\u{8}' as i32 as libc::c_char;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 3934796541983872331;
                }
                102 => {
                    c = '\u{c}' as i32 as libc::c_char;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 3934796541983872331;
                }
                110 => {
                    c = '\n' as i32 as libc::c_char;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 3934796541983872331;
                }
                114 => {
                    c = '\r' as i32 as libc::c_char;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 3934796541983872331;
                }
                115 => {
                    c = ' ' as i32 as libc::c_char;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 3934796541983872331;
                }
                116 => {
                    c = '\t' as i32 as libc::c_char;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 3934796541983872331;
                }
                118 => {
                    c = '\u{b}' as i32 as libc::c_char;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 3934796541983872331;
                }
                92 => {
                    c = '\\' as i32 as libc::c_char;
                    src = unsafe { src.offset(1) };
                    current_block_30 = 3934796541983872331;
                }
                _ => {
                    current_block_30 = 3934796541983872331;
                }
            }
            match current_block_30 {
                16439418194823959314 =>
                /* FALLTHROUGH */
                unsafe {
                    if *src.offset(1 as libc::c_int as isize) as libc::c_int >= '0' as i32
                        && *src.offset(1 as libc::c_int as isize) as libc::c_int <= '7' as i32
                        && *src.offset(2 as libc::c_int as isize) as libc::c_int >= '0' as i32
                        && *src.offset(2 as libc::c_int as isize) as libc::c_int <= '7' as i32
                    {
                        c = ((*src.offset(0 as libc::c_int as isize) as libc::c_int - '0' as i32)
                            << 6 as libc::c_int) as libc::c_char;
                        c = (c as libc::c_int
                            | (*src.offset(1 as libc::c_int as isize) as libc::c_int - '0' as i32)
                                << 3 as libc::c_int) as libc::c_char;
                        c = (c as libc::c_int
                            | *src.offset(2 as libc::c_int as isize) as libc::c_int - '0' as i32)
                            as libc::c_char;
                        src = src.offset(3 as libc::c_int as isize)
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
        *dest = '\u{0}' as i32 as libc::c_char;
    }
}
/* Parse a hex digit. */
extern "C" fn parsedigit(mut c: libc::c_char) -> libc::c_int {
    if c as libc::c_int >= '0' as i32 && c as libc::c_int <= '9' as i32 {
        return c as libc::c_int - '0' as i32;
    } else if c as libc::c_int >= 'a' as i32 && c as libc::c_int <= 'f' as i32 {
        return c as libc::c_int - 'a' as i32;
    } else if c as libc::c_int >= 'A' as i32 && c as libc::c_int <= 'F' as i32 {
        return c as libc::c_int - 'A' as i32;
    } else {
        return -(1 as libc::c_int);
    };
}
/*
 * Note that this implementation does not (and should not!) obey
 * locale settings; you cannot simply substitute strtol here, since
 * it does obey locale.
 */
extern "C" fn mtree_atol(mut p: *mut *mut libc::c_char, mut base: libc::c_int) -> int64_t {
    let mut l: int64_t = 0;
    let mut limit: int64_t = 0;
    let mut digit: libc::c_int = 0;
    let mut last_digit_limit: libc::c_int = 0;
    let p_safe = unsafe { &mut *p };
    if base == 0 as libc::c_int {
        unsafe {
            if **p as libc::c_int != '0' as i32 {
                base = 10 as libc::c_int
            } else if *(*p).offset(1 as libc::c_int as isize) as libc::c_int == 'x' as i32
                || *(*p).offset(1 as libc::c_int as isize) as libc::c_int == 'X' as i32
            {
                *p_safe = (*p).offset(2 as libc::c_int as isize);
                base = 16 as libc::c_int
            } else {
                base = 8 as libc::c_int
            }
        }
    }
    if unsafe { **p as libc::c_int == '-' as i32 } {
        limit = ARCHIVE_MTREE_DEFINED_PARAM.int64_min / base as libc::c_long;
        last_digit_limit = -(ARCHIVE_MTREE_DEFINED_PARAM.int64_min
            % base as libc::c_long) as libc::c_int;
        *p_safe = unsafe { (*p).offset(1) };
        l = 0 as libc::c_int as int64_t;
        digit = unsafe { parsedigit(**p) };
        while digit >= 0 as libc::c_int && digit < base {
            if l < limit || l == limit && digit >= last_digit_limit {
                return ARCHIVE_MTREE_DEFINED_PARAM.int64_min;
            }
            l = l * base as libc::c_long - digit as libc::c_long;
            *p_safe = unsafe { (*p).offset(1) };
            digit = unsafe { parsedigit(**p) }
        }
        return l;
    } else {
        limit = ARCHIVE_MTREE_DEFINED_PARAM.int64_max / base as libc::c_long;
        last_digit_limit = (ARCHIVE_MTREE_DEFINED_PARAM.int64_max
            % base as libc::c_long) as libc::c_int;
        l = 0 as libc::c_int as int64_t;
        digit = unsafe { parsedigit(**p) };
        while digit >= 0 as libc::c_int && digit < base {
            if l > limit || l == limit && digit > last_digit_limit {
                return ARCHIVE_MTREE_DEFINED_PARAM.int64_max;
            }
            l = l * base as libc::c_long + digit as libc::c_long;
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
extern "C" fn readline(
    mut a: *mut archive_read,
    mut mtree: *mut mtree,
    mut start: *mut *mut libc::c_char,
    mut limit: ssize_t,
) -> ssize_t {
    let mut bytes_read: ssize_t = 0;
    let mut total_size: ssize_t = 0 as libc::c_int as ssize_t;
    let mut find_off: ssize_t = 0 as libc::c_int as ssize_t;
    let mut t: *const libc::c_void = 0 as *const libc::c_void;
    let mut nl: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut u: *mut libc::c_char = 0 as *mut libc::c_char;
    loop
    /* Accumulate line in a line buffer. */
    /* Read some more. */
    {
        t = __archive_read_ahead_safe(a, 1 as libc::c_int as size_t, &mut bytes_read);
        if t == 0 as *mut libc::c_void {
            return 0 as libc::c_int as ssize_t;
        }
        if bytes_read < 0 as libc::c_int as libc::c_long {
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        nl = memchr_safe(t, '\n' as i32, bytes_read as libc::c_ulong);
        /* If we found '\n', trim the read to end exactly there. */
        if !nl.is_null() {
            unsafe {
                bytes_read = (nl as *const libc::c_char).offset_from(t as *const libc::c_char)
                    as libc::c_long
                    + 1 as libc::c_int as libc::c_long
            }
        }
        let a_safe = unsafe { &mut *a };
        let mtree_safe = unsafe { &mut *mtree };
        if total_size + bytes_read + 1 as libc::c_int as libc::c_long > limit {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_MTREE_DEFINED_PARAM.archive_errno_file_format,
                b"Line too long\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        if archive_string_ensure_safe(
            &mut mtree_safe.line,
            (total_size + bytes_read + 1 as libc::c_int as libc::c_long) as size_t,
        )
        .is_null()
        {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_MTREE_DEFINED_PARAM.enomem,
                b"Can\'t allocate working buffer\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_MTREE_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        /* Append new bytes to string. */
        unsafe {
            memcpy_safe(
                (*mtree).line.s.offset(total_size as isize) as *mut libc::c_void,
                t,
                bytes_read as libc::c_ulong,
            );
        }
        __archive_read_consume_safe(a, bytes_read);
        total_size += bytes_read;
        unsafe {
            *(*mtree).line.s.offset(total_size as isize) = '\u{0}' as i32 as libc::c_char;
            u = (*mtree).line.s.offset(find_off as isize);
            while *u != 0 {
                if *u.offset(0 as libc::c_int as isize) as libc::c_int == '\n' as i32 {
                    /* Ends with unescaped newline. */
                    *start = (*mtree).line.s;
                    return total_size;
                } else {
                    if *u.offset(0 as libc::c_int as isize) as libc::c_int == '#' as i32 {
                        /* Ends with comment sequence #...\n */
                        if nl.is_null() {
                            break;
                        }
                    } else if *u.offset(0 as libc::c_int as isize) as libc::c_int == '\\' as i32 {
                        if *u.offset(1 as libc::c_int as isize) as libc::c_int == '\n' as i32 {
                            /* Trim escaped newline. */
                            total_size -= 2 as libc::c_int as libc::c_long;
                            *(*mtree).line.s.offset(total_size as isize) =
                                '\u{0}' as i32 as libc::c_char;
                            break;
                        } else if *u.offset(1 as libc::c_int as isize) as libc::c_int
                            != '\u{0}' as i32
                        {
                            /* Skip the two-char escape sequence */
                            u = u.offset(1)
                        }
                    }
                    u = u.offset(1)
                }
            }
            find_off = u.offset_from((*mtree).line.s) as libc::c_long
        }
    }
}
