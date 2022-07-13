use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_struct::struct_transfer::* ;
use rust_ffi::ffi_method::method_call::*;

use super::archive_string::archive_string_default_conversion_for_read;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cpio {
    pub magic: libc::c_int,
    pub read_header: Option<
        unsafe extern "C" fn(
            _: *mut archive_read,
            _: *mut cpio,
            _: *mut archive_entry,
            _: *mut size_t,
            _: *mut size_t,
        ) -> libc::c_int,
    >,
    pub links_head: *mut links_entry,
    pub entry_bytes_remaining: int64_t,
    pub entry_bytes_unconsumed: int64_t,
    pub entry_offset: int64_t,
    pub entry_padding: int64_t,
    pub opt_sconv: *mut archive_string_conv,
    pub sconv_default: *mut archive_string_conv,
    pub init_default_conversion: libc::c_int,
    pub option_pwb: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct links_entry {
    pub next: *mut links_entry,
    pub previous: *mut links_entry,
    pub links: libc::c_uint,
    pub dev: dev_t,
    pub ino: int64_t,
    pub name: *mut libc::c_char,
}

#[no_mangle]
pub extern "C" fn archive_read_support_format_cpio(mut _a: *mut archive) -> libc::c_int {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut cpio: *mut cpio = 0 as *mut cpio;
    let mut r: libc::c_int = 0;
    let mut magic_test: libc::c_int = __archive_check_magic_safe(
        _a,
        ARCHIVE_CPIO_DEFINED_PARAM.archive_read_magic,
        ARCHIVE_CPIO_DEFINED_PARAM.archive_state_new,
        b"archive_read_support_format_cpio\x00" as *const u8 as *const libc::c_char,
    );
    if magic_test == ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    cpio = calloc_safe(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<cpio>() as libc::c_ulong,
    ) as *mut cpio;
    if cpio.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_CPIO_DEFINED_PARAM.enomem,
            b"Can\'t allocate cpio data\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    unsafe {
        (*cpio).magic = ARCHIVE_CPIO_DEFINED_PARAM.cpio_magic;
    }
    r = __archive_read_register_format_safe(
        a,
        cpio as *mut libc::c_void,
        b"cpio\x00" as *const u8 as *const libc::c_char,
        Some(
            archive_read_format_cpio_bid
                as extern "C" fn(_: *mut archive_read, _: libc::c_int) -> libc::c_int,
        ),
        Some(
            archive_read_format_cpio_options
                as extern "C" fn(
                    _: *mut archive_read,
                    _: *const libc::c_char,
                    _: *const libc::c_char,
                ) -> libc::c_int,
        ),
        Some(
            archive_read_format_cpio_read_header
                as extern "C" fn(_: *mut archive_read, _: *mut archive_entry) -> libc::c_int,
        ),
        Some(
            archive_read_format_cpio_read_data
                as extern "C" fn(
                    _: *mut archive_read,
                    _: *mut *const libc::c_void,
                    _: *mut size_t,
                    _: *mut int64_t,
                ) -> libc::c_int,
        ),
        Some(
            archive_read_format_cpio_skip
                as extern "C" fn(_: *mut archive_read) -> libc::c_int,
        ),
        None,
        Some(
            archive_read_format_cpio_cleanup
                as extern "C" fn(_: *mut archive_read) -> libc::c_int,
        ),
        None,
        None,
    );
    if r != ARCHIVE_CPIO_DEFINED_PARAM.archive_ok {
        free_safe(cpio as *mut libc::c_void);
    }
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}

extern "C" fn archive_read_format_cpio_bid(
    mut a: *mut archive_read,
    mut best_bid: libc::c_int,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut cpio: *mut cpio = 0 as *mut cpio;
    let mut bid: libc::c_int = 0;
    /* UNUSED */
    cpio = unsafe { (*(*a).format).data as *mut cpio };
    p = __archive_read_ahead_safe(a, 6 as libc::c_int as size_t, 0 as *mut ssize_t)
        as *const libc::c_uchar;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    bid = 0 as libc::c_int;
    let cpio_safe = unsafe { &mut *cpio };
    if memcmp_safe(
        p as *const libc::c_void,
        b"070707\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        6 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        /* ASCII cpio archive (odc, POSIX.1) */
        cpio_safe.read_header = Some(
            header_odc
                as unsafe extern "C" fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> libc::c_int,
        );
        bid += 48 as libc::c_int
        /*
         * XXX TODO:  More verification; Could check that only octal
         * digits appear in appropriate header locations. XXX
         */
    } else if memcmp_safe(
        p as *const libc::c_void,
        b"070727\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        6 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        /* afio large ASCII cpio archive */
        cpio_safe.read_header = Some(
            header_odc
                as unsafe extern "C" fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> libc::c_int,
        );
        bid += 48 as libc::c_int
        /*
         * XXX TODO:  More verification; Could check that almost hex
         * digits appear in appropriate header locations. XXX
         */
    } else if memcmp_safe(
        p as *const libc::c_void,
        b"070701\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        6 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        /* ASCII cpio archive (SVR4 without CRC) */
        cpio_safe.read_header = Some(
            header_newc
                as unsafe extern "C" fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> libc::c_int,
        );
        bid += 48 as libc::c_int
        /*
         * XXX TODO:  More verification; Could check that only hex
         * digits appear in appropriate header locations. XXX
         */
    } else if memcmp_safe(
        p as *const libc::c_void,
        b"070702\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        6 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        /* ASCII cpio archive (SVR4 with CRC) */
        /* XXX TODO: Flag that we should check the CRC. XXX */
        cpio_safe.read_header = Some(
            header_newc
                as unsafe extern "C" fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> libc::c_int,
        );
        bid += 48 as libc::c_int
        /*
         * XXX TODO:  More verification; Could check that only hex
         * digits appear in appropriate header locations. XXX
         */
    } else if unsafe {
        *p.offset(0 as libc::c_int as isize) as libc::c_int * 256 as libc::c_int
            + *p.offset(1 as libc::c_int as isize) as libc::c_int
            == 0o70707 as libc::c_int
    } {
        /* big-endian binary cpio archives */
        cpio_safe.read_header = Some(
            header_bin_be
                as unsafe extern "C" fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> libc::c_int,
        );
        bid += 16 as libc::c_int
        /* Is more verification possible here? */
    } else if unsafe {
        *p.offset(0 as libc::c_int as isize) as libc::c_int
            + *p.offset(1 as libc::c_int as isize) as libc::c_int * 256 as libc::c_int
            == 0o70707 as libc::c_int
    } {
        /* little-endian binary cpio archives */
        cpio_safe.read_header = Some(
            header_bin_le
                as unsafe extern "C" fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> libc::c_int,
        );
        bid += 16 as libc::c_int
        /* Is more verification possible here? */
    } else {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_warn;
    }
    return bid;
}

extern "C" fn archive_read_format_cpio_options(
    mut a: *mut archive_read,
    mut key: *const libc::c_char,
    mut val: *const libc::c_char,
) -> libc::c_int {
    let mut cpio: *mut cpio = 0 as *mut cpio;
    let mut ret: libc::c_int = ARCHIVE_CPIO_DEFINED_PARAM.archive_failed;
    let cpio_safe;
    let a_safe;
    unsafe {
        cpio = (*(*a).format).data as *mut cpio;
        cpio_safe = &mut *cpio;
        a_safe = &mut *a;
    }
    if strcmp_safe(key, b"compat-2x\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        /* Handle filenames as libarchive 2.x */
        cpio_safe.init_default_conversion = if !val.is_null() {
            1 as libc::c_int
        } else {
            0 as libc::c_int
        };
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
    } else {
        if strcmp_safe(key, b"hdrcharset\x00" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            if unsafe {
                val.is_null()
                    || *val.offset(0 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
            } {
                archive_set_error_safe!(
                    &mut a_safe.archive as *mut archive,
                    ARCHIVE_CPIO_DEFINED_PARAM.archive_errno_misc,
                    b"cpio: hdrcharset option needs a character-set name\x00" as *const u8
                        as *const libc::c_char
                );
            } else {
                cpio_safe.opt_sconv = archive_string_conversion_from_charset_safe(
                    &mut a_safe.archive,
                    val,
                    0 as libc::c_int,
                );
                if !cpio_safe.opt_sconv.is_null() {
                    ret = ARCHIVE_CPIO_DEFINED_PARAM.archive_ok
                } else {
                    ret = ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal
                }
            }
            return ret;
        } else {
            if strcmp_safe(key, b"pwb\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            {
                if unsafe {
                    !val.is_null()
                        && *val.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
                } {
                    cpio_safe.option_pwb = 1 as libc::c_int
                }
                return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
            }
        }
    }
    /* Note: The "warn" return is just to inform the options
     * supervisor that we didn't handle it.  It will generate
     * a suitable error if no one used this option. */
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_warn;
}

extern "C" fn archive_read_format_cpio_read_header(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
) -> libc::c_int {
    let mut cpio: *mut cpio = 0 as *mut cpio;
    let mut h: *const libc::c_void = 0 as *const libc::c_void;
    let mut hl: *const libc::c_void = 0 as *const libc::c_void;
    let mut sconv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    let mut namelength: size_t = 0;
    let mut name_pad: size_t = 0;
    let mut r: libc::c_int = 0;
    let cpio_safe;
    let a_safe;
    let err_loc_safe;
    unsafe {
        cpio = (*(*a).format).data as *mut cpio;
        sconv = (*cpio).opt_sconv;
        cpio_safe = &mut *cpio;
        a_safe = &mut *a;
        err_loc_safe = *__errno_location();
    }

    if sconv.is_null() {
        if cpio_safe.init_default_conversion == 0 {
            cpio_safe.sconv_default =
                unsafe{archive_string_default_conversion_for_read(&mut a_safe.archive)};
            cpio_safe.init_default_conversion = 1 as libc::c_int
        }
        sconv = cpio_safe.sconv_default
    }
    unsafe {
        r = cpio_safe.read_header.expect("non-null function pointer")(
            a,
            cpio,
            entry,
            &mut namelength,
            &mut name_pad,
        );
    }
    if r < ARCHIVE_CPIO_DEFINED_PARAM.archive_warn {
        return r;
    }
    /* Read name from buffer. */
    h = __archive_read_ahead_safe(a, namelength.wrapping_add(name_pad), 0 as *mut ssize_t);
    if h == 0 as *mut libc::c_void {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    if _archive_entry_copy_pathname_l_safe(entry, h as *const libc::c_char, namelength, sconv)
        != 0 as libc::c_int
    {
        if err_loc_safe == ARCHIVE_CPIO_DEFINED_PARAM.enomem {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_CPIO_DEFINED_PARAM.enomem,
                b"Can\'t allocate memory for Pathname\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_CPIO_DEFINED_PARAM.archive_errno_file_format,
            b"Pathname can\'t be converted from %s to current locale.\x00" as *const u8
                as *const libc::c_char,
            archive_string_conversion_charset_name_safe(sconv)
        );
        r = ARCHIVE_CPIO_DEFINED_PARAM.archive_warn
    }
    cpio_safe.entry_offset = 0 as libc::c_int as int64_t;
    __archive_read_consume_safe(a, namelength.wrapping_add(name_pad) as int64_t);
    /* If this is a symlink, read the link contents. */
    if archive_entry_filetype_safe(entry) == ARCHIVE_CPIO_DEFINED_PARAM.ae_iflnk {
        if cpio_safe.entry_bytes_remaining
            > (1024 as libc::c_int * 1024 as libc::c_int) as libc::c_long
        {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_CPIO_DEFINED_PARAM.enomem,
                b"Rejecting malformed cpio archive: symlink contents exceed 1 megabyte\x00"
                    as *const u8 as *const libc::c_char
            );
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        hl = __archive_read_ahead_safe(
            a,
            cpio_safe.entry_bytes_remaining as size_t,
            0 as *mut ssize_t,
        );
        if hl == 0 as *mut libc::c_void {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        if _archive_entry_copy_symlink_l_safe(
            entry,
            hl as *const libc::c_char,
            cpio_safe.entry_bytes_remaining as size_t,
            sconv,
        ) != 0 as libc::c_int
        {
            if err_loc_safe == ARCHIVE_CPIO_DEFINED_PARAM.enomem {
                archive_set_error_safe!(
                    &mut a_safe.archive as *mut archive,
                    ARCHIVE_CPIO_DEFINED_PARAM.enomem,
                    b"Can\'t allocate memory for Linkname\x00" as *const u8 as *const libc::c_char
                );
                return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
            }
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_CPIO_DEFINED_PARAM.archive_errno_file_format,
                b"Linkname can\'t be converted from %s to current locale.\x00" as *const u8
                    as *const libc::c_char,
                archive_string_conversion_charset_name_safe(sconv)
            );
            r = ARCHIVE_CPIO_DEFINED_PARAM.archive_warn
        }
        __archive_read_consume_safe(a, cpio_safe.entry_bytes_remaining);
        cpio_safe.entry_bytes_remaining = 0 as libc::c_int as int64_t
    }
    /* XXX TODO: If the full mode is 0160200, then this is a Solaris
     * ACL description for the following entry.  Read this body
     * and parse it as a Solaris-style ACL, then read the next
     * header.  XXX */
    /* Compare name to "TRAILER!!!" to test for end-of-archive. */
    if namelength == 11 as libc::c_int as libc::c_ulong
        && strncmp_safe(
            h as *const libc::c_char,
            b"TRAILER!!!\x00" as *const u8 as *const libc::c_char,
            11 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
    {
        /* TODO: Store file location of start of block. */
        archive_clear_error_safe(&mut a_safe.archive);
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_eof;
    }
    /* Detect and record hardlinks to previously-extracted entries. */
    if record_hardlink(a, cpio, entry) != ARCHIVE_CPIO_DEFINED_PARAM.archive_ok {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    return r;
}
extern "C" fn archive_read_format_cpio_read_data(
    mut a: *mut archive_read,
    mut buff: *mut *const libc::c_void,
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) -> libc::c_int {
    let mut bytes_read: ssize_t = 0;
    let mut cpio: *mut cpio = 0 as *mut cpio;
    let cpio_safe;
    unsafe {
        cpio = (*(*a).format).data as *mut cpio;
        cpio_safe = &mut *cpio;
    }
    if cpio_safe.entry_bytes_unconsumed != 0 {
        __archive_read_consume_safe(a, cpio_safe.entry_bytes_unconsumed);
        cpio_safe.entry_bytes_unconsumed = 0 as libc::c_int as int64_t
    }
    let size_safe;
    let offset_safe;
    let buff_safe;
    unsafe {
        size_safe = &mut *size;
        offset_safe = &mut *offset;
        buff_safe = &mut *buff;
    }
    if cpio_safe.entry_bytes_remaining > 0 as libc::c_int as libc::c_long {
        *buff_safe = __archive_read_ahead_safe(a, 1 as libc::c_int as size_t, &mut bytes_read);
        if bytes_read <= 0 as libc::c_int as libc::c_long {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        if bytes_read > cpio_safe.entry_bytes_remaining {
            bytes_read = cpio_safe.entry_bytes_remaining
        }
        *size_safe = bytes_read as size_t;
        cpio_safe.entry_bytes_unconsumed = bytes_read;
        *offset_safe = cpio_safe.entry_offset;
        cpio_safe.entry_offset += bytes_read;
        cpio_safe.entry_bytes_remaining -= bytes_read;
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
    } else {
        if cpio_safe.entry_padding != __archive_read_consume_safe(a, cpio_safe.entry_padding) {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        cpio_safe.entry_padding = 0 as libc::c_int as int64_t;
        *buff_safe = 0 as *const libc::c_void;
        *size_safe = 0 as libc::c_int as size_t;
        *offset_safe = cpio_safe.entry_offset;
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_eof;
    };
}

extern "C" fn archive_read_format_cpio_skip(mut a: *mut archive_read) -> libc::c_int {
    let safe_a = unsafe { &mut *a };
    let safe_c = unsafe { &mut *((*(safe_a).format).data as *mut cpio) };
    let mut to_skip: int64_t =
        safe_c.entry_bytes_remaining + safe_c.entry_padding + safe_c.entry_bytes_unconsumed;
    if to_skip != __archive_read_consume_safe(a, to_skip) {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    safe_c.entry_bytes_remaining = 0 as libc::c_int as int64_t;
    safe_c.entry_padding = 0 as libc::c_int as int64_t;
    safe_c.entry_bytes_unconsumed = 0 as libc::c_int as int64_t;
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
/*
 * Skip forward to the next cpio newc header by searching for the
 * 07070[12] string.  This should be generalized and merged with
 * find_odc_header below.
 */
extern "C" fn is_hex(mut p: *const libc::c_char, mut len: size_t) -> libc::c_int {
    let safe_p = unsafe { &*p };
    loop {
        let fresh0 = len;
        len = len.wrapping_sub(1);
        if !(fresh0 > 0 as libc::c_int as libc::c_ulong) {
            break;
        }
        if *safe_p as libc::c_int >= '0' as i32 && *safe_p as libc::c_int <= '9' as i32
            || *safe_p as libc::c_int >= 'a' as i32 && *safe_p as libc::c_int <= 'f' as i32
            || *safe_p as libc::c_int >= 'A' as i32 && *safe_p as libc::c_int <= 'F' as i32
        {
            unsafe { p = p.offset(1) };
        } else {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
extern "C" fn find_newc_header(mut a: *mut archive_read) -> libc::c_int {
    let mut h: *const libc::c_void = 0 as *const libc::c_void;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut q: *const libc::c_char = 0 as *const libc::c_char;
    let mut skip: size_t = 0;
    let mut skipped: size_t = 0 as libc::c_int as size_t;
    let mut bytes: ssize_t = 0;
    loop {
        h = __archive_read_ahead_safe(
            a,
            ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE,
            &mut bytes,
        );
        if h == 0 as *mut libc::c_void {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        p = h as *const libc::c_char;
        q = unsafe { p.offset(bytes as isize) };
        /* Try the typical case first, then go into the slow search.*/
        if memcmp_safe(
            b"07070\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
            p as *const libc::c_void,
            5 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
            && unsafe {
                (*p.offset(5 as libc::c_int as isize) as libc::c_int == '1' as i32
                    || *p.offset(5 as libc::c_int as isize) as libc::c_int == '2' as i32)
            }
            && is_hex(
                p,
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE,
            ) != 0
        {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
        }
        /*
         * Scan ahead until we find something that looks
         * like a newc header.
         */
        unsafe {
            while p.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE as isize) <= q
            {
                match *p.offset(5 as libc::c_int as isize) as libc::c_int {
                    49 | 50 => {
                        if memcmp_safe(
                            b"07070\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
                            p as *const libc::c_void,
                            5 as libc::c_int as libc::c_ulong,
                        ) == 0 as libc::c_int
                            && is_hex(
                                p,
                                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE,
                            ) != 0
                        {
                            skip =
                                p.offset_from(h as *const libc::c_char) as libc::c_long as size_t;
                            __archive_read_consume_safe(a, skip as int64_t);
                            skipped =
                                (skipped as libc::c_ulong).wrapping_add(skip) as size_t as size_t;
                            if skipped > 0 as libc::c_int as libc::c_ulong {
                                archive_set_error_safe!(
                                    &mut (*a).archive as *mut archive,
                                    0 as libc::c_int,
                                    b"Skipped %d bytes before finding valid header\x00" as *const u8
                                        as *const libc::c_char,
                                    skipped as libc::c_int
                                );
                                return ARCHIVE_CPIO_DEFINED_PARAM.archive_warn;
                            }
                            return 0 as libc::c_int;
                        }
                        p = p.offset(2 as libc::c_int as isize)
                    }
                    48 => p = p.offset(1),
                    _ => p = p.offset(6 as libc::c_int as isize),
                }
            }
        }
        skip = unsafe { p.offset_from(h as *const libc::c_char) as libc::c_long as size_t };
        __archive_read_consume_safe(a, skip as int64_t);
        skipped = (skipped as libc::c_ulong).wrapping_add(skip) as size_t as size_t
    }
}

extern "C" fn header_newc(
    mut a: *mut archive_read,
    mut cpio: *mut cpio,
    mut entry: *mut archive_entry,
    mut namelength: *mut size_t,
    mut name_pad: *mut size_t,
) -> libc::c_int {
    let mut h: *const libc::c_void = 0 as *const libc::c_void;
    let mut header: *const libc::c_char = 0 as *const libc::c_char;
    let mut r: libc::c_int = 0;
    r = find_newc_header(a);
    if r < ARCHIVE_CPIO_DEFINED_PARAM.archive_warn {
        return r;
    }
    /* Read fixed-size portion of header. */
    h = __archive_read_ahead_safe(
        a,
        ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE,
        0 as *mut ssize_t,
    );
    if h == 0 as *mut libc::c_void {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    /* Parse out hex fields. */
    header = h as *const libc::c_char;
    let a_safe = unsafe { &mut *a };
    if memcmp_safe(
        unsafe {
            header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MAGIC_OFFSET as isize)
                as *const libc::c_void
        },
        b"070701\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        6 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_svr4_nocrc;
        a_safe.archive.archive_format_name =
            b"ASCII cpio (SVR4 with no CRC)\x00" as *const u8 as *const libc::c_char
    } else if memcmp_safe(
        unsafe {
            header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MAGIC_OFFSET as isize)
                as *const libc::c_void
        },
        b"070702\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        6 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_svr4_crc;
        a_safe.archive.archive_format_name =
            b"ASCII cpio (SVR4 with CRC)\x00" as *const u8 as *const libc::c_char
    }
    unsafe {
        archive_entry_set_devmajor(
            entry,
            atol16(
                header.offset(
                    ARCHIVE_CPIO_DEFINED_PARAM.NEWC_DEVMAJOR_OFFSET as isize,
                ),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_DEVMAJOR_SIZE as libc::c_uint,
            ) as dev_t,
        );
        archive_entry_set_devminor(
            entry,
            atol16(
                header.offset(
                    ARCHIVE_CPIO_DEFINED_PARAM.NEWC_DEVMINOR_OFFSET as isize,
                ),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_DEVMINOR_SIZE as libc::c_uint,
            ) as dev_t,
        );
        archive_entry_set_ino(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_INO_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_INO_SIZE as libc::c_uint,
            ),
        );
        archive_entry_set_mode(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MODE_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MODE_SIZE as libc::c_uint,
            ) as mode_t,
        );
        archive_entry_set_uid(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_UID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_UID_SIZE as libc::c_uint,
            ),
        );
        archive_entry_set_gid(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_GID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_GID_SIZE as libc::c_uint,
            ),
        );
        archive_entry_set_nlink(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_NLINK_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_NLINK_SIZE as libc::c_uint,
            ) as libc::c_uint,
        );
        archive_entry_set_rdevmajor(
            entry,
            atol16(
                header.offset(
                    ARCHIVE_CPIO_DEFINED_PARAM.NEWC_RDEVMAJOR_OFFSET as isize,
                ),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_RDEVMAJOR_SIZE as libc::c_uint,
            ) as dev_t,
        );
        archive_entry_set_rdevminor(
            entry,
            atol16(
                header.offset(
                    ARCHIVE_CPIO_DEFINED_PARAM.NEWC_RDEVMINOR_OFFSET as isize,
                ),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_RDEVMINOR_SIZE as libc::c_uint,
            ) as dev_t,
        );
        archive_entry_set_mtime(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MTIME_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MTIME_SIZE as libc::c_uint,
            ),
            0 as libc::c_int as libc::c_long,
        );
        *namelength = atol16(
            header.offset(
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_NAMESIZE_OFFSET as isize,
            ),
            ARCHIVE_CPIO_DEFINED_PARAM.NEWC_NAMESIZE_SIZE as libc::c_uint,
        ) as size_t;
        /* Pad name to 2 more than a multiple of 4. */
        *name_pad = (2 as libc::c_int as libc::c_ulong).wrapping_sub(*namelength)
            & 3 as libc::c_int as libc::c_ulong;
        /* Make sure that the padded name length fits into size_t. */
        if *name_pad > (18446744073709551615 as libc::c_ulong).wrapping_sub(*namelength) {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_CPIO_DEFINED_PARAM.archive_errno_file_format,
                b"cpio archive has invalid namelength\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        /*
         * Note: entry_bytes_remaining is at least 64 bits and
         * therefore guaranteed to be big enough for a 33-bit file
         * size.
         */
        (*cpio).entry_bytes_remaining = atol16(
            header.offset(
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_FILESIZE_OFFSET as isize,
            ),
            ARCHIVE_CPIO_DEFINED_PARAM.NEWC_FILESIZE_SIZE as libc::c_uint,
        );
    }
    let cpio_safe = unsafe { &mut *cpio };
    archive_entry_set_size_safe(entry, cpio_safe.entry_bytes_remaining);
    /* Pad file contents to a multiple of 4. */
    cpio_safe.entry_padding = 3 as libc::c_int as libc::c_long & -cpio_safe.entry_bytes_remaining;
    __archive_read_consume_safe(
        a,
        ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE as int64_t,
    );
    return r;
}
/*
 * Skip forward to the next cpio odc header by searching for the
 * 070707 string.  This is a hand-optimized search that could
 * probably be easily generalized to handle all character-based
 * cpio variants.
 */
extern "C" fn is_octal(mut p: *const libc::c_char, mut len: size_t) -> libc::c_int {
    loop {
        let fresh1 = len;
        len = len.wrapping_sub(1);
        if !(fresh1 > 0 as libc::c_int as libc::c_ulong) {
            break;
        }
        let p_safe = unsafe { &*p };
        if (*p_safe as libc::c_int) < '0' as i32 || *p_safe as libc::c_int > '7' as i32 {
            return 0 as libc::c_int;
        }
        unsafe { p = p.offset(1) }
    }
    return 1 as libc::c_int;
}
extern "C" fn is_afio_large(mut h: *const libc::c_char, mut len: size_t) -> libc::c_int {
    if len < ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_HEADER_SIZE as libc::c_ulong {
        return 0 as libc::c_int;
    }
    unsafe {
        if *h.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_INO_M_OFFSET as isize)
            as libc::c_int
            != 'm' as i32
            || *h.offset(
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MTIME_N_OFFSET as isize,
            ) as libc::c_int
                != 'n' as i32
            || *h.offset(
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_XSIZE_S_OFFSET as isize,
            ) as libc::c_int
                != 's' as i32
            || *h.offset(
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_FILESIZE_C_OFFSET as isize,
            ) as libc::c_int
                != ':' as i32
        {
            return 0 as libc::c_int;
        }
        if is_hex(
            h.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_DEV_OFFSET as isize),
            (ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_INO_M_OFFSET
                - ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_DEV_OFFSET) as size_t,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        if is_hex(
            h.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MODE_OFFSET as isize),
            (ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MTIME_N_OFFSET
                - ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MODE_OFFSET)
                as size_t,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        if is_hex(
            h.offset(
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NAMESIZE_OFFSET as isize,
            ),
            (ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_XSIZE_S_OFFSET
                - ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NAMESIZE_OFFSET) as size_t,
        ) == 0
        {
            return 0 as libc::c_int;
        }
        if is_hex(
            h.offset(
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_FILESIZE_OFFSET as isize,
            ),
            ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_FILESIZE_SIZE as size_t,
        ) == 0
        {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
extern "C" fn find_odc_header(mut a: *mut archive_read) -> libc::c_int {
    let mut h: *const libc::c_void = 0 as *const libc::c_void;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut q: *const libc::c_char = 0 as *const libc::c_char;
    let mut skip: size_t = 0;
    let mut skipped: size_t = 0 as libc::c_int as size_t;
    let mut bytes: ssize_t = 0;
    loop {
        h = __archive_read_ahead_safe(a, 76 as libc::c_int as size_t, &mut bytes);
        if h == 0 as *mut libc::c_void {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        p = h as *const libc::c_char;
        unsafe {
            q = p.offset(bytes as isize);
        }
        /* Try the typical case first, then go into the slow search.*/
        if memcmp_safe(
            b"070707\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
            p as *const libc::c_void,
            6 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
            && is_octal(
                p,
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_HEADER_SIZE as size_t,
            ) != 0
        {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
        }
        let a_safe = unsafe { &mut *a };
        if memcmp_safe(
            b"070727\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
            p as *const libc::c_void,
            6 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
            && is_afio_large(p, bytes as size_t) != 0
        {
            a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_afio_large;
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
        }
        /*
         * Scan ahead until we find something that looks
         * like an odc header.
         */
        unsafe {
            while p.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_HEADER_SIZE as isize) <= q
            {
                match *p.offset(5 as libc::c_int as isize) as libc::c_int {
                    55 => {
                        if memcmp_safe(
                            b"070707\x00" as *const u8 as *const libc::c_char
                                as *const libc::c_void,
                            p as *const libc::c_void,
                            6 as libc::c_int as libc::c_ulong,
                        ) == 0 as libc::c_int
                            && is_octal(
                                p,
                                ARCHIVE_CPIO_DEFINED_PARAM.ODC_HEADER_SIZE as size_t,
                            ) != 0
                            || memcmp_safe(
                                b"070727\x00" as *const u8 as *const libc::c_char
                                    as *const libc::c_void,
                                p as *const libc::c_void,
                                6 as libc::c_int as libc::c_ulong,
                            ) == 0 as libc::c_int
                                && is_afio_large(p, q.offset_from(p) as libc::c_long as size_t) != 0
                        {
                            skip =
                                p.offset_from(h as *const libc::c_char) as libc::c_long as size_t;
                            __archive_read_consume_safe(a, skip as int64_t);
                            skipped =
                                (skipped as libc::c_ulong).wrapping_add(skip) as size_t as size_t;
                            if *p.offset(4 as libc::c_int as isize) as libc::c_int == '2' as i32 {
                                (*a).archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_afio_large
                            }
                            if skipped > 0 as libc::c_int as libc::c_ulong {
                                archive_set_error_safe!(
                                    &mut (*a).archive as *mut archive,
                                    0 as libc::c_int,
                                    b"Skipped %d bytes before finding valid header\x00" as *const u8
                                        as *const libc::c_char,
                                    skipped as libc::c_int
                                );
                                return ARCHIVE_CPIO_DEFINED_PARAM.archive_warn;
                            }
                            return 0 as libc::c_int;
                        }
                        p = p.offset(2 as libc::c_int as isize)
                    }
                    48 => p = p.offset(1),
                    _ => p = p.offset(6 as libc::c_int as isize),
                }
            }
            skip = p.offset_from(h as *const libc::c_char) as libc::c_long as size_t;
        }
        __archive_read_consume_safe(a, skip as int64_t);
        skipped = (skipped as libc::c_ulong).wrapping_add(skip) as size_t as size_t
    }
}
extern "C" fn header_odc(
    mut a: *mut archive_read,
    mut cpio: *mut cpio,
    mut entry: *mut archive_entry,
    mut namelength: *mut size_t,
    mut name_pad: *mut size_t,
) -> libc::c_int {
    let mut h: *const libc::c_void = 0 as *const libc::c_void;
    let mut r: libc::c_int = 0;
    let mut header: *const libc::c_char = 0 as *const libc::c_char;
    let a_safe = unsafe { &mut *a };
    a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_posix;
    a_safe.archive.archive_format_name =
        b"POSIX octet-oriented cpio\x00" as *const u8 as *const libc::c_char;
    /* Find the start of the next header. */
    r = find_odc_header(a);
    if r < ARCHIVE_CPIO_DEFINED_PARAM.archive_warn {
        return r;
    }
    if a_safe.archive.archive_format
        == ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_afio_large
    {
        let mut r2: libc::c_int = header_afiol(a, cpio, entry, namelength, name_pad);
        if r2 == ARCHIVE_CPIO_DEFINED_PARAM.archive_ok {
            return r;
        } else {
            return r2;
        }
    }
    /* Read fixed-size portion of header. */
    h = __archive_read_ahead_safe(
        a,
        ARCHIVE_CPIO_DEFINED_PARAM.ODC_HEADER_SIZE as size_t,
        0 as *mut ssize_t,
    );
    if h == 0 as *mut libc::c_void {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    /* Parse out octal fields. */
    header = h as *const libc::c_char; /* No padding of filename. */
    unsafe {
        archive_entry_set_dev(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_DEV_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_DEV_SIZE as libc::c_uint,
            ) as dev_t,
        );
        archive_entry_set_ino(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_INO_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_INO_SIZE as libc::c_uint,
            ),
        );
        archive_entry_set_mode(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_MODE_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_MODE_SIZE as libc::c_uint,
            ) as mode_t,
        );
        archive_entry_set_uid(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_UID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_UID_SIZE as libc::c_uint,
            ),
        );
        archive_entry_set_gid(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_GID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_GID_SIZE as libc::c_uint,
            ),
        );
        archive_entry_set_nlink(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_NLINK_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_NLINK_SIZE as libc::c_uint,
            ) as libc::c_uint,
        );
        archive_entry_set_rdev(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_RDEV_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_RDEV_SIZE as libc::c_uint,
            ) as dev_t,
        );
        archive_entry_set_mtime(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_MTIME_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_MTIME_SIZE as libc::c_uint,
            ),
            0 as libc::c_int as libc::c_long,
        );
        *namelength = atol8(
            header.offset(
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_NAMESIZE_OFFSET as isize,
            ),
            ARCHIVE_CPIO_DEFINED_PARAM.ODC_NAMESIZE_SIZE as libc::c_uint,
        ) as size_t;
        *name_pad = 0 as libc::c_int as size_t;
        /*
         * Note: entry_bytes_remaining is at least 64 bits and
         * therefore guaranteed to be big enough for a 33-bit file
         * size.
         */
        (*cpio).entry_bytes_remaining = atol8(
            header.offset(
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_FILESIZE_OFFSET as isize,
            ),
            ARCHIVE_CPIO_DEFINED_PARAM.ODC_FILESIZE_SIZE as libc::c_uint,
        );
    }
    let cpio_safe = unsafe { &mut *cpio };
    archive_entry_set_size_safe(entry, cpio_safe.entry_bytes_remaining);
    cpio_safe.entry_padding = 0 as libc::c_int as int64_t;
    __archive_read_consume_safe(
        a,
        ARCHIVE_CPIO_DEFINED_PARAM.ODC_HEADER_SIZE as int64_t,
    );
    return r;
}
/*
 * NOTE: if a filename suffix is ".z", it is the file gziped by afio.
 * it would be nice that we can show uncompressed file size and we can
 * uncompressed file contents automatically, unfortunately we have nothing
 * to get a uncompressed file size while reading each header. It means
 * we also cannot uncompress file contents under our framework.
 */
extern "C" fn header_afiol(
    mut a: *mut archive_read,
    mut cpio: *mut cpio,
    mut entry: *mut archive_entry,
    mut namelength: *mut size_t,
    mut name_pad: *mut size_t,
) -> libc::c_int {
    let mut h: *const libc::c_void = 0 as *const libc::c_void;
    let mut header: *const libc::c_char = 0 as *const libc::c_char;
    let a_safe = unsafe { &mut *a };
    a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_afio_large;
    a_safe.archive.archive_format_name =
        b"afio large ASCII\x00" as *const u8 as *const libc::c_char;
    /* Read fixed-size portion of header. */
    h = __archive_read_ahead_safe(
        a,
        ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_HEADER_SIZE as size_t,
        0 as *mut ssize_t,
    );
    if h == 0 as *mut libc::c_void {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    /* Parse out octal fields. */
    header = h as *const libc::c_char; /* No padding of filename. */
    unsafe {
        archive_entry_set_dev(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_DEV_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_DEV_SIZE as libc::c_uint,
            ) as dev_t,
        );
        archive_entry_set_ino(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_INO_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_INO_SIZE as libc::c_uint,
            ),
        );
        archive_entry_set_mode(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MODE_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MODE_SIZE as libc::c_uint,
            ) as mode_t,
        );
        archive_entry_set_uid(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_UID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_UID_SIZE as libc::c_uint,
            ),
        );
        archive_entry_set_gid(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_GID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_GID_SIZE as libc::c_uint,
            ),
        );
        archive_entry_set_nlink(
            entry,
            atol16(
                header
                    .offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NLINK_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NLINK_SIZE as libc::c_uint,
            ) as libc::c_uint,
        );
        archive_entry_set_rdev(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_RDEV_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_RDEV_SIZE as libc::c_uint,
            ) as dev_t,
        );
        archive_entry_set_mtime(
            entry,
            atol16(
                header
                    .offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MTIME_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MTIME_SIZE as libc::c_uint,
            ),
            0 as libc::c_int as libc::c_long,
        );
        *namelength = atol16(
            header.offset(
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NAMESIZE_OFFSET as isize,
            ),
            ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NAMESIZE_SIZE as libc::c_uint,
        ) as size_t;
        *name_pad = 0 as libc::c_int as size_t;
        (*cpio).entry_bytes_remaining = atol16(
            header.offset(
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_FILESIZE_OFFSET as isize,
            ),
            ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_FILESIZE_SIZE as libc::c_uint,
        );
    }
    let cpio_safe = unsafe { &mut *cpio };
    archive_entry_set_size_safe(entry, cpio_safe.entry_bytes_remaining);
    cpio_safe.entry_padding = 0 as libc::c_int as int64_t;
    __archive_read_consume_safe(
        a,
        ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_HEADER_SIZE as int64_t,
    );
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
extern "C" fn header_bin_le(
    mut a: *mut archive_read,
    mut cpio: *mut cpio,
    mut entry: *mut archive_entry,
    mut namelength: *mut size_t,
    mut name_pad: *mut size_t,
) -> libc::c_int {
    let mut h: *const libc::c_void = 0 as *const libc::c_void;
    let mut header: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let a_safe = unsafe { &mut *a };
    a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_bin_le;
    a_safe.archive.archive_format_name =
        b"cpio (little-endian binary)\x00" as *const u8 as *const libc::c_char;
    /* Read fixed-size portion of header. */
    h = __archive_read_ahead_safe(
        a,
        ARCHIVE_CPIO_DEFINED_PARAM.BIN_HEADER_SIZE as size_t,
        0 as *mut ssize_t,
    );
    if h == 0 as *mut libc::c_void {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            0 as libc::c_int,
            b"End of file trying to read next cpio header\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    /* Parse out binary fields. */
    header = h as *const libc::c_uchar;
    unsafe {
        archive_entry_set_dev(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_DEV_OFFSET as isize)
                as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_DEV_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int
                    * 256 as libc::c_int) as dev_t,
        );
        archive_entry_set_ino(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_INO_OFFSET as isize)
                as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_INO_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int
                    * 256 as libc::c_int) as la_int64_t,
        );
        archive_entry_set_mode(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_MODE_OFFSET as isize)
                as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_MODE_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int
                    * 256 as libc::c_int) as mode_t,
        );
        if (*cpio).option_pwb != 0 {
            /* turn off random bits left over from V6 inode */
            archive_entry_set_mode(
                entry,
                archive_entry_mode(entry) & 0o67777 as libc::c_int as libc::c_uint,
            ); /* Pad to even. */
            if archive_entry_mode(entry)
                & ARCHIVE_CPIO_DEFINED_PARAM.ae_ifmt as mode_t
                == 0 as libc::c_int as libc::c_uint
            {
                archive_entry_set_mode(
                    entry,
                    archive_entry_mode(entry)
                        | ARCHIVE_CPIO_DEFINED_PARAM.ae_ifreg as mode_t,
                ); /* Pad to even. */
            }
        }
        archive_entry_set_uid(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_UID_OFFSET as isize)
                as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_UID_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int
                    * 256 as libc::c_int) as la_int64_t,
        );
        archive_entry_set_gid(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_GID_OFFSET as isize)
                as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_GID_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int
                    * 256 as libc::c_int) as la_int64_t,
        );
        archive_entry_set_nlink(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_NLINK_OFFSET as isize)
                as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_NLINK_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int
                    * 256 as libc::c_int) as libc::c_uint,
        );
        archive_entry_set_rdev(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_RDEV_OFFSET as isize)
                as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_RDEV_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int
                    * 256 as libc::c_int) as dev_t,
        );
        archive_entry_set_mtime(
            entry,
            le4(header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_MTIME_OFFSET as isize)),
            0 as libc::c_int as libc::c_long,
        );
        *namelength = (*header.offset(
            ARCHIVE_CPIO_DEFINED_PARAM.BIN_NAMESIZE_OFFSET as isize,
        ) as libc::c_int
            + *header.offset(
                (ARCHIVE_CPIO_DEFINED_PARAM.BIN_NAMESIZE_OFFSET
                    + 1 as libc::c_int) as isize,
            ) as libc::c_int
                * 256 as libc::c_int) as size_t;
        *name_pad = *namelength & 1 as libc::c_int as libc::c_ulong;
        (*cpio).entry_bytes_remaining = le4(header.offset(
            ARCHIVE_CPIO_DEFINED_PARAM.BIN_FILESIZE_OFFSET as isize,
        ));
    }
    let cpio_safe = unsafe { &mut *cpio };
    archive_entry_set_size_safe(entry, cpio_safe.entry_bytes_remaining);
    cpio_safe.entry_padding = cpio_safe.entry_bytes_remaining & 1 as libc::c_int as libc::c_long;
    __archive_read_consume_safe(
        a,
        ARCHIVE_CPIO_DEFINED_PARAM.BIN_HEADER_SIZE as int64_t,
    );
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
extern "C" fn header_bin_be(
    mut a: *mut archive_read,
    mut cpio: *mut cpio,
    mut entry: *mut archive_entry,
    mut namelength: *mut size_t,
    mut name_pad: *mut size_t,
) -> libc::c_int {
    let mut h: *const libc::c_void = 0 as *const libc::c_void;
    let mut header: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let a_safe = unsafe { &mut *a };
    a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_bin_be;
    a_safe.archive.archive_format_name =
        b"cpio (big-endian binary)\x00" as *const u8 as *const libc::c_char;
    /* Read fixed-size portion of header. */
    h = __archive_read_ahead_safe(
        a,
        ARCHIVE_CPIO_DEFINED_PARAM.BIN_HEADER_SIZE as size_t,
        0 as *mut ssize_t,
    );
    if h == 0 as *mut libc::c_void {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            0 as libc::c_int,
            b"End of file trying to read next cpio header\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    /* Parse out binary fields. */
    header = h as *const libc::c_uchar;
    unsafe {
        archive_entry_set_dev(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_DEV_OFFSET as isize)
                as libc::c_int
                * 256 as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_DEV_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int) as dev_t,
        );
        archive_entry_set_ino(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_INO_OFFSET as isize)
                as libc::c_int
                * 256 as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_INO_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int) as la_int64_t,
        );
        archive_entry_set_mode(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_MODE_OFFSET as isize)
                as libc::c_int
                * 256 as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_MODE_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int) as mode_t,
        );
        if (*cpio).option_pwb != 0 {
            /* turn off random bits left over from V6 inode */
            archive_entry_set_mode(
                entry,
                archive_entry_mode(entry) & 0o67777 as libc::c_int as libc::c_uint,
            ); /* Pad to even. */
            if archive_entry_mode(entry)
                & ARCHIVE_CPIO_DEFINED_PARAM.ae_ifmt as mode_t
                == 0 as libc::c_int as libc::c_uint
            {
                archive_entry_set_mode(
                    entry,
                    archive_entry_mode(entry)
                        | ARCHIVE_CPIO_DEFINED_PARAM.ae_ifreg as mode_t,
                ); /* Pad to even. */
            }
        }
        archive_entry_set_uid(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_UID_OFFSET as isize)
                as libc::c_int
                * 256 as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_UID_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int) as la_int64_t,
        );
        archive_entry_set_gid(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_GID_OFFSET as isize)
                as libc::c_int
                * 256 as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_GID_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int) as la_int64_t,
        );
        archive_entry_set_nlink(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_NLINK_OFFSET as isize)
                as libc::c_int
                * 256 as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_NLINK_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int) as libc::c_uint,
        );
        archive_entry_set_rdev(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_RDEV_OFFSET as isize)
                as libc::c_int
                * 256 as libc::c_int
                + *header.offset(
                    (ARCHIVE_CPIO_DEFINED_PARAM.BIN_RDEV_OFFSET + 1 as libc::c_int)
                        as isize,
                ) as libc::c_int) as dev_t,
        );
        archive_entry_set_mtime(
            entry,
            be4(header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_MTIME_OFFSET as isize)),
            0 as libc::c_int as libc::c_long,
        );
        *namelength = (*header.offset(
            ARCHIVE_CPIO_DEFINED_PARAM.BIN_NAMESIZE_OFFSET as isize,
        ) as libc::c_int
            * 256 as libc::c_int
            + *header.offset(
                (ARCHIVE_CPIO_DEFINED_PARAM.BIN_NAMESIZE_OFFSET
                    + 1 as libc::c_int) as isize,
            ) as libc::c_int) as size_t;
        *name_pad = *namelength & 1 as libc::c_int as libc::c_ulong;
        (*cpio).entry_bytes_remaining = be4(header.offset(
            ARCHIVE_CPIO_DEFINED_PARAM.BIN_FILESIZE_OFFSET as isize,
        ));
    }
    let cpio_safe = unsafe { &mut *cpio };
    archive_entry_set_size_safe(entry, cpio_safe.entry_bytes_remaining);
    cpio_safe.entry_padding = cpio_safe.entry_bytes_remaining & 1 as libc::c_int as libc::c_long;
    __archive_read_consume_safe(
        a,
        ARCHIVE_CPIO_DEFINED_PARAM.BIN_HEADER_SIZE as int64_t,
    );
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
extern "C" fn archive_read_format_cpio_cleanup(mut a: *mut archive_read) -> libc::c_int {
    let mut cpio: *mut cpio = 0 as *mut cpio;
    let a_safe;
    let cpio_safe;
    a_safe = unsafe { &mut (*(*a).format) };
    cpio = a_safe.data as *mut cpio;
    unsafe {
        cpio_safe = &mut *cpio;
    }
    /* Free inode->name map */
    while !cpio_safe.links_head.is_null() {
        let cpio_2_l_safe;
        unsafe {
            cpio_2_l_safe = &mut (*(*cpio).links_head);
        }
        let mut lp: *mut links_entry;
        lp = cpio_2_l_safe.next;
        free_safe(cpio_2_l_safe.name as *mut libc::c_void);
        free_safe(cpio_safe.links_head as *mut libc::c_void);
        cpio_safe.links_head = lp
    }
    free_safe(cpio as *mut libc::c_void);
    a_safe.data = 0 as *mut libc::c_void;
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
unsafe extern "C" fn le4(mut p: *const libc::c_uchar) -> int64_t {
    return ((*p.offset(0 as libc::c_int as isize) as libc::c_int) << 16 as libc::c_int)
        as libc::c_long
        + ((*p.offset(1 as libc::c_int as isize) as int64_t) << 24 as libc::c_int)
        + ((*p.offset(2 as libc::c_int as isize) as libc::c_int) << 0 as libc::c_int)
            as libc::c_long
        + ((*p.offset(3 as libc::c_int as isize) as libc::c_int) << 8 as libc::c_int)
            as libc::c_long;
}
unsafe extern "C" fn be4(mut p: *const libc::c_uchar) -> int64_t {
    return ((*p.offset(0 as libc::c_int as isize) as int64_t) << 24 as libc::c_int)
        + ((*p.offset(1 as libc::c_int as isize) as libc::c_int) << 16 as libc::c_int)
            as libc::c_long
        + ((*p.offset(2 as libc::c_int as isize) as libc::c_int) << 8 as libc::c_int)
            as libc::c_long
        + *p.offset(3 as libc::c_int as isize) as libc::c_long;
}
/*
 * Note that this implementation does not (and should not!) obey
 * locale settings; you cannot simply substitute strtol here, since
 * it does obey locale.
 */
extern "C" fn atol8(mut p: *const libc::c_char, mut char_cnt: libc::c_uint) -> int64_t {
    let mut l: int64_t = 0;
    let mut digit: libc::c_int = 0;
    l = 0 as libc::c_int as int64_t;
    loop {
        let fresh2 = char_cnt;
        char_cnt = char_cnt.wrapping_sub(1);
        if !(fresh2 > 0 as libc::c_int as libc::c_uint) {
            break;
        }
        let p_safe = unsafe { &*p };
        if *p_safe as libc::c_int >= '0' as i32 && *p_safe as libc::c_int <= '7' as i32 {
            digit = *p_safe as libc::c_int - '0' as i32
        } else {
            return l;
        }
        unsafe {
            p = p.offset(1);
        }
        l <<= 3 as libc::c_int;
        l |= digit as libc::c_long
    }
    return l;
}
extern "C" fn atol16(mut p: *const libc::c_char, mut char_cnt: libc::c_uint) -> int64_t {
    let mut l: int64_t = 0;
    let mut digit: libc::c_int = 0;
    l = 0 as libc::c_int as int64_t;
    loop {
        let fresh3 = char_cnt;
        char_cnt = char_cnt.wrapping_sub(1);
        if !(fresh3 > 0 as libc::c_int as libc::c_uint) {
            break;
        }
        unsafe {
            if *p as libc::c_int >= 'a' as i32 && *p as libc::c_int <= 'f' as i32 {
                digit = *p as libc::c_int - 'a' as i32 + 10 as libc::c_int
            } else if *p as libc::c_int >= 'A' as i32 && *p as libc::c_int <= 'F' as i32 {
                digit = *p as libc::c_int - 'A' as i32 + 10 as libc::c_int
            } else if *p as libc::c_int >= '0' as i32 && *p as libc::c_int <= '9' as i32 {
                digit = *p as libc::c_int - '0' as i32
            } else {
                return l;
            }

            p = p.offset(1);
        }
        l <<= 4 as libc::c_int;
        l |= digit as libc::c_long
    }
    return l;
}
extern "C" fn record_hardlink(
    mut a: *mut archive_read,
    mut cpio: *mut cpio,
    mut entry: *mut archive_entry,
) -> libc::c_int {
    let mut le: *mut links_entry = 0 as *mut links_entry;
    let mut dev: dev_t = 0;
    let mut ino: int64_t = 0;
    if archive_entry_nlink_safe(entry) <= 1 as libc::c_int as libc::c_uint {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
    }
    dev = archive_entry_dev_safe(entry);
    ino = archive_entry_ino64_safe(entry);
    /*
     * First look in the list of multiply-linked files.  If we've
     * already dumped it, convert this entry to a hard link entry.
     */
    unsafe {
        le = (*cpio).links_head;
    }
    while !le.is_null() {
        let le_safe;
        let le_pre;
        let le_next;
        let cpio_safe;
        unsafe {
            le_safe = &mut *le;
            le_pre = &mut (*(*le).previous);
            le_next = &mut (*(*le).next);
            cpio_safe = &mut *cpio;
        }
        if le_safe.dev == dev && le_safe.ino == ino {
            archive_entry_copy_hardlink_safe(entry, le_safe.name);
            le_safe.links = le_safe.links.wrapping_sub(1);

            if le_safe.links <= 0 as libc::c_int as libc::c_uint {
                if !le_safe.previous.is_null() {
                    le_pre.next = le_safe.next
                }
                if !le_safe.next.is_null() {
                    le_next.previous = le_safe.previous
                }
                if cpio_safe.links_head == le {
                    cpio_safe.links_head = le_safe.next
                }
                free_safe(le_safe.name as *mut libc::c_void);
                free_safe(le as *mut libc::c_void);
            }
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
        }
        le = le_safe.next
    }
    le = malloc_safe(::std::mem::size_of::<links_entry>() as libc::c_ulong) as *mut links_entry;
    let a_safe = unsafe { &mut *a };
    if le.is_null() {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_CPIO_DEFINED_PARAM.enomem,
            b"Out of memory adding file to list\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    let cpio_lh_safe;
    let cpio_safe;
    unsafe {
        cpio_safe = &mut *cpio;
        cpio_lh_safe = &mut (*(*cpio).links_head);
    }
    if !cpio_safe.links_head.is_null() {
        cpio_lh_safe.previous = le
    }
    let le_safe = unsafe { &mut *le };
    le_safe.next = cpio_safe.links_head;
    le_safe.previous = 0 as *mut links_entry;
    cpio_safe.links_head = le;
    le_safe.dev = dev;
    le_safe.ino = ino;
    le_safe.links = archive_entry_nlink_safe(entry).wrapping_sub(1 as libc::c_int as libc::c_uint);
    le_safe.name = strdup_safe(archive_entry_pathname_safe(entry));
    if le_safe.name.is_null() {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_CPIO_DEFINED_PARAM.enomem,
            b"Out of memory adding file to list\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
