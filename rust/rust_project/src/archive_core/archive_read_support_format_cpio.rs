use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

use super::archive_string::archive_string_default_conversion_for_read;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cpio {
    pub magic: i32,
    pub read_header: Option<
        unsafe fn(
            _: *mut archive_read,
            _: *mut cpio,
            _: *mut archive_entry,
            _: *mut size_t,
            _: *mut size_t,
        ) -> i32,
    >,
    pub links_head: *mut links_entry,
    pub entry_bytes_remaining: int64_t,
    pub entry_bytes_unconsumed: int64_t,
    pub entry_offset: int64_t,
    pub entry_padding: int64_t,
    pub opt_sconv: *mut archive_string_conv,
    pub sconv_default: *mut archive_string_conv,
    pub init_default_conversion: i32,
    pub option_pwb: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct links_entry {
    pub next: *mut links_entry,
    pub previous: *mut links_entry,
    pub links: u32,
    pub dev: dev_t,
    pub ino: int64_t,
    pub name: *mut u8,
}

#[no_mangle]
pub fn archive_read_support_format_cpio(_a: *mut archive) -> i32 {
    let a: *mut archive_read = _a as *mut archive_read;
    let cpio: *mut cpio;
    let r: i32;
    let magic_test: i32 = unsafe {
        __archive_check_magic_safe(
            _a,
            ARCHIVE_CPIO_DEFINED_PARAM.archive_read_magic,
            ARCHIVE_CPIO_DEFINED_PARAM.archive_state_new,
            b"archive_read_support_format_cpio\x00" as *const u8,
        )
    };
    if magic_test == ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    cpio = unsafe { calloc_safe(1, ::std::mem::size_of::<cpio>() as u64) } as *mut cpio;
    if cpio.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_CPIO_DEFINED_PARAM.enomem,
            b"Can\'t allocate cpio data\x00" as *const u8
        );
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    unsafe {
        (*cpio).magic = ARCHIVE_CPIO_DEFINED_PARAM.cpio_magic;
    }
    r = unsafe {
        __archive_read_register_format_safe(
            a,
            cpio as *mut (),
            b"cpio\x00" as *const u8,
            Some(archive_read_format_cpio_bid as unsafe fn(_: *mut archive_read, _: i32) -> i32),
            Some(
                archive_read_format_cpio_options
                    as unsafe fn(_: *mut archive_read, _: *const u8, _: *const u8) -> i32,
            ),
            Some(
                archive_read_format_cpio_read_header
                    as unsafe fn(_: *mut archive_read, _: *mut archive_entry) -> i32,
            ),
            Some(
                archive_read_format_cpio_read_data
                    as unsafe fn(
                        _: *mut archive_read,
                        _: *mut *const (),
                        _: *mut size_t,
                        _: *mut int64_t,
                    ) -> i32,
            ),
            Some(archive_read_format_cpio_skip as unsafe fn(_: *mut archive_read) -> i32),
            None,
            Some(archive_read_format_cpio_cleanup as unsafe fn(_: *mut archive_read) -> i32),
            None,
            None,
        )
    };
    if r != ARCHIVE_CPIO_DEFINED_PARAM.archive_ok {
        unsafe { free_safe(cpio as *mut ()) };
    }
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}

fn archive_read_format_cpio_bid(a: *mut archive_read, best_bid: i32) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let cpio: *mut cpio;
    let mut bid: i32;
    /* UNUSED */
    cpio = unsafe { (*(*a).format).data as *mut cpio };
    p = unsafe { __archive_read_ahead_safe(a, 6, 0 as *mut ssize_t) } as *const u8;
    if p.is_null() {
        return -1;
    }
    bid = 0;
    let cpio_safe = unsafe { &mut *cpio };
    if unsafe { memcmp_safe(p as *const (), b"070707\x00" as *const u8 as *const (), 6) } == 0 {
        /* ASCII cpio archive (odc, POSIX.1) */
        cpio_safe.read_header = Some(
            header_odc
                as unsafe fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> i32,
        );
        bid += 48
        /*
         * XXX TODO:  More verification; Could check that only octal
         * digits appear in appropriate header locations. XXX
         */
    } else if unsafe { memcmp_safe(p as *const (), b"070727\x00" as *const u8 as *const (), 6) }
        == 0
    {
        /* afio large ASCII cpio archive */
        cpio_safe.read_header = Some(
            header_odc
                as unsafe fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> i32,
        );
        bid += 48
        /*
         * XXX TODO:  More verification; Could check that almost hex
         * digits appear in appropriate header locations. XXX
         */
    } else if unsafe { memcmp_safe(p as *const (), b"070701\x00" as *const u8 as *const (), 6) }
        == 0
    {
        /* ASCII cpio archive (SVR4 without CRC) */
        cpio_safe.read_header = Some(
            header_newc
                as unsafe fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> i32,
        );
        bid += 48
        /*
         * XXX TODO:  More verification; Could check that only hex
         * digits appear in appropriate header locations. XXX
         */
    } else if unsafe { memcmp_safe(p as *const (), b"070702\x00" as *const u8 as *const (), 6) }
        == 0
    {
        /* ASCII cpio archive (SVR4 with CRC) */
        /* XXX TODO: Flag that we should check the CRC. XXX */
        cpio_safe.read_header = Some(
            header_newc
                as unsafe fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> i32,
        );
        bid += 48
        /*
         * XXX TODO:  More verification; Could check that only hex
         * digits appear in appropriate header locations. XXX
         */
    } else if unsafe { *p.offset(0) as i32 * 256 as i32 + *p.offset(1) as i32 == 0o70707 as i32 } {
        /* big-endian binary cpio archives */
        cpio_safe.read_header = Some(
            header_bin_be
                as unsafe fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> i32,
        );
        bid += 16
        /* Is more verification possible here? */
    } else if unsafe { *p.offset(0) as i32 + *p.offset(1) as i32 * 256 as i32 == 0o70707 as i32 } {
        /* little-endian binary cpio archives */
        cpio_safe.read_header = Some(
            header_bin_le
                as unsafe fn(
                    _: *mut archive_read,
                    _: *mut cpio,
                    _: *mut archive_entry,
                    _: *mut size_t,
                    _: *mut size_t,
                ) -> i32,
        );
        bid += 16
        /* Is more verification possible here? */
    } else {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_warn;
    }
    return bid;
}

fn archive_read_format_cpio_options(a: *mut archive_read, key: *const u8, val: *const u8) -> i32 {
    let mut cpio: *mut cpio;
    let mut ret: i32 = ARCHIVE_CPIO_DEFINED_PARAM.archive_failed;
    let cpio_safe;
    let a_safe;
    unsafe {
        cpio = (*(*a).format).data as *mut cpio;
        cpio_safe = &mut *cpio;
        a_safe = &mut *a;
    }
    if unsafe { strcmp_safe(key, b"compat-2x\x00" as *const u8) } == 0 {
        /* Handle filenames as libarchive 2.x */
        cpio_safe.init_default_conversion = if !val.is_null() { 1 } else { 0 };
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
    } else {
        if unsafe { strcmp_safe(key, b"hdrcharset\x00" as *const u8) } == 0 {
            if unsafe { val.is_null() || *val.offset(0) as i32 == 0 } {
                archive_set_error_safe!(
                    &mut a_safe.archive as *mut archive,
                    ARCHIVE_CPIO_DEFINED_PARAM.archive_errno_misc,
                    b"cpio: hdrcharset option needs a character-set name\x00" as *const u8
                        as *const u8
                );
            } else {
                cpio_safe.opt_sconv = unsafe {
                    archive_string_conversion_from_charset_safe(&mut a_safe.archive, val, 0)
                };
                if !cpio_safe.opt_sconv.is_null() {
                    ret = ARCHIVE_CPIO_DEFINED_PARAM.archive_ok
                } else {
                    ret = ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal
                }
            }
            return ret;
        } else {
            if unsafe { strcmp_safe(key, b"pwb\x00" as *const u8) } == 0 {
                if unsafe { !val.is_null() && *val.offset(0) as i32 != 0 } {
                    cpio_safe.option_pwb = 1
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

fn archive_read_format_cpio_read_header(a: *mut archive_read, entry: *mut archive_entry) -> i32 {
    let cpio: *mut cpio;
    let h: *const ();
    let hl: *const ();
    let mut sconv: *mut archive_string_conv;
    let mut namelength: size_t = 0;
    let mut name_pad: size_t = 0;
    let mut r: i32;
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
                unsafe { archive_string_default_conversion_for_read(&mut a_safe.archive) };
            cpio_safe.init_default_conversion = 1
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
    h = unsafe { __archive_read_ahead_safe(a, namelength + name_pad, 0 as *mut ssize_t) };
    if h == 0 as *mut () {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    if unsafe { _archive_entry_copy_pathname_l_safe(entry, h as *const u8, namelength, sconv) } != 0
    {
        if err_loc_safe == ARCHIVE_CPIO_DEFINED_PARAM.enomem {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_CPIO_DEFINED_PARAM.enomem,
                b"Can\'t allocate memory for Pathname\x00" as *const u8
            );
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_CPIO_DEFINED_PARAM.archive_errno_file_format,
            b"Pathname can\'t be converted from %s to current locale.\x00" as *const u8
                as *const u8,
            archive_string_conversion_charset_name_safe(sconv)
        );
        r = ARCHIVE_CPIO_DEFINED_PARAM.archive_warn
    }
    cpio_safe.entry_offset = 0;
    unsafe { __archive_read_consume_safe(a, (namelength + name_pad) as int64_t) };
    /* If this is a symlink, read the link contents. */
    if unsafe { archive_entry_filetype_safe(entry) } == ARCHIVE_CPIO_DEFINED_PARAM.ae_iflnk {
        if cpio_safe.entry_bytes_remaining > (1024 as i32 * 1024 as i32) as i64 {
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_CPIO_DEFINED_PARAM.enomem,
                b"Rejecting malformed cpio archive: symlink contents exceed 1 megabyte\x00"
                    as *const u8
            );
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        hl = unsafe {
            __archive_read_ahead_safe(
                a,
                cpio_safe.entry_bytes_remaining as size_t,
                0 as *mut ssize_t,
            )
        };
        if hl == 0 as *mut () {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        if unsafe {
            _archive_entry_copy_symlink_l_safe(
                entry,
                hl as *const u8,
                cpio_safe.entry_bytes_remaining as size_t,
                sconv,
            )
        } != 0
        {
            if err_loc_safe == ARCHIVE_CPIO_DEFINED_PARAM.enomem {
                archive_set_error_safe!(
                    &mut a_safe.archive as *mut archive,
                    ARCHIVE_CPIO_DEFINED_PARAM.enomem,
                    b"Can\'t allocate memory for Linkname\x00" as *const u8
                );
                return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
            }
            archive_set_error_safe!(
                &mut a_safe.archive as *mut archive,
                ARCHIVE_CPIO_DEFINED_PARAM.archive_errno_file_format,
                b"Linkname can\'t be converted from %s to current locale.\x00" as *const u8
                    as *const u8,
                archive_string_conversion_charset_name_safe(sconv)
            );
            r = ARCHIVE_CPIO_DEFINED_PARAM.archive_warn
        }
        unsafe { __archive_read_consume_safe(a, cpio_safe.entry_bytes_remaining) };
        cpio_safe.entry_bytes_remaining = 0
    }
    /* XXX TODO: If the full mode is 0160200, then this is a Solaris
     * ACL description for the following entry.  Read this body
     * and parse it as a Solaris-style ACL, then read the next
     * header.  XXX */
    /* Compare name to "TRAILER!!!" to test for end-of-archive. */
    if namelength == 11
        && unsafe { strncmp_safe(h as *const u8, b"TRAILER!!!\x00" as *const u8, 11) } == 0
    {
        /* TODO: Store file location of start of block. */
        unsafe { archive_clear_error_safe(&mut a_safe.archive) };
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_eof;
    }
    /* Detect and record hardlinks to previously-extracted entries. */
    if unsafe { record_hardlink(a, cpio, entry) } != ARCHIVE_CPIO_DEFINED_PARAM.archive_ok {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    return r;
}
fn archive_read_format_cpio_read_data(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let mut bytes_read: ssize_t = 0;
    let cpio: *mut cpio;
    let cpio_safe;
    unsafe {
        cpio = (*(*a).format).data as *mut cpio;
        cpio_safe = &mut *cpio;
    }
    if cpio_safe.entry_bytes_unconsumed != 0 {
        unsafe { __archive_read_consume_safe(a, cpio_safe.entry_bytes_unconsumed) };
        cpio_safe.entry_bytes_unconsumed = 0
    }
    let size_safe;
    let offset_safe;
    let buff_safe;
    unsafe {
        size_safe = &mut *size;
        offset_safe = &mut *offset;
        buff_safe = &mut *buff;
    }
    if cpio_safe.entry_bytes_remaining > 0 {
        *buff_safe = unsafe { __archive_read_ahead_safe(a, 1, &mut bytes_read) };
        if bytes_read <= 0 {
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
        if cpio_safe.entry_padding
            != unsafe { __archive_read_consume_safe(a, cpio_safe.entry_padding) }
        {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        cpio_safe.entry_padding = 0;
        *buff_safe = 0 as *const ();
        *size_safe = 0;
        *offset_safe = cpio_safe.entry_offset;
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_eof;
    };
}

fn archive_read_format_cpio_skip(a: *mut archive_read) -> i32 {
    let safe_a = unsafe { &mut *a };
    let safe_c = unsafe { &mut *((*(safe_a).format).data as *mut cpio) };
    let to_skip: int64_t =
        safe_c.entry_bytes_remaining + safe_c.entry_padding + safe_c.entry_bytes_unconsumed;
    if to_skip != unsafe { __archive_read_consume_safe(a, to_skip) } {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    safe_c.entry_bytes_remaining = 0;
    safe_c.entry_padding = 0;
    safe_c.entry_bytes_unconsumed = 0;
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
/*
 * Skip forward to the next cpio newc header by searching for the
 * 07070[12] string.  This should be generalized and merged with
 * find_odc_header below.
 */
fn is_hex(mut p: *const u8, mut len: size_t) -> i32 {
    let safe_p = unsafe { &*p };
    loop {
        let fresh0 = len;
        len = len - 1;
        if !(fresh0 > 0) {
            break;
        }
        if *safe_p as i32 >= '0' as i32 && *safe_p as i32 <= '9' as i32
            || *safe_p as i32 >= 'a' as i32 && *safe_p as i32 <= 'f' as i32
            || *safe_p as i32 >= 'A' as i32 && *safe_p as i32 <= 'F' as i32
        {
            unsafe { p = p.offset(1) };
        } else {
            return 0;
        }
    }
    return 1;
}
fn find_newc_header(a: *mut archive_read) -> i32 {
    let mut h: *const () = 0 as *const ();
    let mut p: *const u8 = 0 as *const u8;
    let mut q: *const u8 = 0 as *const u8;
    let mut skip: size_t = 0;
    let mut skipped: size_t = 0;
    let mut bytes: ssize_t = 0;
    loop {
        h = unsafe {
            __archive_read_ahead_safe(a, ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE, &mut bytes)
        };
        if h == 0 as *mut () {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        p = h as *const u8;
        q = unsafe { p.offset(bytes as isize) };
        /* Try the typical case first, then go into the slow search.*/
        if unsafe { memcmp_safe(b"07070\x00" as *const u8 as *const (), p as *const (), 5) } == 0
            && unsafe { (*p.offset(5) as i32 == '1' as i32 || *p.offset(5) as i32 == '2' as i32) }
            && is_hex(p, ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE) != 0
        {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
        }
        /*
         * Scan ahead until we find something that looks
         * like a newc header.
         */
        unsafe {
            while p.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE as isize) <= q {
                match *p.offset(5) as i32 {
                    49 | 50 => {
                        if memcmp_safe(b"07070\x00" as *const u8 as *const (), p as *const (), 5)
                            == 0
                            && is_hex(p, ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE) != 0
                        {
                            skip = p.offset_from(h as *const u8) as size_t;
                            __archive_read_consume_safe(a, skip as int64_t);
                            skipped = ((skipped as u64) + skip) as size_t;
                            if skipped > 0 {
                                archive_set_error_safe!(
                                    &mut (*a).archive as *mut archive,
                                    0,
                                    b"Skipped %d bytes before finding valid header\x00" as *const u8
                                        as *const u8,
                                    skipped as i32
                                );
                                return ARCHIVE_CPIO_DEFINED_PARAM.archive_warn;
                            }
                            return 0;
                        }
                        p = p.offset(2)
                    }
                    48 => p = p.offset(1),
                    _ => p = p.offset(6),
                }
            }
        }
        skip = unsafe { p.offset_from(h as *const u8) as size_t };
        unsafe { __archive_read_consume_safe(a, skip as int64_t) };
        skipped = ((skipped as u64) + skip) as size_t
    }
}

fn header_newc(
    a: *mut archive_read,
    cpio: *mut cpio,
    entry: *mut archive_entry,
    namelength: *mut size_t,
    name_pad: *mut size_t,
) -> i32 {
    let mut h: *const () = 0 as *const ();
    let mut header: *const u8 = 0 as *const u8;
    let mut r: i32;
    r = find_newc_header(a);
    if r < ARCHIVE_CPIO_DEFINED_PARAM.archive_warn {
        return r;
    }
    /* Read fixed-size portion of header. */
    h = unsafe {
        __archive_read_ahead_safe(
            a,
            ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE,
            0 as *mut ssize_t,
        )
    };
    if h == 0 as *mut () {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    /* Parse out hex fields. */
    header = h as *const u8;
    let a_safe = unsafe { &mut *a };
    if unsafe {
        memcmp_safe(
            unsafe {
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MAGIC_OFFSET as isize) as *const ()
            },
            b"070701\x00" as *const u8 as *const (),
            6,
        )
    } == 0
    {
        a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_svr4_nocrc;
        a_safe.archive.archive_format_name = b"ASCII cpio (SVR4 with no CRC)\x00" as *const u8
    } else if unsafe {
        memcmp_safe(
            unsafe {
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MAGIC_OFFSET as isize) as *const ()
            },
            b"070702\x00" as *const u8 as *const (),
            6,
        )
    } == 0
    {
        a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_svr4_crc;
        a_safe.archive.archive_format_name = b"ASCII cpio (SVR4 with CRC)\x00" as *const u8
    }
    unsafe {
        archive_entry_set_devmajor(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_DEVMAJOR_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_DEVMAJOR_SIZE as u32,
            ) as dev_t,
        );
        archive_entry_set_devminor(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_DEVMINOR_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_DEVMINOR_SIZE as u32,
            ) as dev_t,
        );
        archive_entry_set_ino(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_INO_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_INO_SIZE as u32,
            ),
        );
        archive_entry_set_mode(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MODE_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MODE_SIZE as u32,
            ) as mode_t,
        );
        archive_entry_set_uid(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_UID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_UID_SIZE as u32,
            ),
        );
        archive_entry_set_gid(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_GID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_GID_SIZE as u32,
            ),
        );
        archive_entry_set_nlink(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_NLINK_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_NLINK_SIZE as u32,
            ) as u32,
        );
        archive_entry_set_rdevmajor(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_RDEVMAJOR_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_RDEVMAJOR_SIZE as u32,
            ) as dev_t,
        );
        archive_entry_set_rdevminor(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_RDEVMINOR_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_RDEVMINOR_SIZE as u32,
            ) as dev_t,
        );
        archive_entry_set_mtime(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MTIME_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.NEWC_MTIME_SIZE as u32,
            ),
            0,
        );
        *namelength = atol16(
            header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_NAMESIZE_OFFSET as isize),
            ARCHIVE_CPIO_DEFINED_PARAM.NEWC_NAMESIZE_SIZE as u32,
        ) as size_t;
        /* Pad name to 2 more than a multiple of 4. */
        *name_pad = 2 - (*namelength) & 3;
        /* Make sure that the padded name length fits into size_t. */
        if *name_pad > (ARCHIVE_CPIO_DEFINED_PARAM.size_max as u64) - (*namelength) {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_CPIO_DEFINED_PARAM.archive_errno_file_format,
                b"cpio archive has invalid namelength\x00" as *const u8
            );
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        /*
         * Note: entry_bytes_remaining is at least 64 bits and
         * therefore guaranteed to be big enough for a 33-bit file
         * size.
         */
        (*cpio).entry_bytes_remaining = atol16(
            header.offset(ARCHIVE_CPIO_DEFINED_PARAM.NEWC_FILESIZE_OFFSET as isize),
            ARCHIVE_CPIO_DEFINED_PARAM.NEWC_FILESIZE_SIZE as u32,
        );
    }
    let cpio_safe = unsafe { &mut *cpio };
    unsafe { archive_entry_set_size_safe(entry, cpio_safe.entry_bytes_remaining) };
    /* Pad file contents to a multiple of 4. */
    cpio_safe.entry_padding = 3 & -cpio_safe.entry_bytes_remaining;
    unsafe {
        __archive_read_consume_safe(a, ARCHIVE_CPIO_DEFINED_PARAM.NEWC_HEADER_SIZE as int64_t)
    };
    return r;
}
/*
 * Skip forward to the next cpio odc header by searching for the
 * 070707 string.  This is a hand-optimized search that could
 * probably be easily generalized to handle all character-based
 * cpio variants.
 */
fn is_octal(mut p: *const u8, mut len: size_t) -> i32 {
    loop {
        let fresh1 = len;
        len = len - 1;
        if !(fresh1 > 0) {
            break;
        }
        let p_safe = unsafe { &*p };
        if (*p_safe as i32) < '0' as i32 || *p_safe as i32 > '7' as i32 {
            return 0;
        }
        unsafe { p = p.offset(1) }
    }
    return 1;
}
fn is_afio_large(h: *const u8, len: size_t) -> i32 {
    if len < ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_HEADER_SIZE as u64 {
        return 0;
    }
    unsafe {
        if *h.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_INO_M_OFFSET as isize) as i32 != 'm' as i32
            || *h.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MTIME_N_OFFSET as isize) as i32
                != 'n' as i32
            || *h.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_XSIZE_S_OFFSET as isize) as i32
                != 's' as i32
            || *h.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_FILESIZE_C_OFFSET as isize) as i32
                != ':' as i32
        {
            return 0;
        }
        if is_hex(
            h.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_DEV_OFFSET as isize),
            (ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_INO_M_OFFSET
                - ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_DEV_OFFSET) as size_t,
        ) == 0
        {
            return 0;
        }
        if is_hex(
            h.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MODE_OFFSET as isize),
            (ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MTIME_N_OFFSET
                - ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MODE_OFFSET) as size_t,
        ) == 0
        {
            return 0;
        }
        if is_hex(
            h.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NAMESIZE_OFFSET as isize),
            (ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_XSIZE_S_OFFSET
                - ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NAMESIZE_OFFSET) as size_t,
        ) == 0
        {
            return 0;
        }
        if is_hex(
            h.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_FILESIZE_OFFSET as isize),
            ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_FILESIZE_SIZE as size_t,
        ) == 0
        {
            return 0;
        }
    }
    return 1;
}
fn find_odc_header(a: *mut archive_read) -> i32 {
    let mut h: *const () = 0 as *const ();
    let mut p: *const u8 = 0 as *const u8;
    let mut q: *const u8 = 0 as *const u8;
    let mut skip: size_t = 0;
    let mut skipped: size_t = 0;
    let mut bytes: ssize_t = 0;
    loop {
        h = unsafe { __archive_read_ahead_safe(a, 76, &mut bytes) };
        if h == 0 as *mut () {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
        }
        p = h as *const u8;
        unsafe {
            q = p.offset(bytes as isize);
        }
        /* Try the typical case first, then go into the slow search.*/
        if unsafe { memcmp_safe(b"070707\x00" as *const u8 as *const (), p as *const (), 6) } == 0
            && is_octal(p, ARCHIVE_CPIO_DEFINED_PARAM.ODC_HEADER_SIZE as size_t) != 0
        {
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
        }
        let a_safe = unsafe { &mut *a };
        if unsafe { memcmp_safe(b"070727\x00" as *const u8 as *const (), p as *const (), 6) } == 0
            && is_afio_large(p, bytes as size_t) != 0
        {
            a_safe.archive.archive_format =
                ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_afio_large;
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
        }
        /*
         * Scan ahead until we find something that looks
         * like an odc header.
         */
        unsafe {
            while p.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_HEADER_SIZE as isize) <= q {
                match *p.offset(5) as i32 {
                    55 => {
                        if memcmp_safe(b"070707\x00" as *const u8 as *const (), p as *const (), 6)
                            == 0
                            && is_octal(p, ARCHIVE_CPIO_DEFINED_PARAM.ODC_HEADER_SIZE as size_t)
                                != 0
                            || memcmp_safe(
                                b"070727\x00" as *const u8 as *const (),
                                p as *const (),
                                6,
                            ) == 0
                                && is_afio_large(p, q.offset_from(p) as size_t) != 0
                        {
                            skip = p.offset_from(h as *const u8) as size_t;
                            __archive_read_consume_safe(a, skip as int64_t);
                            skipped = ((skipped as u64) + skip) as size_t;
                            if *p.offset(4) as i32 == '2' as i32 {
                                (*a).archive.archive_format =
                                    ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_afio_large
                            }
                            if skipped > 0 {
                                archive_set_error_safe!(
                                    &mut (*a).archive as *mut archive,
                                    0,
                                    b"Skipped %d bytes before finding valid header\x00" as *const u8
                                        as *const u8,
                                    skipped as i32
                                );
                                return ARCHIVE_CPIO_DEFINED_PARAM.archive_warn;
                            }
                            return 0;
                        }
                        p = p.offset(2)
                    }
                    48 => p = p.offset(1),
                    _ => p = p.offset(6),
                }
            }
            skip = p.offset_from(h as *const u8) as size_t;
        }
        unsafe { __archive_read_consume_safe(a, skip as int64_t) };
        skipped = ((skipped as u64) + skip) as size_t
    }
}
fn header_odc(
    a: *mut archive_read,
    cpio: *mut cpio,
    entry: *mut archive_entry,
    namelength: *mut size_t,
    name_pad: *mut size_t,
) -> i32 {
    let mut h: *const () = 0 as *const ();
    let mut r: i32;
    let mut header: *const u8 = 0 as *const u8;
    let a_safe = unsafe { &mut *a };
    a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_posix;
    a_safe.archive.archive_format_name = b"POSIX octet-oriented cpio\x00" as *const u8;
    /* Find the start of the next header. */
    r = find_odc_header(a);
    if r < ARCHIVE_CPIO_DEFINED_PARAM.archive_warn {
        return r;
    }
    if a_safe.archive.archive_format == ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_afio_large {
        let r2: i32 = unsafe { header_afiol(a, cpio, entry, namelength, name_pad) };
        if r2 == ARCHIVE_CPIO_DEFINED_PARAM.archive_ok {
            return r;
        } else {
            return r2;
        }
    }
    /* Read fixed-size portion of header. */
    h = unsafe {
        __archive_read_ahead_safe(
            a,
            ARCHIVE_CPIO_DEFINED_PARAM.ODC_HEADER_SIZE as size_t,
            0 as *mut ssize_t,
        )
    };
    if h == 0 as *mut () {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    /* Parse out octal fields. */
    header = h as *const u8; /* No padding of filename. */
    unsafe {
        archive_entry_set_dev(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_DEV_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_DEV_SIZE as u32,
            ) as dev_t,
        );
        archive_entry_set_ino(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_INO_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_INO_SIZE as u32,
            ),
        );
        archive_entry_set_mode(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_MODE_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_MODE_SIZE as u32,
            ) as mode_t,
        );
        archive_entry_set_uid(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_UID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_UID_SIZE as u32,
            ),
        );
        archive_entry_set_gid(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_GID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_GID_SIZE as u32,
            ),
        );
        archive_entry_set_nlink(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_NLINK_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_NLINK_SIZE as u32,
            ) as u32,
        );
        archive_entry_set_rdev(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_RDEV_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_RDEV_SIZE as u32,
            ) as dev_t,
        );
        archive_entry_set_mtime(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_MTIME_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.ODC_MTIME_SIZE as u32,
            ),
            0,
        );
        *namelength = atol8(
            header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_NAMESIZE_OFFSET as isize),
            ARCHIVE_CPIO_DEFINED_PARAM.ODC_NAMESIZE_SIZE as u32,
        ) as size_t;
        *name_pad = 0;
        /*
         * Note: entry_bytes_remaining is at least 64 bits and
         * therefore guaranteed to be big enough for a 33-bit file
         * size.
         */
        (*cpio).entry_bytes_remaining = atol8(
            header.offset(ARCHIVE_CPIO_DEFINED_PARAM.ODC_FILESIZE_OFFSET as isize),
            ARCHIVE_CPIO_DEFINED_PARAM.ODC_FILESIZE_SIZE as u32,
        );
    }
    let cpio_safe = unsafe { &mut *cpio };
    unsafe { archive_entry_set_size_safe(entry, cpio_safe.entry_bytes_remaining) };
    cpio_safe.entry_padding = 0;
    unsafe {
        __archive_read_consume_safe(a, ARCHIVE_CPIO_DEFINED_PARAM.ODC_HEADER_SIZE as int64_t)
    };
    return r;
}
/*
 * NOTE: if a filename suffix is ".z", it is the file gziped by afio.
 * it would be nice that we can show uncompressed file size and we can
 * uncompressed file contents automatically, unfortunately we have nothing
 * to get a uncompressed file size while reading each header. It means
 * we also cannot uncompress file contents under our framework.
 */
fn header_afiol(
    a: *mut archive_read,
    cpio: *mut cpio,
    entry: *mut archive_entry,
    namelength: *mut size_t,
    name_pad: *mut size_t,
) -> i32 {
    let mut h: *const () = 0 as *const ();
    let mut header: *const u8 = 0 as *const u8;
    let a_safe = unsafe { &mut *a };
    a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_afio_large;
    a_safe.archive.archive_format_name = b"afio large ASCII\x00" as *const u8;
    /* Read fixed-size portion of header. */
    h = unsafe {
        __archive_read_ahead_safe(
            a,
            ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_HEADER_SIZE as size_t,
            0 as *mut ssize_t,
        )
    };
    if h == 0 as *mut () {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    /* Parse out octal fields. */
    header = h as *const u8; /* No padding of filename. */
    unsafe {
        archive_entry_set_dev(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_DEV_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_DEV_SIZE as u32,
            ) as dev_t,
        );
        archive_entry_set_ino(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_INO_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_INO_SIZE as u32,
            ),
        );
        archive_entry_set_mode(
            entry,
            atol8(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MODE_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MODE_SIZE as u32,
            ) as mode_t,
        );
        archive_entry_set_uid(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_UID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_UID_SIZE as u32,
            ),
        );
        archive_entry_set_gid(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_GID_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_GID_SIZE as u32,
            ),
        );
        archive_entry_set_nlink(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NLINK_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NLINK_SIZE as u32,
            ) as u32,
        );
        archive_entry_set_rdev(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_RDEV_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_RDEV_SIZE as u32,
            ) as dev_t,
        );
        archive_entry_set_mtime(
            entry,
            atol16(
                header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MTIME_OFFSET as isize),
                ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_MTIME_SIZE as u32,
            ),
            0,
        );
        *namelength = atol16(
            header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NAMESIZE_OFFSET as isize),
            ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_NAMESIZE_SIZE as u32,
        ) as size_t;
        *name_pad = 0;
        (*cpio).entry_bytes_remaining = atol16(
            header.offset(ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_FILESIZE_OFFSET as isize),
            ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_FILESIZE_SIZE as u32,
        );
    }
    let cpio_safe = unsafe { &mut *cpio };
    unsafe { archive_entry_set_size_safe(entry, cpio_safe.entry_bytes_remaining) };
    cpio_safe.entry_padding = 0;
    unsafe {
        __archive_read_consume_safe(a, ARCHIVE_CPIO_DEFINED_PARAM.AFIOL_HEADER_SIZE as int64_t)
    };
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
fn header_bin_le(
    a: *mut archive_read,
    cpio: *mut cpio,
    entry: *mut archive_entry,
    namelength: *mut size_t,
    name_pad: *mut size_t,
) -> i32 {
    let mut h: *const () = 0 as *const ();
    let mut header: *const u8 = 0 as *const u8;
    let a_safe = unsafe { &mut *a };
    a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_bin_le;
    a_safe.archive.archive_format_name = b"cpio (little-endian binary)\x00" as *const u8;
    /* Read fixed-size portion of header. */
    h = unsafe {
        __archive_read_ahead_safe(
            a,
            ARCHIVE_CPIO_DEFINED_PARAM.BIN_HEADER_SIZE as size_t,
            0 as *mut ssize_t,
        )
    };
    if h == 0 as *mut () {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            0,
            b"End of file trying to read next cpio header\x00" as *const u8
        );
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    /* Parse out binary fields. */
    header = h as *const u8;
    unsafe {
        archive_entry_set_dev(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_DEV_OFFSET as isize) as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_DEV_OFFSET + 1 as i32) as isize)
                    as i32
                    * 256 as i32) as dev_t,
        );
        archive_entry_set_ino(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_INO_OFFSET as isize) as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_INO_OFFSET + 1 as i32) as isize)
                    as i32
                    * 256 as i32) as la_int64_t,
        );
        archive_entry_set_mode(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_MODE_OFFSET as isize) as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_MODE_OFFSET + 1 as i32) as isize)
                    as i32
                    * 256 as i32) as mode_t,
        );
        if (*cpio).option_pwb != 0 {
            /* turn off random bits left over from V6 inode */
            archive_entry_set_mode(entry, archive_entry_mode(entry) & 0o67777 as i32 as u32); /* Pad to even. */
            if archive_entry_mode(entry) & ARCHIVE_CPIO_DEFINED_PARAM.ae_ifmt as mode_t == 0 {
                archive_entry_set_mode(
                    entry,
                    archive_entry_mode(entry) | ARCHIVE_CPIO_DEFINED_PARAM.ae_ifreg as mode_t,
                ); /* Pad to even. */
            }
        }
        archive_entry_set_uid(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_UID_OFFSET as isize) as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_UID_OFFSET + 1 as i32) as isize)
                    as i32
                    * 256 as i32) as la_int64_t,
        );
        archive_entry_set_gid(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_GID_OFFSET as isize) as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_GID_OFFSET + 1 as i32) as isize)
                    as i32
                    * 256 as i32) as la_int64_t,
        );
        archive_entry_set_nlink(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_NLINK_OFFSET as isize) as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_NLINK_OFFSET + 1 as i32) as isize)
                    as i32
                    * 256 as i32) as u32,
        );
        archive_entry_set_rdev(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_RDEV_OFFSET as isize) as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_RDEV_OFFSET + 1 as i32) as isize)
                    as i32
                    * 256 as i32) as dev_t,
        );
        archive_entry_set_mtime(
            entry,
            le4(header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_MTIME_OFFSET as isize)),
            0,
        );
        *namelength = (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_NAMESIZE_OFFSET as isize)
            as i32
            + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_NAMESIZE_OFFSET + 1 as i32) as isize)
                as i32
                * 256 as i32) as size_t;
        *name_pad = *namelength & 1;
        (*cpio).entry_bytes_remaining =
            le4(header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_FILESIZE_OFFSET as isize));
    }
    let cpio_safe = unsafe { &mut *cpio };
    unsafe { archive_entry_set_size_safe(entry, cpio_safe.entry_bytes_remaining) };
    cpio_safe.entry_padding = cpio_safe.entry_bytes_remaining & 1;
    unsafe {
        __archive_read_consume_safe(a, ARCHIVE_CPIO_DEFINED_PARAM.BIN_HEADER_SIZE as int64_t)
    };
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
fn header_bin_be(
    a: *mut archive_read,
    cpio: *mut cpio,
    entry: *mut archive_entry,
    namelength: *mut size_t,
    name_pad: *mut size_t,
) -> i32 {
    let mut h: *const () = 0 as *const ();
    let mut header: *const u8 = 0 as *const u8;
    let a_safe = unsafe { &mut *a };
    a_safe.archive.archive_format = ARCHIVE_CPIO_DEFINED_PARAM.archive_format_cpio_bin_be;
    a_safe.archive.archive_format_name = b"cpio (big-endian binary)\x00" as *const u8;
    /* Read fixed-size portion of header. */
    h = unsafe {
        __archive_read_ahead_safe(
            a,
            ARCHIVE_CPIO_DEFINED_PARAM.BIN_HEADER_SIZE as size_t,
            0 as *mut ssize_t,
        )
    };
    if h == 0 as *mut () {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            0,
            b"End of file trying to read next cpio header\x00" as *const u8
        );
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    /* Parse out binary fields. */
    header = h as *const u8;
    unsafe {
        archive_entry_set_dev(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_DEV_OFFSET as isize) as i32 * 256 as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_DEV_OFFSET + 1 as i32) as isize)
                    as i32) as dev_t,
        );
        archive_entry_set_ino(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_INO_OFFSET as isize) as i32 * 256 as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_INO_OFFSET + 1 as i32) as isize)
                    as i32) as la_int64_t,
        );
        archive_entry_set_mode(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_MODE_OFFSET as isize) as i32
                * 256 as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_MODE_OFFSET + 1 as i32) as isize)
                    as i32) as mode_t,
        );
        if (*cpio).option_pwb != 0 {
            /* turn off random bits left over from V6 inode */
            archive_entry_set_mode(entry, archive_entry_mode(entry) & 0o67777 as i32 as u32); /* Pad to even. */
            if archive_entry_mode(entry) & ARCHIVE_CPIO_DEFINED_PARAM.ae_ifmt as mode_t == 0 {
                archive_entry_set_mode(
                    entry,
                    archive_entry_mode(entry) | ARCHIVE_CPIO_DEFINED_PARAM.ae_ifreg as mode_t,
                ); /* Pad to even. */
            }
        }
        archive_entry_set_uid(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_UID_OFFSET as isize) as i32 * 256 as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_UID_OFFSET + 1 as i32) as isize)
                    as i32) as la_int64_t,
        );
        archive_entry_set_gid(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_GID_OFFSET as isize) as i32 * 256 as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_GID_OFFSET + 1 as i32) as isize)
                    as i32) as la_int64_t,
        );
        archive_entry_set_nlink(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_NLINK_OFFSET as isize) as i32
                * 256 as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_NLINK_OFFSET + 1 as i32) as isize)
                    as i32) as u32,
        );
        archive_entry_set_rdev(
            entry,
            (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_RDEV_OFFSET as isize) as i32
                * 256 as i32
                + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_RDEV_OFFSET + 1 as i32) as isize)
                    as i32) as dev_t,
        );
        archive_entry_set_mtime(
            entry,
            be4(header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_MTIME_OFFSET as isize)),
            0,
        );
        *namelength = (*header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_NAMESIZE_OFFSET as isize)
            as i32
            * 256 as i32
            + *header.offset((ARCHIVE_CPIO_DEFINED_PARAM.BIN_NAMESIZE_OFFSET + 1 as i32) as isize)
                as i32) as size_t;
        *name_pad = *namelength & 1;
        (*cpio).entry_bytes_remaining =
            be4(header.offset(ARCHIVE_CPIO_DEFINED_PARAM.BIN_FILESIZE_OFFSET as isize));
    }
    let cpio_safe = unsafe { &mut *cpio };
    unsafe { archive_entry_set_size_safe(entry, cpio_safe.entry_bytes_remaining) };
    cpio_safe.entry_padding = cpio_safe.entry_bytes_remaining & 1;
    unsafe {
        __archive_read_consume_safe(a, ARCHIVE_CPIO_DEFINED_PARAM.BIN_HEADER_SIZE as int64_t)
    };
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
fn archive_read_format_cpio_cleanup(mut a: *mut archive_read) -> i32 {
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
        unsafe { free_safe(cpio_2_l_safe.name as *mut ()) };
        unsafe { free_safe(cpio_safe.links_head as *mut ()) };
        cpio_safe.links_head = lp
    }
    unsafe { free_safe(cpio as *mut ()) };
    a_safe.data = 0 as *mut ();
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
fn le4(mut p: *const u8) -> int64_t {
    return (unsafe { *p.offset(0) as i32 } << 16) as i64
        + (unsafe { *p.offset(1) as int64_t } << 24)
        + (unsafe { *p.offset(2) as i32 } << 0) as i64
        + (unsafe { *p.offset(3) as i32 } << 8) as i64;
}
fn be4(mut p: *const u8) -> int64_t {
    return (unsafe { *p.offset(0) as int64_t } << 24)
        + (unsafe { *p.offset(1) as i32 } << 16) as i64
        + (unsafe { *p.offset(2) as i32 } << 8) as i64
        + unsafe { *p.offset(3) } as i64;
}
/*
 * Note that this implementation does not (and should not!) obey
 * locale settings; you cannot simply substitute strtol here, since
 * it does obey locale.
 */
fn atol8(mut p: *const u8, mut char_cnt: u32) -> int64_t {
    let mut l: int64_t;
    let mut digit: i32;
    l = 0;
    loop {
        let fresh2 = char_cnt;
        char_cnt = char_cnt - 1;
        if !(fresh2 > 0) {
            break;
        }
        let p_safe = unsafe { &*p };
        if *p_safe as i32 >= '0' as i32 && *p_safe as i32 <= '7' as i32 {
            digit = *p_safe as i32 - '0' as i32
        } else {
            return l;
        }
        unsafe {
            p = p.offset(1);
        }
        l <<= 3;
        l |= digit as i64
    }
    return l;
}
fn atol16(mut p: *const u8, mut char_cnt: u32) -> int64_t {
    let mut l: int64_t;
    let mut digit: i32;
    l = 0;
    loop {
        let fresh3 = char_cnt;
        char_cnt = char_cnt - 1;
        if !(fresh3 > 0) {
            break;
        }
        unsafe {
            if *p as i32 >= 'a' as i32 && *p as i32 <= 'f' as i32 {
                digit = *p as i32 - 'a' as i32 + 10 as i32
            } else if *p as i32 >= 'A' as i32 && *p as i32 <= 'F' as i32 {
                digit = *p as i32 - 'A' as i32 + 10 as i32
            } else if *p as i32 >= '0' as i32 && *p as i32 <= '9' as i32 {
                digit = *p as i32 - '0' as i32
            } else {
                return l;
            }

            p = p.offset(1);
        }
        l <<= 4;
        l |= digit as i64
    }
    return l;
}
fn record_hardlink(a: *mut archive_read, cpio: *mut cpio, entry: *mut archive_entry) -> i32 {
    let mut le: *mut links_entry = 0 as *mut links_entry;
    let dev: dev_t;
    let ino: int64_t;
    if unsafe { archive_entry_nlink_safe(entry) } <= 1 {
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
    }
    dev = unsafe { archive_entry_dev_safe(entry) };
    ino = unsafe { archive_entry_ino64_safe(entry) };
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
            unsafe { archive_entry_copy_hardlink_safe(entry, le_safe.name) };
            le_safe.links = le_safe.links - 1;

            if le_safe.links <= 0 as u32 {
                if !le_safe.previous.is_null() {
                    le_pre.next = le_safe.next
                }
                if !le_safe.next.is_null() {
                    le_next.previous = le_safe.previous
                }
                if cpio_safe.links_head == le {
                    cpio_safe.links_head = le_safe.next
                }
                unsafe { free_safe(le_safe.name as *mut ()) };
                unsafe { free_safe(le as *mut ()) };
            }
            return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
        }
        le = le_safe.next
    }
    le = unsafe { malloc_safe(::std::mem::size_of::<links_entry>() as u64) } as *mut links_entry;
    let a_safe = unsafe { &mut *a };
    if le.is_null() {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_CPIO_DEFINED_PARAM.enomem,
            b"Out of memory adding file to list\x00" as *const u8
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
    le_safe.links = unsafe { archive_entry_nlink_safe(entry) - 1 };
    le_safe.name = unsafe { strdup_safe(archive_entry_pathname_safe(entry)) };
    if le_safe.name.is_null() {
        archive_set_error_safe!(
            &mut a_safe.archive as *mut archive,
            ARCHIVE_CPIO_DEFINED_PARAM.enomem,
            b"Out of memory adding file to list\x00" as *const u8
        );
        return ARCHIVE_CPIO_DEFINED_PARAM.archive_fatal;
    }
    return ARCHIVE_CPIO_DEFINED_PARAM.archive_ok;
}
