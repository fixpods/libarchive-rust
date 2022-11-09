use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;
#[no_mangle]
pub unsafe extern "C" fn archive_read_support_format_ar(mut _a: *mut archive) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut ar: *mut ar = 0 as *mut ar;
    let mut r: i32 = 0;
    let mut safe_a = unsafe { &mut *a };
    let mut magic_test: i32 = __archive_check_magic_safe(
        _a,
        ARCHIVE_AR_DEFINED_PARAM.archive_read_magic,
        ARCHIVE_AR_DEFINED_PARAM.archive_state_new,
        b"archive_read_support_format_ar\x00" as *const u8 as *const i8,
    );
    if magic_test == ARCHIVE_AR_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
    }
    ar = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<ar>() as u64,
        )
    } as *mut ar;
    if ar.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            12 as i32,
            b"Can\'t allocate ar data\x00" as *const u8 as *const i8
        );
        return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
    }
    unsafe {
        (*ar).strtab = 0 as *mut i8;
        r = __archive_read_register_format(
            a,
            ar as *mut (),
            b"ar\x00" as *const u8 as *const i8,
            Some(
                archive_read_format_ar_bid
                    as unsafe extern "C" fn(_: *mut archive_read, _: i32) -> i32,
            ),
            None,
            Some(
                archive_read_format_ar_read_header
                    as unsafe extern "C" fn(
                        _: *mut archive_read,
                        _: *mut archive_entry,
                    ) -> i32,
            ),
            Some(
                archive_read_format_ar_read_data
                    as unsafe extern "C" fn(
                        _: *mut archive_read,
                        _: *mut *const (),
                        _: *mut size_t,
                        _: *mut int64_t,
                    ) -> i32,
            ),
            Some(
                archive_read_format_ar_skip
                    as unsafe extern "C" fn(_: *mut archive_read) -> i32,
            ),
            None,
            Some(
                archive_read_format_ar_cleanup
                    as unsafe extern "C" fn(_: *mut archive_read) -> i32,
            ),
            None,
            None,
        );
    }

    if r != ARCHIVE_AR_DEFINED_PARAM.archive_ok {
        unsafe { free(ar as *mut ()) };
        return r;
    }
    return ARCHIVE_AR_DEFINED_PARAM.archive_ok;
}

unsafe extern "C" fn archive_read_format_ar_cleanup(mut a: *mut archive_read) -> i32 {
    let mut safe_a = unsafe { &mut *a };
    let mut ar: *mut ar = 0 as *mut ar;
    ar = unsafe { (*(*a).format).data as *mut ar };
    unsafe { free((*ar).strtab as *mut ()) };
    unsafe { free(ar as *mut ()) };
    unsafe { (*safe_a.format).data = 0 as *mut () };
    return ARCHIVE_AR_DEFINED_PARAM.archive_ok;
}

unsafe extern "C" fn archive_read_format_ar_bid(
    mut a: *mut archive_read,
    mut best_bid: i32,
) -> i32 {
    let mut h: *const () = 0 as *const ();
    /* UNUSED */
    /*
     * Verify the 8-byte file signature.
     * TODO: Do we need to check more than this?
     */
    h = unsafe { __archive_read_ahead(a, 8 as i32 as size_t, 0 as *mut ssize_t) }; /* Used to hold parsed numbers before validation. */
    if h == 0 as *mut () {
        return -(1 as i32);
    }
    if unsafe {
        memcmp(
            h,
            b"!<arch>\n\x00" as *const u8 as *const i8 as *const (),
            8 as i32 as u64,
        )
    } == 0 as i32
    {
        return 64 as i32;
    }
    return -(1 as i32);
}
unsafe extern "C" fn _ar_read_header(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
    mut ar: *mut ar,
    mut h: *const i8,
    mut unconsumed: *mut size_t,
) -> i32 {
    let mut filename: [i8; 17] = [0; 17];
    let mut number: uint64_t = 0;
    let mut bsd_name_length: size_t = 0;
    let mut entry_size: size_t = 0;
    let mut p: *mut i8 = 0 as *mut i8;
    let mut st: *mut i8 = 0 as *mut i8;
    let mut b: *const () = 0 as *const ();
    let mut r: i32 = 0;
    let safe_a = unsafe { &mut *a };
    let safe_ar = unsafe { &mut *ar };
    let safe_unconsumed = unsafe { &mut *unconsumed };
    /* Verify the magic signature on the file header. */
    if unsafe {
        strncmp(
            h.offset(58 as i32 as isize),
            b"`\n\x00" as *const u8 as *const i8,
            2 as i32 as u64,
        )
    } != 0 as i32
    {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_AR_DEFINED_PARAM.einval,
            b"Incorrect file header signature\x00" as *const u8 as *const i8
        );
        return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
    }
    /* Copy filename into work buffer. */
    unsafe {
        strncpy(
            filename.as_mut_ptr(),
            h.offset(ARCHIVE_AR_DEFINED_PARAM.ar_name_offset as isize),
            ARCHIVE_AR_DEFINED_PARAM.ar_name_size as u64,
        )
    };
    filename[ARCHIVE_AR_DEFINED_PARAM.ar_name_size as usize] = '\u{0}' as i32 as i8;
    /*
     * Guess the format variant based on the filename.
     */
    if safe_a.archive.archive_format == ARCHIVE_AR_DEFINED_PARAM.archive_format_ar {
        /* We don't already know the variant, so let's guess. */
        /*
         * Biggest clue is presence of '/': GNU starts special
         * filenames with '/', appends '/' as terminator to
         * non-special names, so anything with '/' should be
         * GNU except for BSD long filenames.
         */
        if unsafe {
            strncmp(
                filename.as_mut_ptr(),
                b"#1/\x00" as *const u8 as *const i8,
                3 as i32 as u64,
            )
        } == 0 as i32
        {
            safe_a.archive.archive_format = ARCHIVE_AR_DEFINED_PARAM.archive_format_ar_bsd
        } else if !unsafe { strchr(filename.as_mut_ptr(), '/' as i32).is_null() } {
            safe_a.archive.archive_format = ARCHIVE_AR_DEFINED_PARAM.archive_format_ar_gnu
        } else if unsafe {
            strncmp(
                filename.as_mut_ptr(),
                b"__.SYMDEF\x00" as *const u8 as *const i8,
                9 as i32 as u64,
            )
        } == 0 as i32
        {
            safe_a.archive.archive_format = ARCHIVE_AR_DEFINED_PARAM.archive_format_ar_bsd
        }
        /*
         * XXX Do GNU/SVR4 'ar' programs ever omit trailing '/'
         * if name exactly fills 16-byte field?  If so, we
         * can't assume entries without '/' are BSD. XXX
         */
    }
    /* Update format name from the code. */
    if safe_a.archive.archive_format == ARCHIVE_AR_DEFINED_PARAM.archive_format_ar_gnu {
        safe_a.archive.archive_format_name =
            b"ar (GNU/SVR4)\x00" as *const u8 as *const i8
    } else if safe_a.archive.archive_format == ARCHIVE_AR_DEFINED_PARAM.archive_format_ar_bsd {
        safe_a.archive.archive_format_name = b"ar (BSD)\x00" as *const u8 as *const i8
    } else {
        safe_a.archive.archive_format_name = b"ar\x00" as *const u8 as *const i8
    }
    /*
     * Remove trailing spaces from the filename.  GNU and BSD
     * variants both pad filename area out with spaces.
     * This will only be wrong if GNU/SVR4 'ar' implementations
     * omit trailing '/' for 16-char filenames and we have
     * a 16-char filename that ends in ' '.
     */
    unsafe {
        p = filename
            .as_mut_ptr()
            .offset(16 as i32 as isize)
            .offset(-(1 as i32 as isize));
        while p >= filename.as_mut_ptr() && *p as i32 == ' ' as i32 {
            *p = '\u{0}' as i32 as i8;
            p = p.offset(-1)
        }
    }
    /*
     * Remove trailing slash unless first character is '/'.
     * (BSD entries never end in '/', so this will only trim
     * GNU-format entries.  GNU special entries start with '/'
     * and are not terminated in '/', so we don't trim anything
     * that starts with '/'.)
     */
    if filename[0 as i32 as usize] as i32 != '/' as i32
        && p > filename.as_mut_ptr()
        && unsafe { *p as i32 } == '/' as i32
    {
        unsafe { *p = '\u{0}' as i32 as i8 }
    }
    if p < filename.as_mut_ptr() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_AR_DEFINED_PARAM.archive_errno_misc,
            b"Found entry with empty filename\x00" as *const u8 as *const i8
        );
        return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
    }
    /*
     * '//' is the GNU filename table.
     * Later entries can refer to names in this table.
     */
    if unsafe {
        strcmp(
            filename.as_mut_ptr(),
            b"//\x00" as *const u8 as *const i8,
        )
    } == 0 as i32
    {
        /* This must come before any call to _read_ahead. */
        ar_parse_common_header(ar, entry, h);
        unsafe {
            archive_entry_copy_pathname_safe(entry, filename.as_mut_ptr());
            archive_entry_set_filetype_safe(entry, ARCHIVE_AR_DEFINED_PARAM.ae_ifreg as mode_t);
        }

        /* Get the size of the filename table. */
        number = ar_atol10(
            unsafe { h.offset(ARCHIVE_AR_DEFINED_PARAM.ar_size_offset as isize) },
            ARCHIVE_AR_DEFINED_PARAM.ar_size_size as u32,
        );
        if number > SIZE_MAX as u64
            || number
                > (1024 as i32 * 1024 as i32 * 1024 as i32) as u64
        {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_AR_DEFINED_PARAM.archive_errno_misc,
                b"Filename table too large\x00" as *const u8 as *const i8
            );
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        entry_size = number;
        if entry_size == 0 as i32 as u64 {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_AR_DEFINED_PARAM.einval,
                b"Invalid string table\x00" as *const u8 as *const i8
            );
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        if !safe_ar.strtab.is_null() {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_AR_DEFINED_PARAM.einval,
                b"More than one string tables exist\x00" as *const u8 as *const i8
            );
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        /* Read the filename table into memory. */
        st = unsafe { malloc(entry_size) } as *mut i8;
        if st.is_null() {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_AR_DEFINED_PARAM.enomem,
                b"Can\'t allocate filename table buffer\x00" as *const u8 as *const i8
            );
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        safe_ar.strtab = st;
        safe_ar.strtab_size = entry_size;
        if *safe_unconsumed != 0 {
            unsafe { __archive_read_consume(a, *unconsumed as int64_t) };
            *safe_unconsumed = 0 as i32 as size_t
        }
        b = unsafe { __archive_read_ahead(a, entry_size, 0 as *mut ssize_t) };
        if b == 0 as *mut () {
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        unsafe {
            memcpy(st as *mut (), b, entry_size);
            __archive_read_consume(a, entry_size as int64_t);
        }
        /* All contents are consumed. */
        safe_ar.entry_bytes_remaining = 0 as i32 as int64_t;
        unsafe { archive_entry_set_size(entry, (*ar).entry_bytes_remaining) };
        /* Parse the filename table. */
        return ar_parse_gnu_filename_table(a);
    }
    /*
     * GNU variant handles long filenames by storing /<number>
     * to indicate a name stored in the filename table.
     * XXX TODO: Verify that it's all digits... Don't be fooled
     * by "/9xyz" XXX
     */
    if filename[0 as i32 as usize] as i32 == '/' as i32
        && filename[1 as i32 as usize] as i32 >= '0' as i32
        && filename[1 as i32 as usize] as i32 <= '9' as i32
    {
        number = ar_atol10(
            unsafe {
                h.offset(ARCHIVE_AR_DEFINED_PARAM.ar_name_offset as isize)
                    .offset(1 as i32 as isize)
            },
            (ARCHIVE_AR_DEFINED_PARAM.ar_name_size - 1 as i32) as u32,
        );
        /*
         * If we can't look up the real name, warn and return
         * the entry with the wrong name.
         */
        if safe_ar.strtab.is_null() || number >= safe_ar.strtab_size {
            unsafe {
                archive_set_error_safe!(
                    &mut safe_a.archive as *mut archive,
                    ARCHIVE_AR_DEFINED_PARAM.einval,
                    b"Can\'t find long filename for GNU/SVR4 archive entry\x00" as *const u8
                        as *const i8
                );
                archive_entry_copy_pathname_safe(entry, filename.as_mut_ptr())
            };
            /* Parse the time, owner, mode, size fields. */
            ar_parse_common_header(ar, entry, h);
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        unsafe {
            archive_entry_copy_pathname_safe(entry, &mut *(*ar).strtab.offset(number as isize))
        };
        /* Parse the time, owner, mode, size fields. */
        return ar_parse_common_header(ar, entry, h);
    }
    /*
     * BSD handles long filenames by storing "#1/" followed by the
     * length of filename as a decimal number, then prepends the
     * the filename to the file contents.
     */
    if unsafe {
        strncmp(
            filename.as_mut_ptr(),
            b"#1/\x00" as *const u8 as *const i8,
            3 as i32 as u64,
        )
    } == 0 as i32
    {
        /* Parse the time, owner, mode, size fields. */
        /* This must occur before _read_ahead is called again. */
        ar_parse_common_header(ar, entry, h);
        /* Parse the size of the name, adjust the file size. */
        number = ar_atol10(
            unsafe {
                h.offset(ARCHIVE_AR_DEFINED_PARAM.ar_name_offset as isize)
                    .offset(3 as i32 as isize)
            },
            (ARCHIVE_AR_DEFINED_PARAM.ar_name_size - 3 as i32) as u32,
        );
        /* Sanity check the filename length:
         *   = Must be <= SIZE_MAX - 1
         *   = Must be <= 1MB
         *   = Cannot be bigger than the entire entry
         */
        if number > (SIZE_MAX as u64).wrapping_sub(1 as i32 as u64)
            || number > (1024 as i32 * 1024 as i32) as u64
            || number as int64_t > (safe_ar).entry_bytes_remaining
        {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_AR_DEFINED_PARAM.archive_errno_misc,
                b"Bad input file size\x00" as *const u8 as *const i8
            );
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        bsd_name_length = number;
        (safe_ar).entry_bytes_remaining = ((safe_ar).entry_bytes_remaining as u64)
            .wrapping_sub(bsd_name_length) as int64_t
            as int64_t;
        /* Adjust file size reported to client. */
        unsafe { archive_entry_set_size(entry, (*ar).entry_bytes_remaining) };
        if *safe_unconsumed != 0 {
            unsafe { __archive_read_consume(a, *unconsumed as int64_t) };
            *safe_unconsumed = 0 as i32 as size_t
        }
        /* Read the long name into memory. */
        b = unsafe { __archive_read_ahead(a, bsd_name_length, 0 as *mut ssize_t) };
        if b == 0 as *mut () {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_AR_DEFINED_PARAM.archive_errno_misc,
                b"Truncated input file\x00" as *const u8 as *const i8
            );
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        /* Store it in the entry. */
        p = unsafe { malloc(bsd_name_length.wrapping_add(1 as i32 as u64)) }
            as *mut i8;
        if p.is_null() {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_AR_DEFINED_PARAM.archive_errno_misc,
                b"Can\'t allocate fname buffer\x00" as *const u8 as *const i8
            );
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        unsafe {
            strncpy(p, b as *const i8, bsd_name_length);
            *p.offset(bsd_name_length as isize) = '\u{0}' as i32 as i8;
            __archive_read_consume(a, bsd_name_length as int64_t);
            archive_entry_copy_pathname_safe(entry, p);
            free(p as *mut ())
        };
        return ARCHIVE_AR_DEFINED_PARAM.archive_ok;
    }
    /*
     * "/" is the SVR4/GNU archive symbol table.
     * "/SYM64/" is the SVR4/GNU 64-bit variant archive symbol table.
     */
    if unsafe {
        strcmp(
            filename.as_mut_ptr(),
            b"/\x00" as *const u8 as *const i8,
        )
    } == 0 as i32
        || unsafe {
            strcmp(
                filename.as_mut_ptr(),
                b"/SYM64/\x00" as *const u8 as *const i8,
            )
        } == 0 as i32
    {
        unsafe { archive_entry_copy_pathname_safe(entry, filename.as_mut_ptr()) };
        /* Parse the time, owner, mode, size fields. */
        r = ar_parse_common_header(ar, entry, h);
        /* Force the file type to a regular file. */
        unsafe {
            archive_entry_set_filetype_safe(entry, ARCHIVE_AR_DEFINED_PARAM.ae_ifreg as mode_t)
        };
        return r;
    }
    /*
     * "__.SYMDEF" is a BSD archive symbol table.
     */
    if unsafe {
        strcmp(
            filename.as_mut_ptr(),
            b"__.SYMDEF\x00" as *const u8 as *const i8,
        )
    } == 0 as i32
    {
        unsafe { archive_entry_copy_pathname_safe(entry, filename.as_mut_ptr()) };
        /* Parse the time, owner, mode, size fields. */
        return ar_parse_common_header(ar, entry, h);
    }
    /*
     * Otherwise, this is a standard entry.  The filename
     * has already been trimmed as much as possible, based
     * on our current knowledge of the format.
     */
    unsafe { archive_entry_copy_pathname_safe(entry, filename.as_mut_ptr()) };
    return ar_parse_common_header(ar, entry, h);
}
unsafe extern "C" fn archive_read_format_ar_read_header(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
) -> i32 {
    let mut ar: *mut ar = unsafe { (*(*a).format).data as *mut ar };
    let mut unconsumed: size_t = 0;
    let mut header_data: *const () = 0 as *const ();
    let mut ret: i32 = 0;
    let safe_ar = unsafe { &mut *ar };
    let safe_a = unsafe { &mut *a };
    if safe_ar.read_global_header == 0 {
        /*
         * We are now at the beginning of the archive,
         * so we need first consume the ar global header.
         */
        unsafe { __archive_read_consume(a, 8 as i32 as int64_t) };
        safe_ar.read_global_header = 1 as i32 as i8;
        /* Set a default format code for now. */
        safe_a.archive.archive_format = ARCHIVE_AR_DEFINED_PARAM.archive_format_ar
    }
    /* Read the header for the next file entry. */
    header_data =
        unsafe { __archive_read_ahead(a, 60 as i32 as size_t, 0 as *mut ssize_t) };
    if header_data == 0 as *mut () {
        /* Broken header. */
        return ARCHIVE_AR_DEFINED_PARAM.archive_eof;
    }
    unconsumed = 60 as i32 as size_t;
    ret = unsafe {
        _ar_read_header(
            a,
            entry,
            ar,
            header_data as *const i8,
            &mut unconsumed,
        )
    };
    if unconsumed != 0 {
        unsafe { __archive_read_consume(a, unconsumed as int64_t) };
    }
    return ret;
}
unsafe extern "C" fn ar_parse_common_header(
    mut ar: *mut ar,
    mut entry: *mut archive_entry,
    mut h: *const i8,
) -> i32 {
    let mut n: uint64_t = 0;
    let safe_ar = unsafe { &mut *ar };
    /* Copy remaining header */
    unsafe {
        archive_entry_set_filetype_safe(entry, ARCHIVE_AR_DEFINED_PARAM.ae_ifreg as mode_t);
        archive_entry_set_mtime(
            entry,
            ar_atol10(
                h.offset(ARCHIVE_AR_DEFINED_PARAM.ar_date_offset as isize),
                ARCHIVE_AR_DEFINED_PARAM.ar_date_size as u32,
            ) as time_t,
            0 as i64,
        );
        archive_entry_set_uid(
            entry,
            ar_atol10(
                h.offset(ARCHIVE_AR_DEFINED_PARAM.ar_uid_offset as isize),
                ARCHIVE_AR_DEFINED_PARAM.ar_uid_size as u32,
            ) as uid_t as la_int64_t,
        );
        archive_entry_set_gid(
            entry,
            ar_atol10(
                h.offset(ARCHIVE_AR_DEFINED_PARAM.ar_gid_offset as isize),
                ARCHIVE_AR_DEFINED_PARAM.ar_gid_size as u32,
            ) as gid_t as la_int64_t,
        );
        archive_entry_set_mode(
            entry,
            ar_atol8(
                h.offset(ARCHIVE_AR_DEFINED_PARAM.ar_mode_offset as isize),
                ARCHIVE_AR_DEFINED_PARAM.ar_mode_size as u32,
            ) as mode_t,
        );
        n = ar_atol10(
            h.offset(ARCHIVE_AR_DEFINED_PARAM.ar_size_offset as isize),
            ARCHIVE_AR_DEFINED_PARAM.ar_size_size as u32,
        )
    };
    safe_ar.entry_offset = 0 as i32 as int64_t;
    safe_ar.entry_padding = n.wrapping_rem(2 as i32 as u64) as int64_t;
    unsafe { archive_entry_set_size(entry, n as la_int64_t) };
    safe_ar.entry_bytes_remaining = n as int64_t;
    return ARCHIVE_AR_DEFINED_PARAM.archive_ok;
}
unsafe extern "C" fn archive_read_format_ar_read_data(
    mut a: *mut archive_read,
    mut buff: *mut *const (),
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) -> i32 {
    let mut bytes_read: ssize_t = 0;
    let mut ar: *mut ar = 0 as *mut ar;
    ar = unsafe { (*(*a).format).data as *mut ar };
    let safe_ar = unsafe { &mut *ar };
    let safe_a = unsafe { &mut *a };
    let safe_size = unsafe { &mut *size };
    let safe_offset = unsafe { &mut *offset };
    let safe_buff = unsafe { &mut *buff };
    if safe_ar.entry_bytes_unconsumed != 0 {
        unsafe { __archive_read_consume(a, (*ar).entry_bytes_unconsumed as int64_t) };
        safe_ar.entry_bytes_unconsumed = 0 as i32 as size_t
    }
    if safe_ar.entry_bytes_remaining > 0 as i32 as i64 {
        unsafe { *buff = __archive_read_ahead(a, 1 as i32 as size_t, &mut bytes_read) };
        if bytes_read == 0 as i32 as i64 {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                -(1 as i32),
                b"Truncated ar archive\x00" as *const u8 as *const i8
            );
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        if bytes_read < 0 as i32 as i64 {
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        if bytes_read > safe_ar.entry_bytes_remaining {
            bytes_read = safe_ar.entry_bytes_remaining
        }
        *safe_size = bytes_read as size_t;
        safe_ar.entry_bytes_unconsumed = bytes_read as size_t;
        *safe_offset = safe_ar.entry_offset;
        safe_ar.entry_offset += bytes_read;
        safe_ar.entry_bytes_remaining -= bytes_read;
        return ARCHIVE_AR_DEFINED_PARAM.archive_ok;
    } else {
        let mut skipped: int64_t = unsafe { __archive_read_consume(a, (*ar).entry_padding) };
        if skipped >= 0 as i32 as i64 {
            safe_ar.entry_padding -= skipped
        }
        if safe_ar.entry_padding != 0 {
            if skipped >= 0 as i32 as i64 {
                archive_set_error_safe!(
                    &mut safe_a.archive as *mut archive,
                    ARCHIVE_AR_DEFINED_PARAM.archive_errno_misc,
                    b"Truncated ar archive- failed consuming padding\x00" as *const u8
                        as *const i8
                );
            }
            return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
        }
        *safe_buff = 0 as *const ();
        *safe_size = 0 as i32 as size_t;
        *safe_offset = safe_ar.entry_offset;
        return ARCHIVE_AR_DEFINED_PARAM.archive_eof;
    };
}
unsafe extern "C" fn archive_read_format_ar_skip(mut a: *mut archive_read) -> i32 {
    let mut bytes_skipped: int64_t = 0;
    let mut ar: *mut ar = 0 as *mut ar;
    ar = unsafe { (*(*a).format).data as *mut ar };
    let safe_ar = unsafe { &mut *ar };
    bytes_skipped = unsafe {
        __archive_read_consume(
            a,
            (((*ar).entry_bytes_remaining + (*ar).entry_padding) as u64)
                .wrapping_add((*ar).entry_bytes_unconsumed) as int64_t,
        )
    };
    if bytes_skipped < 0 as i32 as i64 {
        return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
    }
    safe_ar.entry_bytes_remaining = 0 as i32 as int64_t;
    safe_ar.entry_bytes_unconsumed = 0 as i32 as size_t;
    safe_ar.entry_padding = 0 as i32 as int64_t;
    return ARCHIVE_AR_DEFINED_PARAM.archive_ok;
}
unsafe extern "C" fn ar_parse_gnu_filename_table(mut a: *mut archive_read) -> i32 {
    let mut current_block: u64;
    let mut ar: *mut ar = 0 as *mut ar;
    let mut p: *mut i8 = 0 as *mut i8;
    let mut size: size_t = 0;
    ar = unsafe { (*(*a).format).data as *mut ar };
    let ar_safe = unsafe { &mut *ar };
    let safe_a = unsafe { &mut *a };
    size = ar_safe.strtab_size;
    p = ar_safe.strtab;
    loop {
        if !(p < unsafe {
            ar_safe
                .strtab
                .offset(size as isize)
                .offset(-(1 as i32 as isize))
        }) {
            current_block = 13109137661213826276;
            break;
        }
        if unsafe { *p } as i32 == '/' as i32 {
            let fresh0 = p;
            unsafe { p = p.offset(1) };
            unsafe { *fresh0 = '\u{0}' as i32 as i8 };
            if unsafe { *p } as i32 != '\n' as i32 {
                current_block = 17886206266124083048;
                break;
            }
            unsafe { *p = '\u{0}' as i32 as i8 }
        }
        unsafe { p = p.offset(1) };
    }
    match current_block {
        13109137661213826276 =>
        /*
         * GNU ar always pads the table to an even size.
         * The pad character is either '\n' or '`'.
         */
        {
            if !(p != unsafe { ar_safe.strtab.offset(size as isize) }
                && unsafe { *p } as i32 != '\n' as i32
                && unsafe { *p } as i32 != '`' as i32)
            {
                /* Enforce zero termination. */
                unsafe {
                    *(ar_safe)
                        .strtab
                        .offset(size.wrapping_sub(1 as i32 as u64) as isize) =
                        '\u{0}' as i32 as i8
                }; /* Truncate on overflow. */
                return ARCHIVE_AR_DEFINED_PARAM.archive_ok;
            }
        }
        _ => {}
    } /* Truncate on overflow. */
    archive_set_error_safe!(
        &mut safe_a.archive as *mut archive,
        ARCHIVE_AR_DEFINED_PARAM.einval,
        b"Invalid string table\x00" as *const u8 as *const i8
    );
    unsafe { free(ar_safe.strtab as *mut ()) };
    ar_safe.strtab = 0 as *mut i8;
    return ARCHIVE_AR_DEFINED_PARAM.archive_fatal;
}
unsafe extern "C" fn ar_atol8(mut p: *const i8, mut char_cnt: u32) -> uint64_t {
    let mut l: uint64_t = 0;
    let mut limit: uint64_t = 0;
    let mut last_digit_limit: uint64_t = 0;
    let mut digit: u32 = 0;
    let mut base: u32 = 0;
    base = 8 as i32 as u32;
    limit = (SIZE_MAX).wrapping_div(base as u64);
    last_digit_limit = (SIZE_MAX).wrapping_rem(base as u64);

    while (unsafe { *p as i32 == ' ' as i32 }
        || unsafe { *p as i32 == '\t' as i32 })
        && {
            let fresh3 = char_cnt;
            char_cnt = char_cnt.wrapping_sub(1);
            (fresh3) > 0 as i32 as u32
        }
    {
        unsafe { p = p.offset(1) }
    }
    l = 0 as i32 as uint64_t;
    digit = unsafe { (*p as i32 - '0' as i32) as u32 };
    while unsafe { *p as i32 >= '0' as i32 } && digit < base && {
        let fresh4 = char_cnt;
        char_cnt = char_cnt.wrapping_sub(1);
        (fresh4) > 0 as i32 as u32
    } {
        if l > limit || l == limit && digit as u64 > last_digit_limit {
            l = SIZE_MAX;
            break;
        } else {
            l = l
                .wrapping_mul(base as u64)
                .wrapping_add(digit as u64);
            unsafe { p = p.offset(1) };
            digit = (unsafe { *p as i32 } - '0' as i32) as u32
        }
    }
    return l;
}

unsafe extern "C" fn ar_atol10(mut p: *const i8, mut char_cnt: u32) -> uint64_t {
    let mut l: uint64_t = 0;
    let mut limit: uint64_t = 0;
    let mut last_digit_limit: uint64_t = 0;
    let mut base: u32 = 0;
    let mut digit: u32 = 0;
    base = 10 as i32 as u32;
    limit = (SIZE_MAX).wrapping_div(base as u64);
    last_digit_limit = (SIZE_MAX).wrapping_rem(base as u64);

    while (unsafe { *p as i32 == ' ' as i32 }
        || unsafe { *p as i32 == '\t' as i32 })
        && {
            let fresh3 = char_cnt;
            char_cnt = char_cnt.wrapping_sub(1);
            (fresh3) > 0 as i32 as u32
        }
    {
        unsafe { p = p.offset(1) }
    }
    l = 0 as i32 as uint64_t;
    digit = unsafe { (*p as i32 - '0' as i32) as u32 };
    while unsafe { *p as i32 >= '0' as i32 } && digit < base && {
        let fresh4 = char_cnt;
        char_cnt = char_cnt.wrapping_sub(1);
        (fresh4) > 0 as i32 as u32
    } {
        if l > limit || l == limit && digit as u64 > last_digit_limit {
            l = SIZE_MAX;
            break;
        } else {
            l = l
                .wrapping_mul(base as u64)
                .wrapping_add(digit as u64);
            unsafe { p = p.offset(1) };
            digit = (unsafe { *p as i32 } - '0' as i32) as u32
        }
    }
    return l;
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_archive_read_format_ar_read_data(
    mut _a: *mut archive,
    mut buff: *mut *const (),
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut ar: *mut ar = 0 as *mut ar;
    ar = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<ar>() as u64,
        )
    } as *mut ar;
    (*ar).entry_bytes_remaining = 0 as int64_t;
    (*ar).entry_padding = 2147483647 as int64_t;
    (*(*a).format).data = ar as *mut ();
    archive_read_format_ar_read_data(a, buff, size, offset);
    (*ar).entry_bytes_remaining = 1 as int64_t;
    let mut archive_read_filter: *mut archive_read_filter = 0 as *mut archive_read_filter;
    archive_read_filter = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_read_filter>() as u64,
        )
    } as *mut archive_read_filter;
    (*archive_read_filter).client_avail = 10000 as size_t;
    (*archive_read_filter).end_of_file = 'a' as i8;
    archive_read_format_ar_read_data(a, buff, size, offset);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_archive_read_support_format_ar() {
    let mut archive_read: *mut archive_read = 0 as *mut archive_read;
    archive_read = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_read>() as u64,
        )
    } as *mut archive_read;
    (*archive_read).archive.magic = ARCHIVE_AR_DEFINED_PARAM.archive_read_magic;
    (*archive_read).archive.state = ARCHIVE_AR_DEFINED_PARAM.archive_state_new;
    archive_read_support_format_ar(&mut (*archive_read).archive as *mut archive);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test__ar_read_header(
    mut _a: *mut archive,
    mut entry: *mut archive_entry,
    mut h: *const i8,
    mut unconsumed: *mut size_t,
) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    (*a).archive.archive_format = ARCHIVE_AR_DEFINED_PARAM.archive_format_ar;
    let mut ar: *mut ar = 0 as *mut ar;
    ar = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<ar>() as u64,
        )
    } as *mut ar;
    _ar_read_header(a, entry, ar, h, unconsumed);
}
