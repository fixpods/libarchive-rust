use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

use super::archive_string::archive_string_default_conversion_for_read;

#[no_mangle]
pub unsafe fn archive_read_support_format_gnutar(mut a: *mut archive) -> i32 {
    let mut magic_test: i32 = __archive_check_magic_safe(
        a,
        ARCHIVE_TAR_DEFINED_PARAM.archive_read_magic,
        ARCHIVE_TAR_DEFINED_PARAM.archive_state_new,
        b"archive_read_support_format_gnutar\x00" as *const u8 as *const i8,
    );
    if magic_test == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    return archive_read_support_format_tar(a);
}
#[no_mangle]
pub unsafe fn archive_read_support_format_tar(mut _a: *mut archive) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut tar: *mut tar = 0 as *mut tar;
    let mut r: i32 = 0;
    let mut safe_a = unsafe { &mut *a };

    let mut magic_test: i32 = __archive_check_magic_safe(
        _a,
        ARCHIVE_TAR_DEFINED_PARAM.archive_read_magic,
        ARCHIVE_TAR_DEFINED_PARAM.archive_state_new,
        b"archive_read_support_format_tar\x00" as *const u8 as *const i8,
    );
    if magic_test == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    tar = calloc_safe(1 as i32 as u64, ::std::mem::size_of::<tar>() as u64) as *mut tar;
    let mut safe_tar = unsafe { &mut *tar };
    if tar.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_TAR_DEFINED_PARAM.enomem,
            b"Can\'t allocate tar data\x00" as *const u8 as *const i8
        );
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    match () {
        #[cfg(HAVE_COPYFILE_H)]
        _ => {
            safe_tar.process_mac_extensions = 1;
        }

        #[cfg(not(HAVE_COPYFILE_H))]
        _ => {}
    }
    r = __archive_read_register_format_safe(
        a,
        tar as *mut (),
        b"tar\x00" as *const u8 as *const i8,
        Some(archive_read_format_tar_bid as unsafe fn(_: *mut archive_read, _: i32) -> i32),
        Some(
            archive_read_format_tar_options
                as unsafe fn(_: *mut archive_read, _: *const i8, _: *const i8) -> i32,
        ),
        Some(
            archive_read_format_tar_read_header
                as unsafe fn(_: *mut archive_read, _: *mut archive_entry) -> i32,
        ),
        Some(
            archive_read_format_tar_read_data
                as unsafe fn(
                    _: *mut archive_read,
                    _: *mut *const (),
                    _: *mut size_t,
                    _: *mut int64_t,
                ) -> i32,
        ),
        Some(archive_read_format_tar_skip as unsafe fn(_: *mut archive_read) -> i32),
        None,
        Some(archive_read_format_tar_cleanup as unsafe fn(_: *mut archive_read) -> i32),
        None,
        None,
    );
    if r != ARCHIVE_TAR_DEFINED_PARAM.archive_ok {
        free_safe(tar as *mut ());
    }
    return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
}
unsafe fn archive_read_format_tar_cleanup(mut a: *mut archive_read) -> i32 {
    let mut tar: *mut tar = 0 as *mut tar;
    tar = unsafe { (*(*a).format).data as *mut tar };

    gnu_clear_sparse_list(tar);
    let mut safe_tar = unsafe { &mut *tar };
    archive_string_free_safe(&mut safe_tar.acl_text);
    archive_string_free_safe(&mut safe_tar.entry_pathname);
    archive_string_free_safe(&mut safe_tar.entry_pathname_override);
    archive_string_free_safe(&mut safe_tar.entry_linkpath);
    archive_string_free_safe(&mut safe_tar.entry_uname);
    archive_string_free_safe(&mut safe_tar.entry_gname);
    archive_string_free_safe(&mut safe_tar.line);
    archive_string_free_safe(&mut safe_tar.pax_global);
    archive_string_free_safe(&mut safe_tar.pax_header);
    archive_string_free_safe(&mut safe_tar.longname);
    archive_string_free_safe(&mut safe_tar.longlink);
    archive_string_free_safe(&mut safe_tar.localname);
    free_safe(tar as *mut ());
    unsafe { (*(*a).format).data = 0 as *mut () };
    return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
}
/*
 * Validate number field
 *
 * This has to be pretty lenient in order to accommodate the enormous
 * variety of tar writers in the world:
 *  = POSIX (IEEE Std 1003.1-1988) ustar requires octal values with leading
 *    zeros and allows fields to be terminated with space or null characters
 *  = Many writers use different termination (in particular, libarchive
 *    omits terminator bytes to squeeze one or two more digits)
 *  = Many writers pad with space and omit leading zeros
 *  = GNU tar and star write base-256 values if numbers are too
 *    big to be represented in octal
 *
 *  Examples of specific tar headers that we should support:
 *  = Perl Archive::Tar terminates uid, gid, devminor and devmajor with two
 *    null bytes, pads size with spaces and other numeric fields with zeroes
 *  = plexus-archiver prior to 2.6.3 (before switching to commons-compress)
 *    may have uid and gid fields filled with spaces without any octal digits
 *    at all and pads all numeric fields with spaces
 *
 * This should tolerate all variants in use.  It will reject a field
 * where the writer just left garbage after a trailing NUL.
 */
unsafe fn validate_number_field(mut p_field: *const i8, mut i_size: size_t) -> i32 {
    let mut marker: u8 = unsafe { *p_field.offset(0 as i32 as isize) as u8 };
    if marker as i32 == 128 as i32 || marker as i32 == 255 as i32 || marker as i32 == 0 as i32 {
        /* Base-256 marker, there's nothing we can check. */
        return 1 as i32;
    } else {
        /* Must be octal */
        let mut i: size_t = 0 as i32 as size_t;
        /* Skip any leading spaces */
        while i < i_size && unsafe { *p_field.offset(i as isize) as i32 } == ' ' as i32 {
            i = i.wrapping_add(1)
        }
        /* Skip octal digits. */
        while i < i_size
            && unsafe { *p_field.offset(i as isize) as i32 } >= '0' as i32
            && unsafe { *p_field.offset(i as isize) as i32 } <= '7' as i32
        {
            i = i.wrapping_add(1)
        }
        /* Any remaining characters must be space or NUL padding. */
        while i < i_size {
            if unsafe { *p_field.offset(i as isize) as i32 } != ' ' as i32
                && unsafe { *p_field.offset(i as isize) as i32 } != 0 as i32
            {
                return 0 as i32;
            }
            i = i.wrapping_add(1)
        }
        return 1 as i32;
    };
}

unsafe fn archive_read_format_tar_bid(mut a: *mut archive_read, mut best_bid: i32) -> i32 {
    let mut bid: i32 = 0;
    let mut h: *const i8 = 0 as *const i8;
    let mut header: *const archive_entry_header_ustar = 0 as *const archive_entry_header_ustar;
    /* UNUSED */
    bid = 0 as i32;
    /* Now let's look at the actual header and see if it matches. */
    h = __archive_read_ahead_safe(a, 512 as i32 as size_t, 0 as *mut ssize_t) as *const i8;
    if h.is_null() {
        return -(1 as i32);
    }
    /* If it's an end-of-archive mark, we can handle it. */
    if unsafe { *h.offset(0 as i32 as isize) as i32 == 0 as i32 } && archive_block_is_null(h) != 0 {
        /*
         * Usually, I bid the number of bits verified, but
         * in this case, 4096 seems excessive so I picked 10 as
         * an arbitrary but reasonable-seeming value.
         */
        return 10 as i32;
    }
    /* If it's not an end-of-archive mark, it must have a valid checksum.*/
    if checksum(a, h as *const ()) == 0 {
        return 0 as i32;
    } /* Checksum is usually 6 octal digits. */
    bid += 48 as i32;
    header = h as *const archive_entry_header_ustar;
    /* Recognize POSIX formats. */
    if memcmp_safe(
        unsafe { (*header).magic.as_ptr() as *const () },
        b"ustar\x00\x00" as *const u8 as *const i8 as *const (),
        6 as i32 as u64,
    ) == 0 as i32
        && memcmp_safe(
            unsafe { (*header).version.as_ptr() as *const () },
            b"00\x00" as *const u8 as *const i8 as *const (),
            2 as i32 as u64,
        ) == 0 as i32
    {
        bid += 56 as i32
    }
    /* Recognize GNU tar format. */
    if memcmp_safe(
        unsafe { (*header).magic.as_ptr() as *const () },
        b"ustar \x00" as *const u8 as *const i8 as *const (),
        6 as i32 as u64,
    ) == 0 as i32
        && memcmp_safe(
            unsafe { (*header).version.as_ptr() as *const () },
            b" \x00\x00" as *const u8 as *const i8 as *const (),
            2 as i32 as u64,
        ) == 0 as i32
    {
        bid += 56 as i32
    }
    /* Type flag must be null, digit or A-Z, a-z. */
    if unsafe { *header }.typeflag[0 as i32 as usize] as i32 != 0 as i32
        && !(unsafe { *header }.typeflag[0 as i32 as usize] as i32 >= '0' as i32
            && unsafe { *header }.typeflag[0 as i32 as usize] as i32 <= '9' as i32)
        && !(unsafe { *header }.typeflag[0 as i32 as usize] as i32 >= 'A' as i32
            && unsafe { *header }.typeflag[0 as i32 as usize] as i32 <= 'Z' as i32)
        && !(unsafe { *header }.typeflag[0 as i32 as usize] as i32 >= 'a' as i32
            && unsafe { *header }.typeflag[0 as i32 as usize] as i32 <= 'z' as i32)
    {
        return 0 as i32;
    } /* 6 bits of variation in an 8-bit field leaves 2 bits. */
    bid += 2 as i32;
    /*
     * Check format of mode/uid/gid/mtime/size/rdevmajor/rdevminor fields.
     */
    if bid > 0 as i32
        && (validate_number_field(
            unsafe { *header }.mode.as_ptr(),
            ::std::mem::size_of::<[i8; 8]>() as u64,
        ) == 0 as i32
            || validate_number_field(
                unsafe { *header }.uid.as_ptr(),
                ::std::mem::size_of::<[i8; 8]>() as u64,
            ) == 0 as i32
            || validate_number_field(
                unsafe { *header }.gid.as_ptr(),
                ::std::mem::size_of::<[i8; 8]>() as u64,
            ) == 0 as i32
            || validate_number_field(
                unsafe { *header }.mtime.as_ptr(),
                ::std::mem::size_of::<[i8; 12]>() as u64,
            ) == 0 as i32
            || validate_number_field(
                unsafe { *header }.size.as_ptr(),
                ::std::mem::size_of::<[i8; 12]>() as u64,
            ) == 0 as i32
            || validate_number_field(
                unsafe { *header }.rdevmajor.as_ptr(),
                ::std::mem::size_of::<[i8; 8]>() as u64,
            ) == 0 as i32
            || validate_number_field(
                unsafe { *header }.rdevminor.as_ptr(),
                ::std::mem::size_of::<[i8; 8]>() as u64,
            ) == 0 as i32)
    {
        bid = 0 as i32
    }
    return bid;
}

unsafe fn archive_read_format_tar_options(
    mut a: *mut archive_read,
    mut key: *const i8,
    mut val: *const i8,
) -> i32 {
    let mut tar: *mut tar = 0 as *mut tar;
    let mut ret: i32 = -(25 as i32);
    tar = unsafe { (*(*a).format).data as *mut tar };
    let mut safe_tar = unsafe { &mut *tar };
    let mut safe_a = unsafe { &mut *a };
    if strcmp_safe(key, b"compat-2x\x00" as *const u8 as *const i8) == 0 as i32 {
        /* Handle UTF-8 filenames as libarchive 2.x */
        safe_tar.compat_2x =
            (!val.is_null() && unsafe { *val.offset(0 as i32 as isize) } as i32 != 0 as i32) as i32;
        safe_tar.init_default_conversion = safe_tar.compat_2x;
        return 0 as i32;
    } else {
        if strcmp_safe(key, b"hdrcharset\x00" as *const u8 as *const i8) == 0 as i32 {
            if val.is_null() || unsafe { *val.offset(0 as i32 as isize) as i32 } == 0 as i32 {
                archive_set_error_safe!(
                    &mut safe_a.archive as *mut archive,
                    ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                    b"tar: hdrcharset option needs a character-set name\x00" as *const u8
                        as *const i8
                );
            } else {
                safe_tar.opt_sconv =
                    archive_string_conversion_from_charset_safe(&mut safe_a.archive, val, 0 as i32);
                if !safe_tar.opt_sconv.is_null() {
                    ret = ARCHIVE_TAR_DEFINED_PARAM.archive_ok
                } else {
                    ret = ARCHIVE_TAR_DEFINED_PARAM.archive_fatal
                }
            }
            return ret;
        } else {
            if strcmp_safe(key, b"mac-ext\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.process_mac_extensions = (!val.is_null()
                    && unsafe { *val.offset(0 as i32 as isize) as i32 } != 0 as i32)
                    as i32;
                return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
            } else {
                if strcmp_safe(
                    key,
                    b"read_concatenated_archives\x00" as *const u8 as *const i8,
                ) == 0 as i32
                {
                    safe_tar.read_concatenated_archives = (!val.is_null()
                        && unsafe { *val.offset(0 as i32 as isize) as i32 } != 0 as i32)
                        as i32;
                    return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
                }
            }
        }
    }
    /* Note: The "warn" return is just to inform the options
     * supervisor that we didn't handle it.  It will generate
     * a suitable error if no one used this option. */
    return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
}
/* utility function- this exists to centralize the logic of tracking
 * how much unconsumed data we have floating around, and to consume
 * anything outstanding since we're going to do read_aheads
 */
unsafe fn tar_flush_unconsumed(mut a: *mut archive_read, mut unconsumed: *mut size_t) {
    let unconsumed_safe = unsafe { &mut *unconsumed };
    if *unconsumed_safe != 0 {
        /*
                void *data = (void *)__archive_read_ahead(a, *unconsumed, NULL);
                 * this block of code is to poison claimed unconsumed space, ensuring
                 * things break if it is in use still.
                 * currently it WILL break things, so enable it only for debugging this issue
                if (data) {
                    memset(data, 0xff, *unconsumed);
                }
        */
        __archive_read_consume_safe(a, *unconsumed_safe as int64_t);
        *unconsumed_safe = 0 as i32 as size_t
    };
}
/*
 * The function invoked by archive_read_next_header().  This
 * just sets up a few things and then calls the internal
 * tar_read_header() function below.
 */
unsafe fn archive_read_format_tar_read_header(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
) -> i32 {
    /*
     * When converting tar archives to cpio archives, it is
     * essential that each distinct file have a distinct inode
     * number.  To simplify this, we keep a static count here to
     * assign fake dev/inode numbers to each tar entry.  Note that
     * pax format archives may overwrite this with something more
     * useful.
     *
     * Ideally, we would track every file read from the archive so
     * that we could assign the same dev/ino pair to hardlinks,
     * but the memory required to store a complete lookup table is
     * probably not worthwhile just to support the relatively
     * obscure tar->cpio conversion case.
     */
    let mut default_inode: i32 = 0;
    let mut default_dev: i32 = 0;
    let mut tar: *mut tar = 0 as *mut tar;
    let mut p: *const i8 = 0 as *const i8;
    let mut wp: *const wchar_t = 0 as *const wchar_t;
    let mut r: i32 = 0;
    let mut l: size_t = 0;
    let mut unconsumed: size_t = 0 as i32 as size_t;

    /* Assign default device/inode values. */
    archive_entry_set_dev_safe(entry, (1 as i32 + default_dev) as dev_t); /* Don't use zero. */
    default_inode += 1; /* Don't use zero. */
    archive_entry_set_ino_safe(entry, default_inode as la_int64_t);
    /* Limit generated st_ino number to 16 bits. */
    if default_inode >= 0xffff as i32 {
        default_dev += 1; /* Mark this as "unset" */
        default_inode = 0 as i32
    }
    tar = unsafe { (*(*a).format).data as *mut tar };
    let mut safe_tar = unsafe { &mut *tar };
    safe_tar.entry_offset = 0 as i32 as int64_t;
    gnu_clear_sparse_list(tar);
    safe_tar.realsize = -(1 as i32) as int64_t;
    safe_tar.realsize_override = 0 as i32;
    /* Setup default string conversion. */
    safe_tar.sconv = safe_tar.opt_sconv;
    if safe_tar.sconv.is_null() {
        if safe_tar.init_default_conversion == 0 {
            safe_tar.sconv_default =
                unsafe { archive_string_default_conversion_for_read(&mut unsafe { (*a).archive }) };
            safe_tar.init_default_conversion = 1 as i32
        }
        safe_tar.sconv = safe_tar.sconv_default
    }
    r = tar_read_header(a, tar, entry, &mut unconsumed);
    tar_flush_unconsumed(a, &mut unconsumed);
    /*
     * "non-sparse" files are really just sparse files with
     * a single block.
     */
    if safe_tar.sparse_list.is_null() {
        if gnu_add_sparse_entry(a, tar, 0 as i32 as int64_t, safe_tar.entry_bytes_remaining)
            != 0 as i32
        {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
    } else {
        let mut sb: *mut sparse_block = 0 as *mut sparse_block;
        sb = safe_tar.sparse_list;
        while !sb.is_null() {
            if unsafe { (*sb) }.hole == 0 {
                archive_entry_sparse_add_entry_safe(
                    entry,
                    unsafe { (*sb) }.offset,
                    unsafe { (*sb) }.remaining,
                );
            }
            unsafe { sb = (*sb).next }
        }
    }
    if r == ARCHIVE_TAR_DEFINED_PARAM.archive_ok
        && archive_entry_filetype_safe(entry) == ARCHIVE_TAR_DEFINED_PARAM.ae_ifreg as mode_t
    {
        /*
         * "Regular" entry with trailing '/' is really
         * directory: This is needed for certain old tar
         * variants and even for some broken newer ones.
         */
        wp = archive_entry_pathname_w_safe(entry);
        if !wp.is_null() {
            l = wcslen_safe(wp);
            if l > 0 as i32 as u64
                && unsafe { *wp.offset(l.wrapping_sub(1 as i32 as u64) as isize) } == '/' as wchar_t
            {
                archive_entry_set_filetype_safe(
                    entry,
                    ARCHIVE_TAR_DEFINED_PARAM.ae_ifdir as mode_t,
                );
            }
        } else {
            p = archive_entry_pathname_safe(entry);
            if !p.is_null() {
                l = strlen_safe(p);
                if l > 0 as i32 as u64
                    && unsafe { *p.offset(l.wrapping_sub(1 as i32 as u64) as isize) as i32 }
                        == '/' as i32
                {
                    archive_entry_set_filetype_safe(
                        entry,
                        ARCHIVE_TAR_DEFINED_PARAM.ae_ifdir as mode_t,
                    );
                }
            }
        }
    }
    return r;
}
unsafe fn archive_read_format_tar_read_data(
    mut a: *mut archive_read,
    mut buff: *mut *const (),
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) -> i32 {
    let mut bytes_read: ssize_t = 0;
    let mut tar: *mut tar = 0 as *mut tar;
    let mut p: *mut sparse_block = 0 as *mut sparse_block;
    tar = unsafe { (*(*a).format).data } as *mut tar;
    let mut safe_tar = unsafe { &mut *tar };
    let mut safe_a = unsafe { &mut *a };
    loop {
        /* Remove exhausted entries from sparse list. */
        while !safe_tar.sparse_list.is_null()
            && unsafe { (*safe_tar.sparse_list) }.remaining == 0 as i32 as i64
        {
            p = safe_tar.sparse_list;
            safe_tar.sparse_list = unsafe { (*p).next };
            free_safe(p as *mut ());
        }
        if safe_tar.entry_bytes_unconsumed != 0 {
            __archive_read_consume_safe(a, safe_tar.entry_bytes_unconsumed);
            safe_tar.entry_bytes_unconsumed = 0 as i32 as int64_t
        }
        /* Current is hole data and skip this. */
        if safe_tar.sparse_list.is_null() || safe_tar.entry_bytes_remaining == 0 as i32 as i64 {
            if __archive_read_consume_safe(a, safe_tar.entry_padding) < 0 as i32 as i64 {
                return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
            }
            safe_tar.entry_padding = 0 as i32 as int64_t;
            unsafe { *buff = 0 as *const () };
            unsafe { *size = 0 as i32 as size_t };
            unsafe { *offset = safe_tar.realsize };
            return ARCHIVE_TAR_DEFINED_PARAM.archive_eof;
        }
        unsafe { *buff = __archive_read_ahead_safe(a, 1 as i32 as size_t, &mut bytes_read) };
        if bytes_read < 0 as i32 as i64 {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
        if unsafe { *buff } == 0 as *mut () {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                b"Truncated tar archive\x00" as *const u8 as *const i8
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
        if bytes_read > safe_tar.entry_bytes_remaining {
            bytes_read = safe_tar.entry_bytes_remaining
        }
        unsafe {
            if (*safe_tar.sparse_list).remaining < bytes_read {
                bytes_read = (*safe_tar.sparse_list).remaining
            }
        }
        unsafe { *size = bytes_read as size_t };
        unsafe {
            *offset = (*safe_tar.sparse_list).offset;
            (*safe_tar.sparse_list).remaining -= bytes_read;
            (*safe_tar.sparse_list).offset += bytes_read;
        }
        safe_tar.entry_bytes_remaining -= bytes_read;
        safe_tar.entry_bytes_unconsumed = bytes_read;
        if unsafe { (*safe_tar.sparse_list).hole } == 0 {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
        }
    }
}
unsafe fn archive_read_format_tar_skip(mut a: *mut archive_read) -> i32 {
    let mut bytes_skipped: int64_t = 0;
    let mut request: int64_t = 0;
    let mut p: *mut sparse_block = 0 as *mut sparse_block;
    let mut tar: *mut tar = 0 as *mut tar;
    tar = unsafe { (*(*a).format).data as *mut tar };
    let mut safe_tar = unsafe { &mut *tar };
    /* If we're at end of file, return EOF. */
    /* Don't read more than is available in the
     * current sparse block. */
    /* Do not consume the hole of a sparse file. */
    request = 0 as i32 as int64_t;
    p = safe_tar.sparse_list;
    let mut safe_p = unsafe { &mut *p };
    while !p.is_null() {
        if safe_p.hole == 0 {
            if safe_p.remaining >= 9223372036854775807 as i64 - request {
                return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
            }
            request += safe_p.remaining
        }
        p = safe_p.next;
        safe_p = unsafe { &mut *p };
    }
    if request > safe_tar.entry_bytes_remaining {
        request = safe_tar.entry_bytes_remaining
    }
    request += safe_tar.entry_padding + safe_tar.entry_bytes_unconsumed;
    bytes_skipped = __archive_read_consume_safe(a, request);
    if bytes_skipped < 0 as i32 as i64 {
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    safe_tar.entry_bytes_remaining = 0 as i32 as int64_t;
    safe_tar.entry_bytes_unconsumed = 0 as i32 as int64_t;
    safe_tar.entry_padding = 0 as i32 as int64_t;
    /* Free the sparse list. */
    gnu_clear_sparse_list(tar);
    return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
}
/*
 * This function recursively interprets all of the headers associated
 * with a single entry.
 */
unsafe fn tar_read_header(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut unconsumed: *mut size_t,
) -> i32 {
    let mut bytes: ssize_t = 0;
    let mut err: i32 = 0;
    let mut eof_vol_header: i32 = 0;
    let mut h: *const i8 = 0 as *const i8;
    let mut header: *const archive_entry_header_ustar = 0 as *const archive_entry_header_ustar;
    let mut gnuheader: *const archive_entry_header_gnutar = 0 as *const archive_entry_header_gnutar;
    eof_vol_header = 0 as i32;
    let mut safe_a = unsafe { &mut *a };
    let mut safe_tar = unsafe { &mut *tar };
    loop
    /* Loop until we find a workable header record. */
    {
        tar_flush_unconsumed(a, unconsumed);
        /* Read 512-byte header record */
        h = __archive_read_ahead_safe(a, 512 as i32 as size_t, &mut bytes) as *const i8;
        if bytes < 0 as i32 as i64 {
            return bytes as i32;
        }
        if bytes == 0 as i32 as i64 {
            /* EOF at a block boundary. */
            /* Some writers do omit the block of nulls. <sigh> */
            return ARCHIVE_TAR_DEFINED_PARAM.archive_eof;
        }
        if bytes < 512 as i32 as i64 {
            /* Short block at EOF; this is bad. */
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_file_format,
                b"Truncated tar archive\x00" as *const u8 as *const i8
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
        unsafe { *unconsumed = 512 as i32 as size_t };
        /* Header is workable if it's not an end-of-archive mark. */
        if unsafe { *h.offset(0 as i32 as isize) as i32 } != 0 as i32
            || archive_block_is_null(h) == 0
        {
            break;
        }
        /* Ensure format is set for archives with only null blocks. */
        if safe_a.archive.archive_format_name.is_null() {
            safe_a.archive.archive_format = ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar;
            safe_a.archive.archive_format_name = b"tar\x00" as *const u8 as *const i8
        }
        if safe_tar.read_concatenated_archives == 0 {
            /* Try to consume a second all-null record, as well. */
            tar_flush_unconsumed(a, unconsumed);
            h = __archive_read_ahead_safe(a, 512 as i32 as size_t, 0 as *mut ssize_t) as *const i8;
            if !h.is_null()
                && unsafe { *h.offset(0 as i32 as isize) as i32 } == 0 as i32
                && archive_block_is_null(h) != 0
            {
                __archive_read_consume_safe(a, 512 as i32 as int64_t);
            }
            archive_clear_error_safe(&mut safe_a.archive);
            return ARCHIVE_TAR_DEFINED_PARAM.archive_eof;
        }
    }
    /*
     * Note: If the checksum fails and we return ARCHIVE_RETRY,
     * then the client is likely to just retry.  This is a very
     * crude way to search for the next valid header!
     *
     * TODO: Improve this by implementing a real header scan.
     */
    if checksum(a, h as *const ()) == 0 {
        tar_flush_unconsumed(a, unconsumed);
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_TAR_DEFINED_PARAM.einval,
            b"Damaged tar archive\x00" as *const u8 as *const i8
        );
        return ARCHIVE_TAR_DEFINED_PARAM.archive_retry;
        /* Retryable: Invalid header */
    }
    safe_tar.header_recursion_depth += 1;
    if safe_tar.header_recursion_depth > 32 as i32 {
        tar_flush_unconsumed(a, unconsumed);
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_TAR_DEFINED_PARAM.einval,
            b"Too many special headers\x00" as *const u8 as *const i8
        );
        return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
    }
    /* Determine the format variant. */
    header = h as *const archive_entry_header_ustar;
    match unsafe { *header }.typeflag[0 as i32 as usize] as i32 {
        65 => {
            /* Solaris tar ACL */
            safe_a.archive.archive_format =
                ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar_pax_interchange;
            safe_a.archive.archive_format_name = b"Solaris tar\x00" as *const u8 as *const i8;
            err = header_Solaris_ACL(a, tar, entry, h as *const (), unconsumed)
        }
        103 => {
            /* POSIX-standard 'g' header. */
            safe_a.archive.archive_format =
                ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar_pax_interchange;
            safe_a.archive.archive_format_name =
                b"POSIX pax interchange format\x00" as *const u8 as *const i8;
            err = header_pax_global(a, tar, entry, h as *const (), unconsumed);
            if err == ARCHIVE_TAR_DEFINED_PARAM.archive_eof {
                return err;
            }
        }
        75 => {
            /* Long link name (GNU tar, others) */
            err = header_longlink(a, tar, entry, h as *const (), unconsumed)
        }
        76 => {
            /* Long filename (GNU tar, others) */
            err = header_longname(a, tar, entry, h as *const (), unconsumed)
        }
        86 => {
            /* GNU volume header */
            err = header_volume(a, tar, entry, h as *const (), unconsumed);
            if err == ARCHIVE_TAR_DEFINED_PARAM.archive_eof {
                eof_vol_header = 1 as i32
            }
        }
        88 => {
            /* Used by SUN tar; same as 'x'. */
            safe_a.archive.archive_format =
                ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar_pax_interchange;
            safe_a.archive.archive_format_name =
                b"POSIX pax interchange format (Sun variant)\x00" as *const u8 as *const i8;
            err = header_pax_extensions(a, tar, entry, h as *const (), unconsumed)
        }
        120 => {
            /* POSIX-standard 'x' header. */
            safe_a.archive.archive_format =
                ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar_pax_interchange;
            safe_a.archive.archive_format_name =
                b"POSIX pax interchange format\x00" as *const u8 as *const i8;
            err = header_pax_extensions(a, tar, entry, h as *const (), unconsumed)
        }
        _ => {
            gnuheader = h as *const archive_entry_header_gnutar;
            if memcmp_safe(
                unsafe { (*gnuheader) }.magic.as_ptr() as *const (),
                b"ustar  \x00\x00" as *const u8 as *const i8 as *const (),
                8 as i32 as u64,
            ) == 0 as i32
            {
                safe_a.archive.archive_format = ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar_gnutar;
                safe_a.archive.archive_format_name =
                    b"GNU tar format\x00" as *const u8 as *const i8;
                err = header_gnutar(a, tar, entry, h as *const (), unconsumed)
            } else if memcmp_safe(
                unsafe { *header }.magic.as_ptr() as *const (),
                b"ustar\x00" as *const u8 as *const i8 as *const (),
                5 as i32 as u64,
            ) == 0 as i32
            {
                if safe_a.archive.archive_format
                    != ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar_pax_interchange
                {
                    safe_a.archive.archive_format =
                        ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar_ustar;
                    safe_a.archive.archive_format_name =
                        b"POSIX ustar format\x00" as *const u8 as *const i8
                }
                err = header_ustar(a, tar, entry, h as *const ())
            } else {
                safe_a.archive.archive_format = ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar;
                safe_a.archive.archive_format_name =
                    b"tar (non-POSIX)\x00" as *const u8 as *const i8;
                err = header_old_tar(a, tar, entry, h as *const ())
            }
        }
    }
    if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
        return err;
    }
    tar_flush_unconsumed(a, unconsumed);
    h = 0 as *const i8;
    header = 0 as *const archive_entry_header_ustar;
    safe_tar.header_recursion_depth -= 1;
    /* Yuck.  Apple's design here ends up storing long pathname
     * extensions for both the AppleDouble extension entry and the
     * regular entry.
     */
    if (err == ARCHIVE_TAR_DEFINED_PARAM.archive_warn
        || err == ARCHIVE_TAR_DEFINED_PARAM.archive_ok)
        && safe_tar.header_recursion_depth == 0 as i32
        && safe_tar.process_mac_extensions != 0
    {
        let mut err2: i32 = read_mac_metadata_blob(a, tar, entry, h as *const (), unconsumed);
        if err2 < err {
            err = err2
        }
    }
    /* We return warnings or success as-is.  Anything else is fatal. */
    if err == ARCHIVE_TAR_DEFINED_PARAM.archive_warn || err == ARCHIVE_TAR_DEFINED_PARAM.archive_ok
    {
        if safe_tar.sparse_gnu_pending != 0 {
            if safe_tar.sparse_gnu_major == 1 as i32 && safe_tar.sparse_gnu_minor == 0 as i32 {
                let mut bytes_read: ssize_t = 0;
                safe_tar.sparse_gnu_pending = 0 as i32 as i8;
                /* Read initial sparse map. */
                bytes_read = gnu_sparse_10_read(a, tar, unconsumed);
                if bytes_read < 0 as i32 as i64 {
                    return bytes_read as i32;
                }
                safe_tar.entry_bytes_remaining -= bytes_read
            } else {
                archive_set_error_safe!(
                    &mut safe_a.archive as *mut archive,
                    ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                    b"Unrecognized GNU sparse file format\x00" as *const u8 as *const i8
                );
                return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
            }
            safe_tar.sparse_gnu_pending = 0 as i32 as i8
        }
        return err;
    }
    if err == ARCHIVE_TAR_DEFINED_PARAM.archive_eof {
        if eof_vol_header == 0 {
            /* EOF when recursively reading a header is bad. */
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.einval,
                b"Damaged tar archive\x00" as *const u8 as *const i8
            );
        } else {
            /* If we encounter just a GNU volume header treat
             * this situation as an empty archive */
            return ARCHIVE_TAR_DEFINED_PARAM.archive_eof;
        }
    }
    return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
}
/*
 * Return true if block checksum is correct.
 */
unsafe fn checksum(mut a: *mut archive_read, mut h: *const ()) -> i32 {
    let mut bytes: *const u8 = 0 as *const u8;
    let mut header: *const archive_entry_header_ustar = 0 as *const archive_entry_header_ustar;
    let mut check: i32 = 0;
    let mut sum: i32 = 0;
    let mut i: size_t = 0;
    /* UNUSED */
    bytes = h as *const u8;
    header = h as *const archive_entry_header_ustar;
    /* Checksum field must hold an octal number */
    i = 0 as i32 as size_t;
    while i < ::std::mem::size_of::<[i8; 8]>() as u64 {
        let mut c: i8 = unsafe { *header }.checksum[i as usize];
        if c as i32 != ' ' as i32
            && c as i32 != '\u{0}' as i32
            && ((c as i32) < '0' as i32 || c as i32 > '7' as i32)
        {
            return 0 as i32;
        }
        i = i.wrapping_add(1)
    }
    /*
     * Test the checksum.  Note that POSIX specifies _unsigned_
     * bytes for this calculation.
     */
    sum = tar_atol(
        unsafe { *header }.checksum.as_ptr(),
        ::std::mem::size_of::<[i8; 8]>() as u64,
    ) as i32;
    check = 0 as i32;
    i = 0 as i32 as size_t;
    while i < 148 as i32 as u64 {
        unsafe { check += *bytes.offset(i as isize) as i32 };
        i = i.wrapping_add(1)
    }
    while i < 156 as i32 as u64 {
        check += 32 as i32;
        i = i.wrapping_add(1)
    }
    while i < 512 as i32 as u64 {
        unsafe { check += *bytes.offset(i as isize) as i32 };
        i = i.wrapping_add(1)
    }
    if sum == check {
        return 1 as i32;
    }
    /*
     * Repeat test with _signed_ bytes, just in case this archive
     * was created by an old BSD, Solaris, or HP-UX tar with a
     * broken checksum calculation.
     */
    check = 0 as i32;
    i = 0 as i32 as size_t;
    while i < 148 as i32 as u64 {
        unsafe { check += *bytes.offset(i as isize) as libc::c_schar as i32 };
        i = i.wrapping_add(1)
    }
    while i < 156 as i32 as u64 {
        check += 32 as i32;
        i = i.wrapping_add(1)
    }
    while i < 512 as i32 as u64 {
        unsafe { check += *bytes.offset(i as isize) as libc::c_schar as i32 };
        i = i.wrapping_add(1)
    }
    if sum == check {
        return 1 as i32;
    }
    return 0 as i32;
}
/*
 * Return true if this block contains only nulls.
 */
unsafe fn archive_block_is_null(mut p: *const i8) -> i32 {
    let mut i: u32 = 0;
    i = 0 as i32 as u32;
    while i < 512 as i32 as u32 {
        let fresh0 = p;
        unsafe { p = p.offset(1) };
        if unsafe { *fresh0 } != 0 {
            return 0 as i32;
        }
        i = i.wrapping_add(1)
    }
    return 1 as i32;
}
/*
 * Interpret 'A' Solaris ACL header
 */
unsafe fn header_Solaris_ACL(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut h: *const (),
    mut unconsumed: *mut size_t,
) -> i32 {
    let mut header: *const archive_entry_header_ustar = 0 as *const archive_entry_header_ustar;
    let mut size: size_t = 0;
    let mut err: i32 = 0;
    let mut acl_type: i32 = 0;
    let mut type_0: int64_t = 0;
    let mut acl: *mut i8 = 0 as *mut i8;
    let mut p: *mut i8 = 0 as *mut i8;
    let mut safe_tar = unsafe { &mut *tar };
    let mut safe_a = unsafe { &mut *a };
    /*
     * read_body_to_string adds a NUL terminator, but we need a little
     * more to make sure that we don't overrun acl_text later.
     */
    header = h as *const archive_entry_header_ustar;
    size = tar_atol(
        unsafe { *header }.size.as_ptr(),
        ::std::mem::size_of::<[i8; 12]>() as u64,
    ) as size_t;
    err = read_body_to_string(a, tar, &mut safe_tar.acl_text, h, unconsumed);
    if err != ARCHIVE_TAR_DEFINED_PARAM.archive_ok {
        return err;
    }
    /* Recursively read next header */
    err = tar_read_header(a, tar, entry, unconsumed);
    if err != ARCHIVE_TAR_DEFINED_PARAM.archive_ok && err != ARCHIVE_TAR_DEFINED_PARAM.archive_warn
    {
        return err;
    }
    /* TODO: Examine the first characters to see if this
     * is an AIX ACL descriptor.  We'll likely never support
     * them, but it would be polite to recognize and warn when
     * we do see them. */
    /* Leading octal number indicates ACL type and number of entries. */
    acl = safe_tar.acl_text.s;
    p = acl;
    type_0 = 0 as i32 as int64_t;
    while unsafe { *p as i32 != '\u{0}' as i32 && p < acl.offset(size as isize) } {
        if unsafe { (*p as i32) < '0' as i32 || *p as i32 > '7' as i32 } {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                b"Malformed Solaris ACL attribute (invalid digit)\x00" as *const u8 as *const i8
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
        }
        type_0 <<= 3 as i32;
        type_0 += unsafe { (*p as i32 - '0' as i32) } as i64;
        if type_0 > 0o77777777 as i32 as i64 {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                b"Malformed Solaris ACL attribute (count too large)\x00" as *const u8 as *const i8
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
        }
        unsafe { p = p.offset(1) }
    }
    match type_0 as i32 & !(0o777777 as i32) {
        262144 => {
            /* POSIX.1e ACL */
            acl_type = ARCHIVE_TAR_DEFINED_PARAM.archive_entry_acl_type_access
        }
        786432 => {
            /* NFSv4 ACL */
            acl_type = ARCHIVE_TAR_DEFINED_PARAM.archive_entry_acl_type_nfs4
        }
        _ => {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                b"Malformed Solaris ACL attribute (unsupported type %o)\x00" as *const u8
                    as *const i8,
                type_0 as i32
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
        }
    }
    unsafe { p = p.offset(1) };
    if p >= unsafe { acl.offset(size as isize) } {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
            b"Malformed Solaris ACL attribute (body overflow)\x00" as *const u8 as *const i8
        );
        return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
    }
    /* ACL text is null-terminated; find the end. */
    size =
        (size as u64).wrapping_sub(unsafe { p.offset_from(acl) } as i64 as u64) as size_t as size_t;
    acl = p;
    unsafe {
        while *p as i32 != '\u{0}' as i32 && p < acl.offset(size as isize) {
            p = p.offset(1)
        }
    }
    if safe_tar.sconv_acl.is_null() {
        safe_tar.sconv_acl = archive_string_conversion_from_charset_safe(
            &mut safe_a.archive,
            b"UTF-8\x00" as *const u8 as *const i8,
            1 as i32,
        );
        if safe_tar.sconv_acl.is_null() {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
    }
    safe_tar.localname.length = 0 as i32 as size_t;
    archive_strncat_safe(&mut safe_tar.localname, acl as *const (), unsafe {
        p.offset_from(acl) as i64 as size_t
    });
    err = archive_acl_from_text_l_safe(
        archive_entry_acl_safe(entry),
        safe_tar.localname.s,
        acl_type,
        safe_tar.sconv_acl,
    );
    if err != ARCHIVE_TAR_DEFINED_PARAM.archive_ok {
        if unsafe { *__errno_location() == ARCHIVE_TAR_DEFINED_PARAM.enomem } {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.enomem,
                b"Can\'t allocate memory for ACL\x00" as *const u8 as *const i8
            );
        } else {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                b"Malformed Solaris ACL attribute (unparsable)\x00" as *const u8 as *const i8
            );
        }
    }
    return err;
}
/*
 * Interpret 'K' long linkname header.
 */
unsafe fn header_longlink(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut h: *const (),
    mut unconsumed: *mut size_t,
) -> i32 {
    let mut err: i32 = 0;
    let mut safe_tar = unsafe { &mut *tar };
    err = read_body_to_string(a, tar, &mut safe_tar.longlink, h, unconsumed);
    if err != ARCHIVE_TAR_DEFINED_PARAM.archive_ok {
        return err;
    }
    err = unsafe { tar_read_header(a, tar, entry, unconsumed) };
    if err != ARCHIVE_TAR_DEFINED_PARAM.archive_ok && err != ARCHIVE_TAR_DEFINED_PARAM.archive_warn
    {
        return err;
    }
    /* Set symlink if symlink already set, else hardlink. */
    archive_entry_copy_link_safe(entry, safe_tar.longlink.s);
    return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
}
unsafe fn set_conversion_failed_error(
    mut a: *mut archive_read,
    mut sconv: *mut archive_string_conv,
    mut name: *const i8,
) -> i32 {
    let mut safe_a = unsafe { &mut *a };
    if unsafe { *__errno_location() } == ARCHIVE_TAR_DEFINED_PARAM.enomem {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_TAR_DEFINED_PARAM.enomem,
            b"Can\'t allocate memory for %s\x00" as *const u8 as *const i8,
            name
        );
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    archive_set_error_safe!(
        &mut safe_a.archive as *mut archive,
        ARCHIVE_TAR_DEFINED_PARAM.archive_errno_file_format,
        b"%s can\'t be converted from %s to current locale.\x00" as *const u8 as *const i8,
        name,
        archive_string_conversion_charset_name_safe(sconv)
    );
    return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
}
/*
 * Interpret 'L' long filename header.
 */
unsafe fn header_longname(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut h: *const (),
    mut unconsumed: *mut size_t,
) -> i32 {
    let mut err: i32 = 0;
    let mut safe_tar = unsafe { &mut *tar };
    err = read_body_to_string(a, tar, &mut safe_tar.longname, h, unconsumed);
    if err != ARCHIVE_TAR_DEFINED_PARAM.archive_ok {
        return err;
    }
    /* Read and parse "real" header, then override name. */
    err = tar_read_header(a, tar, entry, unconsumed);
    if err != ARCHIVE_TAR_DEFINED_PARAM.archive_ok && err != ARCHIVE_TAR_DEFINED_PARAM.archive_warn
    {
        return err;
    }
    if _archive_entry_copy_pathname_l_safe(
        entry,
        safe_tar.longname.s,
        safe_tar.longname.length,
        safe_tar.sconv,
    ) != 0 as i32
    {
        err = set_conversion_failed_error(
            a,
            safe_tar.sconv,
            b"Pathname\x00" as *const u8 as *const i8,
        )
    }
    return err;
}
/*
 * Interpret 'V' GNU tar volume header.
 */
unsafe fn header_volume(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut h: *const (),
    mut unconsumed: *mut size_t,
) -> i32 {
    /* Just skip this and read the next header. */
    return tar_read_header(a, tar, entry, unconsumed);
}
/*
 * Read body of an archive entry into an archive_string object.
 */
unsafe fn read_body_to_string(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut as_0: *mut archive_string,
    mut h: *const (),
    mut unconsumed: *mut size_t,
) -> i32 {
    let mut size: int64_t = 0;
    let mut header: *const archive_entry_header_ustar = 0 as *const archive_entry_header_ustar;
    let mut src: *const () = 0 as *const ();
    let mut safe_a = unsafe { &mut *a };
    let mut safe_as_0 = unsafe { &mut *as_0 };
    /* UNUSED */
    header = h as *const archive_entry_header_ustar;
    size = tar_atol(
        unsafe { *header }.size.as_ptr(),
        ::std::mem::size_of::<[i8; 12]>() as u64,
    );
    if size > 1048576 as i32 as i64 || size < 0 as i32 as i64 {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_TAR_DEFINED_PARAM.einval,
            b"Special header too large\x00" as *const u8 as *const i8
        );
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    /* Fail if we can't make our buffer big enough. */
    if archive_string_ensure_safe(as_0, (size as size_t).wrapping_add(1 as i32 as u64)).is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_TAR_DEFINED_PARAM.enomem,
            b"No memory\x00" as *const u8 as *const i8
        );
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    tar_flush_unconsumed(a, unconsumed);
    /* Read the body into the string. */
    unsafe { *unconsumed = (size + 511 as i32 as i64 & !(511 as i32) as i64) as size_t };
    src = __archive_read_ahead_safe(a, unsafe { *unconsumed }, 0 as *mut ssize_t);
    if src == 0 as *mut () {
        unsafe { *unconsumed = 0 as i32 as size_t };
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    memcpy_safe(safe_as_0.s as *mut (), src, size as size_t);
    unsafe { *safe_as_0.s.offset(size as isize) = '\u{0}' as i32 as i8 };
    safe_as_0.length = size as size_t;
    return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
}
/*
 * Parse out common header elements.
 *
 * This would be the same as header_old_tar, except that the
 * filename is handled slightly differently for old and POSIX
 * entries  (POSIX entries support a 'prefix').  This factoring
 * allows header_old_tar and header_ustar
 * to handle filenames differently, while still putting most of the
 * common parsing into one place.
 */
unsafe fn header_common(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut h: *const (),
) -> i32 {
    let mut header = 0 as *const archive_entry_header_ustar;
    let mut safe_tar = unsafe { &mut *tar };
    let mut safe_a = unsafe { &mut *a };
    let mut tartype: i8 = 0;
    let mut err: i32 = ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
    header = h as *const archive_entry_header_ustar;
    if unsafe { *header }.linkname[0 as i32 as usize] != 0 {
        safe_tar.entry_linkpath.length = 0 as i32 as size_t;
        archive_strncat_safe(
            &mut safe_tar.entry_linkpath,
            unsafe { *header }.linkname.as_ptr() as *const (),
            ::std::mem::size_of::<[i8; 100]>() as u64,
        );
    } else {
        safe_tar.entry_linkpath.length = 0 as i32 as size_t
    }
    /* Parse out the numeric fields (all are octal) */
    archive_entry_set_mode_safe(
        entry,
        tar_atol(
            unsafe { *header }.mode.as_ptr(),
            ::std::mem::size_of::<[i8; 8]>() as u64,
        ) as mode_t,
    );
    archive_entry_set_uid_safe(
        entry,
        tar_atol(
            unsafe { *header }.uid.as_ptr(),
            ::std::mem::size_of::<[i8; 8]>() as u64,
        ),
    );
    archive_entry_set_gid_safe(
        entry,
        tar_atol(
            unsafe { *header }.gid.as_ptr(),
            ::std::mem::size_of::<[i8; 8]>() as u64,
        ),
    );
    safe_tar.entry_bytes_remaining = tar_atol(
        unsafe { *header }.size.as_ptr(),
        ::std::mem::size_of::<[i8; 12]>() as u64,
    );
    if safe_tar.entry_bytes_remaining < 0 as i32 as i64 {
        safe_tar.entry_bytes_remaining = 0 as i32 as int64_t;
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
            b"Tar entry has negative size\x00" as *const u8 as *const i8
        );
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    if safe_tar.entry_bytes_remaining == 9223372036854775807 as i64 {
        /* Note: tar_atol returns INT64_MAX on overflow */
        safe_tar.entry_bytes_remaining = 0 as i32 as int64_t;
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
            b"Tar entry size overflow\x00" as *const u8 as *const i8
        );
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    safe_tar.realsize = safe_tar.entry_bytes_remaining;
    archive_entry_set_size_safe(entry, safe_tar.entry_bytes_remaining);
    archive_entry_set_mtime_safe(
        entry,
        tar_atol(
            unsafe { *header }.mtime.as_ptr(),
            ::std::mem::size_of::<[i8; 12]>() as u64,
        ),
        0 as i32 as i64,
    );
    /* Handle the tar type flag appropriately. */
    tartype = unsafe { *header }.typeflag[0 as i32 as usize];
    let mut current_block_64: u64;
    match tartype as i32 {
        49 => {
            /* Hard link */
            if _archive_entry_copy_hardlink_l_safe(
                entry,
                safe_tar.entry_linkpath.s,
                safe_tar.entry_linkpath.length,
                safe_tar.sconv,
            ) != 0 as i32
            {
                err = set_conversion_failed_error(
                    a,
                    safe_tar.sconv,
                    b"Linkname\x00" as *const u8 as *const i8,
                );
                if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
                    return err;
                }
            }
            /*
             * The following may seem odd, but: Technically, tar
             * does not store the file type for a "hard link"
             * entry, only the fact that it is a hard link.  So, I
             * leave the type zero normally.  But, pax interchange
             * format allows hard links to have data, which
             * implies that the underlying entry is a regular
             * file.
             */
            if archive_entry_size_safe(entry) > 0 as i32 as i64 {
                archive_entry_set_filetype_safe(
                    entry,
                    ARCHIVE_TAR_DEFINED_PARAM.ae_ifreg as mode_t,
                );
            }
            /*
             * A tricky point: Traditionally, tar readers have
             * ignored the size field when reading hardlink
             * entries, and some writers put non-zero sizes even
             * though the body is empty.  POSIX blessed this
             * convention in the 1988 standard, but broke with
             * this tradition in 2001 by permitting hardlink
             * entries to store valid bodies in pax interchange
             * format, but not in ustar format.  Since there is no
             * hard and fast way to distinguish pax interchange
             * from earlier archives (the 'x' and 'g' entries are
             * optional, after all), we need a heuristic.
             */
            if !(archive_entry_size_safe(entry) == 0 as i32 as i64) {
                if !(safe_a.archive.archive_format
                    == ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar_pax_interchange)
                {
                    if safe_a.archive.archive_format == ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar
                        || safe_a.archive.archive_format
                            == ARCHIVE_TAR_DEFINED_PARAM.archive_format_tar_gnutar
                        || archive_read_format_tar_bid(a, 50 as i32) > 50 as i32
                    {
                        /* Old-style or GNU tar: we must ignore the size. */
                        archive_entry_set_size_safe(entry, 0 as i32 as la_int64_t);
                        safe_tar.entry_bytes_remaining = 0 as i32 as int64_t
                    }
                }
            }
            /*
             * TODO: There are still two cases I'd like to handle:
             *   = a ustar non-pax archive with a hardlink entry at
             *     end-of-archive.  (Look for block of nulls following?)
             *   = a pax archive that has not seen any pax headers
             *     and has an entry which is a hardlink entry storing
             *     a body containing an uncompressed tar archive.
             * The first is worth addressing; I don't see any reliable
             * way to deal with the second possibility.
             */
            current_block_64 = 5372832139739605200;
        }
        50 => {
            /* Symlink */
            archive_entry_set_filetype_safe(entry, ARCHIVE_TAR_DEFINED_PARAM.ae_iflnk as mode_t);
            archive_entry_set_size_safe(entry, 0 as i32 as la_int64_t);
            safe_tar.entry_bytes_remaining = 0 as i32 as int64_t;
            if _archive_entry_copy_symlink_l_safe(
                entry,
                safe_tar.entry_linkpath.s,
                safe_tar.entry_linkpath.length,
                safe_tar.sconv,
            ) != 0 as i32
            {
                err = set_conversion_failed_error(
                    a,
                    safe_tar.sconv,
                    b"Linkname\x00" as *const u8 as *const i8,
                );
                if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
                    return err;
                }
            }
            current_block_64 = 5372832139739605200;
        }
        51 => {
            /* Character device */
            archive_entry_set_filetype_safe(entry, ARCHIVE_TAR_DEFINED_PARAM.ae_ifchr as mode_t);
            archive_entry_set_size_safe(entry, 0 as i32 as la_int64_t);
            safe_tar.entry_bytes_remaining = 0 as i32 as int64_t;
            current_block_64 = 5372832139739605200;
        }
        52 => {
            /* Block device */
            archive_entry_set_filetype_safe(entry, ARCHIVE_TAR_DEFINED_PARAM.ae_ifblk as mode_t);
            archive_entry_set_size_safe(entry, 0 as i32 as la_int64_t);
            safe_tar.entry_bytes_remaining = 0 as i32 as int64_t;
            current_block_64 = 5372832139739605200;
        }
        53 => {
            /* Dir */
            archive_entry_set_filetype_safe(entry, ARCHIVE_TAR_DEFINED_PARAM.ae_ifdir as mode_t);
            archive_entry_set_size_safe(entry, 0 as i32 as la_int64_t);
            safe_tar.entry_bytes_remaining = 0 as i32 as int64_t;
            current_block_64 = 5372832139739605200;
        }
        54 => {
            /* FIFO device */
            archive_entry_set_filetype_safe(entry, ARCHIVE_TAR_DEFINED_PARAM.ae_ififo as mode_t);
            archive_entry_set_size_safe(entry, 0 as i32 as la_int64_t);
            safe_tar.entry_bytes_remaining = 0 as i32 as int64_t;
            current_block_64 = 5372832139739605200;
        }
        68 => {
            /* GNU incremental directory type */
            /*
             * No special handling is actually required here.
             * It might be nice someday to preprocess the file list and
             * provide it to the client, though.
             */
            archive_entry_set_filetype_safe(entry, ARCHIVE_TAR_DEFINED_PARAM.ae_ifdir as mode_t);
            current_block_64 = 5372832139739605200;
        }
        77 => {
            current_block_64 = 5372832139739605200;
        }
        78 => {
            /* Old GNU "long filename" entry. */
            /* The body of this entry is a script for renaming
             * previously-extracted entries.  Ugh.  It will never
             * be supported by libarchive. */
            archive_entry_set_filetype_safe(entry, ARCHIVE_TAR_DEFINED_PARAM.ae_ifreg as mode_t);
            current_block_64 = 5372832139739605200;
        }
        83 | 48 => {
            /* GNU sparse files */
            /*
             * Sparse files are really just regular files with
             * sparse information in the extended area.
             */
            /* FALLTHROUGH */
            /*
             * Enable sparse file "read" support only for regular
             * files and explicit GNU sparse files.  However, we
             * don't allow non-standard file types to be sparse.
             */
            safe_tar.sparse_allowed = 1 as i32;
            current_block_64 = 1050378859040334210;
        }
        _ => {
            current_block_64 = 1050378859040334210;
        }
    }
    match current_block_64 {
        1050378859040334210 =>
        /* FALLTHROUGH */
        /* Regular file  and non-standard types */
        /*
         * Per POSIX: non-recognized types should always be
         * treated as regular files.
         */
        {
            archive_entry_set_filetype_safe(entry, ARCHIVE_TAR_DEFINED_PARAM.ae_ifreg as mode_t);
        }
        _ => {}
    }
    return err;
}
/*
 * Parse out header elements for "old-style" tar archives.
 */
unsafe fn header_old_tar(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut h: *const (),
) -> i32 {
    let mut header: *const archive_entry_header_ustar = 0 as *const archive_entry_header_ustar;
    let mut err: i32 = 0 as i32;
    let mut err2: i32 = 0;
    let mut safe_tar = unsafe { &mut *tar };
    /* Copy filename over (to ensure null termination). */
    header = h as *const archive_entry_header_ustar;
    if _archive_entry_copy_pathname_l_safe(
        entry,
        unsafe { *header }.name.as_ptr(),
        ::std::mem::size_of::<[i8; 100]>() as u64,
        safe_tar.sconv,
    ) != 0 as i32
    {
        err = set_conversion_failed_error(
            a,
            safe_tar.sconv,
            b"Pathname\x00" as *const u8 as *const i8,
        );
        if err == -(30 as i32) {
            return err;
        }
    }
    /* Grab rest of common fields */
    err2 = header_common(a, tar, entry, h);
    if err > err2 {
        err = err2
    }
    safe_tar.entry_padding = 0x1ff as i32 as i64 & -safe_tar.entry_bytes_remaining;
    return err;
}
/*
 * Read a Mac AppleDouble-encoded blob of file metadata,
 * if there is one.
 */
unsafe fn read_mac_metadata_blob(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut h: *const (),
    mut unconsumed: *mut size_t,
) -> i32 {
    let mut size: int64_t = 0;
    let mut data: *const () = 0 as *const ();
    let mut p: *const i8 = 0 as *const i8;
    let mut name: *const i8 = 0 as *const i8;
    let mut wp: *const wchar_t = 0 as *const wchar_t;
    let mut wname: *const wchar_t = 0 as *const wchar_t;
    /* UNUSED */
    wp = archive_entry_pathname_w_safe(entry);
    wname = wp;
    if !wp.is_null() {
        /* Find the last path element. */
        while unsafe { *wp } != '\u{0}' as wchar_t {
            if unsafe {
                *wp.offset(0 as i32 as isize) == '/' as wchar_t
                    && *wp.offset(1 as i32 as isize) != '\u{0}' as wchar_t
            } {
                unsafe { wname = wp.offset(1 as i32 as isize) }
            }
            unsafe { wp = wp.offset(1) }
        }
        /*
         * If last path element starts with "._", then
         * this is a Mac extension.
         */
        if unsafe {
            *wname.offset(0 as i32 as isize) != '.' as wchar_t
                || *wname.offset(1 as i32 as isize) != '_' as wchar_t
                || *wname.offset(2 as i32 as isize) == '\u{0}' as wchar_t
        } {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
        }
    } else {
        /* Find the last path element. */
        p = archive_entry_pathname_safe(entry);
        name = p;
        if p.is_null() {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_failed;
        }
        while unsafe { *p as i32 } != '\u{0}' as i32 {
            if unsafe { *p.offset(0 as i32 as isize) } as i32 == '/' as i32
                && unsafe { *p.offset(1 as i32 as isize) } as i32 != '\u{0}' as i32
            {
                unsafe { name = p.offset(1 as i32 as isize) }
            }
            unsafe { p = p.offset(1) }
        }
        /*
         * If last path element starts with "._", then
         * this is a Mac extension.
         */
        if unsafe {
            *name.offset(0 as i32 as isize) as i32 != '.' as i32
                || *name.offset(1 as i32 as isize) as i32 != '_' as i32
                || *name.offset(2 as i32 as isize) as i32 == '\u{0}' as i32
        } {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
        }
    }
    /* Read the body as a Mac OS metadata blob. */
    size = archive_entry_size_safe(entry);
    /*
     * TODO: Look beyond the body here to peek at the next header.
     * If it's a regular header (not an extension header)
     * that has the wrong name, just return the current
     * entry as-is, without consuming the body here.
     * That would reduce the risk of us mis-identifying
     * an ordinary file that just happened to have
     * a name starting with "._".
     *
     * Q: Is the above idea really possible?  Even
     * when there are GNU or pax extension entries?
     */
    data = __archive_read_ahead_safe(a, size as size_t, 0 as *mut ssize_t);
    if data == 0 as *mut () {
        unsafe { *unconsumed = 0 as i32 as size_t };
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    archive_entry_copy_mac_metadata_safe(entry, data, size as size_t);
    unsafe { *unconsumed = (size + 511 as i32 as i64 & !(511 as i32) as i64) as size_t };
    tar_flush_unconsumed(a, unconsumed);
    return tar_read_header(a, tar, entry, unconsumed);
}
/*
 * Parse a file header for a pax extended archive entry.
 */
unsafe fn header_pax_global(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut h: *const (),
    mut unconsumed: *mut size_t,
) -> i32 {
    let mut err: i32 = 0;
    err = read_body_to_string(a, tar, unsafe { &mut (*tar).pax_global }, h, unconsumed);
    if err != 0 as i32 {
        return err;
    }
    err = tar_read_header(a, tar, entry, unconsumed);
    return err;
}
unsafe fn header_pax_extensions(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut h: *const (),
    mut unconsumed: *mut size_t,
) -> i32 {
    let mut err: i32 = 0;
    let mut err2: i32 = 0;
    let mut safe_tar = unsafe { &mut *tar };
    err = read_body_to_string(a, tar, &mut safe_tar.pax_header, h, unconsumed);
    if err != ARCHIVE_TAR_DEFINED_PARAM.archive_ok {
        return err;
    }
    /* Parse the next header. */
    err = tar_read_header(a, tar, entry, unconsumed);
    if err != ARCHIVE_TAR_DEFINED_PARAM.archive_ok && err != ARCHIVE_TAR_DEFINED_PARAM.archive_warn
    {
        return err;
    }
    /*
     * TODO: Parse global/default options into 'entry' struct here
     * before handling file-specific options.
     *
     * This design (parse standard header, then overwrite with pax
     * extended attribute data) usually works well, but isn't ideal;
     * it would be better to parse the pax extended attributes first
     * and then skip any fields in the standard header that were
     * defined in the pax header.
     */
    err2 = pax_header(a, tar, entry, &mut safe_tar.pax_header);
    err = if err < err2 { err } else { err2 };
    safe_tar.entry_padding = 0x1ff as i32 as i64 & -safe_tar.entry_bytes_remaining;
    return err;
}
/*
 * Parse a file header for a Posix "ustar" archive entry.  This also
 * handles "pax" or "extended ustar" entries.
 */
unsafe fn header_ustar(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut h: *const (),
) -> i32 {
    let mut header: *const archive_entry_header_ustar = 0 as *const archive_entry_header_ustar;
    let mut as_0: *mut archive_string = 0 as *mut archive_string;
    let mut err: i32 = 0 as i32;
    let mut r: i32 = 0;
    let mut safe_tar = unsafe { &mut *tar };

    header = h as *const archive_entry_header_ustar;
    /* Copy name into an internal buffer to ensure null-termination. */
    as_0 = &mut safe_tar.entry_pathname;
    let mut safe_as_0 = unsafe { &mut *as_0 };
    if unsafe { *header }.prefix[0 as i32 as usize] != 0 {
        safe_as_0.length = 0 as i32 as size_t;
        archive_strncat_safe(
            as_0,
            unsafe { *header }.prefix.as_ptr() as *const (),
            ::std::mem::size_of::<[i8; 155]>() as u64,
        );
        if unsafe {
            *safe_as_0
                .s
                .offset(safe_as_0.length.wrapping_sub(1 as i32 as u64) as isize) as i32
        } != '/' as i32
        {
            archive_strappend_char_safe(as_0, '/' as i32 as i8);
        }
        archive_strncat_safe(
            as_0,
            unsafe { *header }.name.as_ptr() as *const (),
            ::std::mem::size_of::<[i8; 100]>() as u64,
        );
    } else {
        safe_as_0.length = 0 as i32 as size_t;
        archive_strncat_safe(
            as_0,
            unsafe { *header }.name.as_ptr() as *const (),
            ::std::mem::size_of::<[i8; 100]>() as u64,
        );
    }
    if _archive_entry_copy_pathname_l_safe(entry, safe_as_0.s, safe_as_0.length, safe_tar.sconv)
        != 0 as i32
    {
        err = set_conversion_failed_error(
            a,
            safe_tar.sconv,
            b"Pathname\x00" as *const u8 as *const i8,
        );
        if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
            return err;
        }
    }
    /* Handle rest of common fields. */
    r = header_common(a, tar, entry, h);
    if r == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
        return r;
    }
    if r < err {
        err = r
    }
    /* Handle POSIX ustar fields. */
    if _archive_entry_copy_uname_l_safe(
        entry,
        unsafe { *header }.uname.as_ptr(),
        ::std::mem::size_of::<[i8; 32]>() as u64,
        safe_tar.sconv,
    ) != 0 as i32
    {
        err =
            set_conversion_failed_error(a, safe_tar.sconv, b"Uname\x00" as *const u8 as *const i8);
        if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
            return err;
        }
    }
    if _archive_entry_copy_gname_l_safe(
        entry,
        unsafe { *header }.gname.as_ptr(),
        ::std::mem::size_of::<[i8; 32]>() as u64,
        safe_tar.sconv,
    ) != 0 as i32
    {
        err =
            set_conversion_failed_error(a, safe_tar.sconv, b"Gname\x00" as *const u8 as *const i8);
        if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
            return err;
        }
    }
    /* Parse out device numbers only for char and block specials. */
    if unsafe { *header }.typeflag[0 as i32 as usize] as i32 == '3' as i32
        || unsafe { (*header) }.typeflag[0 as i32 as usize] as i32 == '4' as i32
    {
        archive_entry_set_rdevmajor_safe(
            entry,
            tar_atol(
                unsafe { *header }.rdevmajor.as_ptr(),
                ::std::mem::size_of::<[i8; 8]>() as u64,
            ) as dev_t,
        );
        archive_entry_set_rdevminor_safe(
            entry,
            tar_atol(
                unsafe { *header }.rdevminor.as_ptr(),
                ::std::mem::size_of::<[i8; 8]>() as u64,
            ) as dev_t,
        );
    }
    safe_tar.entry_padding = 0x1ff as i32 as i64 & -safe_tar.entry_bytes_remaining;
    return err;
}
/*
 * Parse the pax extended attributes record.
 *
 * Returns non-zero if there's an error in the data.
 */
unsafe fn pax_header(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut in_as: *mut archive_string,
) -> i32 {
    let mut attr_length: size_t = 0;
    let mut l: size_t = 0;
    let mut line_length: size_t = 0;
    let mut value_length: size_t = 0;
    let mut p: *mut i8 = 0 as *mut i8;
    let mut key: *mut i8 = 0 as *mut i8;
    let mut value: *mut i8 = 0 as *mut i8;
    let mut as_0: *mut archive_string = 0 as *mut archive_string;
    let mut sconv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    let mut err: i32 = 0;
    let mut err2: i32 = 0;
    let mut safe_in_as = unsafe { &mut *in_as };
    let mut safe_tar = unsafe { &mut *tar };
    let mut safe_a = unsafe { &mut *a };
    let mut safe_as_0 = unsafe { &mut *as_0 };
    let mut attr: *mut i8 = safe_in_as.s;
    attr_length = safe_in_as.length;
    safe_tar.pax_hdrcharset_binary = 0 as i32;
    safe_tar.entry_gname.length = 0 as i32 as size_t;
    safe_tar.entry_linkpath.length = 0 as i32 as size_t;
    safe_tar.entry_pathname.length = 0 as i32 as size_t;
    safe_tar.entry_pathname_override.length = 0 as i32 as size_t;
    safe_tar.entry_uname.length = 0 as i32 as size_t;
    err = 0 as i32;
    while attr_length > 0 as i32 as u64 {
        /* Parse decimal length field at start of line. */
        line_length = 0 as i32 as size_t; /* Record start of line. */
        l = attr_length;
        p = attr;
        while l > 0 as i32 as u64 {
            if unsafe { *p as i32 } == ' ' as i32 {
                unsafe { p = p.offset(1) };
                l = l.wrapping_sub(1);
                break;
            } else {
                if unsafe { (*p as i32) < '0' as i32 || *p as i32 > '9' as i32 } {
                    archive_set_error_safe!(
                        &mut safe_a.archive as *mut archive,
                        ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                        b"Ignoring malformed pax extended attributes\x00" as *const u8 as *const i8
                    );
                    return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
                }
                line_length =
                    (line_length as u64).wrapping_mul(10 as i32 as u64) as size_t as size_t;
                line_length = (line_length as u64)
                    .wrapping_add((unsafe { *p as i32 } - '0' as i32) as u64)
                    as size_t as size_t;
                if line_length > 999999 as i32 as u64 {
                    archive_set_error_safe!(
                        &mut safe_a.archive as *mut archive,
                        ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                        b"Rejecting pax extended attribute > 1MB\x00" as *const u8 as *const i8
                    );
                    return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
                }
                unsafe { p = p.offset(1) };
                l = l.wrapping_sub(1)
            }
        }
        /*
         * Parsed length must be no bigger than available data,
         * at least 1, and the last character of the line must
         * be '\n'.
         */
        if line_length > attr_length
            || line_length < 1 as i32 as u64
            || unsafe { *attr.offset(line_length.wrapping_sub(1 as i32 as u64) as isize) as i32 }
                != '\n' as i32
        {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                b"Ignoring malformed pax extended attribute\x00" as *const u8 as *const i8
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
        }
        /* Null-terminate the line. */
        unsafe {
            *attr.offset(line_length.wrapping_sub(1 as i32 as u64) as isize) = '\u{0}' as i32 as i8
        };
        /* Find end of key and null terminate it. */
        key = p;
        if unsafe { *key.offset(0 as i32 as isize) as i32 } == '=' as i32 {
            return -(1 as i32);
        }
        unsafe {
            while *p as i32 != 0 && *p as i32 != '=' as i32 {
                p = p.offset(1)
            }
        }
        if unsafe { *p as i32 } == '\u{0}' as i32 {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                b"Invalid pax extended attributes\x00" as *const u8 as *const i8
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
        }
        unsafe {
            *p = '\u{0}' as i32 as i8;
            value = p.offset(1 as i32 as isize)
        };
        /* Some values may be binary data */
        value_length = unsafe {
            attr.offset(line_length as isize)
                .offset(-(1 as i32 as isize))
                .offset_from(value) as i64 as size_t
        };
        /* Identify this attribute and set it in the entry. */
        err2 = pax_attribute(a, tar, entry, key, value, value_length);
        if err2 == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
            return err2;
        }
        err = if err < err2 { err } else { err2 };
        /* Skip to next line */
        unsafe { attr = attr.offset(line_length as isize) };
        attr_length = (attr_length as u64).wrapping_sub(line_length) as size_t as size_t
    }
    /*
     * PAX format uses UTF-8 as default charset for its metadata
     * unless hdrcharset=BINARY is present in its header.
     * We apply the charset specified by the hdrcharset option only
     * when the hdrcharset attribute(in PAX header) is BINARY because
     * we respect the charset described in PAX header and BINARY also
     * means that metadata(filename,uname and gname) character-set
     * is unknown.
     */
    if safe_tar.pax_hdrcharset_binary != 0 {
        sconv = safe_tar.opt_sconv
    } else {
        sconv = archive_string_conversion_from_charset_safe(
            &mut safe_a.archive,
            b"UTF-8\x00" as *const u8 as *const i8,
            1 as i32,
        );
        if sconv.is_null() {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
        if safe_tar.compat_2x != 0 {
            archive_string_conversion_set_opt_safe(
                sconv,
                ARCHIVE_TAR_DEFINED_PARAM.sconv_set_opt_utf8_libarchive2x,
            );
        }
    }
    if safe_tar.entry_gname.length > 0 as i32 as u64 {
        if _archive_entry_copy_gname_l_safe(
            entry,
            safe_tar.entry_gname.s,
            safe_tar.entry_gname.length,
            sconv,
        ) != 0 as i32
        {
            err = set_conversion_failed_error(a, sconv, b"Gname\x00" as *const u8 as *const i8);
            if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
                return err;
            }
            /* Use a converted an original name. */
            archive_entry_copy_gname_safe(entry, safe_tar.entry_gname.s);
        }
    }
    if safe_tar.entry_linkpath.length > 0 as i32 as u64 {
        if _archive_entry_copy_link_l_safe(
            entry,
            safe_tar.entry_linkpath.s,
            safe_tar.entry_linkpath.length,
            sconv,
        ) != 0 as i32
        {
            err = set_conversion_failed_error(a, sconv, b"Linkname\x00" as *const u8 as *const i8);
            if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
                return err;
            }
            /* Use a converted an original name. */
            archive_entry_copy_link_safe(entry, safe_tar.entry_linkpath.s);
        }
    }
    /*
     * Some extensions (such as the GNU sparse file extensions)
     * deliberately store a synthetic name under the regular 'path'
     * attribute and the real file name under a different attribute.
     * Since we're supposed to not care about the order, we
     * have no choice but to store all of the various filenames
     * we find and figure it all out afterwards.  This is the
     * figuring out part.
     */
    as_0 = 0 as *mut archive_string;
    safe_as_0 = unsafe { &mut *as_0 };
    if safe_tar.entry_pathname_override.length > 0 as i32 as u64 {
        as_0 = &mut safe_tar.entry_pathname_override;
        safe_as_0 = unsafe { &mut *as_0 };
    } else if safe_tar.entry_pathname.length > 0 as i32 as u64 {
        as_0 = &mut safe_tar.entry_pathname;
        safe_as_0 = unsafe { &mut *as_0 };
    }
    if !as_0.is_null() {
        if _archive_entry_copy_pathname_l_safe(entry, safe_as_0.s, safe_as_0.length, sconv)
            != 0 as i32
        {
            err = set_conversion_failed_error(a, sconv, b"Pathname\x00" as *const u8 as *const i8);
            if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
                return err;
            }
            /* Use a converted an original name. */
            archive_entry_copy_pathname_safe(entry, safe_as_0.s);
        }
    }
    if safe_tar.entry_uname.length > 0 as i32 as u64 {
        if _archive_entry_copy_uname_l_safe(
            entry,
            safe_tar.entry_uname.s,
            safe_tar.entry_uname.length,
            sconv,
        ) != 0 as i32
        {
            err = set_conversion_failed_error(a, sconv, b"Uname\x00" as *const u8 as *const i8);
            if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
                return err;
            }
            /* Use a converted an original name. */
            archive_entry_copy_uname_safe(entry, safe_tar.entry_uname.s);
        }
    }
    return err;
}
unsafe fn pax_attribute_xattr(
    mut entry: *mut archive_entry,
    mut name: *const i8,
    mut value: *const i8,
) -> i32 {
    let mut name_decoded: *mut i8 = 0 as *mut i8;
    let mut value_decoded: *mut () = 0 as *mut ();
    let mut value_len: size_t = 0;
    if strlen_safe(name) < 18 as i32 as u64
        || memcmp_safe(
            name as *const (),
            b"LIBARCHIVE.xattr.\x00" as *const u8 as *const i8 as *const (),
            17 as i32 as u64,
        ) != 0 as i32
    {
        return 3 as i32;
    }
    unsafe { name = name.offset(17 as i32 as isize) };
    /* URL-decode name */
    name_decoded = url_decode(name);
    if name_decoded.is_null() {
        return 2 as i32;
    }
    /* Base-64 decode value */
    value_decoded = base64_decode(value, strlen_safe(value), &mut value_len) as *mut ();
    if value_decoded.is_null() {
        free_safe(name_decoded as *mut ());
        return 1 as i32;
    }
    archive_entry_xattr_add_entry_safe(entry, name_decoded, value_decoded, value_len);
    free_safe(name_decoded as *mut ());
    free_safe(value_decoded);
    return 0 as i32;
}
unsafe fn pax_attribute_schily_xattr(
    mut entry: *mut archive_entry,
    mut name: *const i8,
    mut value: *const i8,
    mut value_length: size_t,
) -> i32 {
    if strlen_safe(name) < 14 as i32 as u64
        || memcmp_safe(
            name as *const (),
            b"SCHILY.xattr.\x00" as *const u8 as *const i8 as *const (),
            13 as i32 as u64,
        ) != 0 as i32
    {
        return 1 as i32;
    }
    unsafe { name = name.offset(13 as i32 as isize) };
    archive_entry_xattr_add_entry_safe(entry, name, value as *const (), value_length);
    return 0 as i32;
}
unsafe fn pax_attribute_rht_security_selinux(
    mut entry: *mut archive_entry,
    mut value: *const i8,
    mut value_length: size_t,
) -> i32 {
    archive_entry_xattr_add_entry_safe(
        entry,
        b"security.selinux\x00" as *const u8 as *const i8,
        value as *const (),
        value_length,
    );
    return 0 as i32;
}
unsafe fn pax_attribute_acl(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut value: *const i8,
    mut type_0: i32,
) -> i32 {
    let mut r: i32 = 0;
    let mut safe_tar = unsafe { &mut *tar };
    let mut safe_a = unsafe { &mut *a };
    let mut errstr: *const i8 = 0 as *const i8;
    match type_0 {
        256 => errstr = b"SCHILY.acl.access\x00" as *const u8 as *const i8,
        512 => errstr = b"SCHILY.acl.default\x00" as *const u8 as *const i8,
        15360 => errstr = b"SCHILY.acl.ace\x00" as *const u8 as *const i8,
        _ => {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                b"Unknown ACL type: %d\x00" as *const u8 as *const i8,
                type_0
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
    }
    if safe_tar.sconv_acl.is_null() {
        safe_tar.sconv_acl = archive_string_conversion_from_charset_safe(
            &mut safe_a.archive,
            b"UTF-8\x00" as *const u8 as *const i8,
            1 as i32,
        );
        if safe_tar.sconv_acl.is_null() {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
    }
    r = archive_acl_from_text_l_safe(
        archive_entry_acl_safe(entry),
        value,
        type_0,
        safe_tar.sconv_acl,
    );
    if r != ARCHIVE_TAR_DEFINED_PARAM.archive_ok {
        if r == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.enomem,
                b"%s %s\x00" as *const u8 as *const i8,
                b"Can\'t allocate memory for \x00" as *const u8 as *const i8,
                errstr
            );
            return r;
        }
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
            b"%s %s\x00" as *const u8 as *const i8,
            b"Parse error: \x00" as *const u8 as *const i8,
            errstr
        );
    }
    return r;
}
/*
 * Parse a single key=value attribute.  key/value pointers are
 * assumed to point into reasonably long-lived storage.
 *
 * Note that POSIX reserves all-lowercase keywords.  Vendor-specific
 * extensions should always have keywords of the form "VENDOR.attribute"
 * In particular, it's quite feasible to support many different
 * vendor extensions here.  I'm using "LIBARCHIVE" for extensions
 * unique to this library.
 *
 * Investigate other vendor-specific extensions and see if
 * any of them look useful.
 */
unsafe fn pax_attribute(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut key: *const i8,
    mut value: *const i8,
    mut value_length: size_t,
) -> i32 {
    let mut s: int64_t = 0; /* Disable compiler warning; do not pass
                             * NULL pointer to strlen_safe().  */
    let mut n: i64 = 0;
    let mut err: i32 = ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
    let mut r: i32 = 0;
    let mut safe_tar = unsafe { &mut *tar };
    let mut safe_a = unsafe { &mut *a };
    if value.is_null() {
        value = b"\x00" as *const u8 as *const i8
    }
    match unsafe { *key.offset(0 as i32 as isize) } as i32 {
        71 => {
            /* Reject GNU.sparse.* headers on non-regular files. */
            if strncmp_safe(
                key,
                b"GNU.sparse\x00" as *const u8 as *const i8,
                10 as i32 as u64,
            ) == 0 as i32
                && safe_tar.sparse_allowed == 0
            {
                archive_set_error_safe!(
                    &mut safe_a.archive as *mut archive,
                    ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                    b"Non-regular file cannot be sparse\x00" as *const u8 as *const i8
                );
                return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
            }
            /* GNU "0.0" sparse pax format. */
            if strcmp_safe(key, b"GNU.sparse.numblocks\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.sparse_offset = -(1 as i32) as int64_t;
                safe_tar.sparse_numbytes = -(1 as i32) as int64_t;
                safe_tar.sparse_gnu_major = 0 as i32;
                safe_tar.sparse_gnu_minor = 0 as i32
            }
            if strcmp_safe(key, b"GNU.sparse.offset\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.sparse_offset = tar_atol10(value, strlen_safe(value));
                if safe_tar.sparse_numbytes != -(1 as i32) as i64 {
                    if gnu_add_sparse_entry(
                        a,
                        tar,
                        safe_tar.sparse_offset,
                        safe_tar.sparse_numbytes,
                    ) != ARCHIVE_TAR_DEFINED_PARAM.archive_ok
                    {
                        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
                    }
                    safe_tar.sparse_offset = -(1 as i32) as int64_t;
                    safe_tar.sparse_numbytes = -(1 as i32) as int64_t
                }
            }
            if strcmp_safe(key, b"GNU.sparse.numbytes\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.sparse_numbytes = tar_atol10(value, strlen_safe(value));
                if safe_tar.sparse_offset != -(1 as i32) as i64 {
                    if gnu_add_sparse_entry(
                        a,
                        tar,
                        safe_tar.sparse_offset,
                        safe_tar.sparse_numbytes,
                    ) != ARCHIVE_TAR_DEFINED_PARAM.archive_ok
                    {
                        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
                    }
                    safe_tar.sparse_offset = -(1 as i32) as int64_t;
                    safe_tar.sparse_numbytes = -(1 as i32) as int64_t
                }
            }
            if strcmp_safe(key, b"GNU.sparse.size\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.realsize = tar_atol10(value, strlen_safe(value));
                archive_entry_set_size_safe(entry, safe_tar.realsize);
                safe_tar.realsize_override = 1 as i32
            }
            /* GNU "0.1" sparse pax format. */
            if strcmp_safe(key, b"GNU.sparse.map\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.sparse_gnu_major = 0 as i32;
                safe_tar.sparse_gnu_minor = 1 as i32;
                if gnu_sparse_01_parse(a, tar, value) != ARCHIVE_TAR_DEFINED_PARAM.archive_ok {
                    return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
                }
            }
            /* GNU "1.0" sparse pax format */
            if strcmp_safe(key, b"GNU.sparse.major\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.sparse_gnu_major = tar_atol10(value, strlen_safe(value)) as i32;
                safe_tar.sparse_gnu_pending = 1 as i32 as i8
            }
            if strcmp_safe(key, b"GNU.sparse.minor\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.sparse_gnu_minor = tar_atol10(value, strlen_safe(value)) as i32;
                safe_tar.sparse_gnu_pending = 1 as i32 as i8
            }
            if strcmp_safe(key, b"GNU.sparse.name\x00" as *const u8 as *const i8) == 0 as i32 {
                /*
                 * The real filename; when storing sparse
                 * files, GNU tar puts a synthesized name into
                 * the regular 'path' attribute in an attempt
                 * to limit confusion. ;-)
                 */
                safe_tar.entry_pathname_override.length = 0 as i32 as size_t;
                archive_strncat_safe(
                    &mut safe_tar.entry_pathname_override,
                    value as *const (),
                    (if value.is_null() {
                        0 as i32 as u64
                    } else {
                        strlen_safe(value)
                    }),
                );
            }
            if strcmp_safe(key, b"GNU.sparse.realsize\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.realsize = tar_atol10(value, strlen_safe(value));
                archive_entry_set_size_safe(entry, safe_tar.realsize);
                safe_tar.realsize_override = 1 as i32
            }
        }
        76 => {
            /* Our extensions */
            /* TODO: Handle arbitrary extended attributes... */
            /*
                    if (strcmp_safe(key, "LIBARCHIVE.xxxxxxx") == 0)
                        archive_entry_set_xxxxxx(entry, value);
            */
            if strcmp_safe(
                key,
                b"LIBARCHIVE.creationtime\x00" as *const u8 as *const i8,
            ) == 0 as i32
            {
                pax_time(value, &mut s, &mut n);
                archive_entry_set_birthtime_safe(entry, s, n);
            }
            if strcmp_safe(key, b"LIBARCHIVE.symlinktype\x00" as *const u8 as *const i8) == 0 as i32
            {
                if strcmp_safe(value, b"file\x00" as *const u8 as *const i8) == 0 as i32 {
                    archive_entry_set_symlink_type_safe(
                        entry,
                        ARCHIVE_TAR_DEFINED_PARAM.ae_symlink_type_file,
                    );
                } else if strcmp_safe(value, b"dir\x00" as *const u8 as *const i8) == 0 as i32 {
                    archive_entry_set_symlink_type_safe(
                        entry,
                        ARCHIVE_TAR_DEFINED_PARAM.ae_symlink_type_directory,
                    );
                }
            }
            if memcmp_safe(
                key as *const (),
                b"LIBARCHIVE.xattr.\x00" as *const u8 as *const i8 as *const (),
                17 as i32 as u64,
            ) == 0 as i32
            {
                pax_attribute_xattr(entry, key, value);
            }
        }
        82 => {
            /* GNU tar uses RHT.security header to store SELinux xattrs
             * SCHILY.xattr.security.selinux == RHT.security.selinux */
            if strcmp_safe(key, b"RHT.security.selinux\x00" as *const u8 as *const i8) == 0 as i32 {
                pax_attribute_rht_security_selinux(entry, value, value_length);
            }
        }
        83 => {
            /* We support some keys used by the "star" archiver */
            if strcmp_safe(key, b"SCHILY.acl.access\x00" as *const u8 as *const i8) == 0 as i32 {
                r = pax_attribute_acl(
                    a,
                    tar,
                    entry,
                    value,
                    ARCHIVE_TAR_DEFINED_PARAM.archive_entry_acl_type_access,
                );
                if r == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
                    return r;
                }
            } else if strcmp_safe(key, b"SCHILY.acl.default\x00" as *const u8 as *const i8)
                == 0 as i32
            {
                r = pax_attribute_acl(
                    a,
                    tar,
                    entry,
                    value,
                    ARCHIVE_TAR_DEFINED_PARAM.archive_entry_acl_type_default,
                );
                if r == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
                    return r;
                }
            } else if strcmp_safe(key, b"SCHILY.acl.ace\x00" as *const u8 as *const i8) == 0 as i32
            {
                r = pax_attribute_acl(
                    a,
                    tar,
                    entry,
                    value,
                    ARCHIVE_TAR_DEFINED_PARAM.archive_entry_acl_type_nfs4,
                );
                if r == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
                    return r;
                }
            } else if strcmp_safe(key, b"SCHILY.devmajor\x00" as *const u8 as *const i8) == 0 as i32
            {
                archive_entry_set_rdevmajor_safe(
                    entry,
                    tar_atol10(value, strlen_safe(value)) as dev_t,
                );
            } else if strcmp_safe(key, b"SCHILY.devminor\x00" as *const u8 as *const i8) == 0 as i32
            {
                archive_entry_set_rdevminor_safe(
                    entry,
                    tar_atol10(value, strlen_safe(value)) as dev_t,
                );
            } else if strcmp_safe(key, b"SCHILY.fflags\x00" as *const u8 as *const i8) == 0 as i32 {
                archive_entry_copy_fflags_text_safe(entry, value);
            } else if strcmp_safe(key, b"SCHILY.dev\x00" as *const u8 as *const i8) == 0 as i32 {
                archive_entry_set_dev_safe(entry, tar_atol10(value, strlen_safe(value)) as dev_t);
            } else if strcmp_safe(key, b"SCHILY.ino\x00" as *const u8 as *const i8) == 0 as i32 {
                archive_entry_set_ino_safe(entry, tar_atol10(value, strlen_safe(value)));
            } else if strcmp_safe(key, b"SCHILY.nlink\x00" as *const u8 as *const i8) == 0 as i32 {
                archive_entry_set_nlink_safe(entry, tar_atol10(value, strlen_safe(value)) as u32);
            } else if strcmp_safe(key, b"SCHILY.realsize\x00" as *const u8 as *const i8) == 0 as i32
            {
                safe_tar.realsize = tar_atol10(value, strlen_safe(value));
                safe_tar.realsize_override = 1 as i32;
                archive_entry_set_size_safe(entry, safe_tar.realsize);
            } else if strncmp_safe(
                key,
                b"SCHILY.xattr.\x00" as *const u8 as *const i8,
                13 as i32 as u64,
            ) == 0 as i32
            {
                pax_attribute_schily_xattr(entry, key, value, value_length);
            } else if strcmp_safe(key, b"SUN.holesdata\x00" as *const u8 as *const i8) == 0 as i32 {
                /* A Solaris extension for sparse. */
                r = solaris_sparse_parse(a, tar, entry, value);
                if r < err {
                    if r == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
                        return r;
                    }
                    err = r;
                    archive_set_error_safe!(
                        &mut safe_a.archive as *mut archive,
                        ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
                        b"Parse error: SUN.holesdata\x00" as *const u8 as *const i8
                    );
                }
            }
        }
        97 => {
            if strcmp_safe(key, b"atime\x00" as *const u8 as *const i8) == 0 as i32 {
                pax_time(value, &mut s, &mut n);
                archive_entry_set_atime_safe(entry, s, n);
            }
        }
        99 => {
            if strcmp_safe(key, b"ctime\x00" as *const u8 as *const i8) == 0 as i32 {
                pax_time(value, &mut s, &mut n);
                archive_entry_set_ctime_safe(entry, s, n);
            } else if !(strcmp_safe(key, b"charset\x00" as *const u8 as *const i8) == 0 as i32) {
                (strcmp_safe(key, b"comment\x00" as *const u8 as *const i8)) == 0 as i32;
            }
        }
        103 => {
            if strcmp_safe(key, b"gid\x00" as *const u8 as *const i8) == 0 as i32 {
                archive_entry_set_gid_safe(entry, tar_atol10(value, strlen_safe(value)));
            } else if strcmp_safe(key, b"gname\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.entry_gname.length = 0 as i32 as size_t;
                archive_strncat_safe(
                    &mut safe_tar.entry_gname,
                    value as *const (),
                    (if value.is_null() {
                        0 as i32 as u64
                    } else {
                        strlen_safe(value)
                    }),
                );
            }
        }
        104 => {
            if strcmp_safe(key, b"hdrcharset\x00" as *const u8 as *const i8) == 0 as i32 {
                if strcmp_safe(value, b"BINARY\x00" as *const u8 as *const i8) == 0 as i32 {
                    /* Binary  mode. */
                    safe_tar.pax_hdrcharset_binary = 1 as i32
                } else if strcmp_safe(
                    value,
                    b"ISO-IR 10646 2000 UTF-8\x00" as *const u8 as *const i8,
                ) == 0 as i32
                {
                    safe_tar.pax_hdrcharset_binary = 0 as i32
                }
            }
        }
        108 => {
            /* pax interchange doesn't distinguish hardlink vs. symlink. */
            if strcmp_safe(key, b"linkpath\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.entry_linkpath.length = 0 as i32 as size_t;
                archive_strncat_safe(
                    &mut safe_tar.entry_linkpath,
                    value as *const (),
                    (if value.is_null() {
                        0 as i32 as u64
                    } else {
                        strlen_safe(value)
                    }),
                );
            }
        }
        109 => {
            if strcmp_safe(key, b"mtime\x00" as *const u8 as *const i8) == 0 as i32 {
                pax_time(value, &mut s, &mut n);
                archive_entry_set_mtime_safe(entry, s, n);
            }
        }
        112 => {
            if strcmp_safe(key, b"path\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.entry_pathname.length = 0 as i32 as size_t;
                archive_strncat_safe(
                    &mut safe_tar.entry_pathname,
                    value as *const (),
                    (if value.is_null() {
                        0 as i32 as u64
                    } else {
                        strlen_safe(value)
                    }),
                );
            }
        }
        115 => {
            /* POSIX has reserved 'security.*' */
            /* Someday: if (strcmp_safe(key, "security.acl") == 0) { ... } */
            if strcmp_safe(key, b"size\x00" as *const u8 as *const i8) == 0 as i32 {
                /* "size" is the size of the data in the entry. */
                safe_tar.entry_bytes_remaining = tar_atol10(value, strlen_safe(value));
                /*
                 * The "size" pax header keyword always overrides the
                 * "size" field in the tar header.
                 * GNU.sparse.realsize, GNU.sparse.size and
                 * SCHILY.realsize override this value.
                 */
                if safe_tar.realsize_override == 0 {
                    archive_entry_set_size_safe(entry, safe_tar.entry_bytes_remaining);
                    safe_tar.realsize = safe_tar.entry_bytes_remaining
                }
            }
        }
        117 => {
            if strcmp_safe(key, b"uid\x00" as *const u8 as *const i8) == 0 as i32 {
                archive_entry_set_uid_safe(entry, tar_atol10(value, strlen_safe(value)));
            } else if strcmp_safe(key, b"uname\x00" as *const u8 as *const i8) == 0 as i32 {
                safe_tar.entry_uname.length = 0 as i32 as size_t;
                archive_strncat_safe(
                    &mut safe_tar.entry_uname,
                    value as *const (),
                    (if value.is_null() {
                        0 as i32 as u64
                    } else {
                        strlen_safe(value)
                    }),
                );
            }
        }
        114 | _ => {}
    }
    return err;
}
/*
 * parse a decimal time value, which may include a fractional portion
 */
unsafe fn pax_time(mut p: *const i8, mut ps: *mut int64_t, mut pn: *mut i64) {
    let mut digit: i8 = 0;
    let mut s: int64_t = 0;
    let mut l: u64 = 0;
    let mut sign: i32 = 0;
    let mut limit: int64_t = 0;
    let mut last_digit_limit: int64_t = 0;
    limit = 9223372036854775807 as i64 / 10 as i32 as i64;
    last_digit_limit = 9223372036854775807 as i64 % 10 as i32 as i64;
    s = 0 as i32 as int64_t;
    sign = 1 as i32;
    if unsafe { *p as i32 } == '-' as i32 {
        sign = -(1 as i32);
        unsafe { p = p.offset(1) }
    }
    while unsafe { *p as i32 >= '0' as i32 && *p as i32 <= '9' as i32 } {
        digit = unsafe { (*p as i32 - '0' as i32) } as i8;
        if s > limit || s == limit && digit as i64 > last_digit_limit {
            s = 9223372036854775807 as i64;
            break;
        } else {
            s = s * 10 as i32 as i64 + digit as i64;
            unsafe { p = p.offset(1) }
        }
    }
    unsafe { *ps = s * sign as i64 };
    /* Calculate nanoseconds. */
    unsafe { *pn = 0 as i32 as i64 };
    if unsafe { *p as i32 } != '.' as i32 {
        return;
    }
    l = 100000000 as u64;
    loop {
        unsafe { p = p.offset(1) };
        if !unsafe { (*p as i32 >= '0' as i32 && *p as i32 <= '9' as i32) } {
            break;
        }
        unsafe {
            *pn = (*pn as u64).wrapping_add(((*p as i32 - '0' as i32) as u64).wrapping_mul(l))
                as i64 as i64
        };
        l = l.wrapping_div(10 as i32 as u64);
        if !(l != 0) {
            break;
        }
    }
}
/*
 * Parse GNU tar header
 */
unsafe fn header_gnutar(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut h: *const (),
    mut unconsumed: *mut size_t,
) -> i32 {
    let mut header: *const archive_entry_header_gnutar = 0 as *const archive_entry_header_gnutar;
    let mut t: int64_t = 0;
    let mut err: i32 = ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
    let mut safe_tar = unsafe { &mut *tar };
    /*
     * GNU header is like POSIX ustar, except 'prefix' is
     * replaced with some other fields. This also means the
     * filename is stored as in old-style archives.
     */
    /* Grab fields common to all tar variants. */
    err = header_common(a, tar, entry, h);
    if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
        return err;
    }
    /* Copy filename over (to ensure null termination). */
    header = h as *const archive_entry_header_gnutar;
    if _archive_entry_copy_pathname_l_safe(
        entry,
        unsafe { *header }.name.as_ptr(),
        ::std::mem::size_of::<[i8; 100]>() as u64,
        safe_tar.sconv,
    ) != 0 as i32
    {
        err = set_conversion_failed_error(
            a,
            safe_tar.sconv,
            b"Pathname\x00" as *const u8 as *const i8,
        );
        if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
            return err;
        }
    }
    /* Fields common to ustar and GNU */
    /* XXX Can the following be factored out since it's common
     * to ustar and gnu tar?  Is it okay to move it down into
     * header_common, perhaps?  */
    if _archive_entry_copy_uname_l_safe(
        entry,
        unsafe { *header }.uname.as_ptr(),
        ::std::mem::size_of::<[i8; 32]>() as u64,
        safe_tar.sconv,
    ) != 0 as i32
    {
        err =
            set_conversion_failed_error(a, safe_tar.sconv, b"Uname\x00" as *const u8 as *const i8);
        if err == ARCHIVE_TAR_DEFINED_PARAM.archive_fatal {
            return err;
        }
    }
    if _archive_entry_copy_gname_l_safe(
        entry,
        unsafe { *header }.gname.as_ptr(),
        ::std::mem::size_of::<[i8; 32]>() as u64,
        safe_tar.sconv,
    ) != 0 as i32
    {
        err =
            set_conversion_failed_error(a, safe_tar.sconv, b"Gname\x00" as *const u8 as *const i8);
        if err == -(30 as i32) {
            return err;
        }
    }
    /* Parse out device numbers only for char and block specials */
    if unsafe { *header }.typeflag[0 as i32 as usize] as i32 == '3' as i32
        || unsafe { *header }.typeflag[0 as i32 as usize] as i32 == '4' as i32
    {
        archive_entry_set_rdevmajor_safe(
            entry,
            tar_atol(
                unsafe { *header }.rdevmajor.as_ptr(),
                ::std::mem::size_of::<[i8; 8]>() as u64,
            ) as dev_t,
        );
        archive_entry_set_rdevminor_safe(
            entry,
            tar_atol(
                unsafe { *header }.rdevminor.as_ptr(),
                ::std::mem::size_of::<[i8; 8]>() as u64,
            ) as dev_t,
        );
    } else {
        archive_entry_set_rdev_safe(entry, 0 as i32 as dev_t);
    }
    safe_tar.entry_padding = 0x1ff as i32 as i64 & -safe_tar.entry_bytes_remaining;
    /* Grab GNU-specific fields. */
    t = tar_atol(
        unsafe { *header }.atime.as_ptr(),
        ::std::mem::size_of::<[i8; 12]>() as u64,
    );
    if t > 0 as i32 as i64 {
        archive_entry_set_atime_safe(entry, t, 0 as i32 as i64);
    }
    t = tar_atol(
        unsafe { *header }.ctime.as_ptr(),
        ::std::mem::size_of::<[i8; 12]>() as u64,
    );
    if t > 0 as i32 as i64 {
        archive_entry_set_ctime_safe(entry, t, 0 as i32 as i64);
    }
    if unsafe { *header }.realsize[0 as i32 as usize] as i32 != 0 as i32 {
        safe_tar.realsize = tar_atol(
            unsafe { *header }.realsize.as_ptr(),
            ::std::mem::size_of::<[i8; 12]>() as u64,
        );
        archive_entry_set_size_safe(entry, safe_tar.realsize);
        safe_tar.realsize_override = 1 as i32
    }
    if unsafe { *header }.sparse[0 as i32 as usize].offset[0 as i32 as usize] as i32 != 0 as i32 {
        if gnu_sparse_old_read(a, tar, header, unconsumed) != ARCHIVE_TAR_DEFINED_PARAM.archive_ok {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
    } else {
        (unsafe { *header }.isextended[0 as i32 as usize] as i32) != 0 as i32;
    }
    return err;
}
unsafe fn gnu_add_sparse_entry(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut offset: int64_t,
    mut remaining: int64_t,
) -> i32 {
    let mut p: *mut sparse_block = 0 as *mut sparse_block;
    let mut safe_a = unsafe { &mut *a };
    let mut safe_tar = unsafe { &mut *tar };
    p = calloc_safe(
        1 as i32 as u64,
        ::std::mem::size_of::<sparse_block>() as u64,
    ) as *mut sparse_block;
    if p.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            12 as i32,
            b"Out of memory\x00" as *const u8 as *const i8
        );
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    if !safe_tar.sparse_last.is_null() {
        unsafe { (*safe_tar.sparse_last).next = p }
    } else {
        safe_tar.sparse_list = p
    }
    safe_tar.sparse_last = p;
    if remaining < 0 as i32 as i64
        || offset < 0 as i32 as i64
        || offset > 9223372036854775807 as i64 - remaining
    {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_TAR_DEFINED_PARAM.archive_errno_misc,
            b"Malformed sparse map data\x00" as *const u8 as *const i8
        );
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    unsafe { (*p).offset = offset };
    unsafe { (*p).remaining = remaining };
    return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
}
unsafe fn gnu_clear_sparse_list(mut tar: *mut tar) {
    let mut safe_tar = unsafe { &mut *tar };
    let mut p: *mut sparse_block = 0 as *mut sparse_block;
    let mut safe_p = unsafe { &mut *p };
    while !safe_tar.sparse_list.is_null() {
        p = safe_tar.sparse_list;
        safe_p = unsafe { &mut *p };
        safe_tar.sparse_list = safe_p.next;
        free_safe(p as *mut ());
    }
    safe_tar.sparse_last = 0 as *mut sparse_block;
}
/*
 * GNU tar old-format sparse data.
 *
 * GNU old-format sparse data is stored in a fixed-field
 * format.  Offset/size values are 11-byte octal fields (same
 * format as 'size' field in ustart header).  These are
 * stored in the header, allocating subsequent header blocks
 * as needed.  Extending the header in this way is a pretty
 * severe POSIX violation; this design has earned GNU tar a
 * lot of criticism.
 */
unsafe fn gnu_sparse_old_read(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut header: *const archive_entry_header_gnutar,
    mut unconsumed: *mut size_t,
) -> i32 {
    let mut bytes_read: ssize_t = 0;
    let mut data: *const () = 0 as *const ();
    let mut ext: *const extended = 0 as *const extended;
    let mut safe_a = unsafe { &mut *a };
    let mut safe_unconsumed = unsafe { &mut *unconsumed };
    let mut safe_tar = unsafe { &mut *tar };
    if gnu_sparse_old_parse(a, tar, unsafe { (*header).sparse.as_ptr() }, 4 as i32)
        != ARCHIVE_TAR_DEFINED_PARAM.archive_ok
    {
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
    }
    if unsafe { (*header).isextended[0 as i32 as usize] as i32 == 0 as i32 } {
        return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
    }
    loop {
        tar_flush_unconsumed(a, unconsumed);
        data = __archive_read_ahead_safe(a, 512 as i32 as size_t, &mut bytes_read);
        if bytes_read < 0 as i32 as i64 {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
        if bytes_read < 512 as i32 as i64 {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_file_format,
                b"Truncated tar archive detected while reading sparse file data\x00" as *const u8
                    as *const i8
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
        *safe_unconsumed = 512 as i32 as size_t;
        ext = data as *const extended;
        if gnu_sparse_old_parse(a, tar, unsafe { (*ext).sparse.as_ptr() }, 21 as i32)
            != ARCHIVE_TAR_DEFINED_PARAM.archive_ok
        {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
        if !unsafe {
            ((*ext).isextended[0 as i32 as usize] as i32 != ARCHIVE_TAR_DEFINED_PARAM.archive_ok)
        } {
            break;
        }
    }
    if !safe_tar.sparse_list.is_null() {
        safe_tar.entry_offset = unsafe { (*safe_tar.sparse_list).offset }
    }
    return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
}
unsafe fn gnu_sparse_old_parse(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut sparse: *const gnu_sparse,
    mut length: i32,
) -> i32 {
    while length > 0 as i32 && unsafe { (*sparse).offset[0 as i32 as usize] as i32 != 0 as i32 } {
        if gnu_add_sparse_entry(
            a,
            tar,
            tar_atol(
                unsafe { (*sparse).offset.as_ptr() },
                ::std::mem::size_of::<[i8; 12]>() as u64,
            ),
            tar_atol(
                unsafe { (*sparse).numbytes.as_ptr() },
                ::std::mem::size_of::<[i8; 12]>() as u64,
            ),
        ) != ARCHIVE_TAR_DEFINED_PARAM.archive_ok
        {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
        }
        unsafe { sparse = sparse.offset(1) };
        length -= 1
    }
    return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
}
/*
 * GNU tar sparse format 0.0
 *
 * Beginning with GNU tar 1.15, sparse files are stored using
 * information in the pax extended header.  The GNU tar maintainers
 * have gone through a number of variations in the process of working
 * out this scheme; fortunately, they're all numbered.
 *
 * Sparse format 0.0 uses attribute GNU.sparse.numblocks to store the
 * number of blocks, and GNU.sparse.offset/GNU.sparse.numbytes to
 * store offset/size for each block.  The repeated instances of these
 * latter fields violate the pax specification (which frowns on
 * duplicate keys), so this format was quickly replaced.
 */
/*
 * GNU tar sparse format 0.1
 *
 * This version replaced the offset/numbytes attributes with
 * a single "map" attribute that stored a list of integers.  This
 * format had two problems: First, the "map" attribute could be very
 * long, which caused problems for some implementations.  More
 * importantly, the sparse data was lost when extracted by archivers
 * that didn't recognize this extension.
 */
unsafe fn gnu_sparse_01_parse(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut p: *const i8,
) -> i32 {
    let mut e: *const i8 = 0 as *const i8;
    let mut offset: int64_t = -(1 as i32) as int64_t;
    let mut size: int64_t = -(1 as i32) as int64_t;
    loop {
        e = p;
        unsafe {
            while *e as i32 != '\u{0}' as i32 && *e as i32 != ',' as i32 {
                if (*e as i32) < '0' as i32 || *e as i32 > '9' as i32 {
                    return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
                }
                e = e.offset(1)
            }
        }
        if offset < 0 as i32 as i64 {
            offset = tar_atol10(p, unsafe { e.offset_from(p) as i64 as size_t });
            if offset < 0 as i32 as i64 {
                return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
            }
        } else {
            size = tar_atol10(p, unsafe { e.offset_from(p) as i64 as size_t });
            if size < 0 as i32 as i64 {
                return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
            }
            if gnu_add_sparse_entry(a, tar, offset, size) != ARCHIVE_TAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
            }
            offset = -(1 as i32) as int64_t
        }
        if unsafe { *e as i32 == '\u{0}' as i32 } {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
        }
        unsafe { p = e.offset(1 as i32 as isize) }
    }
}
/*
 * GNU tar sparse format 1.0
 *
 * The idea: The offset/size data is stored as a series of base-10
 * ASCII numbers prepended to the file data, so that dearchivers that
 * don't support this format will extract the block map along with the
 * data and a separate post-process can restore the sparseness.
 *
 * Unfortunately, GNU tar 1.16 had a bug that added unnecessary
 * padding to the body of the file when using this format.  GNU tar
 * 1.17 corrected this bug without bumping the version number, so
 * it's not possible to support both variants.  This code supports
 * the later variant at the expense of not supporting the former.
 *
 * This variant also replaced GNU.sparse.size with GNU.sparse.realsize
 * and introduced the GNU.sparse.major/GNU.sparse.minor attributes.
 */
/*
 * Read the next line from the input, and parse it as a decimal
 * integer followed by '\n'.  Returns positive integer value or
 * negative on error.
 */
unsafe fn gnu_sparse_10_atol(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut remaining: *mut int64_t,
    mut unconsumed: *mut size_t,
) -> int64_t {
    let mut l: int64_t = 0;
    let mut limit: int64_t = 0;
    let mut last_digit_limit: int64_t = 0;
    let mut p: *const i8 = 0 as *const i8;
    let mut bytes_read: ssize_t = 0;
    let mut base: i32 = 0;
    let mut digit: i32 = 0;
    let mut safe_remaining = unsafe { &mut *remaining };
    base = 10 as i32;
    limit = 9223372036854775807 as i64 / base as i64;
    last_digit_limit = 9223372036854775807 as i64 % base as i64;
    loop
    /*
     * Skip any lines starting with '#'; GNU tar specs
     * don't require this, but they should.
     */
    {
        bytes_read = readline(
            a,
            tar,
            &mut p,
            if *safe_remaining < 100 as i32 as i64 {
                *safe_remaining
            } else {
                100 as i32 as i64
            },
            unconsumed,
        ); /* Truncate on overflow. */
        if bytes_read <= 0 as i32 as i64 {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as int64_t;
        }
        *safe_remaining -= bytes_read;
        if !unsafe { (*p.offset(0 as i32 as isize) as i32 == '#' as i32) } {
            break;
        }
    }
    l = 0 as i32 as int64_t;
    while bytes_read > 0 as i32 as i64 {
        if unsafe { *p as i32 == '\n' as i32 } {
            return l;
        }
        if unsafe { (*p as i32) < '0' as i32 || *p as i32 >= '0' as i32 + base } {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_warn as int64_t;
        }
        digit = unsafe { *p as i32 - '0' as i32 };
        if l > limit || l == limit && digit as i64 > last_digit_limit {
            l = 9223372036854775807 as i64
        } else {
            l = l * base as i64 + digit as i64
        }
        unsafe { p = p.offset(1) };
        bytes_read -= 1
    }
    /* TODO: Error message. */
    return ARCHIVE_TAR_DEFINED_PARAM.archive_warn as int64_t;
}
/*
 * Returns length (in bytes) of the sparse data description
 * that was read.
 */
unsafe fn gnu_sparse_10_read(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut unconsumed: *mut size_t,
) -> ssize_t {
    let mut bytes_read: ssize_t = 0;
    let mut entries: i32 = 0;
    let mut offset: int64_t = 0;
    let mut size: int64_t = 0;
    let mut to_skip: int64_t = 0;
    let mut remaining: int64_t = 0;
    let mut safe_tar = unsafe { &mut *tar };
    /* Clear out the existing sparse list. */
    gnu_clear_sparse_list(tar);
    remaining = safe_tar.entry_bytes_remaining;
    /* Parse entries. */
    entries = gnu_sparse_10_atol(a, tar, &mut remaining, unconsumed) as i32;
    if entries < 0 as i32 {
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as ssize_t;
    }
    loop
    /* Parse the individual entries. */
    {
        let fresh1 = entries;
        entries = entries - 1;
        if !(fresh1 > 0 as i32) {
            break;
        }
        /* Parse offset/size */
        offset = gnu_sparse_10_atol(a, tar, &mut remaining, unconsumed);
        if offset < 0 as i32 as i64 {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        size = gnu_sparse_10_atol(a, tar, &mut remaining, unconsumed);
        if size < 0 as i32 as i64 {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        /* Add a new sparse entry. */
        if gnu_add_sparse_entry(a, tar, offset, size) != ARCHIVE_TAR_DEFINED_PARAM.archive_ok {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as ssize_t;
        }
    }
    /* Skip rest of block... */
    tar_flush_unconsumed(a, unconsumed);
    bytes_read = safe_tar.entry_bytes_remaining - remaining;
    to_skip = 0x1ff as i32 as i64 & -bytes_read;
    /* Fail if tar->entry_bytes_remaing would get negative */
    if to_skip > remaining {
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as ssize_t;
    }
    if to_skip != __archive_read_consume_safe(a, to_skip) {
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as ssize_t;
    }
    return bytes_read + to_skip;
}
/*
 * Solaris pax extension for a sparse file. This is recorded with the
 * data and hole pairs. The way recording sparse information by Solaris'
 * pax simply indicates where data and sparse are, so the stored contents
 * consist of both data and hole.
 */
unsafe fn solaris_sparse_parse(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut entry: *mut archive_entry,
    mut p: *const i8,
) -> i32 {
    let mut e: *const i8 = 0 as *const i8;
    let mut start: int64_t = 0;
    let mut end: int64_t = 0;
    let mut hole: i32 = 1 as i32;
    /* UNUSED */
    end = 0 as i32 as int64_t;
    if unsafe { *p as i32 == ' ' as i32 } {
        unsafe { p = p.offset(1) }
    } else {
        return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
    }
    loop {
        e = p;
        while unsafe { *e as i32 != '\u{0}' as i32 && *e as i32 != ' ' as i32 } {
            if unsafe { (*e as i32) < '0' as i32 || *e as i32 > '9' as i32 } {
                return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
            }
            unsafe { e = e.offset(1) }
        }
        start = end;
        end = tar_atol10(p, unsafe { e.offset_from(p) as i64 as size_t });
        if end < 0 as i32 as i64 {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_warn;
        }
        if start < end {
            if gnu_add_sparse_entry(a, tar, start, end - start)
                != ARCHIVE_TAR_DEFINED_PARAM.archive_ok
            {
                return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal;
            }
            unsafe { (*(*tar).sparse_last).hole = hole }
        }
        if unsafe { *e as i32 == '\u{0}' as i32 } {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_ok;
        }
        unsafe { p = e.offset(1 as i32 as isize) };
        hole = (hole == 0 as i32) as i32
    }
}
/*-
 * Convert text->integer.
 *
 * Traditional tar formats (including POSIX) specify base-8 for
 * all of the standard numeric fields.  This is a significant limitation
 * in practice:
 *   = file size is limited to 8GB
 *   = rdevmajor and rdevminor are limited to 21 bits
 *   = uid/gid are limited to 21 bits
 *
 * There are two workarounds for this:
 *   = pax extended headers, which use variable-length string fields
 *   = GNU tar and STAR both allow either base-8 or base-256 in
 *      most fields.  The high bit is set to indicate base-256.
 *
 * On read, this implementation supports both extensions.
 */
unsafe fn tar_atol(mut p: *const i8, mut char_cnt: size_t) -> int64_t {
    /*
     * Technically, GNU tar considers a field to be in base-256
     * only if the first byte is 0xff or 0x80.
     */
    if unsafe { *p as i32 & 0x80 as i32 != 0 } {
        return tar_atol256(p, char_cnt);
    }
    return tar_atol8(p, char_cnt);
}
/*
 * Note that this implementation does not (and should not!) obey
 * locale settings; you cannot simply substitute strtol here, since
 * it does obey locale.
 */
unsafe fn tar_atol_base_n(mut p: *const i8, mut char_cnt: size_t, mut base: i32) -> int64_t {
    let mut l: int64_t = 0;
    let mut maxval: int64_t = 0;
    let mut limit: int64_t = 0;
    let mut last_digit_limit: int64_t = 0;
    let mut digit: i32 = 0;
    let mut sign: i32 = 0;
    maxval = 9223372036854775807 as i64;
    limit = 9223372036854775807 as i64 / base as i64;
    last_digit_limit = 9223372036854775807 as i64 % base as i64;
    /* the pointer will not be dereferenced if char_cnt is zero
     * due to the way the && operator is evaluated.
     */
    while char_cnt != 0 as i32 as u64
        && unsafe { (*p as i32 == ' ' as i32 || *p as i32 == '\t' as i32) }
    {
        unsafe { p = p.offset(1) };
        char_cnt = char_cnt.wrapping_sub(1)
    }
    sign = 1 as i32;
    if char_cnt != 0 as i32 as u64 && unsafe { *p as i32 == '-' as i32 } {
        sign = -(1 as i32);
        unsafe { p = p.offset(1) };
        char_cnt = char_cnt.wrapping_sub(1);
        maxval = -(9223372036854775807 as i64) - 1 as i32 as i64;
        limit = -((-(9223372036854775807 as i64) - 1 as i32 as i64) / base as i64);
        last_digit_limit = -((-(9223372036854775807 as i64) - 1 as i32 as i64) % base as i64)
    }
    l = 0 as i32 as int64_t;
    if char_cnt != 0 as i32 as u64 {
        unsafe { digit = *p as i32 - '0' as i32 };
        while digit >= 0 as i32 && digit < base && char_cnt != 0 as i32 as u64 {
            if l > limit || l == limit && digit as i64 >= last_digit_limit {
                return maxval;
                /* Truncate on overflow. */
            }
            l = l * base as i64 + digit as i64;
            unsafe { p = p.offset(1) };
            unsafe { digit = *p as i32 - '0' as i32 };
            char_cnt = char_cnt.wrapping_sub(1)
        }
    }
    return if sign < 0 as i32 { -l } else { l };
}
unsafe fn tar_atol8(mut p: *const i8, mut char_cnt: size_t) -> int64_t {
    return tar_atol_base_n(p, char_cnt, 8 as i32);
}
unsafe fn tar_atol10(mut p: *const i8, mut char_cnt: size_t) -> int64_t {
    return tar_atol_base_n(p, char_cnt, 10 as i32);
}

/*
 * Parse a base-256 integer.  This is just a variable-length
 * twos-complement signed binary value in big-endian order, except
 * that the high-order bit is ignored.  The values here can be up to
 * 12 bytes, so we need to be careful about overflowing 64-bit
 * (8-byte) integers.
 *
 * This code unashamedly assumes that the local machine uses 8-bit
 * bytes and twos-complement arithmetic.
 */
unsafe fn tar_atol256(mut _p: *const i8, mut char_cnt: size_t) -> int64_t {
    let mut l: uint64_t = 0;
    let mut p: *const u8 = _p as *const u8;
    let mut c: u8 = 0;
    let mut neg: u8 = 0;
    /* Extend 7-bit 2s-comp to 8-bit 2s-comp, decide sign. */
    c = unsafe { *p };
    if c as i32 & 0x40 as i32 != 0 {
        neg = 0xff as i32 as u8;
        c = (c as i32 | 0x80 as i32) as u8;
        l = !(0 as u64) as uint64_t
    } else {
        neg = 0 as i32 as u8;
        c = (c as i32 & 0x7f as i32) as u8;
        l = 0 as i32 as uint64_t
    }
    /* If more than 8 bytes, check that we can ignore
     * high-order bits without overflow. */
    while char_cnt > ::std::mem::size_of::<int64_t>() as u64 {
        char_cnt = char_cnt.wrapping_sub(1);
        if c as i32 != neg as i32 {
            return if neg as i32 != 0 {
                (-(9223372036854775807 as i64)) - 1 as i32 as i64
            } else {
                9223372036854775807 as i64
            };
        }
        unsafe { p = p.offset(1) };
        c = unsafe { *p }
    }
    /* c is first byte that fits; if sign mismatch, return overflow */
    if (c as i32 ^ neg as i32) & 0x80 as i32 != 0 {
        return if neg as i32 != 0 {
            (-(9223372036854775807 as i64)) - 1 as i32 as i64
        } else {
            9223372036854775807 as i64
        };
    }
    loop
    /* Accumulate remaining bytes. */
    {
        char_cnt = char_cnt.wrapping_sub(1);
        if !(char_cnt > 0 as i32 as u64) {
            break;
        }
        l = l << 8 as i32 | c as u64;
        unsafe { p = p.offset(1) };
        c = unsafe { *p }
    }
    l = l << 8 as i32 | c as u64;
    /* Return signed twos-complement value. */
    return l as int64_t;
}
/*
 * Returns length of line (including trailing newline)
 * or negative on error.  'start' argument is updated to
 * point to first character of line.  This avoids copying
 * when possible.
 */
unsafe fn readline(
    mut a: *mut archive_read,
    mut tar: *mut tar,
    mut start: *mut *const i8,
    mut limit: ssize_t,
    mut unconsumed: *mut size_t,
) -> ssize_t {
    let mut bytes_read: ssize_t = 0; /* Start of line? */
    let mut total_size: ssize_t = 0 as i32 as ssize_t;
    let mut t: *const () = 0 as *const ();
    let mut s: *const i8 = 0 as *const i8;
    let mut p: *mut () = 0 as *mut ();
    let mut safe_a = unsafe { &mut *a };
    let mut safe_unconsumed = unsafe { &mut *unconsumed };
    let mut safe_start = unsafe { &mut *start };
    let mut safe_tar = unsafe { &mut *tar };
    tar_flush_unconsumed(a, unconsumed);
    t = __archive_read_ahead_safe(a, 1 as i32 as size_t, &mut bytes_read);
    if bytes_read <= 0 as i32 as i64 {
        return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as ssize_t;
    }
    s = t as *const i8;
    p = memchr_safe(t, '\n' as i32, bytes_read as u64);
    /* If we found '\n' in the read buffer, return pointer to that. */
    if !p.is_null() {
        bytes_read = unsafe { (p as *const i8).offset(1 as i32 as isize).offset_from(s) as i64 };
        if bytes_read > limit {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_file_format,
                b"Line too long\x00" as *const u8 as *const i8
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        *safe_unconsumed = bytes_read as size_t;
        *safe_start = s;
        return bytes_read;
    }
    *safe_unconsumed = bytes_read as size_t;
    loop
    /* Otherwise, we need to accumulate in a line buffer. */
    {
        if total_size + bytes_read > limit {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.archive_errno_file_format,
                b"Line too long\x00" as *const u8 as *const i8
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        if archive_string_ensure_safe(&mut safe_tar.line, (total_size + bytes_read) as size_t)
            .is_null()
        {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_TAR_DEFINED_PARAM.enomem,
                b"Can\'t allocate working buffer\x00" as *const u8 as *const i8
            );
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        memcpy_safe(
            unsafe { safe_tar.line.s.offset(total_size as isize) as *mut () },
            t,
            bytes_read as u64,
        );
        tar_flush_unconsumed(a, unconsumed);
        total_size += bytes_read;
        /* If we found '\n', clean up and return. */
        if !p.is_null() {
            *safe_start = safe_tar.line.s;
            return total_size;
        }
        /* Read some more. */
        t = __archive_read_ahead_safe(a, 1 as i32 as size_t, &mut bytes_read); /* Start of line? */
        if bytes_read <= 0 as i32 as i64 {
            return ARCHIVE_TAR_DEFINED_PARAM.archive_fatal as ssize_t;
        }
        s = t as *const i8;
        p = memchr_safe(t, '\n' as i32, bytes_read as u64);
        /* If we found '\n', trim the read. */
        if !p.is_null() {
            bytes_read = unsafe { (p as *const i8).offset(1 as i32 as isize).offset_from(s) as i64 }
        }
        *safe_unconsumed = bytes_read as size_t
    }
}
/*
 * base64_decode - Base64 decode
 *
 * This accepts most variations of base-64 encoding, including:
 *    * with or without line breaks
 *    * with or without the final group padded with '=' or '_' characters
 * (The most economical Base-64 variant does not pad the last group and
 * omits line breaks; RFC1341 used for MIME requires both.)
 */
unsafe fn base64_decode(mut s: *const i8, mut len: size_t, mut out_len: *mut size_t) -> *mut i8 {
    static mut digits: [u8; 64] = [
        'A' as i32 as u8,
        'B' as i32 as u8,
        'C' as i32 as u8,
        'D' as i32 as u8,
        'E' as i32 as u8,
        'F' as i32 as u8,
        'G' as i32 as u8,
        'H' as i32 as u8,
        'I' as i32 as u8,
        'J' as i32 as u8,
        'K' as i32 as u8,
        'L' as i32 as u8,
        'M' as i32 as u8,
        'N' as i32 as u8,
        'O' as i32 as u8,
        'P' as i32 as u8,
        'Q' as i32 as u8,
        'R' as i32 as u8,
        'S' as i32 as u8,
        'T' as i32 as u8,
        'U' as i32 as u8,
        'V' as i32 as u8,
        'W' as i32 as u8,
        'X' as i32 as u8,
        'Y' as i32 as u8,
        'Z' as i32 as u8,
        'a' as i32 as u8,
        'b' as i32 as u8,
        'c' as i32 as u8,
        'd' as i32 as u8,
        'e' as i32 as u8,
        'f' as i32 as u8,
        'g' as i32 as u8,
        'h' as i32 as u8,
        'i' as i32 as u8,
        'j' as i32 as u8,
        'k' as i32 as u8,
        'l' as i32 as u8,
        'm' as i32 as u8,
        'n' as i32 as u8,
        'o' as i32 as u8,
        'p' as i32 as u8,
        'q' as i32 as u8,
        'r' as i32 as u8,
        's' as i32 as u8,
        't' as i32 as u8,
        'u' as i32 as u8,
        'v' as i32 as u8,
        'w' as i32 as u8,
        'x' as i32 as u8,
        'y' as i32 as u8,
        'z' as i32 as u8,
        '0' as i32 as u8,
        '1' as i32 as u8,
        '2' as i32 as u8,
        '3' as i32 as u8,
        '4' as i32 as u8,
        '5' as i32 as u8,
        '6' as i32 as u8,
        '7' as i32 as u8,
        '8' as i32 as u8,
        '9' as i32 as u8,
        '+' as i32 as u8,
        '/' as i32 as u8,
    ];
    static mut decode_table: [u8; 128] = [0; 128];
    let mut out: *mut i8 = 0 as *mut i8;
    let mut d: *mut i8 = 0 as *mut i8;
    let mut src: *const u8 = s as *const u8;
    /* If the decode table is not yet initialized, prepare it. */
    if unsafe { decode_table[digits[1 as i32 as usize] as usize] as i32 } != 1 as i32 {
        let mut i: u32 = 0;
        memset_safe(
            unsafe { decode_table.as_mut_ptr() } as *mut (),
            0xff as i32,
            unsafe { ::std::mem::size_of::<[u8; 128]>() as u64 },
        );
        i = 0 as i32 as u32;
        while (i as u64) < unsafe { ::std::mem::size_of::<[u8; 64]>() as u64 } {
            unsafe { decode_table[digits[i as usize] as usize] = i as u8 };
            i = i.wrapping_add(1)
        }
    }
    /* Allocate enough space to hold the entire output. */
    /* Note that we may not use all of this... */
    out = malloc_safe(
        len.wrapping_sub(len.wrapping_div(4 as i32 as u64))
            .wrapping_add(1 as i32 as u64),
    ) as *mut i8;
    if out.is_null() {
        unsafe { *out_len = 0 as i32 as size_t };
        return 0 as *mut i8;
    }
    d = out;
    while len > 0 as i32 as u64 {
        /* Collect the next group of (up to) four characters. */
        let mut v: i32 = 0 as i32;
        let mut group_size: i32 = 0 as i32;
        while group_size < 4 as i32 && len > 0 as i32 as u64 {
            /* '=' or '_' padding indicates final group. */
            if unsafe { *src as i32 } == '=' as i32 || unsafe { *src as i32 } == '_' as i32 {
                len = 0 as i32 as size_t;
                break;
            } else if unsafe {
                *src as i32 > 127 as i32
                    || (*src as i32) < 32 as i32
                    || decode_table[*src as usize] as i32 == 0xff as i32
            } {
                len = len.wrapping_sub(1);
                src = unsafe { src.offset(1) }
            } else {
                v <<= 6 as i32;
                let fresh2 = src;
                unsafe { src = src.offset(1) };
                v |= unsafe { decode_table[*fresh2 as usize] as i32 };
                len = len.wrapping_sub(1);
                group_size += 1
            }
        }
        /* Skip illegal characters (including line breaks) */
        /* Align a short group properly. */
        v <<= 6 as i32 * (4 as i32 - group_size);
        let mut current_block_23: u64;
        /* Unpack the group we just collected. */
        match group_size {
            4 => {
                unsafe { *d.offset(2 as i32 as isize) = (v & 0xff as i32) as i8 };
                current_block_23 = 13843085778775597086;
            }
            3 => {
                current_block_23 = 13843085778775597086;
            }
            2 => {
                current_block_23 = 10880025040852361420;
            }
            1 | _ => {
                current_block_23 = 8704759739624374314;
            }
        }
        match current_block_23 {
            13843085778775597086 =>
            /* FALLTHROUGH */
            {
                unsafe { *d.offset(1 as i32 as isize) = (v >> 8 as i32 & 0xff as i32) as i8 };
                current_block_23 = 10880025040852361420;
            }
            _ => {}
        }
        match current_block_23 {
            10880025040852361420 =>
            /* FALLTHROUGH */
            unsafe { *d.offset(0 as i32 as isize) = (v >> 16 as i32 & 0xff as i32) as i8 },
            _ => {}
        }
        d = unsafe { d.offset((group_size * 3 as i32 / 4 as i32) as isize) }
    }
    unsafe { *out_len = d.offset_from(out) as i64 as size_t };
    return out;
}
unsafe fn url_decode(mut in_0: *const i8) -> *mut i8 {
    let mut out: *mut i8 = 0 as *mut i8;
    let mut d: *mut i8 = 0 as *mut i8;
    let mut s: *const i8 = 0 as *const i8;
    out = malloc_safe(strlen_safe(in_0).wrapping_add(1 as i32 as u64)) as *mut i8;
    if out.is_null() {
        return 0 as *mut i8;
    }
    s = in_0;
    d = out;
    while unsafe { *s as i32 } != '\u{0}' as i32 {
        if unsafe {
            *s.offset(0 as i32 as isize) as i32 == '%' as i32
                && *s.offset(1 as i32 as isize) as i32 != '\u{0}' as i32
                && *s.offset(2 as i32 as isize) as i32 != '\u{0}' as i32
        } {
            /* Try to convert % escape */
            let mut digit1: i32 = tohex(unsafe { *s.offset(1 as i32 as isize) as i32 });
            let mut digit2: i32 = tohex(unsafe { *s.offset(2 as i32 as isize) as i32 });
            if digit1 >= 0 as i32 && digit2 >= 0 as i32 {
                /* Looks good, consume three chars */
                unsafe { s = s.offset(3 as i32 as isize) };
                /* Convert output */
                let fresh3 = d;
                unsafe { d = d.offset(1) };
                unsafe { *fresh3 = (digit1 << 4 as i32 | digit2) as i8 };
                continue;
            }
            /* Else fall through and treat '%' as normal char */
        }
        let fresh4 = s;
        unsafe { s = s.offset(1) };
        let fresh5 = d;
        unsafe { d = d.offset(1) };
        unsafe { *fresh5 = *fresh4 }
    }
    unsafe { *d = '\u{0}' as i32 as i8 };
    return out;
}
unsafe fn tohex(mut c: i32) -> i32 {
    if c >= '0' as i32 && c <= '9' as i32 {
        return c - '0' as i32;
    } else if c >= 'A' as i32 && c <= 'F' as i32 {
        return c - 'A' as i32 + 10 as i32;
    } else if c >= 'a' as i32 && c <= 'f' as i32 {
        return c - 'a' as i32 + 10 as i32;
    } else {
        return -(1 as i32);
    };
}

#[no_mangle]
pub unsafe fn archive_test_tohex(mut c: i32) {
    tohex(c);
    url_decode(b"11" as *const u8 as *const i8);
}

#[no_mangle]
pub unsafe fn archive_test_pax_attribute(
    mut _a: *mut archive,
    mut entry: *mut archive_entry,
    mut key: *const i8,
    mut value: *const i8,
    mut value_length: size_t,
) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut tar: *mut tar = 0 as *mut tar;
    tar = calloc_safe(1 as i32 as u64, ::std::mem::size_of::<tar>() as u64) as *mut tar;
    pax_attribute(a, tar, entry, key, value, value_length);
}
