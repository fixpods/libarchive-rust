use archive_core::archive_endian::*;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;
use rust_ffi::{archive_set_error_safe, archive_string_sprintf_safe, sprintf_safe};
use std::mem::size_of;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lha {
    pub entry_offset: int64_t,
    pub entry_bytes_remaining: int64_t,
    pub entry_unconsumed: int64_t,
    pub entry_crc_calculated: uint16_t,
    pub header_size: size_t,
    pub level: u8,
    pub method: [u8; 3],
    pub compsize: int64_t,
    pub origsize: int64_t,
    pub setflag: i32,
    pub birthtime: time_t,
    pub birthtime_tv_nsec: i64,
    pub mtime: time_t,
    pub mtime_tv_nsec: i64,
    pub atime: time_t,
    pub atime_tv_nsec: i64,
    pub mode: mode_t,
    pub uid: int64_t,
    pub gid: int64_t,
    pub uname: archive_string,
    pub gname: archive_string,
    pub header_crc: uint16_t,
    pub crc: uint16_t,
    pub sconv_dir: *mut archive_string_conv,
    pub sconv_fname: *mut archive_string_conv,
    pub opt_sconv: *mut archive_string_conv,
    pub dirname: archive_string,
    pub filename: archive_string,
    pub ws: archive_wstring,
    pub dos_attr: u8,
    pub found_first_header: u8,
    pub directory: u8,
    pub decompress_init: u8,
    pub end_of_entry: u8,
    pub end_of_entry_cleanup: u8,
    pub entry_is_compressed: u8,
    pub format_name: [u8; 64],
    pub strm: lzh_stream,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lzh_stream {
    pub next_in: *const u8,
    pub avail_in: i32,
    pub total_in: int64_t,
    pub ref_ptr: *const u8,
    pub avail_out: i32,
    pub total_out: int64_t,
    pub ds: *mut lzh_dec,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lzh_dec {
    pub state: i32,
    pub w_size: i32,
    pub w_mask: i32,
    pub w_buff: *mut u8,
    pub w_pos: i32,
    pub copy_pos: i32,
    pub copy_len: i32,
    pub br: lzh_br,
    pub lt: huffman,
    pub pt: huffman,
    pub blocks_avail: i32,
    pub pos_pt_len_size: i32,
    pub pos_pt_len_bits: i32,
    pub literal_pt_len_size: i32,
    pub literal_pt_len_bits: i32,
    pub reading_position: i32,
    pub loop_0: i32,
    pub error: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct huffman {
    pub len_size: i32,
    pub len_avail: i32,
    pub len_bits: i32,
    pub freq: [i32; 17],
    pub bitlen: *mut u8,
    pub max_bits: i32,
    pub shift_bits: i32,
    pub tbl_bits: i32,
    pub tree_used: i32,
    pub tree_avail: i32,
    pub tbl: *mut uint16_t,
    pub tree: *mut htree_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct htree_t {
    pub left: uint16_t,
    pub right: uint16_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lzh_br {
    pub cache_buffer: uint64_t,
    pub cache_avail: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union archive_temporary_u {
    pub i: uint32_t,
    pub c: [u8; 4],
}

#[no_mangle]
pub fn archive_read_support_format_lha(mut _a: *mut archive) -> i32 {
    let a: *mut archive_read = _a as *mut archive_read;
    let r: i32;
    let mut magic_test: i32 = unsafe {
        __archive_check_magic_safe(
            _a,
            ARCHIVE_LHA_DEFINED_PARAM.archive_read_magic,
            ARCHIVE_LHA_DEFINED_PARAM.archive_state_new,
            b"archive_read_support_format_lha\x00" as *const u8,
        )
    };
    if magic_test == ARCHIVE_LHA_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    let lha = unsafe { &mut *(calloc_safe(1, size_of::<lha>() as u64) as *mut lha) };
    if (lha as *mut lha).is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.enomem,
            b"Can\'t allocate lha data\x00" as *const u8
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    lha.ws.s = 0 as *mut wchar_t;
    lha.ws.length = 0;
    lha.ws.buffer_length = 0;
    r = unsafe {
        __archive_read_register_format_safe(
            a,
            lha as *mut lha as *mut (),
            b"lha\x00" as *const u8,
            Some(archive_read_format_lha_bid),
            Some(archive_read_format_lha_options),
            Some(archive_read_format_lha_read_header),
            Some(archive_read_format_lha_read_data),
            Some(archive_read_format_lha_read_data_skip),
            None,
            Some(archive_read_format_lha_cleanup),
            None,
            None,
        )
    };
    if r != ARCHIVE_LHA_DEFINED_PARAM.archive_ok {
        unsafe { free_safe(lha as *mut lha as *mut ()) };
    }
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

fn lha_check_header_format(mut h: *const ()) -> size_t {
    let p: *const u8 = h as *const u8;
    let mut next_skip_bytes: size_t;
    let p_char =
        unsafe { *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 3) as isize) as char };
    match p_char {
        /*
         * "-lh0-" ... "-lh7-" "-lhd-"
         * "-lzs-" "-lz5-"
         */
        '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | 'd' | 's' => {
            next_skip_bytes = 4;
            /* b0 == 0 means the end of an LHa archive file.    */
            if !(unsafe { *p.offset(0) } == 0) {
                if !(unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_method_offset as isize) }
                    != '-' as u8
                    || unsafe {
                        *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 1) as isize)
                    } != 'l' as u8
                    || unsafe {
                        *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 4) as isize)
                    } != '-' as u8)
                {
                    if unsafe {
                        *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 2) as isize)
                    } == 'h' as u8
                    {
                        /* "-lh?-" */
                        if unsafe {
                            *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 3) as isize)
                        } != 's' as u8
                        {
                            if unsafe {
                                *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize)
                            } == 0
                            {
                                return 0;
                            }
                            if unsafe {
                                *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize)
                            } <= 3
                                && unsafe {
                                    *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_attr_offset as isize)
                                } == 0x20 as u8
                            {
                                return 0;
                            }
                        }
                    }
                    if unsafe {
                        *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 2) as isize)
                    } == 'z' as u8
                    {
                        /* LArc extensions: -lzs-,-lz4- and -lz5- */
                        if unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize) }
                            == 0
                        {
                            if unsafe {
                                *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 3) as isize)
                            } == 's' as u8
                                || unsafe {
                                    *p.offset(
                                        (ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 3) as isize,
                                    )
                                } == '4' as u8
                                || unsafe {
                                    *p.offset(
                                        (ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 3) as isize,
                                    )
                                } == '5' as u8
                            {
                                return 0;
                            }
                        }
                    }
                }
            }
        }
        'h' => next_skip_bytes = 1,
        'z' => next_skip_bytes = 1,
        'l' => next_skip_bytes = 2,
        '-' => next_skip_bytes = 3,
        _ => next_skip_bytes = 4,
    }
    return next_skip_bytes;
}

/* Minimum header size. */
fn archive_read_format_lha_bid(mut a: *mut archive_read, mut best_bid: i32) -> i32 {
    let mut p: *const u8;
    let mut buff: *const ();
    let mut bytes_avail: ssize_t = 0;
    let mut offset: ssize_t;
    let mut window: ssize_t;
    let mut next: size_t;
    /* If there's already a better bid than we can ever
    make, don't bother testing. */
    if best_bid > 30 {
        return -1;
    }
    p = unsafe {
        __archive_read_ahead_safe(
            a,
            ARCHIVE_LHA_DEFINED_PARAM.h_size as size_t,
            0 as *mut ssize_t,
        )
    } as *const u8;
    if p.is_null() {
        return -1;
    }
    if lha_check_header_format(p as *const ()) == 0 {
        return 30;
    }
    if unsafe { *p.offset(0 as isize) } == 'M' as u8
        && unsafe { *p.offset(1 as isize) } == 'Z' as u8
    {
        /* PE file */
        offset = 0;
        window = 4096;
        while offset < 1024 * 20 {
            buff = unsafe {
                __archive_read_ahead_safe(a, (offset + window) as size_t, &mut bytes_avail)
            };
            if buff.is_null() {
                /* Remaining bytes are less than window. */
                window >>= 1;
                if window < (ARCHIVE_LHA_DEFINED_PARAM.h_size + 3) as i64 {
                    return 0;
                }
            } else {
                p = unsafe { (buff as *const u8).offset(offset as isize) };
                while unsafe {
                    p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_size as isize)
                        < (buff as *const u8).offset(bytes_avail as isize)
                } {
                    next = lha_check_header_format(p as *const ());
                    if next == 0 {
                        return 30;
                    }
                    p = p.wrapping_offset(next as isize);
                }
                offset = unsafe { p.offset_from(buff as *const u8) } as i64
            }
        }
    }
    return 0;
}

fn archive_read_format_lha_options(
    mut a: *mut archive_read,
    mut key: *const u8,
    mut val: *const u8,
) -> i32 {
    let safe_a = unsafe { &mut *a };
    let mut lha = { unsafe { &mut *((*safe_a.format).data as *mut lha) } };
    let mut ret: i32 = ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
    if unsafe { strcmp_safe(key, b"hdrcharset\x00" as *const u8) == 0 } {
        if val.is_null() || unsafe { *val.offset(0) } == 0 {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_LHA_DEFINED_PARAM.archive_errno_misc,
                b"lha: hdrcharset option needs a character-set name\x00" as *const u8
            );
        } else {
            lha.opt_sconv =
                unsafe { archive_string_conversion_from_charset_safe(&mut safe_a.archive, val, 0) };
            if !lha.opt_sconv.is_null() {
                ret = ARCHIVE_LHA_DEFINED_PARAM.archive_ok
            } else {
                ret = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal
            }
        }
        return ret;
    }
    /* Note: The "warn" return is just to inform the options
     * supervisor that we didn't handle it.  It will generate
     * a suitable error if no one used this option. */
    return ARCHIVE_LHA_DEFINED_PARAM.archive_warn;
}

fn lha_skip_sfx(mut a: *mut archive_read) -> i32 {
    let mut h: *const ();
    let mut p: *const u8;
    let mut q: *const u8;
    let mut next: size_t;
    let mut skip: size_t;
    let mut bytes: ssize_t = 0;
    let mut window: ssize_t;
    window = 4096;
    loop {
        h = unsafe { __archive_read_ahead_safe(a, window as size_t, &mut bytes) };
        if h == 0 as *mut () {
            /* Remaining bytes are less than window. */
            window >>= 1;
            if window < (ARCHIVE_LHA_DEFINED_PARAM.h_size + 3) as i64 {
                break;
            }
        } else {
            if bytes < ARCHIVE_LHA_DEFINED_PARAM.h_size as i64 {
                break;
            }
            p = h as *const u8;
            q = p.wrapping_offset(bytes as isize);
            /*
             * Scan ahead until we find something that looks
             * like the lha header.
             */
            while unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_size as isize) } < q {
                next = lha_check_header_format(p as *const ());
                if next == 0 {
                    skip = unsafe { p.offset_from(h as *const u8) } as size_t;
                    unsafe { __archive_read_consume_safe(a, skip as int64_t) };
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                }
                p = unsafe { p.offset(next as isize) }
            }
            skip = unsafe { p.offset_from(h as *const u8) } as size_t;
            unsafe { __archive_read_consume_safe(a, skip as int64_t) };
        }
    }
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
        b"Couldn\'t find out LHa header\x00" as *const u8
    );
    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
}

fn truncated_error(mut a: *mut archive_read) -> i32 {
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
        b"Truncated LHa header\x00" as *const u8
    );
    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
}

fn archive_read_format_lha_read_header(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
) -> i32 {
    let mut linkname: archive_wstring = archive_wstring {
        s: 0 as *mut wchar_t,
        length: 0,
        buffer_length: 0,
    };
    let mut pathname: archive_wstring = archive_wstring {
        s: 0 as *mut wchar_t,
        length: 0,
        buffer_length: 0,
    };
    let safe_a = unsafe { &mut *a };
    let mut p: *const u8 = 0 as *const u8;
    let mut signature: *const u8 = 0 as *const u8;
    let mut err: i32 = 0;
    let mut conv_buffer: archive_mstring = archive_mstring {
        aes_mbs: archive_string {
            s: 0 as *mut u8,
            length: 0,
            buffer_length: 0,
        },
        aes_utf8: archive_string {
            s: 0 as *mut u8,
            length: 0,
            buffer_length: 0,
        },
        aes_wcs: archive_wstring {
            s: 0 as *mut wchar_t,
            length: 0,
            buffer_length: 0,
        },
        aes_mbs_in_locale: archive_string {
            s: 0 as *mut u8,
            length: 0,
            buffer_length: 0,
        },
        aes_set: 0,
    };
    let mut conv_buffer_p: *const wchar_t = 0 as *const wchar_t;
    lha_crc16_init();
    safe_a.archive.archive_format = ARCHIVE_LHA_DEFINED_PARAM.archive_format_lha;
    if safe_a.archive.archive_format_name.is_null() {
        safe_a.archive.archive_format_name = b"lha\x00" as *const u8
    }
    let mut lha = unsafe { &mut *((*safe_a.format).data as *mut lha) };
    lha.decompress_init = 0;
    lha.end_of_entry = 0;
    lha.end_of_entry_cleanup = 0;
    lha.entry_unconsumed = 0;
    p = unsafe {
        __archive_read_ahead_safe(
            a,
            ARCHIVE_LHA_DEFINED_PARAM.h_size as size_t,
            0 as *mut ssize_t,
        )
    } as *const u8;
    if p.is_null() {
        /*
         * LHa archiver added 0 to the tail of its archive file as
         * the mark of the end of the archive.
         */
        signature =
            unsafe { __archive_read_ahead_safe(a, size_of::<u8>() as u64, 0 as *mut ssize_t) }
                as *const u8;
        if signature.is_null() || unsafe { *signature.offset(0 as isize) } == 0 {
            return ARCHIVE_LHA_DEFINED_PARAM.archive_eof;
        }
        return truncated_error(a);
    }
    signature = p as *const u8;
    if lha.found_first_header == 0
        && unsafe { *signature.offset(0 as isize) } == 'M' as u8
        && unsafe { *signature.offset(1 as isize) } == 'Z' as u8
    {
        /* This is an executable?  Must be self-extracting...   */
        err = lha_skip_sfx(a);
        if err < ARCHIVE_LHA_DEFINED_PARAM.archive_warn {
            return err;
        }
        p = unsafe { __archive_read_ahead_safe(a, size_of::<u8>() as u64, 0 as *mut ssize_t) }
            as *const u8;
        if p.is_null() {
            return truncated_error(a);
        }
        signature = p as *const u8
    }
    /* signature[0] == 0 means the end of an LHa archive file. */
    if unsafe { *signature.offset(0 as isize) } == 0 {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_eof;
    }
    /*
     * Check the header format and method type.
     */
    if lha_check_header_format(p as *const ()) != 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Bad LHa file\x00" as *const u8
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    /* We've found the first header. */
    lha.found_first_header = 1;
    /* Set a default value and common data */
    lha.header_size = 0;
    lha.level = unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize) };
    lha.method[0] =
        unsafe { *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 1) as isize) } as u8;
    lha.method[1] =
        unsafe { *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 2) as isize) } as u8;
    lha.method[2] =
        unsafe { *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 3) as isize) } as u8;
    if unsafe {
        memcmp_safe(
            lha.method.as_mut_ptr() as *const (),
            b"lhd\x00" as *const u8 as *const (),
            3,
        ) == 0
    } {
        lha.directory = 1
    } else {
        lha.directory = 0
    }
    if unsafe {
        memcmp_safe(
            lha.method.as_mut_ptr() as *const (),
            b"lh0\x00" as *const u8 as *const (),
            3,
        ) == 0
            || memcmp_safe(
                lha.method.as_mut_ptr() as *const (),
                b"lz4\x00" as *const u8 as *const (),
                3,
            ) == 0
    } {
        lha.entry_is_compressed = 0
    } else {
        lha.entry_is_compressed = 1
    }
    lha.compsize = 0;
    lha.origsize = 0;
    lha.setflag = 0;
    lha.birthtime = 0;
    lha.birthtime_tv_nsec = 0;
    lha.mtime = 0;
    lha.mtime_tv_nsec = 0;
    lha.atime = 0;
    lha.atime_tv_nsec = 0;
    lha.mode = if lha.directory != 0 { 0o777 } else { 0o666 } as mode_t;
    lha.uid = 0;
    lha.gid = 0;
    lha.dirname.length = 0;
    lha.filename.length = 0;
    lha.dos_attr = 0;
    if !lha.opt_sconv.is_null() {
        lha.sconv_dir = lha.opt_sconv;
        lha.sconv_fname = lha.opt_sconv
    } else {
        lha.sconv_dir = 0 as *mut archive_string_conv;
        lha.sconv_fname = 0 as *mut archive_string_conv
    }
    match unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize) } as i32 {
        0 => err = lha_read_file_header_0(a, lha),
        1 => err = lha_read_file_header_1(a, lha),
        2 => err = lha_read_file_header_2(a, lha),
        3 => err = lha_read_file_header_3(a, lha),
        _ => {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
                b"Unsupported LHa header level %d\x00" as *const u8,
                *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize) as i32
            );
            err = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal
        }
    }
    if err < ARCHIVE_LHA_DEFINED_PARAM.archive_warn {
        return err;
    }
    if lha.directory == 0 && lha.filename.length == 0 {
        /* The filename has not been set */
        return truncated_error(a);
    }
    /*
     * Make a pathname from a dirname and a filename, after converting to Unicode.
     * This is because codepages might differ between dirname and filename.
     */
    pathname.s = 0 as *mut wchar_t;
    pathname.length = 0;
    pathname.buffer_length = 0;
    linkname.s = 0 as *mut wchar_t;
    linkname.length = 0;
    linkname.buffer_length = 0;
    conv_buffer.aes_mbs.s = 0 as *mut u8;
    conv_buffer.aes_mbs.length = 0;
    conv_buffer.aes_mbs.buffer_length = 0;
    conv_buffer.aes_mbs_in_locale.s = 0 as *mut u8;
    conv_buffer.aes_mbs_in_locale.length = 0;
    conv_buffer.aes_mbs_in_locale.buffer_length = 0;
    conv_buffer.aes_utf8.s = 0 as *mut u8;
    conv_buffer.aes_utf8.length = 0;
    conv_buffer.aes_utf8.buffer_length = 0;
    conv_buffer.aes_wcs.s = 0 as *mut wchar_t;
    conv_buffer.aes_wcs.length = 0;
    conv_buffer.aes_wcs.buffer_length = 0;
    if 0 != unsafe {
        archive_mstring_copy_mbs_len_l_safe(
            &mut conv_buffer,
            lha.dirname.s,
            lha.dirname.length,
            lha.sconv_dir,
        )
    } {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Pathname cannot be converted from %s to Unicode.\x00" as *const u8,
            archive_string_conversion_charset_name_safe(lha.sconv_dir)
        );
        err = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal
    } else if 0
        != unsafe {
            archive_mstring_get_wcs_safe(&mut safe_a.archive, &mut conv_buffer, &mut conv_buffer_p)
        }
    {
        err = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal
    }
    if err == ARCHIVE_LHA_DEFINED_PARAM.archive_fatal {
        unsafe { archive_mstring_clean_safe(&mut conv_buffer) };
        unsafe { archive_wstring_free_safe(&mut pathname) };
        unsafe { archive_wstring_free_safe(&mut linkname) };
        return err;
    }
    pathname.length = 0;
    unsafe { archive_wstring_concat_safe(&mut pathname, &mut conv_buffer.aes_wcs) };
    conv_buffer.aes_mbs.length = 0;
    conv_buffer.aes_mbs_in_locale.length = 0;
    conv_buffer.aes_utf8.length = 0;
    conv_buffer.aes_wcs.length = 0;
    if 0 != unsafe {
        archive_mstring_copy_mbs_len_l_safe(
            &mut conv_buffer,
            lha.filename.s,
            lha.filename.length,
            lha.sconv_fname,
        )
    } {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Pathname cannot be converted from %s to Unicode.\x00" as *const u8,
            archive_string_conversion_charset_name_safe(lha.sconv_fname)
        );
        err = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal
    } else if 0
        != unsafe {
            archive_mstring_get_wcs_safe(&mut safe_a.archive, &mut conv_buffer, &mut conv_buffer_p)
        }
    {
        err = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal
    }
    if err == ARCHIVE_LHA_DEFINED_PARAM.archive_fatal {
        unsafe { archive_mstring_clean_safe(&mut conv_buffer) };
        unsafe { archive_wstring_free_safe(&mut pathname) };
        unsafe { archive_wstring_free_safe(&mut linkname) };
        return err;
    }
    unsafe { archive_wstring_concat_safe(&mut pathname, &mut conv_buffer.aes_wcs) };
    unsafe { archive_mstring_clean_safe(&mut conv_buffer) };
    if lha.mode & ARCHIVE_LHA_DEFINED_PARAM.ae_ifmt as mode_t
        == ARCHIVE_LHA_DEFINED_PARAM.ae_iflnk as mode_t
    {
        /*
         * Extract the symlink-name if it's included in the pathname.
         */
        if lha_parse_linkname(&mut linkname, &mut pathname) == 0 {
            /* We couldn't get the symlink-name. */
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
                b"Unknown symlink-name\x00" as *const u8
            );
            unsafe { archive_wstring_free_safe(&mut pathname) };
            unsafe { archive_wstring_free_safe(&mut linkname) };
            return ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
        }
    } else {
        /*
         * Make sure a file-type is set.
         * The mode has been overridden if it is in the extended data.
         */
        lha.mode = lha.mode & !(ARCHIVE_LHA_DEFINED_PARAM.ae_ifmt as mode_t)
            | (if lha.directory != 0 {
                ARCHIVE_LHA_DEFINED_PARAM.ae_ifdir as mode_t
            } else {
                ARCHIVE_LHA_DEFINED_PARAM.ae_ifreg as mode_t
            })
    } /* read only. */
    if lha.setflag & ARCHIVE_LHA_DEFINED_PARAM.unix_mode_is_set == 0 && lha.dos_attr as i32 & 1 != 0
    {
        lha.mode &= !(0o222) as u32
    }
    /*
     * Set basic file parameters.
     */
    unsafe { archive_entry_copy_pathname_w_safe(entry, pathname.s) };
    unsafe { archive_wstring_free_safe(&mut pathname) };
    if linkname.length > 0 {
        unsafe { archive_entry_copy_symlink_w_safe(entry, linkname.s) };
    } else {
        unsafe { archive_entry_set_symlink_safe(entry, 0 as *const u8) };
    }
    unsafe { archive_wstring_free_safe(&mut linkname) };
    /*
     * When a header level is 0, there is a possibility that
     * a pathname and a symlink has '\' character, a directory
     * separator in DOS/Windows. So we should convert it to '/'.
     */
    if unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize) } == 0 {
        lha_replace_path_separator(lha, entry);
    }
    unsafe { archive_entry_set_mode_safe(entry, lha.mode) };
    unsafe { archive_entry_set_uid_safe(entry, lha.uid) };
    unsafe { archive_entry_set_gid_safe(entry, lha.gid) };
    if lha.uname.length > 0 {
        unsafe { archive_entry_set_uname_safe(entry, lha.uname.s) };
    }
    if lha.gname.length > 0 {
        unsafe { archive_entry_set_gname_safe(entry, lha.gname.s) };
    }
    if lha.setflag & ARCHIVE_LHA_DEFINED_PARAM.birthtime_is_set != 0 {
        unsafe { archive_entry_set_birthtime_safe(entry, lha.birthtime, lha.birthtime_tv_nsec) };
        unsafe { archive_entry_set_ctime_safe(entry, lha.birthtime, lha.birthtime_tv_nsec) };
    } else {
        unsafe { archive_entry_unset_birthtime_safe(entry) };
        unsafe { archive_entry_unset_ctime_safe(entry) };
    }
    unsafe { archive_entry_set_mtime_safe(entry, lha.mtime, lha.mtime_tv_nsec) };
    if lha.setflag & ARCHIVE_LHA_DEFINED_PARAM.atime_is_set != 0 {
        unsafe { archive_entry_set_atime_safe(entry, lha.atime, lha.atime_tv_nsec) };
    } else {
        unsafe { archive_entry_unset_atime_safe(entry) };
    }
    if lha.directory != 0 || !unsafe { archive_entry_symlink_safe(entry).is_null() } {
        unsafe { archive_entry_unset_size_safe(entry) };
    } else {
        unsafe { archive_entry_set_size_safe(entry, lha.origsize) };
    }
    /*
     * Prepare variables used to read a file content.
     */
    lha.entry_bytes_remaining = lha.compsize;
    if lha.entry_bytes_remaining < 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid LHa entry size\x00" as *const u8
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    lha.entry_offset = 0;
    lha.entry_crc_calculated = 0 as uint16_t;
    /*
     * This file does not have a content.
     */
    if lha.directory != 0 || lha.compsize == 0 {
        lha.end_of_entry = 1
    }
    sprintf_safe!(
        lha.format_name.as_mut_ptr(),
        b"lha -%c%c%c-\x00" as *const u8,
        lha.method[0] as i32,
        lha.method[1] as i32,
        lha.method[2] as i32
    );
    safe_a.archive.archive_format_name = lha.format_name.as_mut_ptr();
    return err;
}

/*
 * Replace a DOS path separator '\' by a character '/'.
 * Some multi-byte character set have  a character '\' in its second byte.
 */
fn lha_replace_path_separator(lha: &mut lha, entry: *mut archive_entry) {
    let mut wp: *const wchar_t;
    let mut i: size_t;
    wp = unsafe { archive_entry_pathname_w_safe(entry) };
    if !wp.is_null() {
        lha.ws.length = 0;
        unsafe {
            archive_wstrncat_safe(
                &mut lha.ws,
                wp,
                if wp.is_null() { 0 } else { wcslen_safe(wp) },
            )
        };
        i = 0;
        while i < lha.ws.length {
            if unsafe { *lha.ws.s.offset(i as isize) } == '\\' as wchar_t {
                unsafe { *lha.ws.s.offset(i as isize) = '/' as wchar_t }
            }
            i = i + 1
        }
        unsafe { archive_entry_copy_pathname_w_safe(entry, lha.ws.s) };
    }
    wp = unsafe { archive_entry_symlink_w_safe(entry) };
    if !wp.is_null() {
        lha.ws.length = 0;
        unsafe {
            archive_wstrncat_safe(
                &mut lha.ws,
                wp,
                if wp.is_null() { 0 } else { wcslen_safe(wp) },
            )
        };
        i = 0;
        while i < lha.ws.length {
            if unsafe { *lha.ws.s.offset(i as isize) } == '\\' as wchar_t {
                unsafe { *lha.ws.s.offset(i as isize) = '/' as wchar_t }
            }
            i = i + 1
        }
        unsafe { archive_entry_copy_symlink_w_safe(entry, lha.ws.s) };
    };
}

fn lha_read_file_header_0(a: *mut archive_read, lha: &mut lha) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let extdsize: i32;
    let namelen: i32;
    let headersum: u8;
    let sum_calculated: u8;
    p = unsafe {
        __archive_read_ahead_safe(
            a,
            ARCHIVE_LHA_DEFINED_PARAM.h0_fixed_size as size_t,
            0 as *mut ssize_t,
        ) as *const u8
    };
    if p.is_null() {
        return truncated_error(a);
    }
    lha.header_size =
        (unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_header_size_offset as isize) } + 2) as u64;
    headersum = unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_header_sum_offset as isize) };
    lha.compsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_comp_size_offset as isize) }
                as *const (),
        ) as int64_t;
    lha.origsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_orig_size_offset as isize) }
                as *const (),
        ) as int64_t;
    lha.mtime =
        lha_dos_time(unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_dos_time_offset as isize) });
    namelen = unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_name_len_offset as isize) } as i32;
    extdsize = lha.header_size as i32 - ARCHIVE_LHA_DEFINED_PARAM.h0_fixed_size - namelen;
    if (namelen > 221 || extdsize < 0) && extdsize != -2 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid LHa header\x00" as *const u8
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    p = unsafe { __archive_read_ahead_safe(a, lha.header_size, 0 as *mut ssize_t) } as *const u8;
    if p.is_null() {
        return truncated_error(a);
    }
    lha.filename.length = 0;
    unsafe {
        archive_strncat_safe(
            &mut lha.filename,
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_file_name_offset as isize) }
                as *const (),
            namelen as size_t,
        )
    };
    /* When extdsize == -2, A CRC16 value is not present in the header. */
    if extdsize >= 0 {
        lha.crc = archive_le16dec(unsafe {
            p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_file_name_offset as isize)
                .offset(namelen as isize)
        } as *const ());
        lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.crc_is_set
    }
    sum_calculated = lha_calcsum(0, p as *const (), 2, lha.header_size - 2);
    /* Read an extended header */
    if extdsize > 0 {
        /* This extended data is set by 'LHa for UNIX' only.
         * Maybe fixed size.
         */
        p = unsafe {
            p.offset((ARCHIVE_LHA_DEFINED_PARAM.h0_file_name_offset + namelen + 2) as isize)
        };
        if unsafe { *p.offset(0 as isize) } == 'U' as u8 && extdsize == 12 {
            /* p[1] is a minor version. */
            lha.mtime = archive_le32dec(unsafe { &*p.offset(2 as isize) } as *const u8 as *const ())
                as time_t;
            lha.mode = archive_le16dec(unsafe { &*p.offset(6 as isize) } as *const u8 as *const ())
                as mode_t;
            lha.uid = archive_le16dec(unsafe { &*p.offset(8 as isize) } as *const u8 as *const ())
                as int64_t;
            lha.gid = archive_le16dec(unsafe { &*p.offset(10 as isize) } as *const u8 as *const ())
                as int64_t;
            lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.unix_mode_is_set
        }
    }
    unsafe { __archive_read_consume_safe(a, lha.header_size as int64_t) };
    if sum_calculated != headersum {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_misc,
            b"LHa header sum error\x00" as *const u8
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

/*
 * Header 1 format
 *
 * +0              +1         +2               +7            +11
 * +---------------+----------+----------------+-------------+
 * |header size(*1)|header sum|compression type|skip size(*2)|
 * +---------------+----------+----------------+-------------+
 *                             <---------------(*1)----------*
 *
 * +11               +15       +17       +19            +20              +21
 * +-----------------+---------+---------+--------------+----------------+
 * |uncompressed size|time(DOS)|date(DOS)|attribute(DOS)|header level(=1)|
 * +-----------------+---------+---------+--------------+----------------+
 * *-------------------------------(*1)----------------------------------*
 *
 * +21             +22       +22+(*3)   +22+(*3)+2  +22+(*3)+3  +22+(*3)+3+(*4)
 * +---------------+---------+----------+-----------+-----------+
 * |name length(*3)|file name|file CRC16|  creator  |padding(*4)|
 * +---------------+---------+----------+-----------+-----------+
 *                  <--(*3)->
 * *----------------------------(*1)----------------------------*
 *
 * +22+(*3)+3+(*4)  +22+(*3)+3+(*4)+2     +22+(*3)+3+(*4)+2+(*5)
 * +----------------+---------------------+------------------------+
 * |next header size| extended header(*5) |     compressed data    |
 * +----------------+---------------------+------------------------+
 * *------(*1)-----> <--------------------(*2)-------------------->
 */
fn lha_read_file_header_1(a: *mut archive_read, lha: &mut lha) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let mut extdsize: size_t = 0;
    let mut err: i32 = 0;
    let err2: i32;
    let namelen: i32;
    let padding: i32;
    let headersum: u8;
    let sum_calculated: u8;
    err = ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
    p = unsafe {
        __archive_read_ahead_safe(
            a,
            ARCHIVE_LHA_DEFINED_PARAM.h1_fixed_size as size_t,
            0 as *mut ssize_t,
        )
    } as *const u8;
    if p.is_null() {
        return truncated_error(a);
    }
    lha.header_size =
        (unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_header_size_offset as isize) } as i32 + 2)
            as size_t;
    headersum = unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_header_sum_offset as isize) };
    /* Note: An extended header size is included in a compsize. */
    lha.compsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_comp_size_offset as isize) }
                as *const (),
        ) as int64_t;
    lha.origsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_orig_size_offset as isize) }
                as *const (),
        ) as int64_t;
    lha.mtime =
        lha_dos_time(unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_dos_time_offset as isize) });
    namelen = unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_name_len_offset as isize) } as i32;
    /* Calculate a padding size. The result will be normally 0 only(?) */
    padding = lha.header_size as i32 - ARCHIVE_LHA_DEFINED_PARAM.h1_fixed_size - namelen;
    if !(namelen > 230 || padding < 0) {
        p = unsafe { __archive_read_ahead_safe(a, lha.header_size, 0 as *mut ssize_t) }
            as *const u8;
        if p.is_null() {
            return truncated_error(a);
        }
        let mut invalid = false;
        for i in 0..namelen {
            if unsafe { *p.offset((i + ARCHIVE_LHA_DEFINED_PARAM.h1_file_name_offset) as isize) }
                == 0xff as u8
            {
                invalid = true;
                break;
                /* Invalid filename. */
            }
        }
        if !invalid {
            lha.filename.length = 0;
            unsafe {
                archive_strncat_safe(
                    &mut lha.filename,
                    p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_file_name_offset as isize) as *const (),
                    namelen as size_t,
                )
            };
            lha.crc = archive_le16dec(unsafe {
                p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_file_name_offset as isize)
                    .offset(namelen as isize)
            } as *const ());
            lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.crc_is_set;
            sum_calculated = lha_calcsum(0, p as *const (), 2, lha.header_size - 2);
            /* Consume used bytes but not include `next header size' data
             * since it will be consumed in lha_read_file_extended_header(). */
            unsafe { __archive_read_consume_safe(a, (lha.header_size - 2) as int64_t) };
            /* Read extended headers */
            err2 = lha_read_file_extended_header(
                a,
                lha,
                0 as *mut uint16_t,
                2,
                (lha.compsize + 2) as size_t,
                &mut extdsize,
            );
            if err2 < ARCHIVE_LHA_DEFINED_PARAM.archive_warn {
                return err2;
            }
            if err2 < err {
                err = err2
            }
            /* Get a real compressed file size. */
            lha.compsize -= extdsize as i64 - 2; /* Invalid compressed file size */
            if !(lha.compsize < 0) {
                if sum_calculated != headersum {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_LHA_DEFINED_PARAM.archive_errno_misc,
                        b"LHa header sum error\x00" as *const u8
                    );
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
                }
                return err;
            }
        }
    }
    // invalid
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
        b"Invalid LHa header\x00" as *const u8
    );
    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
}

/*
 * Header 2 format
 *
 * +0              +2               +7                  +11               +15
 * +---------------+----------------+-------------------+-----------------+
 * |header size(*1)|compression type|compressed size(*2)|uncompressed size|
 * +---------------+----------------+-------------------+-----------------+
 *  <--------------------------------(*1)---------------------------------*
 *
 * +15               +19          +20              +21        +23         +24
 * +-----------------+------------+----------------+----------+-----------+
 * |data/time(time_t)| 0x20 fixed |header level(=2)|file CRC16|  creator  |
 * +-----------------+------------+----------------+----------+-----------+
 * *---------------------------------(*1)---------------------------------*
 *
 * +24              +26                 +26+(*3)      +26+(*3)+(*4)
 * +----------------+-------------------+-------------+-------------------+
 * |next header size|extended header(*3)| padding(*4) |  compressed data  |
 * +----------------+-------------------+-------------+-------------------+
 * *--------------------------(*1)-------------------> <------(*2)------->
 *
 */
fn lha_read_file_header_2(a: *mut archive_read, lha: &mut lha) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let mut extdsize: size_t = 0;
    let mut err: i32 = 0;
    let padding: i32;
    let mut header_crc: uint16_t = 0;
    p = unsafe {
        __archive_read_ahead_safe(
            a,
            ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as size_t,
            0 as *mut ssize_t,
        )
    } as *const u8;
    if p.is_null() {
        return truncated_error(a);
    }
    lha.header_size = archive_le16dec(unsafe {
        p.offset(ARCHIVE_LHA_DEFINED_PARAM.h2_header_size_offset as isize)
    } as *const ()) as size_t;
    lha.compsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h2_comp_size_offset as isize) }
                as *const (),
        ) as int64_t;
    lha.origsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h2_orig_size_offset as isize) }
                as *const (),
        ) as int64_t;
    lha.mtime =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h2_time_offset as isize) } as *const (),
        ) as time_t;
    lha.crc = archive_le16dec(
        unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h2_crc_offset as isize) } as *const (),
    );
    lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.crc_is_set;
    if lha.header_size < ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as u64 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid LHa header size\x00" as *const u8
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    header_crc = lha_crc16(
        0,
        p as *const (),
        ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as size_t,
    );
    unsafe { __archive_read_consume_safe(a, ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as int64_t) };
    /* Read extended headers */
    err = lha_read_file_extended_header(
        a,
        lha,
        &mut header_crc,
        2,
        lha.header_size - (ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as u64),
        &mut extdsize,
    );
    if err < ARCHIVE_LHA_DEFINED_PARAM.archive_warn {
        return err;
    }
    /* Calculate a padding size. The result will be normally 0 or 1. */
    padding =
        lha.header_size as i32 - (ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as u64 + extdsize) as i32;
    if padding > 0 {
        p = unsafe { __archive_read_ahead_safe(a, padding as size_t, 0 as *mut ssize_t) }
            as *const u8;
        if p.is_null() {
            return truncated_error(a);
        }
        header_crc = lha_crc16(header_crc, p as *const (), padding as size_t);
        unsafe { __archive_read_consume_safe(a, padding as int64_t) };
    }
    if header_crc != lha.header_crc {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"LHa header CRC error\x00" as *const u8
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    return err;
}

/*
 * Header 3 format
 *
 * +0           +2               +7                  +11               +15
 * +------------+----------------+-------------------+-----------------+
 * | 0x04 fixed |compression type|compressed size(*2)|uncompressed size|
 * +------------+----------------+-------------------+-----------------+
 *  <-------------------------------(*1)-------------------------------*
 *
 * +15               +19          +20              +21        +23         +24
 * +-----------------+------------+----------------+----------+-----------+
 * |date/time(time_t)| 0x20 fixed |header level(=3)|file CRC16|  creator  |
 * +-----------------+------------+----------------+----------+-----------+
 * *--------------------------------(*1)----------------------------------*
 *
 * +24             +28              +32                 +32+(*3)
 * +---------------+----------------+-------------------+-----------------+
 * |header size(*1)|next header size|extended header(*3)| compressed data |
 * +---------------+----------------+-------------------+-----------------+
 * *------------------------(*1)-----------------------> <------(*2)----->
 *
 */
fn lha_read_file_header_3(mut a: *mut archive_read, mut lha: &mut lha) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let mut extdsize: size_t = 0;
    let err: i32;
    let mut header_crc: uint16_t = 0;
    p = unsafe {
        __archive_read_ahead_safe(
            a,
            ARCHIVE_LHA_DEFINED_PARAM.h3_fixed_size as size_t,
            0 as *mut ssize_t,
        )
    } as *const u8;
    if p.is_null() {
        return truncated_error(a);
    }
    if !(archive_le16dec(
        unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_field_len_offset as isize) } as *const (),
    ) as i32
        != 4)
    {
        lha.header_size = archive_le32dec(unsafe {
            p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_header_size_offset as isize)
        } as *const ()) as size_t;
        lha.compsize = archive_le32dec(unsafe {
            p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_comp_size_offset as isize)
        } as *const ()) as int64_t;
        lha.origsize = archive_le32dec(unsafe {
            p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_orig_size_offset as isize)
        } as *const ()) as int64_t;
        lha.mtime =
            archive_le32dec(
                unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_time_offset as isize) } as *const (),
            ) as time_t;
        lha.crc =
            archive_le16dec(
                unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_crc_offset as isize) } as *const (),
            );
        lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.crc_is_set;

        if !(lha.header_size < (ARCHIVE_LHA_DEFINED_PARAM.h3_fixed_size + 4) as u64) {
            header_crc = lha_crc16(
                0,
                p as *const (),
                ARCHIVE_LHA_DEFINED_PARAM.h3_fixed_size as size_t,
            );
            unsafe {
                __archive_read_consume_safe(a, ARCHIVE_LHA_DEFINED_PARAM.h3_fixed_size as int64_t)
            };
            /* Read extended headers */
            err = lha_read_file_extended_header(
                a,
                lha,
                &mut header_crc,
                4,
                lha.header_size - (ARCHIVE_LHA_DEFINED_PARAM.h3_fixed_size as u64),
                &mut extdsize,
            );
            if err < ARCHIVE_LHA_DEFINED_PARAM.archive_warn {
                return err;
            }
            if header_crc != lha.header_crc {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
                    b"LHa header CRC error\x00" as *const u8
                );
                return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
            }
            return err;
        }
    }
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
        b"Invalid LHa header\x00" as *const u8
    );
    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
}

/*
* Extended header format
*
* +0             +2        +3  -- used in header 1 and 2
* +0             +4        +5  -- used in header 3
* +--------------+---------+-------------------+--------------+--
* |ex-header size|header id|        data       |ex-header size| .......
* +--------------+---------+-------------------+--------------+--
*  <-------------( ex-header size)------------> <-- next extended header --*
*
* If the ex-header size is zero, it is the make of the end of extended
* headers.
*
*/
fn lha_read_file_extended_header(
    a: *mut archive_read,
    lha: &mut lha,
    crc: *mut uint16_t,
    sizefield_length: i32,
    limitsize: size_t,
    total_size: &mut size_t,
) -> i32 {
    let safe_a = unsafe { &mut *a };
    let mut h: *const () = 0 as *const ();
    let mut extdheader: *const u8 = 0 as *const u8;
    let mut extdsize: size_t = 0;
    let mut datasize: size_t;
    let mut i: u32 = 0;
    let mut extdtype: u8;
    *total_size = sizefield_length as size_t;
    loop {
        /* Read an extended header size. */
        h = unsafe { __archive_read_ahead_safe(a, sizefield_length as size_t, 0 as *mut ssize_t) };
        if h == 0 as *mut () {
            return truncated_error(a);
        }
        /* Check if the size is the zero indicates the end of the
         * extended header. */
        if sizefield_length as u64 == size_of::<uint16_t>() as u64 {
            extdsize = archive_le16dec(h) as size_t
        } else {
            extdsize = archive_le32dec(h) as size_t
        }
        if extdsize == 0 {
            /* End of extended header */
            if !crc.is_null() {
                unsafe { *crc = lha_crc16(*crc, h, sizefield_length as size_t) }
            }
            unsafe { __archive_read_consume_safe(a, sizefield_length as int64_t) };
            return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
        }
        /* Sanity check to the extended header size. */
        if (*total_size + extdsize) > limitsize || extdsize <= sizefield_length as size_t {
            break;
        }
        /* Read the extended header. */
        h = unsafe { __archive_read_ahead_safe(a, extdsize, 0 as *mut ssize_t) };
        if h == 0 as *mut () {
            return truncated_error(a);
        }
        *total_size = (*total_size as u64 + extdsize) as size_t;
        extdheader = h as *const u8;
        /* Get the extended header type. */
        extdtype = unsafe { *extdheader.offset(sizefield_length as isize) };
        /* Calculate an extended data size. */
        datasize = extdsize - (1 + sizefield_length) as u64;
        /* Skip an extended header size field and type field. */
        extdheader = unsafe { extdheader.offset((sizefield_length + 1) as isize) };
        if !crc.is_null() && extdtype as i32 != ARCHIVE_LHA_DEFINED_PARAM.ext_header_crc {
            unsafe { *crc = lha_crc16(*crc, h, extdsize) }
        }
        if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_header_crc {
            /* We only use a header CRC. Following data will not
             * be used. */
            if datasize >= 2 {
                lha.header_crc = archive_le16dec(extdheader as *const ());
                if !crc.is_null() {
                    static mut zeros: [i8; 2] = [0, 0];
                    unsafe {
                        *crc = lha_crc16(*crc, h, extdsize - datasize);
                        /* CRC value itself as zero */
                        *crc = lha_crc16(*crc, zeros.as_ptr() as *const (), 2 as size_t);
                        *crc = lha_crc16(
                            *crc,
                            extdheader.offset(2 as isize) as *const (),
                            datasize - 2,
                        )
                    }
                }
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_filename {
            if datasize == 0 {
                /* maybe directory header */
                lha.filename.length = 0 as size_t
            } else {
                if unsafe { *extdheader.offset(0 as isize) } == '\u{0}' as u8 {
                    break;
                }
                lha.filename.length = 0;
                unsafe {
                    archive_strncat_safe(
                        &mut lha.filename,
                        extdheader as *const u8 as *const (),
                        datasize,
                    )
                };
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_utf16_filename {
            if datasize == 0 {
                /* maybe directory header */
                lha.filename.length = 0 as size_t
            } else if datasize & 1 != 0 {
                /* UTF-16 characters take always 2 or 4 bytes */
                break;
            } else {
                if unsafe { *extdheader.offset(0 as isize) } == '\u{0}' as u8 {
                    break;
                }
                lha.filename.length = 0;
                unsafe {
                    archive_array_append_safe(&mut lha.filename, extdheader as *const u8, datasize)
                };
                /* Setup a string conversion for a filename. */
                lha.sconv_fname = unsafe {
                    archive_string_conversion_from_charset_safe(
                        &mut safe_a.archive,
                        b"UTF-16LE\x00" as *const u8,
                        1,
                    )
                };
                if lha.sconv_fname.is_null() {
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
                }
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_directory {
            if datasize == 0 || unsafe { *extdheader.offset(0 as isize) } == '\u{0}' as u8 {
                /* no directory name data. exit this case. */
                break;
            } else {
                lha.dirname.length = 0;
                unsafe {
                    archive_strncat_safe(
                        &mut lha.dirname,
                        extdheader as *const u8 as *const (),
                        datasize,
                    )
                };
                /*
                 * Convert directory delimiter from 0xFF
                 * to '/' for local system.
                 */
                i = 0;
                while (i as u64) < lha.dirname.length {
                    if unsafe { *lha.dirname.s.offset(i as isize) } as u8 == 0xff {
                        unsafe { *lha.dirname.s.offset(i as isize) = '/' as u8 }
                    }
                    i = i + 1
                }
                /* Is last character directory separator? */
                if unsafe { *lha.dirname.s.offset((lha.dirname.length - 1) as isize) } != '/' as u8
                {
                    /* invalid directory data */
                    break;
                }
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_utf16_directory {
            /* UTF-16 characters take always 2 or 4 bytes */
            if datasize == 0
                || datasize & 1 != 0
                || unsafe { *extdheader.offset(0 as isize) } == '\u{0}' as u8
            {
                /* no directory name data. exit this case. */
                break;
            } else {
                lha.dirname.length = 0;
                unsafe {
                    archive_array_append_safe(&mut lha.dirname, extdheader as *const u8, datasize);
                    lha.sconv_dir = archive_string_conversion_from_charset_safe(
                        &mut safe_a.archive,
                        b"UTF-16LE\x00" as *const u8,
                        1,
                    )
                };
                if lha.sconv_dir.is_null() {
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
                } else {
                    /*
                     * Convert directory delimiter from 0xFFFF
                     * to '/' for local system.
                     */
                    let mut dirSep: uint16_t = 0;
                    let mut d: uint16_t = 1;
                    if archive_be16dec(&mut d as *mut uint16_t as *const ()) == 1 {
                        dirSep = 0x2f00 as uint16_t
                    } else {
                        dirSep = 0x2f as uint16_t
                    }
                    /* UTF-16LE character */
                    let mut utf16name: *mut uint16_t = lha.dirname.s as *mut uint16_t;
                    i = 0;
                    while (i as u64) < lha.dirname.length / 2 {
                        if unsafe { *utf16name.offset(i as isize) } as u16 == 0xffff {
                            unsafe { *utf16name.offset(i as isize) = dirSep }
                        }
                        i = i + 1
                    }
                    /* Is last character directory separator? */
                    if unsafe { *utf16name.offset((lha.dirname.length / 2 - 1) as isize) } != dirSep
                    {
                        break;
                    }
                }
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_dos_attr {
            if datasize == 2 {
                lha.dos_attr = (archive_le16dec(extdheader as *const ()) as i32 & 0xff) as u8
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_timestamp {
            if datasize == (size_of::<uint64_t>() as u64) * 3 {
                lha.birthtime = lha_win_time(
                    archive_le64dec(extdheader as *const ()),
                    &mut lha.birthtime_tv_nsec,
                );
                extdheader = unsafe { extdheader.offset(size_of::<uint64_t>() as isize) };
                lha.mtime = lha_win_time(
                    archive_le64dec(extdheader as *const ()),
                    &mut lha.mtime_tv_nsec,
                );
                extdheader = unsafe { extdheader.offset(size_of::<uint64_t>() as isize) };
                lha.atime = lha_win_time(
                    archive_le64dec(extdheader as *const ()),
                    &mut lha.atime_tv_nsec,
                );
                lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.birthtime_is_set
                    | ARCHIVE_LHA_DEFINED_PARAM.atime_is_set
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_filesize {
            if datasize == (size_of::<uint64_t>() as u64 * 2) {
                lha.compsize = archive_le64dec(extdheader as *const ()) as int64_t;
                extdheader = unsafe { extdheader.offset(size_of::<uint64_t>() as isize) };
                lha.origsize = archive_le64dec(extdheader as *const ()) as int64_t
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_codepage {
            /* Get an archived filename charset from codepage.
             * This overwrites the charset specified by
             * hdrcharset option. */
            if datasize == size_of::<uint32_t>() as u64 {
                let mut cp: archive_string = archive_string {
                    s: 0 as *mut u8,
                    length: 0,
                    buffer_length: 0,
                };
                let mut charset: *const u8 = 0 as *const u8;
                cp.s = 0 as *mut u8;
                cp.length = 0;
                cp.buffer_length = 0;
                match archive_le32dec(extdheader as *const ()) {
                    65001 => {
                        /* UTF-8 */
                        charset = b"UTF-8\x00" as *const u8
                    }
                    _ => {
                        archive_string_sprintf_safe!(
                            &mut cp as *mut archive_string,
                            b"CP%d\x00" as *const u8,
                            archive_le32dec(extdheader as *const ()) as i32
                        );
                        charset = cp.s
                    }
                }
                lha.sconv_dir = unsafe {
                    archive_string_conversion_from_charset_safe(&mut safe_a.archive, charset, 1)
                };
                lha.sconv_fname = unsafe {
                    archive_string_conversion_from_charset_safe(&mut safe_a.archive, charset, 1)
                };
                unsafe { archive_string_free_safe(&mut cp) };
                if lha.sconv_dir.is_null() {
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
                }
                if lha.sconv_fname.is_null() {
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
                }
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_unix_mode {
            if datasize == size_of::<uint16_t>() as u64 {
                lha.mode = archive_le16dec(extdheader as *const ()) as mode_t;
                lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.unix_mode_is_set
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_unix_gid_uid {
            if datasize == (size_of::<uint16_t>() as u64) * 2 {
                lha.gid = archive_le16dec(extdheader as *const ()) as int64_t;
                lha.uid = archive_le16dec(unsafe { extdheader.offset(2 as isize) } as *const ())
                    as int64_t
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_unix_gname {
            if datasize > 0 {
                lha.gname.length = 0;
                unsafe {
                    archive_strncat_safe(
                        &mut lha.gname,
                        extdheader as *const u8 as *const (),
                        datasize,
                    )
                };
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_unix_uname {
            if datasize > 0 {
                lha.uname.length = 0;
                unsafe {
                    archive_strncat_safe(
                        &mut lha.uname,
                        extdheader as *const u8 as *const (),
                        datasize,
                    )
                };
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_unix_mtime {
            if datasize == size_of::<uint32_t>() as u64 {
                lha.mtime = archive_le32dec(extdheader as *const ()) as time_t
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_os2_new_attr {
            /* This extended header is OS/2 depend. */
            if datasize == 16 {
                lha.dos_attr = (archive_le16dec(extdheader as *const ()) as i32 & 0xff) as u8;
                lha.mode = archive_le16dec(unsafe { extdheader.offset(2 as isize) } as *const ())
                    as mode_t;
                lha.gid = archive_le16dec(unsafe { extdheader.offset(4 as isize) } as *const ())
                    as int64_t;
                lha.uid = archive_le16dec(unsafe { extdheader.offset(6 as isize) } as *const ())
                    as int64_t;
                lha.birthtime =
                    archive_le32dec(unsafe { extdheader.offset(8 as isize) } as *const ())
                        as time_t;
                lha.atime = archive_le32dec(unsafe { extdheader.offset(12 as isize) } as *const ())
                    as time_t;
                lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.unix_mode_is_set
                    | ARCHIVE_LHA_DEFINED_PARAM.birthtime_is_set
                    | ARCHIVE_LHA_DEFINED_PARAM.atime_is_set
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_new_attr {
            if datasize == 20 {
                lha.mode = archive_le32dec(extdheader as *const ());
                lha.gid = archive_le32dec(unsafe { extdheader.offset(4 as isize) } as *const ())
                    as int64_t;
                lha.uid = archive_le32dec(unsafe { extdheader.offset(8 as isize) } as *const ())
                    as int64_t;
                lha.birthtime =
                    archive_le32dec(unsafe { extdheader.offset(12 as isize) } as *const ())
                        as time_t;
                lha.atime = archive_le32dec(unsafe { extdheader.offset(16 as isize) } as *const ())
                    as time_t;
                lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.unix_mode_is_set
                    | ARCHIVE_LHA_DEFINED_PARAM.birthtime_is_set
                    | ARCHIVE_LHA_DEFINED_PARAM.atime_is_set
            }
        } else if extdtype as i32 == ARCHIVE_LHA_DEFINED_PARAM.ext_timezone {
        }
        /* Not supported */
        unsafe { __archive_read_consume_safe(a, extdsize as int64_t) };
    }
    /* invalid directory data */
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
        b"Invalid extended LHa header\x00" as *const u8
    );
    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
}

fn lha_end_of_entry(a: *mut archive_read) -> i32 {
    let mut lha = unsafe { &mut *((*(*a).format).data as *mut lha) };
    let mut r: i32 = ARCHIVE_LHA_DEFINED_PARAM.archive_eof;
    if lha.end_of_entry_cleanup == 0 {
        if lha.setflag & ARCHIVE_LHA_DEFINED_PARAM.crc_is_set != 0
            && lha.crc != lha.entry_crc_calculated
        {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_LHA_DEFINED_PARAM.archive_errno_misc,
                b"LHa data CRC error\x00" as *const u8
            );
            r = ARCHIVE_LHA_DEFINED_PARAM.archive_warn
        }
        /* End-of-entry cleanup done. */
        lha.end_of_entry_cleanup = 1
    }
    return r;
}

fn archive_read_format_lha_read_data(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let safe_a = unsafe { &mut *a };
    let safe_buff = unsafe { &mut *buff };
    let safe_size = unsafe { &mut *size };
    let safe_offset = unsafe { &mut *offset };
    let mut lha = unsafe { &mut *((*safe_a.format).data as *mut lha) };
    let r: i32;
    if lha.entry_unconsumed != 0 {
        /* Consume as much as the decompressor actually used. */
        unsafe { __archive_read_consume_safe(a, lha.entry_unconsumed) };
        lha.entry_unconsumed = 0
    }
    if lha.end_of_entry != 0 {
        *safe_offset = lha.entry_offset;
        *safe_size = 0;
        *safe_buff = 0 as *const ();
        return lha_end_of_entry(a);
    }
    if lha.entry_is_compressed != 0 {
        r = lha_read_data_lzh(safe_a, safe_buff, safe_size, safe_offset)
    } else {
        /* No compression. */
        r = lha_read_data_none(safe_a, safe_buff, safe_size, safe_offset)
    }
    return r;
}

/*
* Read a file content in no compression.
*
* Returns ARCHIVE_OK if successful, ARCHIVE_FATAL otherwise, sets
* lha->end_of_entry if it consumes all of the data.
*/
fn lha_read_data_none(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let lha = unsafe { &mut *((*(*a).format).data as *mut lha) };
    let lha_safe = unsafe { &mut *lha };
    let mut bytes_avail: ssize_t = 0;
    if lha_safe.entry_bytes_remaining == 0 {
        unsafe { *buff = 0 as *const () };
        unsafe { *size = 0 };
        unsafe { *offset = lha_safe.entry_offset };
        lha_safe.end_of_entry = 1;
        return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
    }
    /*
     * Note: '1' here is a performance optimization.
     * Recall that the decompression layer returns a count of
     * available bytes; asking for more than that forces the
     * decompressor to combine reads by copying data.
     */
    unsafe { *buff = __archive_read_ahead_safe(a, 1, &mut bytes_avail) };
    if bytes_avail <= 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Truncated LHa file data\x00" as *const u8
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    if bytes_avail > lha_safe.entry_bytes_remaining {
        bytes_avail = lha_safe.entry_bytes_remaining
    }
    lha_safe.entry_crc_calculated = lha_crc16(
        lha_safe.entry_crc_calculated,
        unsafe { *buff },
        bytes_avail as size_t,
    );
    unsafe { *size = bytes_avail as size_t };
    unsafe { *offset = lha_safe.entry_offset };
    lha_safe.entry_offset += bytes_avail;
    lha_safe.entry_bytes_remaining -= bytes_avail;
    if lha_safe.entry_bytes_remaining == 0 {
        lha_safe.end_of_entry = 1
    }
    lha_safe.entry_unconsumed = bytes_avail;
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

/*
* Read a file content in LZHUFF encoding.
*
* Returns ARCHIVE_OK if successful, returns ARCHIVE_WARN if compression is
* unsupported, ARCHIVE_FATAL otherwise, sets lha->end_of_entry if it consumes
* all of the data.
*/
fn lha_read_data_lzh(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let lha = unsafe { &mut *((*(*a).format).data as *mut lha) };
    let lha_safe = unsafe { &mut *lha };
    let mut bytes_avail: ssize_t = 0;
    let mut r: i32;
    /* If we haven't yet read any data, initialize the decompressor. */
    if lha_safe.decompress_init == 0 {
        r = lzh_decode_init(&mut lha_safe.strm, lha_safe.method.as_mut_ptr());
        if r == ARCHIVE_LHA_DEFINED_PARAM.archive_ok {
        } else if r == ARCHIVE_LHA_DEFINED_PARAM.archive_failed {
            /* Unsupported compression. */
            unsafe {
                *buff = 0 as *const ();
                *size = 0;
                *offset = 0
            };
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
                b"Unsupported lzh compression method -%c%c%c-\x00" as *const u8,
                lha_safe.method[0] as i32,
                lha_safe.method[1] as i32,
                lha_safe.method[2] as i32
            );
            /* We know compressed size; just skip it. */
            archive_read_format_lha_read_data_skip(a);
            return ARCHIVE_LHA_DEFINED_PARAM.archive_warn;
        } else {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_LHA_DEFINED_PARAM.enomem,
                b"Couldn\'t allocate memory for lzh decompression\x00" as *const u8
            );
            return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
        }
        /* We've initialized decompression for this stream. */
        lha_safe.decompress_init = 1;
        lha_safe.strm.avail_out = 0;
        lha_safe.strm.total_out = 0
    }
    /*
     * Note: '1' here is a performance optimization.
     * Recall that the decompression layer returns a count of
     * available bytes; asking for more than that forces the
     * decompressor to combine reads by copying data.
     */
    lha_safe.strm.next_in =
        unsafe { __archive_read_ahead_safe(a, 1 as size_t, &mut bytes_avail) } as *const u8;
    if bytes_avail <= 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Truncated LHa file body\x00" as *const u8
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    if bytes_avail > lha_safe.entry_bytes_remaining {
        bytes_avail = lha_safe.entry_bytes_remaining
    }
    lha_safe.strm.avail_in = bytes_avail as i32;
    lha_safe.strm.total_in = 0;
    lha_safe.strm.avail_out = 0;
    r = lzh_decode(
        &mut lha_safe.strm,
        (bytes_avail == lha_safe.entry_bytes_remaining) as i32,
    );
    if r == ARCHIVE_LHA_DEFINED_PARAM.archive_ok {
    } else if r == ARCHIVE_LHA_DEFINED_PARAM.archive_eof {
        lha_safe.end_of_entry = 1
    } else {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_misc,
            b"Bad lzh data\x00" as *const u8
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
    }
    lha_safe.entry_unconsumed = lha_safe.strm.total_in;
    lha_safe.entry_bytes_remaining -= lha_safe.strm.total_in;
    if lha_safe.strm.avail_out != 0 {
        unsafe { *offset = lha_safe.entry_offset };
        unsafe { *size = lha_safe.strm.avail_out as size_t };
        unsafe { *buff = lha_safe.strm.ref_ptr as *const () };
        lha_safe.entry_crc_calculated =
            lha_crc16(lha_safe.entry_crc_calculated, unsafe { *buff }, unsafe {
                *size
            });
        lha_safe.entry_offset = (lha_safe.entry_offset as u64 + unsafe { *size }) as int64_t
    } else {
        unsafe { *offset = lha_safe.entry_offset };
        unsafe { *size = 0 };
        unsafe { *buff = 0 as *const () };
        if lha_safe.end_of_entry != 0 {
            return lha_end_of_entry(a);
        }
    }
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

/*
 * Skip a file content.
 */
fn archive_read_format_lha_read_data_skip(a: *mut archive_read) -> i32 {
    let lha = unsafe { &mut *((*(*a).format).data as *mut lha) };
    let bytes_skipped: int64_t;
    if lha.entry_unconsumed != 0 {
        /* Consume as much as the decompressor actually used. */
        unsafe { __archive_read_consume_safe(a, lha.entry_unconsumed) };
        lha.entry_unconsumed = 0
    }
    /* if we've already read to end of data, we're done. */
    if lha.end_of_entry_cleanup != 0 {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
    }
    /*
     * If the length is at the beginning, we can skip the
     * compressed data much more quickly.
     */
    bytes_skipped = unsafe { __archive_read_consume_safe(a, lha.entry_bytes_remaining) };
    if bytes_skipped < 0 {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    /* This entry is finished and done. */
    lha.end_of_entry = 1;
    lha.end_of_entry_cleanup = lha.end_of_entry;
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

fn archive_read_format_lha_cleanup(a: *mut archive_read) -> i32 {
    let safe_a_format = unsafe { &mut *(*a).format };
    let lha = unsafe { &mut *((*(*a).format).data as *mut lha) };
    lzh_decode_free(&mut lha.strm);
    unsafe { archive_string_free_safe(&mut lha.dirname) };
    unsafe { archive_string_free_safe(&mut lha.filename) };
    unsafe { archive_string_free_safe(&mut lha.uname) };
    unsafe { archive_string_free_safe(&mut lha.gname) };
    unsafe { archive_wstring_free_safe(&mut lha.ws) };
    unsafe { free_safe(lha as *mut lha as *mut ()) };
    safe_a_format.data = 0 as *mut ();
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

/*
* 'LHa for UNIX' utility has archived a symbolic-link name after
* a pathname with '|' character.
* This function extracts the symbolic-link name from the pathname.
*
* example.
*   1. a symbolic-name is 'aaa/bb/cc'
*   2. a filename is 'xxx/bbb'
*  then a archived pathname is 'xxx/bbb|aaa/bb/cc'
*/
fn lha_parse_linkname(linkname: &mut archive_wstring, pathname: &mut archive_wstring) -> i32 {
    let linkptr = unsafe { &mut *wcschr_safe(pathname.s, '|' as wchar_t) };
    let symlen: size_t;
    if !(linkptr as *mut wchar_t).is_null() {
        symlen = unsafe { wcslen_safe((linkptr as *mut wchar_t).offset(1 as isize)) };
        linkname.length = 0;
        unsafe {
            archive_wstrncat_safe(
                linkname,
                (linkptr as *mut wchar_t).offset(1 as isize),
                symlen,
            )
        };
        *linkptr = 0;
        pathname.length = unsafe { wcslen_safe(pathname.s) };
        return 1;
    }
    return 0;
}

/* Convert an MSDOS-style date/time into Unix-style time. */
fn lha_dos_time(p: *const u8) -> time_t {
    let mut msTime: i32 = 0; /* Years since 1900. */
    let mut msDate: i32 = 0; /* Month number.     */
    let mut ts: tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: 0 as *const u8,
    }; /* Day of month.     */
    msTime = archive_le16dec(p as *const ()) as i32;
    msDate = archive_le16dec(unsafe { p.offset(2 as isize) } as *const ()) as i32;
    unsafe { memset_safe(&mut ts as *mut tm as *mut (), 0, size_of::<tm>() as u64) };
    ts.tm_year = (msDate >> 9 & 0x7f) + 80;
    ts.tm_mon = (msDate >> 5 & 0xf) - 1;
    ts.tm_mday = msDate & 0x1f;
    ts.tm_hour = msTime >> 11 & 0x1f;
    ts.tm_min = msTime >> 5 & 0x3f;
    ts.tm_sec = msTime << 1 & 0x3e;
    ts.tm_isdst = -(1);
    return unsafe { mktime_safe(&mut ts) };
}

/* Convert an MS-Windows-style date/time into Unix-style time. */
fn lha_win_time(mut wintime: uint64_t, mut ns: &mut i64) -> time_t {
    if wintime >= ARCHIVE_LHA_DEFINED_PARAM.epoc_time {
        wintime = wintime - ARCHIVE_LHA_DEFINED_PARAM.epoc_time; /* 1970-01-01 00:00:00 (UTC) */
        if !(ns as *mut i64).is_null() {
            *ns = (wintime % 10000000) as i64 * 100
        }
        return (wintime / 10000000) as time_t;
    } else {
        if !(ns as *mut i64).is_null() {
            *ns = 0
        }
        return 0;
    };
}

fn lha_calcsum(mut sum: u8, pp: *const (), offset: i32, mut size: size_t) -> u8 {
    let mut p: *const u8 = pp as *const u8;
    p = unsafe { p.offset(offset as isize) };
    while size > 0 {
        sum = (sum + unsafe { &*p }) as u8;
        p = unsafe { p.offset(1) };
        size = size - 1
    }
    return sum;
}

static mut crc16tbl: [[uint16_t; 256]; 2] = [[0; 256]; 2];

fn lha_crc16_init() {
    let mut i: u32 = 0;
    let mut crc16init: i32 = 0;
    if crc16init != 0 {
        return;
    }
    crc16init = 1;
    i = 0;
    while i < 256 {
        let mut j: u32 = 0;
        let mut crc: uint16_t = i as uint16_t;
        j = 8;
        while j != 0 {
            crc = (crc as i32 >> 1 ^ (crc as i32 & 1) * 0xa001) as uint16_t;
            j = j - 1
        }
        unsafe {
            crc16tbl[0][i as usize] = crc;
        }
        i = i + 1
    }
    i = 0;
    while i < 256 {
        unsafe {
            crc16tbl[1][i as usize] = (crc16tbl[0][i as usize] as i32 >> 8
                ^ crc16tbl[0][(crc16tbl[0][i as usize] & 0xff) as usize] as i32)
                as uint16_t;
        }
        i = i + 1
    }
}

fn lha_crc16(mut crc: uint16_t, pp: *const (), mut len: size_t) -> uint16_t {
    let mut p: *const u8 = pp as *const u8;
    let mut buff: *const uint16_t = 0 as *const uint16_t;
    let u: archive_temporary_u = archive_temporary_u {
        i: 0x1020304 as uint32_t,
    };
    if len == 0 {
        return crc;
    }
    /* Process unaligned address. */
    if p as uintptr_t & 0x1 as uintptr_t != 0 {
        crc = (crc as i32 >> 8
            ^ unsafe { crc16tbl[0] }[((crc as i32 ^ unsafe { *p } as i32) & 0xff) as usize] as i32)
            as uint16_t;
        unsafe { p = p.offset(1) };
        len = len - 1
    }
    buff = p as *const uint16_t;
    /*
     * Modern C compiler such as GCC does not unroll automatically yet
     * without unrolling pragma, and Clang is so. So we should
     * unroll this loop for its performance.
     */
    while len >= 8 {
        /* This if statement expects compiler optimization will
         * remove the statement which will not be executed. */
        /* Visual Studio */
        /* All clang versions have __builtin_bswap16() */
        /* Big endian */
        if unsafe { u.c[0] } == 1 {
            crc = (crc ^ unsafe { *buff }.swap_bytes()) as uint16_t;
            unsafe { buff = buff.offset(1) }
        } else {
            crc = (crc ^ unsafe { *buff }) as uint16_t;
            unsafe { buff = buff.offset(1) }
        }
        crc = (unsafe { crc16tbl[1][(crc & 0xff) as usize] }
            ^ unsafe { crc16tbl[0][(crc >> 8) as usize] }) as uint16_t;
        if unsafe { u.c[0] } == 1 {
            crc = (crc ^ unsafe { *buff }.swap_bytes()) as uint16_t;
            unsafe { buff = buff.offset(1) }
        } else {
            crc = (crc ^ unsafe { *buff }) as uint16_t;
            unsafe { buff = buff.offset(1) }
        }
        crc = (unsafe { crc16tbl[1][(crc & 0xff) as usize] }
            ^ unsafe { crc16tbl[0][(crc >> 8) as usize] }) as uint16_t;
        if unsafe { u.c[0] } == 1 {
            crc = (crc ^ unsafe { *buff }.swap_bytes()) as uint16_t;
            unsafe { buff = buff.offset(1) }
        } else {
            crc = (crc ^ unsafe { *buff }) as uint16_t;
            unsafe {
                buff = buff.offset(1);
            }
        }
        crc = (unsafe { crc16tbl[1][(crc & 0xff) as usize] }
            ^ unsafe { crc16tbl[0][(crc >> 8) as usize] }) as uint16_t;
        if unsafe { u.c[0] } == 1 {
            crc = (crc ^ unsafe { *buff }.swap_bytes()) as uint16_t;
            unsafe { buff = buff.offset(1) }
        } else {
            crc = (crc ^ unsafe { *buff }) as uint16_t;
            unsafe {
                buff = buff.offset(1);
            }
        }
        crc = (unsafe { crc16tbl[1][(crc & 0xff) as usize] }
            ^ unsafe { crc16tbl[0][(crc >> 8) as usize] }) as uint16_t;
        len = len - 8
    }
    p = buff as *const u8;
    while len != 0 {
        crc = (crc >> 8 ^ unsafe { crc16tbl[0][((crc ^ *p as u16) & 0xff) as usize] }) as uint16_t;
        unsafe {
            p = p.offset(1);
        }
        len = len - 1
    }
    return crc;
}

/*
 * Initialize LZHUF decoder.
 *
 * Returns ARCHIVE_OK if initialization was successful.
 * Returns ARCHIVE_FAILED if method is unsupported.
 * Returns ARCHIVE_FATAL if initialization failed; memory allocation
 * error occurred.
 */
fn lzh_decode_init(strm: &mut lzh_stream, method: *const u8) -> i32 {
    let mut w_bits: i32 = 0;
    let w_size: i32;
    if strm.ds.is_null() {
        strm.ds = unsafe { calloc_safe(1, size_of::<lzh_dec>() as u64) } as *mut lzh_dec;
        if strm.ds.is_null() {
            return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
        }
    }
    let ds = unsafe { &mut *strm.ds };
    ds.error = ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
    if method.is_null()
        || unsafe { *method.offset(0 as isize) } != 'l' as u8
        || unsafe { *method.offset(1 as isize) } != 'h' as u8
    {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
    }
    let method_char = unsafe { *method.offset(2 as isize) } as char;
    match method_char {
        '5' => w_bits = 13,                                   /* 8KiB for window */
        '6' => w_bits = 15,                                   /* 32KiB for window */
        '7' => w_bits = 16,                                   /* 64KiB for window */
        _ => return ARCHIVE_LHA_DEFINED_PARAM.archive_failed, /* Not supported. */
    }
    ds.error = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    /* Expand a window size up to 128 KiB for decompressing process
     * performance whatever its original window size is. */
    ds.w_size = 1 << 17;
    ds.w_mask = ds.w_size - 1;
    if ds.w_buff.is_null() {
        ds.w_buff = unsafe { malloc_safe(ds.w_size as u64) } as *mut u8;
        if ds.w_buff.is_null() {
            return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
        }
    }
    w_size = 1 << w_bits;
    unsafe {
        memset_safe(
            ds.w_buff
                .offset(ds.w_size as isize)
                .offset(-(w_size as isize)) as *mut (),
            0x20,
            w_size as u64,
        )
    };
    ds.w_pos = 0;
    ds.state = 0;
    ds.pos_pt_len_size = w_bits + 1;
    ds.pos_pt_len_bits = if w_bits == 15 || w_bits == 16 { 5 } else { 4 };
    ds.literal_pt_len_size = ARCHIVE_LHA_DEFINED_PARAM.pt_bitlen_size;
    ds.literal_pt_len_bits = 5;
    ds.br.cache_buffer = 0;
    ds.br.cache_avail = 0;
    if lzh_huffman_init(
        &mut ds.lt,
        ARCHIVE_LHA_DEFINED_PARAM.lt_bitlen_size as size_t,
        16,
    ) != ARCHIVE_LHA_DEFINED_PARAM.archive_ok
    {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    ds.lt.len_bits = 9;
    if lzh_huffman_init(
        &mut ds.pt,
        ARCHIVE_LHA_DEFINED_PARAM.pt_bitlen_size as size_t,
        16,
    ) != ARCHIVE_LHA_DEFINED_PARAM.archive_ok
    {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    ds.error = 0;
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

/*
 * Release LZHUF decoder.
 */
fn lzh_decode_free(strm: &mut lzh_stream) {
    if strm.ds.is_null() {
        return;
    }
    let mut ds = unsafe { &mut *strm.ds };
    unsafe { free_safe(ds.w_buff as *mut ()) };
    lzh_huffman_free(&mut ds.lt);
    lzh_huffman_free(&mut ds.pt);
    unsafe { free_safe(strm.ds as *mut ()) };
    strm.ds = 0 as *mut lzh_dec;
}

/* Notify how many bits we consumed. */
static cache_masks: [uint16_t; 20] = [
    0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff, 0xfff, 0x1fff, 0x3fff,
    0x7fff, 0xffff, 0xffff, 0xffff, 0xffff,
];

/*
 * Shift away used bits in the cache data and fill it up with following bits.
 * Call this when cache buffer does not have enough bits you need.
 *
 * Returns 1 if the cache buffer is full.
 * Returns 0 if the cache buffer is not full; input buffer is empty.
 */
/*
 * Shift away used bits in the cache data and fill it up with following bits.
 * Call this when cache buffer does not have enough bits you need.
 *
 * Returns 1 if the cache buffer is full.
 * Returns 0 if the cache buffer is not full; input buffer is empty.
 */
fn lzh_br_fillup(strm: &mut lzh_stream, br: &mut lzh_br) -> i32 {
    let mut n: i32 = ARCHIVE_LHA_DEFINED_PARAM.cache_bits - br.cache_avail;
    loop {
        let x: i32 = n >> 3;
        if strm.avail_in >= x {
            match x {
                8 => {
                    br.cache_buffer = (unsafe { *strm.next_in.offset(0 as isize) } as uint64_t)
                        << 56
                        | (unsafe { *strm.next_in.offset(1 as isize) } as uint64_t) << 48
                        | (unsafe { *strm.next_in.offset(2 as isize) } as uint64_t) << 40
                        | (unsafe { *strm.next_in.offset(3 as isize) } as uint64_t) << 32
                        | ((unsafe { *strm.next_in.offset(4 as isize) } as uint32_t) << 24) as u64
                        | ((unsafe { *strm.next_in.offset(5 as isize) } as uint32_t) << 16) as u64
                        | ((unsafe { *strm.next_in.offset(6 as isize) } as uint32_t) << 8) as u64
                        | unsafe { *strm.next_in.offset(7 as isize) } as u64;
                    strm.next_in = unsafe { strm.next_in.offset(8 as isize) };
                    strm.avail_in -= 8;
                    br.cache_avail += 8 * 8;
                    return 1;
                }
                7 => {
                    br.cache_buffer = br.cache_buffer << 56
                        | (unsafe { *strm.next_in.offset(0 as isize) } as uint64_t) << 48
                        | (unsafe { *strm.next_in.offset(1 as isize) } as uint64_t) << 40
                        | (unsafe { *strm.next_in.offset(2 as isize) } as uint64_t) << 32
                        | ((unsafe { *strm.next_in.offset(3 as isize) } as uint32_t) << 24) as u64
                        | ((unsafe { *strm.next_in.offset(4 as isize) } as uint32_t) << 16) as u64
                        | ((unsafe { *strm.next_in.offset(5 as isize) } as uint32_t) << 8) as u64
                        | unsafe { *strm.next_in.offset(6 as isize) } as u64;
                    strm.next_in = unsafe { strm.next_in.offset(7 as isize) };
                    strm.avail_in -= 7;
                    br.cache_avail += 7 * 8;
                    return 1;
                }
                6 => {
                    br.cache_buffer = br.cache_buffer << 48
                        | (unsafe { *strm.next_in.offset(0 as isize) } as uint64_t) << 40
                        | (unsafe { *strm.next_in.offset(1 as isize) } as uint64_t) << 32
                        | ((unsafe { *strm.next_in.offset(2 as isize) } as uint32_t) << 24) as u64
                        | ((unsafe { *strm.next_in.offset(3 as isize) } as uint32_t) << 16) as u64
                        | ((unsafe { *strm.next_in.offset(4 as isize) } as uint32_t) << 8) as u64
                        | unsafe { *strm.next_in.offset(5 as isize) } as u64;
                    strm.next_in = unsafe { strm.next_in.offset(6 as isize) };
                    strm.avail_in -= 6;
                    br.cache_avail += 6 * 8;
                    return 1;
                }
                0 => {
                    /* We have enough compressed data in
                     * the cache buffer.*/
                    return 1;
                }
                _ => {}
            }
        }
        if strm.avail_in == 0 {
            /* There is not enough compressed data to fill up the
             * cache buffer. */
            return 0;
        }
        let next_in = unsafe { &*strm.next_in };
        strm.next_in = unsafe { strm.next_in.offset(1) };
        br.cache_buffer = br.cache_buffer << 8 | *next_in as u64;
        strm.avail_in -= 1;
        br.cache_avail += 8;
        n -= 8
    }
}

/*
 * Decode LZHUF.
 *
 * 1. Returns ARCHIVE_OK if output buffer or input buffer are empty.
 *    Please set available buffer and call this function again.
 * 2. Returns ARCHIVE_EOF if decompression has been completed.
 * 3. Returns ARCHIVE_FAILED if an error occurred; compressed data
 *    is broken or you do not set 'last' flag properly.
 * 4. 'last' flag is very important, you must set 1 to the flag if there
 *    is no input data. The lha compressed data format does not provide how
 *    to know the compressed data is really finished.
 *    Note: lha command utility check if the total size of output bytes is
 *    reached the uncompressed size recorded in its header. it does not mind
 *    that the decoding process is properly finished.
 *    GNU ZIP can decompress another compressed file made by SCO LZH compress.
 *    it handles EOF as null to fill read buffer with zero until the decoding
 *    process meet 2 bytes of zeros at reading a size of a next chunk, so the
 *    zeros are treated as the mark of the end of the data although the zeros
 *    is dummy, not the file data.
 */

fn lzh_decode(strm: &mut lzh_stream, last: i32) -> i32 {
    let ds = unsafe { &mut *strm.ds };
    let avail_in: i32;
    let mut r: i32 = 0;
    if ds.error != 0 {
        return ds.error;
    }
    avail_in = strm.avail_in;
    loop {
        if ds.state < ARCHIVE_LHA_DEFINED_PARAM.st_get_literal {
            r = lzh_read_blocks(strm, last)
        } else {
            r = lzh_decode_blocks(strm, last)
        }
        if !(r == 100) {
            break;
        }
    }
    strm.total_in += (avail_in - strm.avail_in) as i64;
    return r;
}

fn lzh_emit_window(strm: *mut lzh_stream, s: size_t) {
    let strm_safe = unsafe { &mut *strm };
    let ds = unsafe { &mut *strm_safe.ds };
    strm_safe.ref_ptr = ds.w_buff;
    strm_safe.avail_out = s as i32;
    strm_safe.total_out = strm_safe.total_out + s as i64;
}

fn lzh_read_blocks(strm: *mut lzh_stream, last: i32) -> i32 {
    let strm_safe = unsafe { &mut *strm };
    let mut ds = unsafe { &mut *strm_safe.ds };
    let mut br = &mut ds.br;
    let mut c: i32 = 0;
    let mut i: i32 = 0;
    let mut rbits: u32 = 0;
    /* condition flow control */
    let mut current_block: u64;
    let ST_RD_BLOCK_AND_ST_RD_PT_1 = 0;
    let ST_RD_PT_2 = 2;
    let ST_RD_PT_3 = 3;
    let ST_RD_PT_4 = 4;
    let ST_RD_LITERAL_1 = 5;
    let ST_RD_LITERAL_2 = 6;
    let ST_RD_LITERAL_3 = 7;
    let ST_RD_POS_DATA_1 = 8;

    's_19: loop {
        if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_block {
            /*
             * Read a block number indicates how many blocks
             * we will handle. The block is composed of a
             * literal and a match, sometimes a literal only
             * in particular, there are no reference data at
             * the beginning of the decompression.
             */
            if !(br.cache_avail >= 16 || lzh_br_fillup(strm_safe, br) != 0) {
                if last == 0 {
                    /* We need following data. */
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                }
                if br.cache_avail >= 8 {
                    /*
                     * It seems there are extra bits.
                     *  1. Compressed data is broken.
                     *  2. `last' flag does not properly
                     *     set.
                     */
                    break;
                } else {
                    if ds.w_pos > 0 {
                        lzh_emit_window(strm_safe, ds.w_pos as size_t);
                        ds.w_pos = 0;
                        return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                    }
                    /* End of compressed data; we have completely
                     * handled all compressed data. */
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_eof;
                }
            } else {
                ds.blocks_avail =
                    (br.cache_buffer >> br.cache_avail - 16) as i32 & cache_masks[16] as i32;
                if ds.blocks_avail == 0 {
                    break;
                }
                br.cache_avail -= 16;
                /*
                 * Read a literal table compressed in huffman
                 * coding.
                 */
                ds.pt.len_size = ds.literal_pt_len_size;
                ds.pt.len_bits = ds.literal_pt_len_bits;
                ds.reading_position = 0
            }
            current_block = ST_RD_BLOCK_AND_ST_RD_PT_1;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_1 {
            current_block = ST_RD_BLOCK_AND_ST_RD_PT_1;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_2 {
            current_block = ST_RD_PT_2;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_3 {
            current_block = ST_RD_PT_3;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_4 {
            current_block = ST_RD_PT_4;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_1 {
            current_block = ST_RD_LITERAL_1;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_2 {
            current_block = ST_RD_LITERAL_2;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_3 {
            current_block = ST_RD_LITERAL_3;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_pos_data_1 {
            current_block = ST_RD_POS_DATA_1;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_get_literal {
            return 100;
        } else {
            continue;
        }

        if current_block == ST_RD_BLOCK_AND_ST_RD_PT_1
        /* Note: ST_RD_PT_1, ST_RD_PT_2 and ST_RD_PT_4 are
         * used in reading both a literal table and a
         * position table. */
        {
            if !(br.cache_avail >= ds.pt.len_bits
                || lzh_br_fillup(strm_safe, br) != 0
                || br.cache_avail >= ds.pt.len_bits)
            {
                if last != 0 {
                    break; /* Truncated data. */
                }
                ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_1;
                return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
            } else {
                ds.pt.len_avail = (br.cache_buffer >> br.cache_avail - ds.pt.len_bits) as i32
                    & cache_masks[ds.pt.len_bits as usize] as i32;
                br.cache_avail -= ds.pt.len_bits
            }
            current_block = ST_RD_PT_2;
        }

        if current_block == ST_RD_PT_2
        /* FALL THROUGH */
        {
            if ds.pt.len_avail == 0 {
                /* Invalid data. */
                /* There is no bitlen. */
                if !(br.cache_avail >= ds.pt.len_bits
                    || lzh_br_fillup(strm_safe, br) != 0
                    || br.cache_avail >= ds.pt.len_bits)
                {
                    if last != 0 {
                        break; /* Truncated data.*/
                    } /* Invalid data. */
                    ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_2;
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                } else {
                    let len_bits = ds.pt.len_bits;
                    if lzh_make_fake_table(
                        &mut ds.pt,
                        ((br.cache_buffer >> br.cache_avail - len_bits) as i32
                            & cache_masks[len_bits as usize] as i32)
                            as uint16_t,
                    ) == 0
                    {
                        break;
                    }
                    br.cache_avail -= ds.pt.len_bits;
                    if ds.reading_position != 0 {
                        ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_get_literal
                    } else {
                        ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_1
                    }
                    continue;
                }
            } else {
                if ds.pt.len_avail > ds.pt.len_size {
                    break;
                }
                ds.loop_0 = 0;
                unsafe {
                    memset_safe(
                        ds.pt.freq.as_mut_ptr() as *mut (),
                        0,
                        size_of::<[i32; 17]>() as u64,
                    )
                };
                if ds.pt.len_avail < 3 || ds.pt.len_size == ds.pos_pt_len_size {
                    ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_4;
                    continue;
                }
            }
            current_block = ST_RD_PT_3;
        }

        if current_block == ST_RD_PT_3
        /* FALL THROUGH */
        {
            ds.loop_0 = lzh_read_pt_bitlen(strm_safe, ds.loop_0, 3); /* Invalid data. */
            if ds.loop_0 < 3 {
                if ds.loop_0 < 0 || last != 0 {
                    break;
                }
                /* Not completed, get following data. */
                ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_3;
                return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
            } else if !(br.cache_avail >= 2
                || lzh_br_fillup(strm_safe, br) != 0
                || br.cache_avail >= 2)
            {
                /* There are some null in bitlen of the literal. */
                if last != 0 {
                    break; /* Truncated data. */
                } /* Invalid data. */
                ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_3;
                return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
            } else {
                c = (br.cache_buffer >> br.cache_avail - 2) as i32 & cache_masks[2] as i32;
                br.cache_avail -= 2;
                if c > ds.pt.len_avail - 3 {
                    break;
                }
                i = 3;
                loop {
                    let c_old = c;
                    c = c - 1;
                    if !(c_old > 0) {
                        break;
                    }
                    let i_old = i;
                    i = i + 1;
                    unsafe { *ds.pt.bitlen.offset(i_old as isize) = 0 as u8 }
                }
                ds.loop_0 = i
            }
            current_block = ST_RD_PT_4;
        }

        if current_block == ST_RD_PT_4
        /* FALL THROUGH */
        {
            ds.loop_0 = lzh_read_pt_bitlen(strm_safe, ds.loop_0, ds.pt.len_avail); /* Invalid data. */
            if ds.loop_0 < ds.pt.len_avail {
                if ds.loop_0 < 0 || last != 0 {
                    break;
                }
                /* Not completed, get following data. */
                ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_4; /* Invalid data */
                return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
            } else {
                if lzh_make_huffman_table(&mut ds.pt) == 0 {
                    break;
                }
                if ds.reading_position != 0 {
                    ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_get_literal;
                    continue;
                }
            }
            current_block = ST_RD_LITERAL_1;
        }

        if current_block == ST_RD_LITERAL_1
        /* FALL THROUGH */
        {
            if !(br.cache_avail >= ds.lt.len_bits
                || lzh_br_fillup(strm_safe, br) != 0
                || br.cache_avail >= ds.lt.len_bits)
            {
                if last != 0 {
                    break; /* Truncated data. */
                }
                ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_1;
                return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
            } else {
                ds.lt.len_avail = (br.cache_buffer >> br.cache_avail - ds.lt.len_bits) as i32
                    & cache_masks[ds.lt.len_bits as usize] as i32;
                br.cache_avail -= ds.lt.len_bits
            }
            current_block = ST_RD_LITERAL_2;
        }

        if current_block == ST_RD_LITERAL_2
        /* FALL THROUGH */
        {
            if ds.lt.len_avail == 0 {
                /* Invalid data */
                /* There is no bitlen. */
                if !(br.cache_avail >= ds.lt.len_bits
                    || lzh_br_fillup(strm_safe, br) != 0
                    || br.cache_avail >= ds.lt.len_bits)
                {
                    if last != 0 {
                        break; /* Truncated data.*/
                    } /* Invalid data */
                    ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_2;
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                } else {
                    let len_bits = ds.lt.len_bits;
                    if lzh_make_fake_table(
                        &mut ds.lt,
                        ((br.cache_buffer >> br.cache_avail - len_bits) as i32
                            & cache_masks[len_bits as usize] as i32)
                            as uint16_t,
                    ) == 0
                    {
                        break;
                    }
                    br.cache_avail -= ds.lt.len_bits;
                    ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pos_data_1;
                    continue;
                }
            } else {
                if ds.lt.len_avail > ds.lt.len_size {
                    break;
                }
                ds.loop_0 = 0;
                unsafe {
                    memset_safe(
                        ds.lt.freq.as_mut_ptr() as *mut (),
                        0,
                        size_of::<[i32; 17]>() as u64,
                    )
                };
            }
            current_block = ST_RD_LITERAL_3;
        }

        if current_block == ST_RD_LITERAL_3
        /* FALL THROUGH */
        {
            i = ds.loop_0; /* Truncated data.*/
            while i < ds.lt.len_avail {
                if !(br.cache_avail >= ds.pt.max_bits
                    || lzh_br_fillup(strm_safe, br) != 0
                    || br.cache_avail >= ds.pt.max_bits)
                {
                    if last != 0 {
                        break 's_19;
                    }
                    ds.loop_0 = i;
                    ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_3;
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                } else {
                    rbits = ((br.cache_buffer >> br.cache_avail - ds.pt.max_bits) as i32
                        & cache_masks[ds.pt.max_bits as usize] as i32)
                        as u32;
                    c = lzh_decode_huffman(&mut ds.pt, rbits);
                    if c > 2 {
                        /* Note: 'c' will never be more than
                         * eighteen since it's limited by
                         * PT_BITLEN_SIZE, which is being set
                         * to ds->pt.len_size through
                         * ds->literal_pt_len_size. */
                        br.cache_avail -= unsafe { *ds.pt.bitlen.offset(c as isize) } as i32;
                        c -= 2;
                        ds.lt.freq[c as usize] += 1;
                        let i_old = i;
                        i = i + 1;
                        unsafe { *ds.lt.bitlen.offset(i_old as isize) = c as u8 }
                    } else if c == 0 {
                        br.cache_avail -= unsafe { *ds.pt.bitlen.offset(c as isize) } as i32;
                        let i_old = i;
                        i = i + 1;
                        unsafe { *ds.lt.bitlen.offset(i_old as isize) = 0 as u8 }
                    } else {
                        /* c == 1 or c == 2 */
                        let mut n: i32 = if c == 1 { 4 } else { 9 }; /* Invalid data */
                        if !(br.cache_avail
                            >= unsafe { *ds.pt.bitlen.offset(c as isize) } as i32 + n
                            || lzh_br_fillup(strm_safe, br) != 0
                            || br.cache_avail
                                >= unsafe { *ds.pt.bitlen.offset(c as isize) } as i32 + n)
                        {
                            if last != 0 {
                                break 's_19; /* Invalid data */
                            }
                            ds.loop_0 = i;
                            ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_3;
                            return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                        } else {
                            br.cache_avail -= unsafe { *ds.pt.bitlen.offset(c as isize) } as i32;
                            c = (br.cache_buffer >> br.cache_avail - n) as i32
                                & cache_masks[n as usize] as i32;
                            br.cache_avail -= n;
                            c += if n == 4 { 3 } else { 20 };
                            if i + c > ds.lt.len_avail {
                                break 's_19;
                            }
                            unsafe {
                                memset_safe(
                                    unsafe { &mut *ds.lt.bitlen.offset(i as isize) } as *mut u8
                                        as *mut (),
                                    0,
                                    c as u64,
                                )
                            };
                            i += c
                        }
                    }
                }
            }
            if i > ds.lt.len_avail || lzh_make_huffman_table(&mut ds.lt) == 0 {
                break;
            }
        }

        /* FALL THROUGH */
        /*
         * Read a position table compressed in huffman
         * coding.
         */
        ds.pt.len_size = ds.pos_pt_len_size;
        ds.pt.len_bits = ds.pos_pt_len_bits;
        ds.reading_position = 1;
        ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_1
    }
    /* Truncated data. */
    ds.error = ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
    return ds.error;
}

fn lzh_decode_blocks(mut strm: *mut lzh_stream, mut last: i32) -> i32 {
    let strm_safe = unsafe { &mut *strm };
    let mut current_block: u64;
    let mut ds = unsafe { &mut *strm_safe.ds };
    let mut bre: lzh_br = ds.br;
    let mut lt = &mut ds.lt;
    let mut pt = &mut ds.pt;
    let mut w_buff: *mut u8 = ds.w_buff;
    let mut lt_bitlen: *mut u8 = lt.bitlen;
    let mut pt_bitlen: *mut u8 = pt.bitlen;
    let mut blocks_avail: i32 = ds.blocks_avail;
    let mut c: i32 = 0;
    let mut copy_len: i32 = ds.copy_len;
    let mut copy_pos: i32 = ds.copy_pos;
    let mut w_pos: i32 = ds.w_pos;
    let w_mask: i32 = ds.w_mask;
    let w_size: i32 = ds.w_size;
    let lt_max_bits: i32 = lt.max_bits;
    let pt_max_bits: i32 = pt.max_bits;
    let mut state: i32 = ds.state;
    's_43: loop {
        if state == ARCHIVE_LHA_DEFINED_PARAM.st_get_literal {
            current_block = 0;
        } else if state == ARCHIVE_LHA_DEFINED_PARAM.st_get_pos_1 {
            current_block = 1;
        } else if state == ARCHIVE_LHA_DEFINED_PARAM.st_get_pos_2 {
            current_block = 2;
        } else if state == ARCHIVE_LHA_DEFINED_PARAM.st_copy_data {
            current_block = 3;
        } else {
            continue;
        }
        loop {
            match current_block {
                0 => {
                    if blocks_avail == 0 {
                        /* We have decoded all blocks.
                         * Let's handle next blocks. */
                        ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_block;
                        ds.br = bre;
                        ds.blocks_avail = 0;
                        ds.w_pos = w_pos;
                        ds.copy_pos = 0;
                        return 100;
                    }
                    /* lzh_br_read_ahead() always try to fill the
                     * cache buffer up. In specific situation we
                     * are close to the end of the data, the cache
                     * buffer will not be full and thus we have to
                     * determine if the cache buffer has some bits
                     * as much as we need after lzh_br_read_ahead()
                     * failed. */
                    if !(bre.cache_avail >= lt_max_bits
                        || lzh_br_fillup(strm_safe, &mut bre) != 0
                        || bre.cache_avail >= lt_max_bits)
                    {
                        if last == 0 {
                            current_block = 6;
                            break 's_43;
                            /* Over read. */
                        }
                        /* Remaining bits are less than
                         * maximum bits(lt.max_bits) but maybe
                         * it still remains as much as we need,
                         * so we should try to use it with
                         * dummy bits. */
                        c = lzh_decode_huffman(
                            lt,
                            ((bre.cache_buffer << lt_max_bits - bre.cache_avail) as i32
                                & cache_masks[lt_max_bits as usize] as i32)
                                as u32,
                        );
                        bre.cache_avail -= unsafe { *lt_bitlen.offset(c as isize) } as i32;
                        if !(bre.cache_avail >= 0) {
                            current_block = 5;
                            break 's_43;
                        }
                    } else {
                        c = lzh_decode_huffman(
                            lt,
                            ((bre.cache_buffer >> bre.cache_avail - lt_max_bits) as i32
                                & cache_masks[lt_max_bits as usize] as i32)
                                as u32,
                        );
                        bre.cache_avail -= unsafe { *lt_bitlen.offset(c as isize) } as i32
                    }
                    blocks_avail -= 1;
                    if c > ARCHIVE_LHA_DEFINED_PARAM.uchar_max {
                        /* Current block is a match data. */
                        /* 'c' is the length of a match pattern we have
                         * already extracted, which has be stored in
                         * window(ds->w_buff). */
                        copy_len = c - (ARCHIVE_LHA_DEFINED_PARAM.uchar_max + 1)
                            + ARCHIVE_LHA_DEFINED_PARAM.minmatch;
                        /* FALL THROUGH */
                        current_block = 1;
                    } else {
                        /*
                         * 'c' is exactly a literal code.
                         */
                        /* Save a decoded code to reference it
                         * afterward. */
                        unsafe {
                            *w_buff.offset(w_pos as isize) = c as u8;
                        }
                        w_pos += 1;
                        if !(w_pos >= w_size) {
                            current_block = 0;
                            continue;
                        }
                        w_pos = 0;
                        lzh_emit_window(strm_safe, w_size as size_t);
                        current_block = 6;
                        break 's_43;
                    }
                }
                2 =>
                /* FALL THROUGH */
                {
                    if copy_pos > 1 {
                        /* We need an additional adjustment number to
                         * the position. */
                        let mut p: i32 = copy_pos - 1; /* Truncated data.*/
                        if !(bre.cache_avail >= p
                            || lzh_br_fillup(strm_safe, &mut bre) != 0
                            || bre.cache_avail >= p)
                        {
                            if last != 0 {
                                current_block = 5;
                                break 's_43;
                            }
                            state = ARCHIVE_LHA_DEFINED_PARAM.st_get_pos_2;
                            ds.copy_len = copy_len;
                            ds.copy_pos = copy_pos;
                            current_block = 6;
                            break 's_43;
                        } else {
                            copy_pos = ((1) << p)
                                + ((bre.cache_buffer >> bre.cache_avail - p) as i32
                                    & cache_masks[p as usize] as i32);
                            bre.cache_avail -= p
                        }
                    }
                    /* The position is actually a distance from the last
                     * code we had extracted and thus we have to convert
                     * it to a position of the window. */
                    copy_pos = w_pos - copy_pos - 1 & w_mask;
                    /* FALL THROUGH */
                    current_block = 3;
                }
                1 =>
                /*
                 * Get a reference position.
                 */
                {
                    if !(bre.cache_avail >= pt_max_bits
                        || lzh_br_fillup(strm_safe, &mut bre) != 0
                        || bre.cache_avail >= pt_max_bits)
                    {
                        if last == 0 {
                            state = ARCHIVE_LHA_DEFINED_PARAM.st_get_pos_1;
                            ds.copy_len = copy_len;
                            current_block = 6;
                            break 's_43;
                        } else {
                            copy_pos = lzh_decode_huffman(
                                pt,
                                ((bre.cache_buffer << pt_max_bits - bre.cache_avail) as i32
                                    & cache_masks[pt_max_bits as usize] as i32)
                                    as u32,
                            );
                            bre.cache_avail -=
                                unsafe { *pt_bitlen.offset(copy_pos as isize) } as i32;
                            if !(bre.cache_avail >= 0) {
                                current_block = 5;
                                break 's_43;
                            } else {
                                current_block = 2;
                            }
                        }
                    /* Over read. */
                    } else {
                        copy_pos = lzh_decode_huffman(
                            pt,
                            ((bre.cache_buffer >> bre.cache_avail - pt_max_bits) as i32
                                & cache_masks[pt_max_bits as usize] as i32)
                                as u32,
                        );
                        bre.cache_avail -= unsafe { *pt_bitlen.offset(copy_pos as isize) } as i32;
                        current_block = 2;
                    }
                }
                _ =>
                /*
                 * Copy `copy_len' bytes as extracted data from
                 * the window into the output buffer.
                 */
                {
                    let mut l: i32 = 0;
                    l = copy_len;
                    if copy_pos > w_pos {
                        if l > w_size - copy_pos {
                            l = w_size - copy_pos
                        }
                    } else if l > w_size - w_pos {
                        l = w_size - w_pos
                    }
                    if copy_pos + l < w_pos || w_pos + l < copy_pos {
                        /* No overlap. */
                        unsafe {
                            memcpy_safe(
                                w_buff.offset(w_pos as isize) as *mut (),
                                w_buff.offset(copy_pos as isize) as *const (),
                                l as u64,
                            )
                        };
                    } else {
                        let s: *const u8;
                        let mut d: *mut u8 = 0 as *mut u8;
                        let mut li: i32 = 0;
                        d = unsafe { w_buff.offset(w_pos as isize) };
                        s = unsafe { w_buff.offset(copy_pos as isize) };
                        while li < l - 1 {
                            unsafe {
                                *d.offset(li as isize) = *s.offset(li as isize);
                            }
                            li += 1;
                            unsafe {
                                *d.offset(li as isize) = *s.offset(li as isize);
                            }
                            li += 1
                        }
                        if li < l {
                            unsafe { *d.offset(li as isize) = *s.offset(li as isize) }
                        }
                    }
                    w_pos += l;
                    if w_pos == w_size {
                        w_pos = 0;
                        lzh_emit_window(strm_safe, w_size as size_t);
                        if copy_len <= l {
                            state = ARCHIVE_LHA_DEFINED_PARAM.st_get_literal
                        } else {
                            state = ARCHIVE_LHA_DEFINED_PARAM.st_copy_data;
                            ds.copy_len = copy_len - l;
                            ds.copy_pos = copy_pos + l & w_mask
                        }
                        current_block = 6;
                        break 's_43;
                    } else if copy_len <= l {
                        /* A copy of current pattern ended. */
                        state = ARCHIVE_LHA_DEFINED_PARAM.st_get_literal;
                        break;
                    } else {
                        copy_len -= l;
                        copy_pos = copy_pos + l & w_mask;
                        current_block = 3;
                    }
                }
            }
        }
    }
    match current_block {
        5 => {
            ds.error = ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
            return ds.error;
        }
        _ => {
            ds.br = bre;
            ds.blocks_avail = blocks_avail;
            ds.state = state;
            ds.w_pos = w_pos;
            return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
        }
    };
}

fn lzh_huffman_init(hf: &mut huffman, len_size: size_t, tbl_bits: i32) -> i32 {
    let mut bits: i32 = 0;
    if hf.bitlen.is_null() {
        hf.bitlen = unsafe { malloc_safe(len_size * (size_of::<u8>() as u64)) } as *mut u8;
        if hf.bitlen.is_null() {
            return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
        }
    }
    if hf.tbl.is_null() {
        if tbl_bits < ARCHIVE_LHA_DEFINED_PARAM.htbl_bits {
            bits = tbl_bits
        } else {
            bits = ARCHIVE_LHA_DEFINED_PARAM.htbl_bits
        }
        hf.tbl = unsafe {
            malloc_safe(((1 as size_t) << bits).wrapping_mul(size_of::<uint16_t>() as u64))
        } as *mut uint16_t;
        if hf.tbl.is_null() {
            return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
        }
    }
    if hf.tree.is_null() && tbl_bits > ARCHIVE_LHA_DEFINED_PARAM.htbl_bits {
        hf.tree_avail = (1) << tbl_bits - ARCHIVE_LHA_DEFINED_PARAM.htbl_bits + 4;
        hf.tree = unsafe { malloc_safe((hf.tree_avail as u64) * (size_of::<htree_t>() as u64)) }
            as *mut htree_t;
        if hf.tree.is_null() {
            return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
        }
    }
    hf.len_size = len_size as i32;
    hf.tbl_bits = tbl_bits;
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

fn lzh_huffman_free(hf: &mut huffman) {
    unsafe { free_safe(hf.bitlen as *mut ()) };
    unsafe { free_safe(hf.tbl as *mut ()) };
    unsafe { free_safe(hf.tree as *mut ()) };
}

static bitlen_tbl: [u8; 1024] = [
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13,
    14, 14, 14, 14, 15, 15, 16, 0,
];

fn lzh_read_pt_bitlen(strm: &mut lzh_stream, start: i32, end: i32) -> i32 {
    let ds = unsafe { &mut *strm.ds };
    let br = &mut ds.br;
    let mut c: i32 = 0;
    let mut i: i32 = start;
    while i < end {
        /*
         *  bit pattern     the number we need
         *     000           ->  0
         *     001           ->  1
         *     010           ->  2
         *     ...
         *     110           ->  6
         *     1110          ->  7
         *     11110         ->  8
         *     ...
         *     1111111111110 ->  16
         */
        if !(br.cache_avail >= 3 || lzh_br_fillup(strm, br) != 0 || br.cache_avail >= 3) {
            return i;
        }
        c = (br.cache_buffer >> br.cache_avail - 3) as i32 & cache_masks[3] as i32;
        if c == 7 {
            if !(br.cache_avail >= 13 || lzh_br_fillup(strm, br) != 0 || br.cache_avail >= 13) {
                return i;
            }
            c = bitlen_tbl[((br.cache_buffer >> br.cache_avail - 13) as i32
                & cache_masks[13] as i32
                & 0x3ff) as usize] as i32;
            if c != 0 {
                br.cache_avail -= c - 3
            } else {
                return -1;
            }
            /* Invalid data. */
        } else {
            br.cache_avail -= 3
        }
        let i_old = i;
        i = i + 1;
        unsafe { *ds.pt.bitlen.offset(i_old as isize) = c as u8 };
        ds.pt.freq[c as usize] += 1
    }
    return i;
}

fn lzh_make_fake_table(hf: &mut huffman, c: uint16_t) -> i32 {
    if c as i32 >= hf.len_size {
        return 0;
    }
    unsafe {
        *hf.tbl.offset(0 as isize) = c;
    }
    hf.max_bits = 0;
    hf.shift_bits = 0;
    unsafe {
        *hf.bitlen.offset(*hf.tbl.offset(0 as isize) as isize) = 0;
    }
    return 1;
}

/*
 * Make a huffman coding table.
 */
fn lzh_make_huffman_table(hf: &mut huffman) -> i32 {
    let mut tbl: *mut uint16_t = 0 as *mut uint16_t;
    let mut bitlen: *const u8 = 0 as *const u8;
    let mut bitptn: [i32; 17] = [0; 17];
    let mut weight: [i32; 17] = [0; 17];
    let mut i: i32;
    let mut maxbits: i32 = 0;
    let mut ptn: i32;
    let mut tbl_size: i32;
    let mut w: i32;
    let mut diffbits: i32;
    let len_avail: i32;
    /*
     * Initialize bit patterns.
     */
    ptn = 0;
    i = 1;
    w = 1 << 15;
    while i <= 16 {
        bitptn[i as usize] = ptn;
        weight[i as usize] = w;
        if hf.freq[i as usize] != 0 {
            ptn += hf.freq[i as usize] * w;
            maxbits = i
        }
        i += 1;
        w >>= 1
    }
    if ptn != 0x10000 || maxbits > hf.tbl_bits {
        return 0; /* Invalid */
    }
    hf.max_bits = maxbits;
    /*
     * Cut out extra bits which we won't house in the table.
     * This preparation reduces the same calculation in the for-loop
     * making the table.
     */
    if maxbits < 16 {
        let mut ebits: i32 = 16 - maxbits;
        i = 1;
        while i <= maxbits {
            bitptn[i as usize] >>= ebits;
            weight[i as usize] >>= ebits;
            i += 1
        }
    }
    if maxbits > ARCHIVE_LHA_DEFINED_PARAM.htbl_bits {
        let mut htbl_max: u32 = 0;
        let mut p: *mut uint16_t = 0 as *mut uint16_t;
        diffbits = maxbits - ARCHIVE_LHA_DEFINED_PARAM.htbl_bits;
        i = 1;
        while i <= ARCHIVE_LHA_DEFINED_PARAM.htbl_bits {
            bitptn[i as usize] >>= diffbits;
            weight[i as usize] >>= diffbits;
            i += 1
        }
        htbl_max = (bitptn[ARCHIVE_LHA_DEFINED_PARAM.htbl_bits as usize]
            + weight[ARCHIVE_LHA_DEFINED_PARAM.htbl_bits as usize]
                * hf.freq[ARCHIVE_LHA_DEFINED_PARAM.htbl_bits as usize]) as u32;
        p = unsafe { &mut *hf.tbl.offset(htbl_max as isize) } as *mut uint16_t;
        while p < unsafe {
            &mut *hf
                .tbl
                .offset(((1 as u32) << ARCHIVE_LHA_DEFINED_PARAM.htbl_bits) as isize)
        } as *mut uint16_t
        {
            let fresh13 = unsafe { &mut *p };
            unsafe {
                p = p.offset(1);
            }
            *fresh13 = 0
        }
    } else {
        diffbits = 0
    }
    hf.shift_bits = diffbits;
    /*
     * Make the table.
     */
    tbl_size = (1) << ARCHIVE_LHA_DEFINED_PARAM.htbl_bits;
    tbl = hf.tbl;
    bitlen = hf.bitlen;
    len_avail = hf.len_avail;
    hf.tree_used = 0;
    i = 0;
    while i < len_avail {
        let mut p_0: *mut uint16_t = 0 as *mut uint16_t;
        let len: i32;
        let mut cnt: i32 = 0;
        let mut bit: uint16_t = 0;
        let mut extlen: i32 = 0;
        let mut ht = unsafe { &mut *(0 as *mut htree_t) };
        if !(unsafe { *bitlen.offset(i as isize) } == 0) {
            /* Get a bit pattern */
            len = unsafe { *bitlen.offset(i as isize) } as i32;
            ptn = bitptn[len as usize];
            cnt = weight[len as usize];
            if len <= ARCHIVE_LHA_DEFINED_PARAM.htbl_bits {
                /* Calculate next bit pattern */
                bitptn[len as usize] = ptn + cnt; /* Invalid */
                if bitptn[len as usize] > tbl_size {
                    return 0;
                }
                /* Update the table */
                p_0 = unsafe { &mut *tbl.offset(ptn as isize) } as *mut uint16_t;
                if cnt > 7 {
                    let mut pc: *mut uint16_t = 0 as *mut uint16_t;
                    cnt -= 8;
                    pc = unsafe { &mut *p_0.offset(cnt as isize) } as *mut uint16_t;
                    unsafe {
                        *pc.offset(0 as isize) = i as uint16_t;
                        *pc.offset(1 as isize) = i as uint16_t;
                        *pc.offset(2 as isize) = i as uint16_t;
                        *pc.offset(3 as isize) = i as uint16_t;
                        *pc.offset(4 as isize) = i as uint16_t;
                        *pc.offset(5 as isize) = i as uint16_t;
                        *pc.offset(6 as isize) = i as uint16_t;
                        *pc.offset(7 as isize) = i as uint16_t;
                    }
                    if cnt > 7 {
                        cnt -= 8;
                        unsafe {
                            memcpy_safe(
                                &mut *p_0.offset(cnt as isize) as *mut uint16_t as *mut (),
                                pc as *const (),
                                8 * (size_of::<uint16_t>() as u64),
                            )
                        };
                        pc = unsafe { &mut *p_0.offset(cnt as isize) } as *mut uint16_t;
                        while cnt > 15 {
                            cnt -= 16;
                            unsafe {
                                memcpy_safe(
                                    &mut *p_0.offset(cnt as isize) as *mut uint16_t as *mut (),
                                    pc as *const (),
                                    16 * (size_of::<uint16_t>() as u64),
                                )
                            };
                        }
                    }
                    if cnt != 0 {
                        unsafe {
                            memcpy_safe(
                                p_0 as *mut (),
                                pc as *const (),
                                (cnt as u64) * (size_of::<uint16_t>() as u64),
                            )
                        };
                    }
                } else {
                    while cnt > 1 {
                        cnt -= 1;
                        unsafe {
                            *p_0.offset(cnt as isize) = i as uint16_t;
                        }
                        cnt -= 1;
                        unsafe { *p_0.offset(cnt as isize) = i as uint16_t }
                    }
                    if cnt != 0 {
                        cnt -= 1;
                        unsafe { *p_0.offset(cnt as isize) = i as uint16_t }
                    }
                }
            } else {
                /*
                 * A bit length is too big to be housed to a direct table,
                 * so we use a tree model for its extra bits.
                 */
                bitptn[len as usize] = ptn + cnt; /* Invalid */
                bit = (1 << diffbits - 1) as uint16_t; /* Invalid */
                extlen = len - ARCHIVE_LHA_DEFINED_PARAM.htbl_bits; /* Invalid */
                p_0 = unsafe { &mut *tbl.offset((ptn >> diffbits) as isize) } as *mut uint16_t; /* Invalid */
                let safe_p_0 = unsafe { &mut *p_0 };
                if *safe_p_0 == 0 {
                    *safe_p_0 = (len_avail + hf.tree_used) as uint16_t; /* Invalid */
                    let tree_used_old = hf.tree_used; /* Invalid */
                    hf.tree_used = hf.tree_used + 1;
                    ht = unsafe {
                        &mut *(&mut *hf.tree.offset(tree_used_old as isize) as *mut htree_t)
                    };
                    if hf.tree_used > hf.tree_avail {
                        return 0;
                    }
                    ht.left = 0;
                    ht.right = 0
                } else {
                    if (*safe_p_0 as i32) < len_avail
                        || *safe_p_0 as i32 >= len_avail + hf.tree_used
                    {
                        return 0;
                    }
                    ht = unsafe {
                        &mut *(&mut *hf.tree.offset((*safe_p_0 as i32 - len_avail) as isize)
                            as *mut htree_t)
                    }
                }
                loop {
                    extlen -= 1;
                    if !(extlen > 0) {
                        break;
                    }
                    if ptn & bit as i32 != 0 {
                        if (ht.left as i32) < len_avail {
                            ht.left = (len_avail + hf.tree_used) as uint16_t;
                            let fresh15 = hf.tree_used;
                            hf.tree_used = hf.tree_used + 1;
                            ht = unsafe {
                                &mut *(&mut *hf.tree.offset(fresh15 as isize) as *mut htree_t)
                            };
                            if hf.tree_used > hf.tree_avail {
                                return 0;
                            }
                            ht.left = 0;
                            ht.right = 0
                        } else {
                            ht = unsafe {
                                &mut *(&mut *hf.tree.offset((ht.left as i32 - len_avail) as isize)
                                    as *mut htree_t)
                            }
                        }
                    } else if (ht.right as i32) < len_avail {
                        ht.right = (len_avail + hf.tree_used) as uint16_t;
                        let fresh16 = hf.tree_used;
                        hf.tree_used = hf.tree_used + 1;
                        ht = unsafe {
                            &mut *(&mut *hf.tree.offset(fresh16 as isize) as *mut htree_t)
                        };
                        if hf.tree_used > hf.tree_avail {
                            return 0;
                        }
                        ht.left = 0;
                        ht.right = 0
                    } else {
                        ht = unsafe {
                            &mut *(&mut *hf.tree.offset((ht.right as i32 - len_avail) as isize)
                                as *mut htree_t)
                        }
                    }
                    bit = bit >> 1
                }
                if ptn & bit as i32 != 0 {
                    if ht.left != 0 {
                        return 0;
                    }
                    ht.left = i as uint16_t
                } else {
                    if ht.right != 0 {
                        return 0;
                    }
                    ht.right = i as uint16_t
                }
            }
        }
        i += 1
    }
    return 1;
}

fn lzh_decode_huffman_tree(hf: *mut huffman, rbits: u32, mut c: i32) -> i32 {
    let hf_safe = unsafe { &mut *hf };
    let mut ht: *mut htree_t = 0 as *mut htree_t;
    let mut extlen: i32 = 0;
    ht = hf_safe.tree;
    extlen = hf_safe.shift_bits;
    while c >= hf_safe.len_avail {
        c -= hf_safe.len_avail;
        let fresh17 = extlen;
        extlen = extlen - 1;
        if fresh17 <= 0 || c >= hf_safe.tree_used {
            return 0;
        }
        if rbits & (1 as u32) << extlen != 0 {
            c = (unsafe { *ht.offset(c as isize) }).left as i32
        } else {
            c = (unsafe { *ht.offset(c as isize) }).right as i32
        }
    }
    return c;
}

fn lzh_decode_huffman(hf: &mut huffman, rbits: u32) -> i32 {
    let mut c: i32 = 0;
    /*
     * At first search an index table for a bit pattern.
     * If it fails, search a huffman tree for.
     */
    c = unsafe { *hf.tbl.offset((rbits >> hf.shift_bits) as isize) } as i32;
    if c < hf.len_avail || hf.len_avail == 0 {
        return c;
    }
    /* This bit pattern needs to be found out at a huffman tree. */
    return lzh_decode_huffman_tree(hf, rbits, c);
}

#[no_mangle]
pub fn archive_test_archive_read_support_format_lha() {
    let mut archive_read: *mut archive_read = 0 as *mut archive_read;
    archive_read = unsafe { calloc_safe(1, size_of::<archive_read>() as u64) } as *mut archive_read;
    unsafe { (*archive_read).archive.magic = ARCHIVE_AR_DEFINED_PARAM.archive_read_magic };
    unsafe { (*archive_read).archive.state = ARCHIVE_AR_DEFINED_PARAM.archive_state_new };
    archive_read_support_format_lha(unsafe { &mut (*archive_read).archive as *mut archive });
}

#[no_mangle]
fn archive_test_lha_check_header_format(h: *const ()) {
    lha_check_header_format(h);
}

#[no_mangle]
fn archive_test_archive_read_format_lha_options(_a: *mut archive, key: *const u8, val: *const u8) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    archive_read_format_lha_options(a, key, val);
}

#[no_mangle]
fn archive_test_lha_skip_sfx(_a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    lha_skip_sfx(a);
    let mut archive_read_filter: *mut archive_read_filter = 0 as *mut archive_read_filter;
    archive_read_filter = unsafe { calloc_safe(1, size_of::<archive_read_filter>() as u64) }
        as *mut archive_read_filter;
    unsafe { (*a).filter = archive_read_filter as *mut archive_read_filter };
    unsafe { (*archive_read_filter).fatal = 'a' as u8 };
    lha_skip_sfx(a);
}

#[no_mangle]
fn archive_test_lha_read_data_none(_a: *mut archive) {
    let mut size: size_t = 2;
    let mut size2: *mut size_t = &size as *const size_t as *mut size_t;
    let mut offset: int64_t = 1;
    let mut offset2: *mut int64_t = &offset as *const int64_t as *mut int64_t;
    let mut buff: *mut () = 0 as *const () as *mut ();
    let mut buff2: *mut *const () =
        &buff as *const *mut () as *mut *mut () as *mut *const ();
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut lha: *mut lha = 0 as *mut lha;
    lha = unsafe { calloc_safe(1, size_of::<lha>() as u64) } as *mut lha;
    unsafe { (*lha).entry_bytes_remaining = 0 };
    unsafe { (*(*a).format).data = lha as *mut () };
    lha_read_data_none(a, buff2, size2, offset2);
}

#[no_mangle]
fn archive_test_lha_read_data_lzh(_a: *mut archive) {
    let mut size: size_t = 2;
    let mut size2: *mut size_t = &size as *const size_t as *mut size_t;
    let mut offset: int64_t = 1;
    let mut offset2: *mut int64_t = &offset as *const int64_t as *mut int64_t;
    let mut buff: *mut () = 0 as *const () as *mut ();
    let mut buff2: *mut *const () =
        &buff as *const *mut () as *mut *mut () as *mut *const ();
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut lha: *mut lha = 0 as *mut lha;
    lha = unsafe { calloc_safe(1, size_of::<lha>() as u64) } as *mut lha;
    unsafe { (*lha).decompress_init = 0 };
    unsafe { (*lha).method[0] = 'a' as u8 };
    unsafe { (*(*a).format).data = lha as *mut () };
    lha_read_data_lzh(a, buff2, size2, offset2);
}

#[no_mangle]
pub fn archive_test_lzh_emit_window() {
    let mut lzh_stream: *mut lzh_stream = 0 as *mut lzh_stream;
    lzh_stream = unsafe { calloc_safe(1, size_of::<lzh_stream>() as u64) } as *mut lzh_stream;
    let mut lzh_dec: *mut lzh_dec = 0 as *mut lzh_dec;
    lzh_dec = unsafe { calloc_safe(1, size_of::<lzh_dec>() as u64) } as *mut lzh_dec;
    unsafe { (*lzh_stream).ds = lzh_dec as *mut lzh_dec };
    unsafe { (*lzh_dec).w_buff = 1 as *mut u8 };
    lzh_emit_window(lzh_stream, 1);
}

#[no_mangle]
pub fn archive_test_lzh_decode_huffman_tree() {
    let mut huffman: *mut huffman = 0 as *mut huffman;
    huffman = unsafe { calloc_safe(1, size_of::<huffman>() as u64) } as *mut huffman;
    let htree_t: *mut htree_t = unsafe { calloc_safe(1, size_of::<htree_t>() as u64) } as *mut htree_t;
    unsafe { (*huffman).tree = htree_t as *mut htree_t };
    unsafe { (*huffman).shift_bits = 1 };
    unsafe { (*huffman).len_avail = 1 };
    unsafe { (*huffman).tree_used = 2 };
    lzh_decode_huffman_tree(huffman, 1, 2);
}

#[no_mangle]
fn archive_test_truncated_error(_a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    truncated_error(a);
}

#[no_mangle]
fn archive_test_lzh_decode_blocks() {
    let mut strm: *mut lzh_stream = 0 as *mut lzh_stream;
    strm = unsafe { calloc_safe(1, size_of::<lzh_stream>() as u64) } as *mut lzh_stream;
    let mut lzh_dec: *mut lzh_dec = 0 as *mut lzh_dec;
    lzh_dec = unsafe { calloc_safe(1, size_of::<lzh_dec>() as u64) } as *mut lzh_dec;
    unsafe { (*strm).ds = lzh_dec as *mut lzh_dec };
    unsafe { (*lzh_dec).state = 10 };
    unsafe { (*lzh_dec).br.cache_avail = -20 };
    unsafe { (*lzh_dec).copy_pos = 2 };
    lzh_decode_blocks(strm, 0);
    unsafe { (*lzh_dec).state = 11 };
    lzh_decode_blocks(strm, 1);
    lzh_decode_blocks(strm, 0);
}

#[no_mangle]
fn archive_test_lzh_read_blocks() {
    let mut strm: *mut lzh_stream = 0 as *mut lzh_stream;
    strm = unsafe { calloc_safe(1, size_of::<lzh_stream>() as u64) } as *mut lzh_stream;
    let mut lzh_dec: *mut lzh_dec = 0 as *mut lzh_dec;
    lzh_dec = unsafe { calloc_safe(1, size_of::<lzh_dec>() as u64) } as *mut lzh_dec;
    unsafe { (*strm).ds = lzh_dec as *mut lzh_dec };
    unsafe { (*lzh_dec).pt.len_bits = 1 };
    unsafe { (*lzh_dec).lt.len_bits = 1 };
    unsafe { (*lzh_dec).pt.max_bits = 1 };
    unsafe { (*lzh_dec).state = 1 };
    unsafe { (*lzh_dec).br.cache_avail = -20 };
    unsafe { (*lzh_dec).copy_pos = 2 };
    lzh_read_blocks(strm, 0);
    lzh_read_blocks(strm, 1);
    unsafe { (*lzh_dec).state = 2 };
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
    unsafe { (*lzh_dec).state = 3 };
    unsafe { (*lzh_dec).loop_0 = 3 };
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
    unsafe { (*lzh_dec).state = 4 };
    unsafe { (*lzh_dec).pt.len_avail = 10000 };
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
    unsafe { (*lzh_dec).state = 5 };
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
    unsafe { (*lzh_dec).state = 6 };
    unsafe { (*lzh_dec).lt.len_avail = 0 };
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
    unsafe { (*lzh_dec).state = 7 };
    unsafe { (*lzh_dec).lt.len_avail = 4 };
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
}
