use archive_core::archive_endian::*;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;
use rust_ffi::{archive_set_error_safe, archive_string_sprintf_safe, sprintf_safe};

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lha {
    pub entry_offset: int64_t,
    pub entry_bytes_remaining: int64_t,
    pub entry_unconsumed: int64_t,
    pub entry_crc_calculated: uint16_t,
    pub header_size: size_t,
    pub level: libc::c_uchar,
    pub method: [libc::c_char; 3],
    pub compsize: int64_t,
    pub origsize: int64_t,
    pub setflag: libc::c_int,
    pub birthtime: time_t,
    pub birthtime_tv_nsec: libc::c_long,
    pub mtime: time_t,
    pub mtime_tv_nsec: libc::c_long,
    pub atime: time_t,
    pub atime_tv_nsec: libc::c_long,
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
    pub dos_attr: libc::c_uchar,
    pub found_first_header: libc::c_char,
    pub directory: libc::c_char,
    pub decompress_init: libc::c_char,
    pub end_of_entry: libc::c_char,
    pub end_of_entry_cleanup: libc::c_char,
    pub entry_is_compressed: libc::c_char,
    pub format_name: [libc::c_char; 64],
    pub strm: lzh_stream,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lzh_stream {
    pub next_in: *const libc::c_uchar,
    pub avail_in: libc::c_int,
    pub total_in: int64_t,
    pub ref_ptr: *const libc::c_uchar,
    pub avail_out: libc::c_int,
    pub total_out: int64_t,
    pub ds: *mut lzh_dec,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lzh_dec {
    pub state: libc::c_int,
    pub w_size: libc::c_int,
    pub w_mask: libc::c_int,
    pub w_buff: *mut libc::c_uchar,
    pub w_pos: libc::c_int,
    pub copy_pos: libc::c_int,
    pub copy_len: libc::c_int,
    pub br: lzh_br,
    pub lt: huffman,
    pub pt: huffman,
    pub blocks_avail: libc::c_int,
    pub pos_pt_len_size: libc::c_int,
    pub pos_pt_len_bits: libc::c_int,
    pub literal_pt_len_size: libc::c_int,
    pub literal_pt_len_bits: libc::c_int,
    pub reading_position: libc::c_int,
    pub loop_0: libc::c_int,
    pub error: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct huffman {
    pub len_size: libc::c_int,
    pub len_avail: libc::c_int,
    pub len_bits: libc::c_int,
    pub freq: [libc::c_int; 17],
    pub bitlen: *mut libc::c_uchar,
    pub max_bits: libc::c_int,
    pub shift_bits: libc::c_int,
    pub tbl_bits: libc::c_int,
    pub tree_used: libc::c_int,
    pub tree_avail: libc::c_int,
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
    pub cache_avail: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union archive_temporary_u {
    pub i: uint32_t,
    pub c: [libc::c_char; 4],
}

#[no_mangle]
pub unsafe extern "C" fn archive_read_support_format_lha(mut _a: *mut archive) -> libc::c_int {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut r: libc::c_int = 0;
    let mut magic_test: libc::c_int = __archive_check_magic_safe(
        _a,
        ARCHIVE_LHA_DEFINED_PARAM.archive_read_magic,
        ARCHIVE_LHA_DEFINED_PARAM.archive_state_new,
        b"archive_read_support_format_lha\x00" as *const u8 as *const libc::c_char,
    );
    if magic_test == -(30 as libc::c_int) {
        return -(30 as libc::c_int);
    }
    let mut lha = unsafe {
        &mut *(calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<lha>() as libc::c_ulong,
        ) as *mut lha)
    };
    if (lha as *mut lha).is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.enomem,
            b"Can\'t allocate lha data\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    lha.ws.s = 0 as *mut wchar_t;
    lha.ws.length = 0 as libc::c_int as size_t;
    lha.ws.buffer_length = 0 as libc::c_int as size_t;
    r = __archive_read_register_format_safe(
        a,
        lha as *mut lha as *mut libc::c_void,
        b"lha\x00" as *const u8 as *const libc::c_char,
        Some(
            archive_read_format_lha_bid
                as unsafe extern "C" fn(_: *mut archive_read, _: libc::c_int) -> libc::c_int,
        ),
        Some(
            archive_read_format_lha_options
                as unsafe extern "C" fn(
                    _: *mut archive_read,
                    _: *const libc::c_char,
                    _: *const libc::c_char,
                ) -> libc::c_int,
        ),
        Some(
            archive_read_format_lha_read_header
                as unsafe extern "C" fn(_: *mut archive_read, _: *mut archive_entry) -> libc::c_int,
        ),
        Some(
            archive_read_format_lha_read_data
                as unsafe extern "C" fn(
                    _: *mut archive_read,
                    _: *mut *const libc::c_void,
                    _: *mut size_t,
                    _: *mut int64_t,
                ) -> libc::c_int,
        ),
        Some(
            archive_read_format_lha_read_data_skip
                as unsafe extern "C" fn(_: *mut archive_read) -> libc::c_int,
        ),
        None,
        Some(
            archive_read_format_lha_cleanup
                as unsafe extern "C" fn(_: *mut archive_read) -> libc::c_int,
        ),
        None,
        None,
    );
    if r != ARCHIVE_LHA_DEFINED_PARAM.archive_ok {
        free_safe(lha as *mut lha as *mut libc::c_void);
    }
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

unsafe extern "C" fn lha_check_header_format(mut h: *const libc::c_void) -> size_t {
    let mut p: *const libc::c_uchar = h as *const libc::c_uchar;
    let mut next_skip_bytes: size_t = 0;
    let mut current_block_11: u64;
    match unsafe {
        *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 3 as libc::c_int) as isize)
    } as libc::c_int
    {
        48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 100 | 115 => {
            /*
             * "-lh0-" ... "-lh7-" "-lhd-"
             * "-lzs-" "-lz5-"
             */
            next_skip_bytes = 4 as libc::c_int as size_t;
            /* b0 == 0 means the end of an LHa archive file.    */
            if !(unsafe { *p.offset(0 as libc::c_int as isize) } as libc::c_int == 0 as libc::c_int)
            {
                if !(unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_method_offset as isize) }
                    as libc::c_int
                    != '-' as i32
                    || unsafe {
                        *p.offset(
                            (ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 1 as libc::c_int) as isize,
                        )
                    } as libc::c_int
                        != 'l' as i32
                    || unsafe {
                        *p.offset(
                            (ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 4 as libc::c_int) as isize,
                        )
                    } as libc::c_int
                        != '-' as i32)
                {
                    if unsafe {
                        *p.offset(
                            (ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 2 as libc::c_int) as isize,
                        )
                    } as libc::c_int
                        == 'h' as i32
                    {
                        /* "-lh?-" */
                        if unsafe {
                            *p.offset(
                                (ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 3 as libc::c_int)
                                    as isize,
                            )
                        } as libc::c_int
                            == 's' as i32
                        {
                            current_block_11 = 14648156034262866959;
                        } else {
                            if unsafe {
                                *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize)
                            } as libc::c_int
                                == 0 as libc::c_int
                            {
                                return 0 as libc::c_int as size_t;
                            }
                            if unsafe {
                                *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize)
                            } as libc::c_int
                                <= 3 as libc::c_int
                                && unsafe {
                                    *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_attr_offset as isize)
                                } as libc::c_int
                                    == 0x20 as libc::c_int
                            {
                                return 0 as libc::c_int as size_t;
                            }
                            current_block_11 = 17860125682698302841;
                        }
                    } else {
                        current_block_11 = 17860125682698302841;
                    }
                    match current_block_11 {
                        14648156034262866959 => {}
                        _ => {
                            if unsafe {
                                *p.offset(
                                    (ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 2 as libc::c_int)
                                        as isize,
                                )
                            } as libc::c_int
                                == 'z' as i32
                            {
                                /* LArc extensions: -lzs-,-lz4- and -lz5- */
                                if !(unsafe {
                                    *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize)
                                } as libc::c_int
                                    != 0 as libc::c_int)
                                {
                                    if unsafe {
                                        *p.offset(
                                            (ARCHIVE_LHA_DEFINED_PARAM.h_method_offset
                                                + 3 as libc::c_int)
                                                as isize,
                                        )
                                    } as libc::c_int
                                        == 's' as i32
                                        || unsafe {
                                            *p.offset(
                                                (ARCHIVE_LHA_DEFINED_PARAM.h_method_offset
                                                    + 3 as libc::c_int)
                                                    as isize,
                                            )
                                        } as libc::c_int
                                            == '4' as i32
                                        || unsafe {
                                            *p.offset(
                                                (ARCHIVE_LHA_DEFINED_PARAM.h_method_offset
                                                    + 3 as libc::c_int)
                                                    as isize,
                                            )
                                        } as libc::c_int
                                            == '5' as i32
                                    {
                                        return 0 as libc::c_int as size_t;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        104 => next_skip_bytes = 1 as libc::c_int as size_t,
        122 => next_skip_bytes = 1 as libc::c_int as size_t,
        108 => next_skip_bytes = 2 as libc::c_int as size_t,
        45 => next_skip_bytes = 3 as libc::c_int as size_t,
        _ => next_skip_bytes = 4 as libc::c_int as size_t,
    }
    return next_skip_bytes;
}

/* Minimum header size. */
unsafe extern "C" fn archive_read_format_lha_bid(
    mut a: *mut archive_read,
    mut best_bid: libc::c_int,
) -> libc::c_int {
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut buff: *const libc::c_void = 0 as *const libc::c_void;
    let mut bytes_avail: ssize_t = 0;
    let mut offset: ssize_t = 0;
    let mut window: ssize_t = 0;
    let mut next: size_t = 0;
    /* If there's already a better bid than we can ever
    make, don't bother testing. */
    if best_bid > 30 as libc::c_int {
        return -(1 as libc::c_int);
    }
    p = __archive_read_ahead_safe(
        a,
        ARCHIVE_LHA_DEFINED_PARAM.h_size as size_t,
        0 as *mut ssize_t,
    ) as *const libc::c_char;
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    if lha_check_header_format(p as *const libc::c_void) == 0 as libc::c_int as libc::c_ulong {
        return 30 as libc::c_int;
    }
    if unsafe { *p.offset(0 as libc::c_int as isize) } as libc::c_int == 'M' as i32
        && unsafe { *p.offset(1 as libc::c_int as isize) } as libc::c_int == 'Z' as i32
    {
        /* PE file */
        offset = 0 as libc::c_int as ssize_t;
        window = 4096 as libc::c_int as ssize_t;
        while offset < (1024 as libc::c_int * 20 as libc::c_int) as libc::c_long {
            buff = __archive_read_ahead_safe(a, (offset + window) as size_t, &mut bytes_avail);
            if buff == 0 as *mut libc::c_void {
                /* Remaining bytes are less than window. */
                window >>= 1 as libc::c_int;
                if window < (ARCHIVE_LHA_DEFINED_PARAM.h_size + 3 as libc::c_int) as libc::c_long {
                    return 0 as libc::c_int;
                }
            } else {
                p = unsafe { (buff as *const libc::c_char).offset(offset as isize) };
                while unsafe {
                    p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_size as isize)
                        < (buff as *const libc::c_char).offset(bytes_avail as isize)
                } {
                    next = lha_check_header_format(p as *const libc::c_void);
                    if next == 0 as libc::c_int as libc::c_ulong {
                        return 30 as libc::c_int;
                    }
                    unsafe { p = p.offset(next as isize) }
                }
                offset = unsafe { p.offset_from(buff as *const libc::c_char) } as libc::c_long
            }
        }
    }
    return 0 as libc::c_int;
}

unsafe extern "C" fn archive_read_format_lha_options(
    mut a: *mut archive_read,
    mut key: *const libc::c_char,
    mut val: *const libc::c_char,
) -> libc::c_int {
    let safe_a = unsafe { &mut *a };
    let mut lha = unsafe { &mut *((*safe_a.format).data as *mut lha) };
    let mut ret: libc::c_int = ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
    if strcmp_safe(key, b"hdrcharset\x00" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        if val.is_null()
            || unsafe { *val.offset(0 as libc::c_int as isize) } as libc::c_int == 0 as libc::c_int
        {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_LHA_DEFINED_PARAM.archive_errno_misc,
                b"lha: hdrcharset option needs a character-set name\x00" as *const u8
                    as *const libc::c_char
            );
        } else {
            lha.opt_sconv = archive_string_conversion_from_charset_safe(
                &mut safe_a.archive,
                val,
                0 as libc::c_int,
            );
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

unsafe extern "C" fn lha_skip_sfx(mut a: *mut archive_read) -> libc::c_int {
    let mut h: *const libc::c_void = 0 as *const libc::c_void;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut q: *const libc::c_char = 0 as *const libc::c_char;
    let mut next: size_t = 0;
    let mut skip: size_t = 0;
    let mut bytes: ssize_t = 0;
    let mut window: ssize_t = 0;
    window = 4096 as libc::c_int as ssize_t;
    loop {
        h = __archive_read_ahead_safe(a, window as size_t, &mut bytes);
        if h == 0 as *mut libc::c_void {
            /* Remaining bytes are less than window. */
            window >>= 1 as libc::c_int;
            if window < (ARCHIVE_LHA_DEFINED_PARAM.h_size + 3 as libc::c_int) as libc::c_long {
                break;
            }
        } else {
            if bytes < ARCHIVE_LHA_DEFINED_PARAM.h_size as libc::c_long {
                break;
            }
            p = h as *const libc::c_char;
            q = unsafe { p.offset(bytes as isize) };
            /*
             * Scan ahead until we find something that looks
             * like the lha header.
             */
            while unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_size as isize) } < q {
                next = lha_check_header_format(p as *const libc::c_void);
                if next == 0 as libc::c_int as libc::c_ulong {
                    skip = unsafe { p.offset_from(h as *const libc::c_char) } as libc::c_long
                        as size_t;
                    __archive_read_consume_safe(a, skip as int64_t);
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                }
                p = unsafe { p.offset(next as isize) }
            }
            skip = unsafe { p.offset_from(h as *const libc::c_char) } as libc::c_long as size_t;
            __archive_read_consume_safe(a, skip as int64_t);
        }
    }
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
        b"Couldn\'t find out LHa header\x00" as *const u8 as *const libc::c_char
    );
    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
}

unsafe extern "C" fn truncated_error(mut a: *mut archive_read) -> libc::c_int {
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
        b"Truncated LHa header\x00" as *const u8 as *const libc::c_char
    );
    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
}

unsafe extern "C" fn archive_read_format_lha_read_header(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
) -> libc::c_int {
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
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut signature: *const libc::c_char = 0 as *const libc::c_char;
    let mut err: libc::c_int = 0;
    let mut conv_buffer: archive_mstring = archive_mstring {
        aes_mbs: archive_string {
            s: 0 as *mut libc::c_char,
            length: 0,
            buffer_length: 0,
        },
        aes_utf8: archive_string {
            s: 0 as *mut libc::c_char,
            length: 0,
            buffer_length: 0,
        },
        aes_wcs: archive_wstring {
            s: 0 as *mut wchar_t,
            length: 0,
            buffer_length: 0,
        },
        aes_mbs_in_locale: archive_string {
            s: 0 as *mut libc::c_char,
            length: 0,
            buffer_length: 0,
        },
        aes_set: 0,
    };
    let mut conv_buffer_p: *const wchar_t = 0 as *const wchar_t;
    lha_crc16_init();
    safe_a.archive.archive_format = ARCHIVE_LHA_DEFINED_PARAM.archive_format_lha;
    if safe_a.archive.archive_format_name.is_null() {
        safe_a.archive.archive_format_name = b"lha\x00" as *const u8 as *const libc::c_char
    }
    let mut lha = unsafe { &mut *((*safe_a.format).data as *mut lha) };
    lha.decompress_init = 0 as libc::c_int as libc::c_char;
    lha.end_of_entry = 0 as libc::c_int as libc::c_char;
    lha.end_of_entry_cleanup = 0 as libc::c_int as libc::c_char;
    lha.entry_unconsumed = 0 as libc::c_int as int64_t;
    p = __archive_read_ahead_safe(
        a,
        ARCHIVE_LHA_DEFINED_PARAM.h_size as size_t,
        0 as *mut ssize_t,
    ) as *const libc::c_uchar;
    if p.is_null() {
        /*
         * LHa archiver added 0 to the tail of its archive file as
         * the mark of the end of the archive.
         */
        signature = __archive_read_ahead_safe(
            a,
            ::std::mem::size_of::<libc::c_char>() as libc::c_ulong,
            0 as *mut ssize_t,
        ) as *const libc::c_char;
        if signature.is_null()
            || unsafe { *signature.offset(0 as libc::c_int as isize) } as libc::c_int
                == 0 as libc::c_int
        {
            return ARCHIVE_LHA_DEFINED_PARAM.archive_eof;
        }
        return truncated_error(a);
    }
    signature = p as *const libc::c_char;
    if lha.found_first_header as libc::c_int == 0 as libc::c_int
        && unsafe { *signature.offset(0 as libc::c_int as isize) } as libc::c_int == 'M' as i32
        && unsafe { *signature.offset(1 as libc::c_int as isize) } as libc::c_int == 'Z' as i32
    {
        /* This is an executable?  Must be self-extracting...   */
        err = lha_skip_sfx(a);
        if err < ARCHIVE_LHA_DEFINED_PARAM.archive_warn {
            return err;
        }
        p = __archive_read_ahead_safe(
            a,
            ::std::mem::size_of::<libc::c_uchar>() as libc::c_ulong,
            0 as *mut ssize_t,
        ) as *const libc::c_uchar;
        if p.is_null() {
            return truncated_error(a);
        }
        signature = p as *const libc::c_char
    }
    /* signature[0] == 0 means the end of an LHa archive file. */
    if unsafe { *signature.offset(0 as libc::c_int as isize) } as libc::c_int == 0 as libc::c_int {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_eof;
    }
    /*
     * Check the header format and method type.
     */
    if lha_check_header_format(p as *const libc::c_void) != 0 as libc::c_int as libc::c_ulong {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Bad LHa file\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    /* We've found the first header. */
    lha.found_first_header = 1 as libc::c_int as libc::c_char;
    /* Set a default value and common data */
    lha.header_size = 0 as libc::c_int as size_t;
    lha.level = unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize) };
    lha.method[0 as libc::c_int as usize] = unsafe {
        *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 1 as libc::c_int) as isize)
    } as libc::c_char;
    lha.method[1 as libc::c_int as usize] = unsafe {
        *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 2 as libc::c_int) as isize)
    } as libc::c_char;
    lha.method[2 as libc::c_int as usize] = unsafe {
        *p.offset((ARCHIVE_LHA_DEFINED_PARAM.h_method_offset + 3 as libc::c_int) as isize)
    } as libc::c_char;
    if memcmp_safe(
        lha.method.as_mut_ptr() as *const libc::c_void,
        b"lhd\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        3 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        lha.directory = 1 as libc::c_int as libc::c_char
    } else {
        lha.directory = 0 as libc::c_int as libc::c_char
    }
    if memcmp_safe(
        lha.method.as_mut_ptr() as *const libc::c_void,
        b"lh0\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        3 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
        || memcmp_safe(
            lha.method.as_mut_ptr() as *const libc::c_void,
            b"lz4\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
            3 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
    {
        lha.entry_is_compressed = 0 as libc::c_int as libc::c_char
    } else {
        lha.entry_is_compressed = 1 as libc::c_int as libc::c_char
    }
    lha.compsize = 0 as libc::c_int as int64_t;
    lha.origsize = 0 as libc::c_int as int64_t;
    lha.setflag = 0 as libc::c_int;
    lha.birthtime = 0 as libc::c_int as time_t;
    lha.birthtime_tv_nsec = 0 as libc::c_int as libc::c_long;
    lha.mtime = 0 as libc::c_int as time_t;
    lha.mtime_tv_nsec = 0 as libc::c_int as libc::c_long;
    lha.atime = 0 as libc::c_int as time_t;
    lha.atime_tv_nsec = 0 as libc::c_int as libc::c_long;
    lha.mode = if lha.directory as libc::c_int != 0 {
        0o777 as libc::c_int
    } else {
        0o666 as libc::c_int
    } as mode_t;
    lha.uid = 0 as libc::c_int as int64_t;
    lha.gid = 0 as libc::c_int as int64_t;
    lha.dirname.length = 0 as libc::c_int as size_t;
    lha.filename.length = 0 as libc::c_int as size_t;
    lha.dos_attr = 0 as libc::c_int as libc::c_uchar;
    if !lha.opt_sconv.is_null() {
        lha.sconv_dir = lha.opt_sconv;
        lha.sconv_fname = lha.opt_sconv
    } else {
        lha.sconv_dir = 0 as *mut archive_string_conv;
        lha.sconv_fname = 0 as *mut archive_string_conv
    }
    match unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize) } as libc::c_int {
        0 => err = lha_read_file_header_0(a, lha),
        1 => err = lha_read_file_header_1(a, lha),
        2 => err = lha_read_file_header_2(a, lha),
        3 => err = lha_read_file_header_3(a, lha),
        _ => {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
                b"Unsupported LHa header level %d\x00" as *const u8 as *const libc::c_char,
                *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize) as libc::c_int
            );
            err = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal
        }
    }
    if err < ARCHIVE_LHA_DEFINED_PARAM.archive_warn {
        return err;
    }
    if lha.directory == 0 && lha.filename.length == 0 as libc::c_int as libc::c_ulong {
        /* The filename has not been set */
        return truncated_error(a);
    }
    /*
     * Make a pathname from a dirname and a filename, after converting to Unicode.
     * This is because codepages might differ between dirname and filename.
     */
    pathname.s = 0 as *mut wchar_t;
    pathname.length = 0 as libc::c_int as size_t;
    pathname.buffer_length = 0 as libc::c_int as size_t;
    linkname.s = 0 as *mut wchar_t;
    linkname.length = 0 as libc::c_int as size_t;
    linkname.buffer_length = 0 as libc::c_int as size_t;
    conv_buffer.aes_mbs.s = 0 as *mut libc::c_char;
    conv_buffer.aes_mbs.length = 0 as libc::c_int as size_t;
    conv_buffer.aes_mbs.buffer_length = 0 as libc::c_int as size_t;
    conv_buffer.aes_mbs_in_locale.s = 0 as *mut libc::c_char;
    conv_buffer.aes_mbs_in_locale.length = 0 as libc::c_int as size_t;
    conv_buffer.aes_mbs_in_locale.buffer_length = 0 as libc::c_int as size_t;
    conv_buffer.aes_utf8.s = 0 as *mut libc::c_char;
    conv_buffer.aes_utf8.length = 0 as libc::c_int as size_t;
    conv_buffer.aes_utf8.buffer_length = 0 as libc::c_int as size_t;
    conv_buffer.aes_wcs.s = 0 as *mut wchar_t;
    conv_buffer.aes_wcs.length = 0 as libc::c_int as size_t;
    conv_buffer.aes_wcs.buffer_length = 0 as libc::c_int as size_t;
    if 0 as libc::c_int
        != archive_mstring_copy_mbs_len_l_safe(
            &mut conv_buffer,
            lha.dirname.s,
            lha.dirname.length,
            lha.sconv_dir,
        )
    {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Pathname cannot be converted from %s to Unicode.\x00" as *const u8
                as *const libc::c_char,
            archive_string_conversion_charset_name_safe(lha.sconv_dir)
        );
        err = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal
    } else if 0 as libc::c_int
        != archive_mstring_get_wcs_safe(&mut safe_a.archive, &mut conv_buffer, &mut conv_buffer_p)
    {
        err = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal
    }
    if err == ARCHIVE_LHA_DEFINED_PARAM.archive_fatal {
        archive_mstring_clean_safe(&mut conv_buffer);
        archive_wstring_free_safe(&mut pathname);
        archive_wstring_free_safe(&mut linkname);
        return err;
    }
    pathname.length = 0 as libc::c_int as size_t;
    archive_wstring_concat_safe(&mut pathname, &mut conv_buffer.aes_wcs);
    conv_buffer.aes_mbs.length = 0 as libc::c_int as size_t;
    conv_buffer.aes_mbs_in_locale.length = 0 as libc::c_int as size_t;
    conv_buffer.aes_utf8.length = 0 as libc::c_int as size_t;
    conv_buffer.aes_wcs.length = 0 as libc::c_int as size_t;
    if 0 as libc::c_int
        != archive_mstring_copy_mbs_len_l_safe(
            &mut conv_buffer,
            lha.filename.s,
            lha.filename.length,
            lha.sconv_fname,
        )
    {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Pathname cannot be converted from %s to Unicode.\x00" as *const u8
                as *const libc::c_char,
            archive_string_conversion_charset_name_safe(lha.sconv_fname)
        );
        err = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal
    } else if 0 as libc::c_int
        != archive_mstring_get_wcs_safe(&mut safe_a.archive, &mut conv_buffer, &mut conv_buffer_p)
    {
        err = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal
    }
    if err == ARCHIVE_LHA_DEFINED_PARAM.archive_fatal {
        archive_mstring_clean_safe(&mut conv_buffer);
        archive_wstring_free_safe(&mut pathname);
        archive_wstring_free_safe(&mut linkname);
        return err;
    }
    archive_wstring_concat_safe(&mut pathname, &mut conv_buffer.aes_wcs);
    archive_mstring_clean_safe(&mut conv_buffer);
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
                b"Unknown symlink-name\x00" as *const u8 as *const libc::c_char
            );
            archive_wstring_free_safe(&mut pathname);
            archive_wstring_free_safe(&mut linkname);
            return ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
        }
    } else {
        /*
         * Make sure a file-type is set.
         * The mode has been overridden if it is in the extended data.
         */
        lha.mode = lha.mode & !(ARCHIVE_LHA_DEFINED_PARAM.ae_ifmt as mode_t)
            | (if lha.directory as libc::c_int != 0 {
                ARCHIVE_LHA_DEFINED_PARAM.ae_ifdir as mode_t
            } else {
                ARCHIVE_LHA_DEFINED_PARAM.ae_ifreg as mode_t
            })
    } /* read only. */
    if lha.setflag & ARCHIVE_LHA_DEFINED_PARAM.unix_mode_is_set == 0 as libc::c_int
        && lha.dos_attr as libc::c_int & 1 as libc::c_int != 0 as libc::c_int
    {
        lha.mode &= !(0o222 as libc::c_int) as libc::c_uint
    }
    /*
     * Set basic file parameters.
     */
    archive_entry_copy_pathname_w_safe(entry, pathname.s);
    archive_wstring_free_safe(&mut pathname);
    if linkname.length > 0 as libc::c_int as libc::c_ulong {
        archive_entry_copy_symlink_w_safe(entry, linkname.s);
    } else {
        archive_entry_set_symlink_safe(entry, 0 as *const libc::c_char);
    }
    archive_wstring_free_safe(&mut linkname);
    /*
     * When a header level is 0, there is a possibility that
     * a pathname and a symlink has '\' character, a directory
     * separator in DOS/Windows. So we should convert it to '/'.
     */
    if unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h_level_offset as isize) } as libc::c_int
        == 0 as libc::c_int
    {
        lha_replace_path_separator(lha, entry);
    }
    archive_entry_set_mode_safe(entry, lha.mode);
    archive_entry_set_uid_safe(entry, lha.uid);
    archive_entry_set_gid_safe(entry, lha.gid);
    if lha.uname.length > 0 as libc::c_int as libc::c_ulong {
        archive_entry_set_uname_safe(entry, lha.uname.s);
    }
    if lha.gname.length > 0 as libc::c_int as libc::c_ulong {
        archive_entry_set_gname_safe(entry, lha.gname.s);
    }
    if lha.setflag & ARCHIVE_LHA_DEFINED_PARAM.birthtime_is_set != 0 {
        archive_entry_set_birthtime_safe(entry, lha.birthtime, lha.birthtime_tv_nsec);
        archive_entry_set_ctime_safe(entry, lha.birthtime, lha.birthtime_tv_nsec);
    } else {
        archive_entry_unset_birthtime_safe(entry);
        archive_entry_unset_ctime_safe(entry);
    }
    archive_entry_set_mtime_safe(entry, lha.mtime, lha.mtime_tv_nsec);
    if lha.setflag & ARCHIVE_LHA_DEFINED_PARAM.atime_is_set != 0 {
        archive_entry_set_atime_safe(entry, lha.atime, lha.atime_tv_nsec);
    } else {
        archive_entry_unset_atime_safe(entry);
    }
    if lha.directory as libc::c_int != 0 || !archive_entry_symlink_safe(entry).is_null() {
        archive_entry_unset_size_safe(entry);
    } else {
        archive_entry_set_size_safe(entry, lha.origsize);
    }
    /*
     * Prepare variables used to read a file content.
     */
    lha.entry_bytes_remaining = lha.compsize;
    if lha.entry_bytes_remaining < 0 as libc::c_int as libc::c_long {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid LHa entry size\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    lha.entry_offset = 0 as libc::c_int as int64_t;
    lha.entry_crc_calculated = 0 as libc::c_int as uint16_t;
    /*
     * This file does not have a content.
     */
    if lha.directory as libc::c_int != 0 || lha.compsize == 0 as libc::c_int as libc::c_long {
        lha.end_of_entry = 1 as libc::c_int as libc::c_char
    }
    sprintf_safe!(
        lha.format_name.as_mut_ptr(),
        b"lha -%c%c%c-\x00" as *const u8 as *const libc::c_char,
        lha.method[0 as libc::c_int as usize] as libc::c_int,
        lha.method[1 as libc::c_int as usize] as libc::c_int,
        lha.method[2 as libc::c_int as usize] as libc::c_int
    );
    safe_a.archive.archive_format_name = lha.format_name.as_mut_ptr();
    return err;
}

/*
 * Replace a DOS path separator '\' by a character '/'.
 * Some multi-byte character set have  a character '\' in its second byte.
 */
unsafe extern "C" fn lha_replace_path_separator(mut lha: &mut lha, mut entry: *mut archive_entry) {
    let mut wp: *const wchar_t = 0 as *const wchar_t;
    let mut i: size_t = 0;
    wp = archive_entry_pathname_w_safe(entry);
    if !wp.is_null() {
        lha.ws.length = 0 as libc::c_int as size_t;
        archive_wstrncat_safe(
            &mut lha.ws,
            wp,
            if wp.is_null() {
                0 as libc::c_int as libc::c_ulong
            } else {
                wcslen_safe(wp)
            },
        );
        i = 0 as libc::c_int as size_t;
        while i < lha.ws.length {
            if unsafe { *lha.ws.s.offset(i as isize) } == '\\' as wchar_t {
                unsafe { *lha.ws.s.offset(i as isize) = '/' as wchar_t }
            }
            i = i.wrapping_add(1)
        }
        archive_entry_copy_pathname_w_safe(entry, lha.ws.s);
    }
    wp = archive_entry_symlink_w_safe(entry);
    if !wp.is_null() {
        lha.ws.length = 0 as libc::c_int as size_t;
        archive_wstrncat_safe(
            &mut lha.ws,
            wp,
            if wp.is_null() {
                0 as libc::c_int as libc::c_ulong
            } else {
                wcslen_safe(wp)
            },
        );
        i = 0 as libc::c_int as size_t;
        while i < lha.ws.length {
            if unsafe { *lha.ws.s.offset(i as isize) } == '\\' as wchar_t {
                unsafe { *lha.ws.s.offset(i as isize) = '/' as wchar_t }
            }
            i = i.wrapping_add(1)
        }
        archive_entry_copy_symlink_w_safe(entry, lha.ws.s);
    };
}

unsafe extern "C" fn lha_read_file_header_0(
    mut a: *mut archive_read,
    mut lha: &mut lha,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut extdsize: libc::c_int = 0;
    let mut namelen: libc::c_int = 0;
    let mut headersum: libc::c_uchar = 0;
    let mut sum_calculated: libc::c_uchar = 0;
    p = __archive_read_ahead_safe(
        a,
        ARCHIVE_LHA_DEFINED_PARAM.h0_fixed_size as size_t,
        0 as *mut ssize_t,
    ) as *const libc::c_uchar;
    if p.is_null() {
        return truncated_error(a);
    }
    lha.header_size =
        (unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_header_size_offset as isize) }
            as libc::c_int
            + 2 as libc::c_int) as size_t;
    headersum = unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_header_sum_offset as isize) };
    lha.compsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_comp_size_offset as isize) }
                as *const libc::c_void,
        ) as int64_t;
    lha.origsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_orig_size_offset as isize) }
                as *const libc::c_void,
        ) as int64_t;
    lha.mtime =
        lha_dos_time(unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_dos_time_offset as isize) });
    namelen =
        unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_name_len_offset as isize) } as libc::c_int;
    extdsize = lha.header_size as libc::c_int - ARCHIVE_LHA_DEFINED_PARAM.h0_fixed_size - namelen;
    if (namelen > 221 as libc::c_int || extdsize < 0 as libc::c_int)
        && extdsize != -(2 as libc::c_int)
    {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid LHa header\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    p = __archive_read_ahead_safe(a, lha.header_size, 0 as *mut ssize_t) as *const libc::c_uchar;
    if p.is_null() {
        return truncated_error(a);
    }
    lha.filename.length = 0 as libc::c_int as size_t;
    archive_strncat_safe(
        &mut lha.filename,
        unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_file_name_offset as isize) }
            as *const libc::c_void,
        namelen as size_t,
    );
    /* When extdsize == -2, A CRC16 value is not present in the header. */
    if extdsize >= 0 as libc::c_int {
        lha.crc = archive_le16dec(unsafe {
            p.offset(ARCHIVE_LHA_DEFINED_PARAM.h0_file_name_offset as isize)
                .offset(namelen as isize)
        } as *const libc::c_void);
        lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.crc_is_set
    }
    sum_calculated = lha_calcsum(
        0 as libc::c_int as libc::c_uchar,
        p as *const libc::c_void,
        2 as libc::c_int,
        lha.header_size
            .wrapping_sub(2 as libc::c_int as libc::c_ulong),
    );
    /* Read an extended header */
    if extdsize > 0 as libc::c_int {
        /* This extended data is set by 'LHa for UNIX' only.
         * Maybe fixed size.
         */
        p = unsafe {
            p.offset(
                (ARCHIVE_LHA_DEFINED_PARAM.h0_file_name_offset + namelen + 2 as libc::c_int)
                    as isize,
            )
        };
        if unsafe { *p.offset(0 as libc::c_int as isize) } as libc::c_int == 'U' as i32
            && extdsize == 12 as libc::c_int
        {
            /* p[1] is a minor version. */
            lha.mtime = archive_le32dec(unsafe { &*p.offset(2 as libc::c_int as isize) }
                as *const libc::c_uchar
                as *const libc::c_void) as time_t;
            lha.mode = archive_le16dec(unsafe { &*p.offset(6 as libc::c_int as isize) }
                as *const libc::c_uchar
                as *const libc::c_void) as mode_t;
            lha.uid = archive_le16dec(unsafe { &*p.offset(8 as libc::c_int as isize) }
                as *const libc::c_uchar
                as *const libc::c_void) as int64_t;
            lha.gid = archive_le16dec(unsafe { &*p.offset(10 as libc::c_int as isize) }
                as *const libc::c_uchar
                as *const libc::c_void) as int64_t;
            lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.unix_mode_is_set
        }
    }
    __archive_read_consume_safe(a, lha.header_size as int64_t);
    if sum_calculated as libc::c_int != headersum as libc::c_int {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_misc,
            b"LHa header sum error\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

unsafe extern "C" fn lha_read_file_header_1(
    mut a: *mut archive_read,
    mut lha: &mut lha,
) -> libc::c_int {
    let mut current_block: u64;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut extdsize: size_t = 0;
    let mut i: libc::c_int = 0;
    let mut err: libc::c_int = 0;
    let mut err2: libc::c_int = 0;
    let mut namelen: libc::c_int = 0;
    let mut padding: libc::c_int = 0;
    let mut headersum: libc::c_uchar = 0;
    let mut sum_calculated: libc::c_uchar = 0;
    err = ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
    p = __archive_read_ahead_safe(
        a,
        ARCHIVE_LHA_DEFINED_PARAM.h1_fixed_size as size_t,
        0 as *mut ssize_t,
    ) as *const libc::c_uchar;
    if p.is_null() {
        return truncated_error(a);
    }
    lha.header_size =
        (unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_header_size_offset as isize) }
            as libc::c_int
            + 2 as libc::c_int) as size_t;
    headersum = unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_header_sum_offset as isize) };
    /* Note: An extended header size is included in a compsize. */
    lha.compsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_comp_size_offset as isize) }
                as *const libc::c_void,
        ) as int64_t;
    lha.origsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_orig_size_offset as isize) }
                as *const libc::c_void,
        ) as int64_t;
    lha.mtime =
        lha_dos_time(unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_dos_time_offset as isize) });
    namelen =
        unsafe { *p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_name_len_offset as isize) } as libc::c_int;
    /* Calculate a padding size. The result will be normally 0 only(?) */
    padding = lha.header_size as libc::c_int - ARCHIVE_LHA_DEFINED_PARAM.h1_fixed_size - namelen;
    if !(namelen > 230 as libc::c_int || padding < 0 as libc::c_int) {
        p = __archive_read_ahead_safe(a, lha.header_size, 0 as *mut ssize_t)
            as *const libc::c_uchar;
        if p.is_null() {
            return truncated_error(a);
        }
        i = 0 as libc::c_int;
        loop {
            if !(i < namelen) {
                current_block = 17833034027772472439;
                break;
            }
            if unsafe { *p.offset((i + ARCHIVE_LHA_DEFINED_PARAM.h1_file_name_offset) as isize) }
                as libc::c_int
                == 0xff as libc::c_int
            {
                current_block = 7310071999204176054;
                break;
                /* Invalid filename. */
            }
            i += 1
        }
        match current_block {
            7310071999204176054 => {}
            _ => {
                lha.filename.length = 0 as libc::c_int as size_t;
                archive_strncat_safe(
                    &mut lha.filename,
                    unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_file_name_offset as isize) }
                        as *const libc::c_void,
                    namelen as size_t,
                );
                lha.crc = archive_le16dec(unsafe {
                    p.offset(ARCHIVE_LHA_DEFINED_PARAM.h1_file_name_offset as isize)
                        .offset(namelen as isize)
                } as *const libc::c_void);
                lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.crc_is_set;
                sum_calculated = lha_calcsum(
                    0 as libc::c_int as libc::c_uchar,
                    p as *const libc::c_void,
                    2 as libc::c_int,
                    lha.header_size
                        .wrapping_sub(2 as libc::c_int as libc::c_ulong),
                );
                /* Consume used bytes but not include `next header size' data
                 * since it will be consumed in lha_read_file_extended_header(). */
                __archive_read_consume_safe(
                    a,
                    lha.header_size
                        .wrapping_sub(2 as libc::c_int as libc::c_ulong)
                        as int64_t,
                );
                /* Read extended headers */
                err2 = lha_read_file_extended_header(
                    a,
                    lha,
                    0 as *mut uint16_t,
                    2 as libc::c_int,
                    (lha.compsize + 2 as libc::c_int as libc::c_long) as size_t,
                    &mut extdsize,
                );
                if err2 < ARCHIVE_LHA_DEFINED_PARAM.archive_warn {
                    return err2;
                }
                if err2 < err {
                    err = err2
                }
                /* Get a real compressed file size. */
                lha.compsize = (lha.compsize as libc::c_ulong)
                    .wrapping_sub(extdsize.wrapping_sub(2 as libc::c_int as libc::c_ulong))
                    as int64_t as int64_t; /* Invalid compressed file size */
                if !(lha.compsize < 0 as libc::c_int as libc::c_long) {
                    if sum_calculated as libc::c_int != headersum as libc::c_int {
                        archive_set_error_safe!(
                            &mut (*a).archive as *mut archive,
                            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_misc,
                            b"LHa header sum error\x00" as *const u8 as *const libc::c_char
                        );
                        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
                    }
                    return err;
                }
            }
        }
    }
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
        b"Invalid LHa header\x00" as *const u8 as *const libc::c_char
    );
    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
}

unsafe extern "C" fn lha_read_file_header_2(
    mut a: *mut archive_read,
    mut lha: &mut lha,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut extdsize: size_t = 0;
    let mut err: libc::c_int = 0;
    let mut padding: libc::c_int = 0;
    let mut header_crc: uint16_t = 0;
    p = __archive_read_ahead_safe(
        a,
        ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as size_t,
        0 as *mut ssize_t,
    ) as *const libc::c_uchar;
    if p.is_null() {
        return truncated_error(a);
    }
    lha.header_size = archive_le16dec(unsafe {
        p.offset(ARCHIVE_LHA_DEFINED_PARAM.h2_header_size_offset as isize)
    } as *const libc::c_void) as size_t;
    lha.compsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h2_comp_size_offset as isize) }
                as *const libc::c_void,
        ) as int64_t;
    lha.origsize =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h2_orig_size_offset as isize) }
                as *const libc::c_void,
        ) as int64_t;
    lha.mtime =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h2_time_offset as isize) }
                as *const libc::c_void,
        ) as time_t;
    lha.crc = archive_le16dec(
        unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h2_crc_offset as isize) }
            as *const libc::c_void,
    );
    lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.crc_is_set;
    if lha.header_size < ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as libc::c_ulong {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid LHa header size\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    header_crc = lha_crc16(
        0 as libc::c_int as uint16_t,
        p as *const libc::c_void,
        ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as size_t,
    );
    __archive_read_consume_safe(a, ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as int64_t);
    /* Read extended headers */
    err = lha_read_file_extended_header(
        a,
        lha,
        &mut header_crc,
        2 as libc::c_int,
        lha.header_size
            .wrapping_sub(ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as libc::c_ulong),
        &mut extdsize,
    );
    if err < ARCHIVE_LHA_DEFINED_PARAM.archive_warn {
        return err;
    }
    /* Calculate a padding size. The result will be normally 0 or 1. */
    padding = lha.header_size as libc::c_int
        - (ARCHIVE_LHA_DEFINED_PARAM.h2_fixed_size as libc::c_ulong).wrapping_add(extdsize)
            as libc::c_int;
    if padding > 0 as libc::c_int {
        p = __archive_read_ahead_safe(a, padding as size_t, 0 as *mut ssize_t)
            as *const libc::c_uchar;
        if p.is_null() {
            return truncated_error(a);
        }
        header_crc = lha_crc16(header_crc, p as *const libc::c_void, padding as size_t);
        __archive_read_consume_safe(a, padding as int64_t);
    }
    if header_crc as libc::c_int != lha.header_crc as libc::c_int {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"LHa header CRC error\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    return err;
}

unsafe extern "C" fn lha_read_file_header_3(
    mut a: *mut archive_read,
    mut lha: &mut lha,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut extdsize: size_t = 0;
    let mut err: libc::c_int = 0;
    let mut header_crc: uint16_t = 0;
    p = __archive_read_ahead_safe(
        a,
        ARCHIVE_LHA_DEFINED_PARAM.h3_fixed_size as size_t,
        0 as *mut ssize_t,
    ) as *const libc::c_uchar;
    if p.is_null() {
        return truncated_error(a);
    }
    if !(archive_le16dec(
        unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_field_len_offset as isize) }
            as *const libc::c_void,
    ) as libc::c_int
        != 4 as libc::c_int)
    {
        lha.header_size = archive_le32dec(unsafe {
            p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_header_size_offset as isize)
        } as *const libc::c_void) as size_t;
        lha.compsize = archive_le32dec(unsafe {
            p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_comp_size_offset as isize)
        } as *const libc::c_void) as int64_t;
        lha.origsize = archive_le32dec(unsafe {
            p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_orig_size_offset as isize)
        } as *const libc::c_void) as int64_t;
        lha.mtime =
            archive_le32dec(
                unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_time_offset as isize) }
                    as *const libc::c_void,
            ) as time_t;
        lha.crc =
            archive_le16dec(
                unsafe { p.offset(ARCHIVE_LHA_DEFINED_PARAM.h3_crc_offset as isize) }
                    as *const libc::c_void,
            );
        lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.crc_is_set;

        if !(lha.header_size
            < (ARCHIVE_LHA_DEFINED_PARAM.h3_fixed_size + 4 as libc::c_int) as libc::c_ulong)
        {
            header_crc = lha_crc16(
                0 as libc::c_int as uint16_t,
                p as *const libc::c_void,
                ARCHIVE_LHA_DEFINED_PARAM.h3_fixed_size as size_t,
            );
            __archive_read_consume_safe(a, ARCHIVE_LHA_DEFINED_PARAM.h3_fixed_size as int64_t);
            /* Read extended headers */
            err = lha_read_file_extended_header(
                a,
                lha,
                &mut header_crc,
                4 as libc::c_int,
                lha.header_size
                    .wrapping_sub(ARCHIVE_LHA_DEFINED_PARAM.h3_fixed_size as libc::c_ulong),
                &mut extdsize,
            );
            if err < ARCHIVE_LHA_DEFINED_PARAM.archive_warn {
                return err;
            }
            if header_crc as libc::c_int != lha.header_crc as libc::c_int {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
                    b"LHa header CRC error\x00" as *const u8 as *const libc::c_char
                );
                return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
            }
            return err;
        }
    }
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
        b"Invalid LHa header\x00" as *const u8 as *const libc::c_char
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
unsafe extern "C" fn lha_read_file_extended_header(
    mut a: *mut archive_read,
    mut lha: &mut lha,
    mut crc: *mut uint16_t,
    mut sizefield_length: libc::c_int,
    mut limitsize: size_t,
    mut total_size: &mut size_t,
) -> libc::c_int {
    let safe_a = unsafe { &mut *a };
    let mut h: *const libc::c_void = 0 as *const libc::c_void;
    let mut extdheader: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut extdsize: size_t = 0;
    let mut datasize: size_t = 0;
    let mut i: libc::c_uint = 0;
    let mut extdtype: libc::c_uchar = 0;
    /* Header CRC and information*/
    /* Filename             */
    /* Directory name       */
    /* MS-DOS attribute     */
    /* Windows time stamp       */
    /* Large file size      */
    /* Time zone            */
    /* UTF-16 filename      */
    /* UTF-16 directory name    */
    /* Codepage         */
    /* File permission      */
    /* gid,uid          */
    /* Group name           */
    /* User name            */
    /* Modified time        */
    /* new attribute(OS/2 only) */
    /* new attribute        */
    *total_size = sizefield_length as size_t;
    loop {
        /* Read an extended header size. */
        h = __archive_read_ahead_safe(a, sizefield_length as size_t, 0 as *mut ssize_t);
        if h == 0 as *mut libc::c_void {
            return truncated_error(a);
        }
        /* Check if the size is the zero indicates the end of the
         * extended header. */
        if sizefield_length as libc::c_ulong == ::std::mem::size_of::<uint16_t>() as libc::c_ulong {
            extdsize = archive_le16dec(h) as size_t
        } else {
            extdsize = archive_le32dec(h) as size_t
        }
        if extdsize == 0 as libc::c_int as libc::c_ulong {
            /* End of extended header */
            if !crc.is_null() {
                unsafe { *crc = lha_crc16(*crc, h, sizefield_length as size_t) }
            }
            __archive_read_consume_safe(a, sizefield_length as int64_t);
            return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
        }
        /* Sanity check to the extended header size. */
        if (*total_size).wrapping_add(extdsize) > limitsize
            || extdsize <= sizefield_length as size_t
        {
            break;
        }
        /* Read the extended header. */
        h = __archive_read_ahead_safe(a, extdsize, 0 as *mut ssize_t);
        if h == 0 as *mut libc::c_void {
            return truncated_error(a);
        }
        *total_size = (*total_size as libc::c_ulong).wrapping_add(extdsize) as size_t as size_t;
        extdheader = h as *const libc::c_uchar;
        /* Get the extended header type. */
        extdtype = unsafe { *extdheader.offset(sizefield_length as isize) };
        /* Calculate an extended data size. */
        datasize = extdsize.wrapping_sub((1 as libc::c_int + sizefield_length) as libc::c_ulong);
        /* Skip an extended header size field and type field. */
        extdheader = unsafe { extdheader.offset((sizefield_length + 1 as libc::c_int) as isize) };
        if !crc.is_null() && extdtype as libc::c_int != ARCHIVE_LHA_DEFINED_PARAM.ext_header_crc {
            unsafe { *crc = lha_crc16(*crc, h, extdsize) }
        }
        if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_header_crc {
            /* We only use a header CRC. Following data will not
             * be used. */
            if datasize >= 2 as libc::c_int as libc::c_ulong {
                lha.header_crc = archive_le16dec(extdheader as *const libc::c_void);
                if !crc.is_null() {
                    static mut zeros: [libc::c_char; 2] = [
                        0 as libc::c_int as libc::c_char,
                        0 as libc::c_int as libc::c_char,
                    ];
                    unsafe {
                        *crc = lha_crc16(*crc, h, extdsize.wrapping_sub(datasize));
                        /* CRC value itself as zero */
                        *crc = lha_crc16(
                            *crc,
                            zeros.as_ptr() as *const libc::c_void,
                            2 as libc::c_int as size_t,
                        );
                        *crc = lha_crc16(
                            *crc,
                            extdheader.offset(2 as libc::c_int as isize) as *const libc::c_void,
                            datasize.wrapping_sub(2 as libc::c_int as libc::c_ulong),
                        )
                    }
                }
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_filename {
            if datasize == 0 as libc::c_int as libc::c_ulong {
                /* maybe directory header */
                lha.filename.length = 0 as libc::c_int as size_t
            } else {
                if unsafe { *extdheader.offset(0 as libc::c_int as isize) } as libc::c_int
                    == '\u{0}' as i32
                {
                    break;
                }
                lha.filename.length = 0 as libc::c_int as size_t;
                archive_strncat_safe(
                    &mut lha.filename,
                    extdheader as *const libc::c_char as *const libc::c_void,
                    datasize,
                );
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_utf16_filename {
            if datasize == 0 as libc::c_int as libc::c_ulong {
                /* maybe directory header */
                lha.filename.length = 0 as libc::c_int as size_t
            } else if datasize & 1 as libc::c_int as libc::c_ulong != 0 {
                /* UTF-16 characters take always 2 or 4 bytes */
                break;
            } else {
                if unsafe { *extdheader.offset(0 as libc::c_int as isize) } as libc::c_int
                    == '\u{0}' as i32
                {
                    break;
                }
                lha.filename.length = 0 as libc::c_int as size_t;
                archive_array_append_safe(
                    &mut lha.filename,
                    extdheader as *const libc::c_char,
                    datasize,
                );
                /* Setup a string conversion for a filename. */
                lha.sconv_fname = archive_string_conversion_from_charset_safe(
                    &mut safe_a.archive,
                    b"UTF-16LE\x00" as *const u8 as *const libc::c_char,
                    1 as libc::c_int,
                );
                if lha.sconv_fname.is_null() {
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
                }
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_directory {
            if datasize == 0 as libc::c_int as libc::c_ulong
                || unsafe { *extdheader.offset(0 as libc::c_int as isize) } as libc::c_int
                    == '\u{0}' as i32
            {
                /* no directory name data. exit this case. */
                break;
            } else {
                lha.dirname.length = 0 as libc::c_int as size_t;
                archive_strncat_safe(
                    &mut lha.dirname,
                    extdheader as *const libc::c_char as *const libc::c_void,
                    datasize,
                );
                /*
                 * Convert directory delimiter from 0xFF
                 * to '/' for local system.
                 */
                i = 0 as libc::c_int as libc::c_uint;
                while (i as libc::c_ulong) < lha.dirname.length {
                    if unsafe { *lha.dirname.s.offset(i as isize) } as libc::c_uchar as libc::c_int
                        == 0xff as libc::c_int
                    {
                        unsafe { *lha.dirname.s.offset(i as isize) = '/' as i32 as libc::c_char }
                    }
                    i = i.wrapping_add(1)
                }
                /* Is last character directory separator? */
                if unsafe {
                    *lha.dirname.s.offset(
                        lha.dirname
                            .length
                            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                            as isize,
                    )
                } as libc::c_int
                    != '/' as i32
                {
                    /* invalid directory data */
                    break;
                }
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_utf16_directory {
            /* UTF-16 characters take always 2 or 4 bytes */
            if datasize == 0 as libc::c_int as libc::c_ulong
                || datasize & 1 as libc::c_int as libc::c_ulong != 0
                || unsafe { *extdheader.offset(0 as libc::c_int as isize) } as libc::c_int
                    == '\u{0}' as i32
            {
                /* no directory name data. exit this case. */
                break;
            } else {
                lha.dirname.length = 0 as libc::c_int as size_t;
                archive_array_append_safe(
                    &mut lha.dirname,
                    extdheader as *const libc::c_char,
                    datasize,
                );
                lha.sconv_dir = archive_string_conversion_from_charset_safe(
                    &mut safe_a.archive,
                    b"UTF-16LE\x00" as *const u8 as *const libc::c_char,
                    1 as libc::c_int,
                );
                if lha.sconv_dir.is_null() {
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
                } else {
                    /*
                     * Convert directory delimiter from 0xFFFF
                     * to '/' for local system.
                     */
                    let mut dirSep: uint16_t = 0;
                    let mut d: uint16_t = 1 as libc::c_int as uint16_t;
                    if archive_be16dec(&mut d as *mut uint16_t as *const libc::c_void)
                        as libc::c_int
                        == 1 as libc::c_int
                    {
                        dirSep = 0x2f00 as libc::c_int as uint16_t
                    } else {
                        dirSep = 0x2f as libc::c_int as uint16_t
                    }
                    /* UTF-16LE character */
                    let mut utf16name: *mut uint16_t = lha.dirname.s as *mut uint16_t;
                    i = 0 as libc::c_int as libc::c_uint;
                    while (i as libc::c_ulong)
                        < lha
                            .dirname
                            .length
                            .wrapping_div(2 as libc::c_int as libc::c_ulong)
                    {
                        if unsafe { *utf16name.offset(i as isize) } as libc::c_int
                            == 0xffff as libc::c_int
                        {
                            unsafe { *utf16name.offset(i as isize) = dirSep }
                        }
                        i = i.wrapping_add(1)
                    }
                    /* Is last character directory separator? */
                    if unsafe {
                        *utf16name.offset(
                            lha.dirname
                                .length
                                .wrapping_div(2 as libc::c_int as libc::c_ulong)
                                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                as isize,
                        )
                    } as libc::c_int
                        != dirSep as libc::c_int
                    {
                        break;
                    }
                }
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_dos_attr {
            if datasize == 2 as libc::c_int as libc::c_ulong {
                lha.dos_attr = (archive_le16dec(extdheader as *const libc::c_void) as libc::c_int
                    & 0xff as libc::c_int) as libc::c_uchar
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_timestamp {
            if datasize
                == (::std::mem::size_of::<uint64_t>() as libc::c_ulong)
                    .wrapping_mul(3 as libc::c_int as libc::c_ulong)
            {
                lha.birthtime = lha_win_time(
                    archive_le64dec(extdheader as *const libc::c_void),
                    &mut lha.birthtime_tv_nsec,
                );
                extdheader = unsafe {
                    extdheader.offset(::std::mem::size_of::<uint64_t>() as libc::c_ulong as isize)
                };
                lha.mtime = lha_win_time(
                    archive_le64dec(extdheader as *const libc::c_void),
                    &mut lha.mtime_tv_nsec,
                );
                extdheader = unsafe {
                    extdheader.offset(::std::mem::size_of::<uint64_t>() as libc::c_ulong as isize)
                };
                lha.atime = lha_win_time(
                    archive_le64dec(extdheader as *const libc::c_void),
                    &mut lha.atime_tv_nsec,
                );
                lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.birthtime_is_set
                    | ARCHIVE_LHA_DEFINED_PARAM.atime_is_set
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_filesize {
            if datasize
                == (::std::mem::size_of::<uint64_t>() as libc::c_ulong)
                    .wrapping_mul(2 as libc::c_int as libc::c_ulong)
            {
                lha.compsize = archive_le64dec(extdheader as *const libc::c_void) as int64_t;
                extdheader = unsafe {
                    extdheader.offset(::std::mem::size_of::<uint64_t>() as libc::c_ulong as isize)
                };
                lha.origsize = archive_le64dec(extdheader as *const libc::c_void) as int64_t
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_codepage {
            /* Get an archived filename charset from codepage.
             * This overwrites the charset specified by
             * hdrcharset option. */
            if datasize == ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                let mut cp: archive_string = archive_string {
                    s: 0 as *mut libc::c_char,
                    length: 0,
                    buffer_length: 0,
                };
                let mut charset: *const libc::c_char = 0 as *const libc::c_char;
                cp.s = 0 as *mut libc::c_char;
                cp.length = 0 as libc::c_int as size_t;
                cp.buffer_length = 0 as libc::c_int as size_t;
                match archive_le32dec(extdheader as *const libc::c_void) {
                    65001 => {
                        /* UTF-8 */
                        charset = b"UTF-8\x00" as *const u8 as *const libc::c_char
                    }
                    _ => {
                        archive_string_sprintf_safe!(
                            &mut cp as *mut archive_string,
                            b"CP%d\x00" as *const u8 as *const libc::c_char,
                            archive_le32dec(extdheader as *const libc::c_void) as libc::c_int
                        );
                        charset = cp.s
                    }
                }
                lha.sconv_dir = archive_string_conversion_from_charset_safe(
                    &mut safe_a.archive,
                    charset,
                    1 as libc::c_int,
                );
                lha.sconv_fname = archive_string_conversion_from_charset_safe(
                    &mut safe_a.archive,
                    charset,
                    1 as libc::c_int,
                );
                archive_string_free_safe(&mut cp);
                if lha.sconv_dir.is_null() {
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
                }
                if lha.sconv_fname.is_null() {
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
                }
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_unix_mode {
            if datasize == ::std::mem::size_of::<uint16_t>() as libc::c_ulong {
                lha.mode = archive_le16dec(extdheader as *const libc::c_void) as mode_t;
                lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.unix_mode_is_set
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_unix_gid_uid {
            if datasize
                == (::std::mem::size_of::<uint16_t>() as libc::c_ulong)
                    .wrapping_mul(2 as libc::c_int as libc::c_ulong)
            {
                lha.gid = archive_le16dec(extdheader as *const libc::c_void) as int64_t;
                lha.uid =
                    archive_le16dec(unsafe { extdheader.offset(2 as libc::c_int as isize) }
                        as *const libc::c_void) as int64_t
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_unix_gname {
            if datasize > 0 as libc::c_int as libc::c_ulong {
                lha.gname.length = 0 as libc::c_int as size_t;
                archive_strncat_safe(
                    &mut lha.gname,
                    extdheader as *const libc::c_char as *const libc::c_void,
                    datasize,
                );
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_unix_uname {
            if datasize > 0 as libc::c_int as libc::c_ulong {
                lha.uname.length = 0 as libc::c_int as size_t;
                archive_strncat_safe(
                    &mut lha.uname,
                    extdheader as *const libc::c_char as *const libc::c_void,
                    datasize,
                );
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_unix_mtime {
            if datasize == ::std::mem::size_of::<uint32_t>() as libc::c_ulong {
                lha.mtime = archive_le32dec(extdheader as *const libc::c_void) as time_t
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_os2_new_attr {
            /* This extended header is OS/2 depend. */
            if datasize == 16 as libc::c_int as libc::c_ulong {
                lha.dos_attr = (archive_le16dec(extdheader as *const libc::c_void) as libc::c_int
                    & 0xff as libc::c_int) as libc::c_uchar;
                lha.mode =
                    archive_le16dec(unsafe { extdheader.offset(2 as libc::c_int as isize) }
                        as *const libc::c_void) as mode_t;
                lha.gid =
                    archive_le16dec(unsafe { extdheader.offset(4 as libc::c_int as isize) }
                        as *const libc::c_void) as int64_t;
                lha.uid =
                    archive_le16dec(unsafe { extdheader.offset(6 as libc::c_int as isize) }
                        as *const libc::c_void) as int64_t;
                lha.birthtime =
                    archive_le32dec(unsafe { extdheader.offset(8 as libc::c_int as isize) }
                        as *const libc::c_void) as time_t;
                lha.atime =
                    archive_le32dec(unsafe { extdheader.offset(12 as libc::c_int as isize) }
                        as *const libc::c_void) as time_t;
                lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.unix_mode_is_set
                    | ARCHIVE_LHA_DEFINED_PARAM.birthtime_is_set
                    | ARCHIVE_LHA_DEFINED_PARAM.atime_is_set
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_new_attr {
            if datasize == 20 as libc::c_int as libc::c_ulong {
                lha.mode = archive_le32dec(extdheader as *const libc::c_void);
                lha.gid =
                    archive_le32dec(unsafe { extdheader.offset(4 as libc::c_int as isize) }
                        as *const libc::c_void) as int64_t;
                lha.uid =
                    archive_le32dec(unsafe { extdheader.offset(8 as libc::c_int as isize) }
                        as *const libc::c_void) as int64_t;
                lha.birthtime =
                    archive_le32dec(unsafe { extdheader.offset(12 as libc::c_int as isize) }
                        as *const libc::c_void) as time_t;
                lha.atime =
                    archive_le32dec(unsafe { extdheader.offset(16 as libc::c_int as isize) }
                        as *const libc::c_void) as time_t;
                lha.setflag |= ARCHIVE_LHA_DEFINED_PARAM.unix_mode_is_set
                    | ARCHIVE_LHA_DEFINED_PARAM.birthtime_is_set
                    | ARCHIVE_LHA_DEFINED_PARAM.atime_is_set
            }
        } else if extdtype as libc::c_int == ARCHIVE_LHA_DEFINED_PARAM.ext_timezone {
        }
        /* Not supported */
        __archive_read_consume_safe(a, extdsize as int64_t);
    }
    /* invalid directory data */
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
        b"Invalid extended LHa header\x00" as *const u8 as *const libc::c_char
    );
    return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
}

unsafe extern "C" fn lha_end_of_entry(mut a: *mut archive_read) -> libc::c_int {
    let mut lha = unsafe { &mut *((*(*a).format).data as *mut lha) };
    let mut r: libc::c_int = ARCHIVE_LHA_DEFINED_PARAM.archive_eof;
    if lha.end_of_entry_cleanup == 0 {
        if lha.setflag & ARCHIVE_LHA_DEFINED_PARAM.crc_is_set != 0
            && lha.crc as libc::c_int != lha.entry_crc_calculated as libc::c_int
        {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_LHA_DEFINED_PARAM.archive_errno_misc,
                b"LHa data CRC error\x00" as *const u8 as *const libc::c_char
            );
            r = ARCHIVE_LHA_DEFINED_PARAM.archive_warn
        }
        /* End-of-entry cleanup done. */
        lha.end_of_entry_cleanup = 1 as libc::c_int as libc::c_char
    }
    return r;
}

unsafe extern "C" fn archive_read_format_lha_read_data(
    mut a: *mut archive_read,
    mut buff: *mut *const libc::c_void,
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) -> libc::c_int {
    let safe_a = unsafe { &mut *a };
    let safe_buff = unsafe { &mut *buff };
    let safe_size = unsafe { &mut *size };
    let safe_offset = unsafe { &mut *offset };
    let mut lha = unsafe { &mut *((*safe_a.format).data as *mut lha) };
    let mut r: libc::c_int = 0;
    if lha.entry_unconsumed != 0 {
        /* Consume as much as the decompressor actually used. */
        __archive_read_consume_safe(a, lha.entry_unconsumed);
        lha.entry_unconsumed = 0 as libc::c_int as int64_t
    }
    if lha.end_of_entry != 0 {
        *safe_offset = lha.entry_offset;
        *safe_size = 0 as libc::c_int as size_t;
        *safe_buff = 0 as *const libc::c_void;
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
unsafe extern "C" fn lha_read_data_none(
    mut a: &mut archive_read,
    mut buff: &mut *const libc::c_void,
    mut size: &mut size_t,
    mut offset: &mut int64_t,
) -> libc::c_int {
    let mut lha = unsafe { &mut *((*a.format).data as *mut lha) };
    let mut bytes_avail: ssize_t = 0;
    if lha.entry_bytes_remaining == 0 as libc::c_int as libc::c_long {
        *buff = 0 as *const libc::c_void;
        *size = 0 as libc::c_int as size_t;
        *offset = lha.entry_offset;
        lha.end_of_entry = 1 as libc::c_int as libc::c_char;
        return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
    }
    /*
     * Note: '1' here is a performance optimization.
     * Recall that the decompression layer returns a count of
     * available bytes; asking for more than that forces the
     * decompressor to combine reads by copying data.
     */
    *buff = __archive_read_ahead_safe(a, 1 as libc::c_int as size_t, &mut bytes_avail);
    if bytes_avail <= 0 as libc::c_int as libc::c_long {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Truncated LHa file data\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    if bytes_avail > lha.entry_bytes_remaining {
        bytes_avail = lha.entry_bytes_remaining
    }
    lha.entry_crc_calculated = lha_crc16(lha.entry_crc_calculated, *buff, bytes_avail as size_t);
    *size = bytes_avail as size_t;
    *offset = lha.entry_offset;
    lha.entry_offset += bytes_avail;
    lha.entry_bytes_remaining -= bytes_avail;
    if lha.entry_bytes_remaining == 0 as libc::c_int as libc::c_long {
        lha.end_of_entry = 1 as libc::c_int as libc::c_char
    }
    lha.entry_unconsumed = bytes_avail;
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

/*
* Read a file content in LZHUFF encoding.
*
* Returns ARCHIVE_OK if successful, returns ARCHIVE_WARN if compression is
* unsupported, ARCHIVE_FATAL otherwise, sets lha->end_of_entry if it consumes
* all of the data.
*/
unsafe extern "C" fn lha_read_data_lzh(
    mut a: &mut archive_read,
    mut buff: &mut *const libc::c_void,
    mut size: &mut size_t,
    mut offset: &mut int64_t,
) -> libc::c_int {
    let mut lha = unsafe { &mut *((*a.format).data as *mut lha) };
    let mut bytes_avail: ssize_t = 0;
    let mut r: libc::c_int = 0;
    /* If we haven't yet read any data, initialize the decompressor. */
    if lha.decompress_init == 0 {
        r = lzh_decode_init(&mut lha.strm, lha.method.as_mut_ptr());
        if r == ARCHIVE_LHA_DEFINED_PARAM.archive_ok {
        } else if r == ARCHIVE_LHA_DEFINED_PARAM.archive_failed {
            /* Unsupported compression. */
            *buff = 0 as *const libc::c_void;
            *size = 0 as libc::c_int as size_t;
            *offset = 0 as libc::c_int as int64_t;
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
                b"Unsupported lzh compression method -%c%c%c-\x00" as *const u8
                    as *const libc::c_char,
                lha.method[0 as libc::c_int as usize] as libc::c_int,
                lha.method[1 as libc::c_int as usize] as libc::c_int,
                lha.method[2 as libc::c_int as usize] as libc::c_int
            );
            /* We know compressed size; just skip it. */
            archive_read_format_lha_read_data_skip(a);
            return ARCHIVE_LHA_DEFINED_PARAM.archive_warn;
        } else {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_LHA_DEFINED_PARAM.enomem,
                b"Couldn\'t allocate memory for lzh decompression\x00" as *const u8
                    as *const libc::c_char
            );
            return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
        }
        /* We've initialized decompression for this stream. */
        lha.decompress_init = 1 as libc::c_int as libc::c_char;
        lha.strm.avail_out = 0 as libc::c_int;
        lha.strm.total_out = 0 as libc::c_int as int64_t
    }
    /*
     * Note: '1' here is a performance optimization.
     * Recall that the decompression layer returns a count of
     * available bytes; asking for more than that forces the
     * decompressor to combine reads by copying data.
     */
    lha.strm.next_in = __archive_read_ahead_safe(a, 1 as libc::c_int as size_t, &mut bytes_avail)
        as *const libc::c_uchar;
    if bytes_avail <= 0 as libc::c_int as libc::c_long {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_file_format,
            b"Truncated LHa file body\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    if bytes_avail > lha.entry_bytes_remaining {
        bytes_avail = lha.entry_bytes_remaining
    }
    lha.strm.avail_in = bytes_avail as libc::c_int;
    lha.strm.total_in = 0 as libc::c_int as int64_t;
    lha.strm.avail_out = 0 as libc::c_int;
    r = lzh_decode(
        &mut lha.strm,
        (bytes_avail == lha.entry_bytes_remaining) as libc::c_int,
    );
    if r == ARCHIVE_LHA_DEFINED_PARAM.archive_ok {
    } else if r == ARCHIVE_LHA_DEFINED_PARAM.archive_eof {
        lha.end_of_entry = 1 as libc::c_int as libc::c_char
    } else {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_LHA_DEFINED_PARAM.archive_errno_misc,
            b"Bad lzh data\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
    }
    lha.entry_unconsumed = lha.strm.total_in;
    lha.entry_bytes_remaining -= lha.strm.total_in;
    if lha.strm.avail_out != 0 {
        *offset = lha.entry_offset;
        *size = lha.strm.avail_out as size_t;
        *buff = lha.strm.ref_ptr as *const libc::c_void;
        lha.entry_crc_calculated = lha_crc16(lha.entry_crc_calculated, *buff, *size);
        lha.entry_offset =
            (lha.entry_offset as libc::c_ulong).wrapping_add(*size) as int64_t as int64_t
    } else {
        *offset = lha.entry_offset;
        *size = 0 as libc::c_int as size_t;
        *buff = 0 as *const libc::c_void;
        if lha.end_of_entry != 0 {
            return lha_end_of_entry(a);
        }
    }
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

/*
 * Skip a file content.
 */
unsafe extern "C" fn archive_read_format_lha_read_data_skip(
    mut a: *mut archive_read,
) -> libc::c_int {
    let mut lha = unsafe { &mut *((*(*a).format).data as *mut lha) };
    let mut bytes_skipped: int64_t = 0;
    if lha.entry_unconsumed != 0 {
        /* Consume as much as the decompressor actually used. */
        __archive_read_consume_safe(a, lha.entry_unconsumed);
        lha.entry_unconsumed = 0 as libc::c_int as int64_t
    }
    /* if we've already read to end of data, we're done. */
    if lha.end_of_entry_cleanup != 0 {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
    }
    /*
     * If the length is at the beginning, we can skip the
     * compressed data much more quickly.
     */
    bytes_skipped = __archive_read_consume_safe(a, lha.entry_bytes_remaining);
    if bytes_skipped < 0 as libc::c_int as libc::c_long {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    /* This entry is finished and done. */
    lha.end_of_entry = 1 as libc::c_int as libc::c_char;
    lha.end_of_entry_cleanup = lha.end_of_entry;
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

unsafe extern "C" fn archive_read_format_lha_cleanup(mut a: *mut archive_read) -> libc::c_int {
    let safe_a_format = unsafe { &mut *(*a).format };
    let mut lha = unsafe { &mut *((*(*a).format).data as *mut lha) };
    lzh_decode_free(&mut lha.strm);
    archive_string_free_safe(&mut lha.dirname);
    archive_string_free_safe(&mut lha.filename);
    archive_string_free_safe(&mut lha.uname);
    archive_string_free_safe(&mut lha.gname);
    archive_wstring_free_safe(&mut lha.ws);
    free_safe(lha as *mut lha as *mut libc::c_void);
    safe_a_format.data = 0 as *mut libc::c_void;
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
unsafe extern "C" fn lha_parse_linkname(
    mut linkname: &mut archive_wstring,
    mut pathname: &mut archive_wstring,
) -> libc::c_int {
    let mut linkptr = unsafe { &mut *wcschr_safe(pathname.s, '|' as wchar_t) };
    let mut symlen: size_t = 0;
    if !(linkptr as *mut wchar_t).is_null() {
        symlen =
            wcslen_safe(unsafe { (linkptr as *mut wchar_t).offset(1 as libc::c_int as isize) });
        linkname.length = 0 as libc::c_int as size_t;
        archive_wstrncat_safe(
            linkname,
            unsafe { (linkptr as *mut wchar_t).offset(1 as libc::c_int as isize) },
            symlen,
        );
        *linkptr = 0 as wchar_t;
        pathname.length = wcslen_safe(pathname.s);
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}

/* Convert an MSDOS-style date/time into Unix-style time. */
unsafe extern "C" fn lha_dos_time(mut p: *const libc::c_uchar) -> time_t {
    let mut msTime: libc::c_int = 0; /* Years since 1900. */
    let mut msDate: libc::c_int = 0; /* Month number.     */
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
        tm_zone: 0 as *const libc::c_char,
    }; /* Day of month.     */
    msTime = archive_le16dec(p as *const libc::c_void) as libc::c_int;
    msDate = archive_le16dec(unsafe { p.offset(2 as libc::c_int as isize) } as *const libc::c_void)
        as libc::c_int;
    memset_safe(
        &mut ts as *mut tm as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<tm>() as libc::c_ulong,
    );
    ts.tm_year = (msDate >> 9 as libc::c_int & 0x7f as libc::c_int) + 80 as libc::c_int;
    ts.tm_mon = (msDate >> 5 as libc::c_int & 0xf as libc::c_int) - 1 as libc::c_int;
    ts.tm_mday = msDate & 0x1f as libc::c_int;
    ts.tm_hour = msTime >> 11 as libc::c_int & 0x1f as libc::c_int;
    ts.tm_min = msTime >> 5 as libc::c_int & 0x3f as libc::c_int;
    ts.tm_sec = msTime << 1 as libc::c_int & 0x3e as libc::c_int;
    ts.tm_isdst = -(1 as libc::c_int);
    return mktime_safe(&mut ts);
}

/* Convert an MS-Windows-style date/time into Unix-style time. */
unsafe extern "C" fn lha_win_time(mut wintime: uint64_t, mut ns: &mut libc::c_long) -> time_t {
    if wintime as libc::c_ulonglong >= ARCHIVE_LHA_DEFINED_PARAM.epoc_time {
        wintime = (wintime as libc::c_ulonglong).wrapping_sub(ARCHIVE_LHA_DEFINED_PARAM.epoc_time)
            as uint64_t as uint64_t; /* 1970-01-01 00:00:00 (UTC) */
        if !(ns as *mut libc::c_long).is_null() {
            *ns = wintime.wrapping_rem(10000000 as libc::c_int as libc::c_ulong) as libc::c_long
                * 100 as libc::c_int as libc::c_long
        }
        return wintime.wrapping_div(10000000 as libc::c_int as libc::c_ulong) as time_t;
    } else {
        if !(ns as *mut libc::c_long).is_null() {
            *ns = 0 as libc::c_int as libc::c_long
        }
        return 0 as libc::c_int as time_t;
    };
}

unsafe extern "C" fn lha_calcsum(
    mut sum: libc::c_uchar,
    mut pp: *const libc::c_void,
    mut offset: libc::c_int,
    mut size: size_t,
) -> libc::c_uchar {
    let mut p: *const libc::c_uchar = pp as *const libc::c_uchar;
    p = unsafe { p.offset(offset as isize) };
    while size > 0 as libc::c_int as libc::c_ulong {
        let fresh0 = unsafe { &*p };
        p = unsafe { p.offset(1) };
        sum = (sum as libc::c_int + *fresh0 as libc::c_int) as libc::c_uchar;
        size = size.wrapping_sub(1)
    }
    return sum;
}

static mut crc16tbl: [[uint16_t; 256]; 2] = [[0; 256]; 2];

unsafe extern "C" fn lha_crc16_init() {
    let mut i: libc::c_uint = 0;
    let mut crc16init: libc::c_int = 0 as libc::c_int;
    if crc16init != 0 {
        return;
    }
    crc16init = 1 as libc::c_int;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        let mut j: libc::c_uint = 0;
        let mut crc: uint16_t = i as uint16_t;
        j = 8 as libc::c_int as libc::c_uint;
        while j != 0 {
            crc = (crc as libc::c_int >> 1 as libc::c_int
                ^ (crc as libc::c_int & 1 as libc::c_int) * 0xa001 as libc::c_int)
                as uint16_t;
            j = j.wrapping_sub(1)
        }
        unsafe {
            crc16tbl[0 as libc::c_int as usize][i as usize] = crc;
        }
        i = i.wrapping_add(1)
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < 256 as libc::c_int as libc::c_uint {
        unsafe {
            crc16tbl[1 as libc::c_int as usize][i as usize] =
                (crc16tbl[0 as libc::c_int as usize][i as usize] as libc::c_int >> 8 as libc::c_int
                    ^ crc16tbl[0 as libc::c_int as usize][(crc16tbl[0 as libc::c_int as usize]
                        [i as usize]
                        as libc::c_int
                        & 0xff as libc::c_int)
                        as usize] as libc::c_int) as uint16_t;
        }
        i = i.wrapping_add(1)
    }
}

unsafe extern "C" fn lha_crc16(
    mut crc: uint16_t,
    mut pp: *const libc::c_void,
    mut len: size_t,
) -> uint16_t {
    let mut p: *const libc::c_uchar = pp as *const libc::c_uchar;
    let mut buff: *const uint16_t = 0 as *const uint16_t;
    let u: archive_temporary_u = archive_temporary_u {
        i: 0x1020304 as libc::c_int as uint32_t,
    };
    if len == 0 as libc::c_int as libc::c_ulong {
        return crc;
    }
    /* Process unaligned address. */
    if p as uintptr_t & 0x1 as libc::c_int as uintptr_t != 0 {
        let fresh1 = p;
        unsafe { p = p.offset(1) };
        crc = (crc as libc::c_int >> 8 as libc::c_int
            ^ unsafe { crc16tbl[0 as libc::c_int as usize] }[((crc as libc::c_int
                ^ unsafe { *fresh1 } as libc::c_int)
                & 0xff as libc::c_int)
                as usize] as libc::c_int) as uint16_t;
        len = len.wrapping_sub(1)
    }
    buff = p as *const uint16_t;
    /*
     * Modern C compiler such as GCC does not unroll automatically yet
     * without unrolling pragma, and Clang is so. So we should
     * unroll this loop for its performance.
     */
    while len >= 8 as libc::c_int as libc::c_ulong {
        /* This if statement expects compiler optimization will
         * remove the statement which will not be executed. */
        /* Visual Studio */
        /* All clang versions have __builtin_bswap16() */
        /* Big endian */
        if unsafe { u.c[0 as libc::c_int as usize] } as libc::c_int == 1 as libc::c_int {
            crc = (crc as libc::c_int ^ unsafe { (*buff) }.swap_bytes() as libc::c_int) as uint16_t;
            unsafe { buff = buff.offset(1) }
        } else {
            let fresh2 = buff;
            unsafe {
                buff = buff.offset(1);
            }
            crc = (crc as libc::c_int ^ unsafe { *fresh2 } as libc::c_int) as uint16_t
        }
        crc = (unsafe {
            crc16tbl[1 as libc::c_int as usize][(crc as libc::c_int & 0xff as libc::c_int) as usize]
        } as libc::c_int
            ^ unsafe {
                crc16tbl[0 as libc::c_int as usize]
                    [(crc as libc::c_int >> 8 as libc::c_int) as usize]
            } as libc::c_int) as uint16_t;
        if unsafe { u.c[0 as libc::c_int as usize] } as libc::c_int == 1 as libc::c_int {
            crc = (crc as libc::c_int ^ unsafe { (*buff) }.swap_bytes() as libc::c_int) as uint16_t;
            unsafe { buff = buff.offset(1) }
        } else {
            let fresh3 = buff;
            unsafe {
                buff = buff.offset(1);
            }
            crc = (crc as libc::c_int ^ unsafe { *fresh3 } as libc::c_int) as uint16_t
        }
        crc = (unsafe {
            crc16tbl[1 as libc::c_int as usize][(crc as libc::c_int & 0xff as libc::c_int) as usize]
        } as libc::c_int
            ^ unsafe {
                crc16tbl[0 as libc::c_int as usize]
                    [(crc as libc::c_int >> 8 as libc::c_int) as usize]
            } as libc::c_int) as uint16_t;
        if unsafe { u.c[0 as libc::c_int as usize] } as libc::c_int == 1 as libc::c_int {
            crc = (crc as libc::c_int ^ unsafe { (*buff) }.swap_bytes() as libc::c_int) as uint16_t;
            unsafe { buff = buff.offset(1) }
        } else {
            let fresh4 = buff;
            unsafe {
                buff = buff.offset(1);
            }
            crc = (crc as libc::c_int ^ unsafe { *fresh4 } as libc::c_int) as uint16_t
        }
        crc = (unsafe {
            crc16tbl[1 as libc::c_int as usize][(crc as libc::c_int & 0xff as libc::c_int) as usize]
        } as libc::c_int
            ^ unsafe {
                crc16tbl[0 as libc::c_int as usize]
                    [(crc as libc::c_int >> 8 as libc::c_int) as usize]
            } as libc::c_int) as uint16_t;
        if unsafe { u.c[0 as libc::c_int as usize] } as libc::c_int == 1 as libc::c_int {
            crc = (crc as libc::c_int ^ unsafe { (*buff) }.swap_bytes() as libc::c_int) as uint16_t;
            unsafe { buff = buff.offset(1) }
        } else {
            let fresh5 = buff;
            unsafe {
                buff = buff.offset(1);
            }
            crc = (crc as libc::c_int ^ unsafe { *fresh5 } as libc::c_int) as uint16_t
        }
        crc = (unsafe {
            crc16tbl[1 as libc::c_int as usize][(crc as libc::c_int & 0xff as libc::c_int) as usize]
        } as libc::c_int
            ^ unsafe {
                crc16tbl[0 as libc::c_int as usize]
                    [(crc as libc::c_int >> 8 as libc::c_int) as usize]
            } as libc::c_int) as uint16_t;
        len = (len as libc::c_ulong).wrapping_sub(8 as libc::c_int as libc::c_ulong) as size_t
            as size_t
    }
    p = buff as *const libc::c_uchar;
    while len != 0 {
        let fresh6 = p;
        unsafe {
            p = p.offset(1);
        }
        crc = (crc as libc::c_int >> 8 as libc::c_int
            ^ unsafe {
                crc16tbl[0 as libc::c_int as usize][((crc as libc::c_int
                    ^ unsafe { *fresh6 } as libc::c_int)
                    & 0xff as libc::c_int)
                    as usize]
            } as libc::c_int) as uint16_t;
        len = len.wrapping_sub(1)
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
unsafe extern "C" fn lzh_decode_init(
    mut strm: &mut lzh_stream,
    mut method: *const libc::c_char,
) -> libc::c_int {
    let mut w_bits: libc::c_int = 0;
    let mut w_size: libc::c_int = 0;
    if strm.ds.is_null() {
        strm.ds = calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<lzh_dec>() as libc::c_ulong,
        ) as *mut lzh_dec;
        if strm.ds.is_null() {
            return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
        }
    }
    let ds = unsafe { &mut *strm.ds };
    ds.error = ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
    if method.is_null()
        || unsafe { *method.offset(0 as libc::c_int as isize) } as libc::c_int != 'l' as i32
        || unsafe { *method.offset(1 as libc::c_int as isize) } as libc::c_int != 'h' as i32
    {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
    }
    match unsafe { *method.offset(2 as libc::c_int as isize) } as libc::c_int {
        53 => {
            w_bits = 13 as libc::c_int
            /* Not supported. */
        }
        54 => w_bits = 15 as libc::c_int,
        55 => {
            /* 32KiB for window */
            w_bits = 16 as libc::c_int
        }
        _ => return ARCHIVE_LHA_DEFINED_PARAM.archive_failed,
    } /* 64KiB for window */
    ds.error = ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    /* Expand a window size up to 128 KiB for decompressing process
     * performance whatever its original window size is. */
    ds.w_size = ((1 as libc::c_uint) << 17 as libc::c_int) as libc::c_int;
    ds.w_mask = ds.w_size - 1 as libc::c_int;
    if ds.w_buff.is_null() {
        ds.w_buff = malloc_safe(ds.w_size as libc::c_ulong) as *mut libc::c_uchar;
        if ds.w_buff.is_null() {
            return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
        }
    }
    w_size = ((1 as libc::c_uint) << w_bits) as libc::c_int;
    memset_safe(
        unsafe {
            ds.w_buff
                .offset(ds.w_size as isize)
                .offset(-(w_size as isize))
        } as *mut libc::c_void,
        0x20 as libc::c_int,
        w_size as libc::c_ulong,
    );
    ds.w_pos = 0 as libc::c_int;
    ds.state = 0 as libc::c_int;
    ds.pos_pt_len_size = w_bits + 1 as libc::c_int;
    ds.pos_pt_len_bits = if w_bits == 15 as libc::c_int || w_bits == 16 as libc::c_int {
        5 as libc::c_int
    } else {
        4 as libc::c_int
    };
    ds.literal_pt_len_size = ARCHIVE_LHA_DEFINED_PARAM.pt_bitlen_size;
    ds.literal_pt_len_bits = 5 as libc::c_int;
    ds.br.cache_buffer = 0 as libc::c_int as uint64_t;
    ds.br.cache_avail = 0 as libc::c_int;
    if lzh_huffman_init(
        &mut ds.lt,
        ARCHIVE_LHA_DEFINED_PARAM.lt_bitlen_size as size_t,
        16 as libc::c_int,
    ) != ARCHIVE_LHA_DEFINED_PARAM.archive_ok
    {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    ds.lt.len_bits = 9 as libc::c_int;
    if lzh_huffman_init(
        &mut ds.pt,
        ARCHIVE_LHA_DEFINED_PARAM.pt_bitlen_size as size_t,
        16 as libc::c_int,
    ) != ARCHIVE_LHA_DEFINED_PARAM.archive_ok
    {
        return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
    }
    ds.error = 0 as libc::c_int;
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

/*
 * Release LZHUF decoder.
 */
unsafe extern "C" fn lzh_decode_free(mut strm: &mut lzh_stream) {
    if strm.ds.is_null() {
        return;
    }
    let mut ds = unsafe { &mut *strm.ds };
    free_safe(ds.w_buff as *mut libc::c_void);
    lzh_huffman_free(&mut ds.lt);
    lzh_huffman_free(&mut ds.pt);
    free_safe(strm.ds as *mut libc::c_void);
    strm.ds = 0 as *mut lzh_dec;
}

/* Notify how many bits we consumed. */
static cache_masks: [uint16_t; 20] = [
    0 as libc::c_int as uint16_t,
    0x1 as libc::c_int as uint16_t,
    0x3 as libc::c_int as uint16_t,
    0x7 as libc::c_int as uint16_t,
    0xf as libc::c_int as uint16_t,
    0x1f as libc::c_int as uint16_t,
    0x3f as libc::c_int as uint16_t,
    0x7f as libc::c_int as uint16_t,
    0xff as libc::c_int as uint16_t,
    0x1ff as libc::c_int as uint16_t,
    0x3ff as libc::c_int as uint16_t,
    0x7ff as libc::c_int as uint16_t,
    0xfff as libc::c_int as uint16_t,
    0x1fff as libc::c_int as uint16_t,
    0x3fff as libc::c_int as uint16_t,
    0x7fff as libc::c_int as uint16_t,
    0xffff as libc::c_int as uint16_t,
    0xffff as libc::c_int as uint16_t,
    0xffff as libc::c_int as uint16_t,
    0xffff as libc::c_int as uint16_t,
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
unsafe extern "C" fn lzh_br_fillup(mut strm: &mut lzh_stream, mut br: &mut lzh_br) -> libc::c_int {
    let mut n: libc::c_int = (ARCHIVE_LHA_DEFINED_PARAM.cache_bits as libc::c_ulong)
        .wrapping_sub(br.cache_avail as libc::c_ulong) as libc::c_int;
    loop {
        let x: libc::c_int = n >> 3 as libc::c_int;
        if strm.avail_in >= x {
            match x {
                8 => {
                    br.cache_buffer = (unsafe { *strm.next_in.offset(0 as libc::c_int as isize) }
                        as uint64_t)
                        << 56 as libc::c_int
                        | (unsafe { *strm.next_in.offset(1 as libc::c_int as isize) } as uint64_t)
                            << 48 as libc::c_int
                        | (unsafe { *strm.next_in.offset(2 as libc::c_int as isize) } as uint64_t)
                            << 40 as libc::c_int
                        | (unsafe { *strm.next_in.offset(3 as libc::c_int as isize) } as uint64_t)
                            << 32 as libc::c_int
                        | ((unsafe { *strm.next_in.offset(4 as libc::c_int as isize) } as uint32_t)
                            << 24 as libc::c_int) as libc::c_ulong
                        | ((unsafe { *strm.next_in.offset(5 as libc::c_int as isize) } as uint32_t)
                            << 16 as libc::c_int) as libc::c_ulong
                        | ((unsafe { *strm.next_in.offset(6 as libc::c_int as isize) } as uint32_t)
                            << 8 as libc::c_int) as libc::c_ulong
                        | unsafe { *strm.next_in.offset(7 as libc::c_int as isize) } as uint32_t
                            as libc::c_ulong;
                    strm.next_in = unsafe { strm.next_in.offset(8 as libc::c_int as isize) };
                    strm.avail_in -= 8 as libc::c_int;
                    br.cache_avail += 8 as libc::c_int * 8 as libc::c_int;
                    return 1 as libc::c_int;
                }
                7 => {
                    br.cache_buffer = br.cache_buffer << 56 as libc::c_int
                        | (unsafe { *strm.next_in.offset(0 as libc::c_int as isize) } as uint64_t)
                            << 48 as libc::c_int
                        | (unsafe { *strm.next_in.offset(1 as libc::c_int as isize) } as uint64_t)
                            << 40 as libc::c_int
                        | (unsafe { *strm.next_in.offset(2 as libc::c_int as isize) } as uint64_t)
                            << 32 as libc::c_int
                        | ((unsafe { *strm.next_in.offset(3 as libc::c_int as isize) } as uint32_t)
                            << 24 as libc::c_int) as libc::c_ulong
                        | ((unsafe { *strm.next_in.offset(4 as libc::c_int as isize) } as uint32_t)
                            << 16 as libc::c_int) as libc::c_ulong
                        | ((unsafe { *strm.next_in.offset(5 as libc::c_int as isize) } as uint32_t)
                            << 8 as libc::c_int) as libc::c_ulong
                        | unsafe { *strm.next_in.offset(6 as libc::c_int as isize) } as uint32_t
                            as libc::c_ulong;
                    strm.next_in = unsafe { strm.next_in.offset(7 as libc::c_int as isize) };
                    strm.avail_in -= 7 as libc::c_int;
                    br.cache_avail += 7 as libc::c_int * 8 as libc::c_int;
                    return 1 as libc::c_int;
                }
                6 => {
                    br.cache_buffer = br.cache_buffer << 48 as libc::c_int
                        | (unsafe { *strm.next_in.offset(0 as libc::c_int as isize) } as uint64_t)
                            << 40 as libc::c_int
                        | (unsafe { *strm.next_in.offset(1 as libc::c_int as isize) } as uint64_t)
                            << 32 as libc::c_int
                        | ((unsafe { *strm.next_in.offset(2 as libc::c_int as isize) } as uint32_t)
                            << 24 as libc::c_int) as libc::c_ulong
                        | ((unsafe { *strm.next_in.offset(3 as libc::c_int as isize) } as uint32_t)
                            << 16 as libc::c_int) as libc::c_ulong
                        | ((unsafe { *strm.next_in.offset(4 as libc::c_int as isize) } as uint32_t)
                            << 8 as libc::c_int) as libc::c_ulong
                        | unsafe { *strm.next_in.offset(5 as libc::c_int as isize) } as uint32_t
                            as libc::c_ulong;
                    strm.next_in = unsafe { strm.next_in.offset(6 as libc::c_int as isize) };
                    strm.avail_in -= 6 as libc::c_int;
                    br.cache_avail += 6 as libc::c_int * 8 as libc::c_int;
                    return 1 as libc::c_int;
                }
                0 => {
                    /* We have enough compressed data in
                     * the cache buffer.*/
                    return 1 as libc::c_int;
                }
                _ => {}
            }
        }
        if strm.avail_in == 0 as libc::c_int {
            /* There is not enough compressed data to fill up the
             * cache buffer. */
            return 0 as libc::c_int;
        }
        let fresh7 = unsafe { &*strm.next_in };
        strm.next_in = unsafe { strm.next_in.offset(1) };
        br.cache_buffer = br.cache_buffer << 8 as libc::c_int | *fresh7 as libc::c_ulong;
        strm.avail_in -= 1;
        br.cache_avail += 8 as libc::c_int;
        n -= 8 as libc::c_int
    }
}

unsafe extern "C" fn lzh_decode(mut strm: &mut lzh_stream, mut last: libc::c_int) -> libc::c_int {
    let mut ds = unsafe { &mut *strm.ds };
    let mut avail_in: libc::c_int = 0;
    let mut r: libc::c_int = 0;
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
        if !(r == 100 as libc::c_int) {
            break;
        }
    }
    strm.total_in += (avail_in - strm.avail_in) as libc::c_long;
    return r;
}

unsafe extern "C" fn lzh_emit_window(mut strm: &mut lzh_stream, mut s: size_t) {
    let strm_safe = unsafe { &mut *strm };
    let ds = unsafe { &mut *strm_safe.ds };
    strm_safe.ref_ptr = ds.w_buff;
    strm_safe.avail_out = s as libc::c_int;
    strm_safe.total_out = (strm_safe.total_out as libc::c_ulong).wrapping_add(s) as int64_t as int64_t;
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
unsafe extern "C" fn lzh_read_blocks(
    mut strm: &mut lzh_stream,
    mut last: libc::c_int,
) -> libc::c_int {
    let strm_safe = unsafe { &mut *strm };
    let mut current_block: u64;
    let mut ds = unsafe { &mut *strm.ds };
    let mut br = &mut ds.br;
    let mut c: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut rbits: libc::c_uint = 0;
    's_19: loop {
        if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_block {
            /*
             * Read a block number indicates how many blocks
             * we will handle. The block is composed of a
             * literal and a match, sometimes a literal only
             * in particular, there are no reference data at
             * the beginning of the decompression.
             */
            if !(br.cache_avail >= 16 as libc::c_int || lzh_br_fillup(strm_safe, br) != 0) {
                if last == 0 {
                    /* We need following data. */
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                }
                if br.cache_avail >= 8 as libc::c_int {
                    /*
                     * It seems there are extra bits.
                     *  1. Compressed data is broken.
                     *  2. `last' flag does not properly
                     *     set.
                     */
                    break;
                } else {
                    if ds.w_pos > 0 as libc::c_int {
                        lzh_emit_window(strm_safe, ds.w_pos as size_t);
                        ds.w_pos = 0 as libc::c_int;
                        return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                    }
                    /* End of compressed data; we have completely
                     * handled all compressed data. */
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_eof;
                }
            } else {
                ds.blocks_avail = (br.cache_buffer >> br.cache_avail - 16 as libc::c_int)
                    as uint16_t as libc::c_int
                    & cache_masks[16 as libc::c_int as usize] as libc::c_int;
                if ds.blocks_avail == 0 as libc::c_int {
                    break;
                }
                br.cache_avail -= 16 as libc::c_int;
                /*
                 * Read a literal table compressed in huffman
                 * coding.
                 */
                ds.pt.len_size = ds.literal_pt_len_size;
                ds.pt.len_bits = ds.literal_pt_len_bits;
                ds.reading_position = 0 as libc::c_int
            }
            current_block = 16334903743006538945;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_1 {
            current_block = 16334903743006538945;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_2 {
            current_block = 15806087812640832660;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_3 {
            current_block = 14809079967989167248;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_4 {
            current_block = 11402235509028400542;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_1 {
            current_block = 8266133950150071838;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_2 {
            current_block = 340123238355120661;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_3 {
            current_block = 4937514680701116003;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_rd_pos_data_1 {
            current_block = 16871217396860862036;
        } else if ds.state == ARCHIVE_LHA_DEFINED_PARAM.st_get_literal {
            return 100 as libc::c_int;
        } else {
            continue;
        }

        match current_block {
            16334903743006538945 =>
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
                    ds.pt.len_avail = (br.cache_buffer >> br.cache_avail - ds.pt.len_bits)
                        as uint16_t as libc::c_int
                        & cache_masks[ds.pt.len_bits as usize] as libc::c_int;
                    br.cache_avail -= ds.pt.len_bits
                }
                current_block = 15806087812640832660;
            }
            _ => {}
        }
        match current_block {
            15806087812640832660 =>
            /* FALL THROUGH */
            {
                if ds.pt.len_avail == 0 as libc::c_int {
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
                            ((br.cache_buffer >> br.cache_avail - len_bits) as uint16_t
                                as libc::c_int
                                & cache_masks[len_bits as usize] as libc::c_int)
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
                    ds.loop_0 = 0 as libc::c_int;
                    memset_safe(
                        ds.pt.freq.as_mut_ptr() as *mut libc::c_void,
                        0 as libc::c_int,
                        ::std::mem::size_of::<[libc::c_int; 17]>() as libc::c_ulong,
                    );
                    if ds.pt.len_avail < 3 as libc::c_int || ds.pt.len_size == ds.pos_pt_len_size {
                        ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_4;
                        continue;
                    }
                }
                current_block = 14809079967989167248;
            }
            _ => {}
        }
        match current_block {
            14809079967989167248 =>
            /* FALL THROUGH */
            {
                ds.loop_0 = lzh_read_pt_bitlen(strm_safe, ds.loop_0, 3 as libc::c_int); /* Invalid data. */
                if ds.loop_0 < 3 as libc::c_int {
                    if ds.loop_0 < 0 as libc::c_int || last != 0 {
                        break;
                    }
                    /* Not completed, get following data. */
                    ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_3;
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                } else if !(br.cache_avail >= 2 as libc::c_int
                    || lzh_br_fillup(strm_safe, br) != 0
                    || br.cache_avail >= 2 as libc::c_int)
                {
                    /* There are some null in bitlen of the literal. */
                    if last != 0 {
                        break; /* Truncated data. */
                    } /* Invalid data. */
                    ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_3;
                    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                } else {
                    c = (br.cache_buffer >> br.cache_avail - 2 as libc::c_int) as uint16_t
                        as libc::c_int
                        & cache_masks[2 as libc::c_int as usize] as libc::c_int;
                    br.cache_avail -= 2 as libc::c_int;
                    if c > ds.pt.len_avail - 3 as libc::c_int {
                        break;
                    }
                    i = 3 as libc::c_int;
                    loop {
                        let fresh8 = c;
                        c = c - 1;
                        if !(fresh8 > 0 as libc::c_int) {
                            break;
                        }
                        let fresh9 = i;
                        i = i + 1;
                        unsafe {
                            *ds.pt.bitlen.offset(fresh9 as isize) =
                                0 as libc::c_int as libc::c_uchar
                        }
                    }
                    ds.loop_0 = i
                }
                current_block = 11402235509028400542;
            }
            _ => {}
        }
        match current_block {
            11402235509028400542 =>
            /* FALL THROUGH */
            {
                ds.loop_0 = lzh_read_pt_bitlen(strm_safe, ds.loop_0, ds.pt.len_avail); /* Invalid data. */
                if ds.loop_0 < ds.pt.len_avail {
                    if ds.loop_0 < 0 as libc::c_int || last != 0 {
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
                current_block = 8266133950150071838;
            }
            _ => {}
        }
        match current_block {
            8266133950150071838 =>
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
                    ds.lt.len_avail = (br.cache_buffer >> br.cache_avail - ds.lt.len_bits)
                        as uint16_t as libc::c_int
                        & cache_masks[ds.lt.len_bits as usize] as libc::c_int;
                    br.cache_avail -= ds.lt.len_bits
                }
                current_block = 340123238355120661;
            }
            _ => {}
        }
        match current_block {
            340123238355120661 =>
            /* FALL THROUGH */
            {
                if ds.lt.len_avail == 0 as libc::c_int {
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
                            ((br.cache_buffer >> br.cache_avail - len_bits) as uint16_t
                                as libc::c_int
                                & cache_masks[len_bits as usize] as libc::c_int)
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
                    ds.loop_0 = 0 as libc::c_int;
                    memset_safe(
                        ds.lt.freq.as_mut_ptr() as *mut libc::c_void,
                        0 as libc::c_int,
                        ::std::mem::size_of::<[libc::c_int; 17]>() as libc::c_ulong,
                    );
                }
                current_block = 4937514680701116003;
            }
            _ => {}
        }
        match current_block {
            4937514680701116003 =>
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
                        rbits = ((br.cache_buffer >> br.cache_avail - ds.pt.max_bits) as uint16_t
                            as libc::c_int
                            & cache_masks[ds.pt.max_bits as usize] as libc::c_int)
                            as libc::c_uint;
                        c = lzh_decode_huffman(&mut ds.pt, rbits);
                        if c > 2 as libc::c_int {
                            /* Note: 'c' will never be more than
                             * eighteen since it's limited by
                             * PT_BITLEN_SIZE, which is being set
                             * to ds->pt.len_size through
                             * ds->literal_pt_len_size. */
                            br.cache_avail -=
                                unsafe { *ds.pt.bitlen.offset(c as isize) } as libc::c_int;
                            c -= 2 as libc::c_int;
                            ds.lt.freq[c as usize] += 1;
                            let fresh10 = i;
                            i = i + 1;
                            unsafe { *ds.lt.bitlen.offset(fresh10 as isize) = c as libc::c_uchar }
                        } else if c == 0 as libc::c_int {
                            br.cache_avail -=
                                unsafe { *ds.pt.bitlen.offset(c as isize) } as libc::c_int;
                            let fresh11 = i;
                            i = i + 1;
                            unsafe {
                                *ds.lt.bitlen.offset(fresh11 as isize) =
                                    0 as libc::c_int as libc::c_uchar
                            }
                        } else {
                            /* c == 1 or c == 2 */
                            let mut n: libc::c_int = if c == 1 as libc::c_int {
                                4 as libc::c_int
                            } else {
                                9 as libc::c_int
                            }; /* Invalid data */
                            if !(br.cache_avail
                                >= unsafe { *ds.pt.bitlen.offset(c as isize) } as libc::c_int + n
                                || lzh_br_fillup(strm_safe, br) != 0
                                || br.cache_avail
                                    >= unsafe { *ds.pt.bitlen.offset(c as isize) } as libc::c_int
                                        + n)
                            {
                                if last != 0 {
                                    break 's_19; /* Invalid data */
                                }
                                ds.loop_0 = i;
                                ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_literal_3;
                                return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
                            } else {
                                br.cache_avail -=
                                    unsafe { *ds.pt.bitlen.offset(c as isize) } as libc::c_int;
                                c = (br.cache_buffer >> br.cache_avail - n) as uint16_t
                                    as libc::c_int
                                    & cache_masks[n as usize] as libc::c_int;
                                br.cache_avail -= n;
                                c += if n == 4 as libc::c_int {
                                    3 as libc::c_int
                                } else {
                                    20 as libc::c_int
                                };
                                if i + c > ds.lt.len_avail {
                                    break 's_19;
                                }
                                memset_safe(
                                    unsafe { &mut *ds.lt.bitlen.offset(i as isize) }
                                        as *mut libc::c_uchar
                                        as *mut libc::c_void,
                                    0 as libc::c_int,
                                    c as libc::c_ulong,
                                );
                                i += c
                            }
                        }
                    }
                }
                if i > ds.lt.len_avail || lzh_make_huffman_table(&mut ds.lt) == 0 {
                    break;
                }
            }
            _ => {}
        }
        /* FALL THROUGH */
        /*
         * Read a position table compressed in huffman
         * coding.
         */
        ds.pt.len_size = ds.pos_pt_len_size;
        ds.pt.len_bits = ds.pos_pt_len_bits;
        ds.reading_position = 1 as libc::c_int;
        ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_pt_1
    }
    /* Truncated data. */
    ds.error = ARCHIVE_LHA_DEFINED_PARAM.archive_failed;
    return ds.error;
}

unsafe extern "C" fn lzh_decode_blocks(
    mut strm: &mut lzh_stream,
    mut last: libc::c_int,
) -> libc::c_int {
    let strm_safe = unsafe { &mut *strm };
    let mut current_block: u64;
    let mut ds = unsafe { &mut *strm.ds };
    let mut bre: lzh_br = ds.br;
    let mut lt = &mut ds.lt;
    let mut pt = &mut ds.pt;
    let mut w_buff: *mut libc::c_uchar = ds.w_buff;
    let mut lt_bitlen: *mut libc::c_uchar = lt.bitlen;
    let mut pt_bitlen: *mut libc::c_uchar = pt.bitlen;
    let mut blocks_avail: libc::c_int = ds.blocks_avail;
    let mut c: libc::c_int = 0 as libc::c_int;
    let mut copy_len: libc::c_int = ds.copy_len;
    let mut copy_pos: libc::c_int = ds.copy_pos;
    let mut w_pos: libc::c_int = ds.w_pos;
    let mut w_mask: libc::c_int = ds.w_mask;
    let mut w_size: libc::c_int = ds.w_size;
    let mut lt_max_bits: libc::c_int = lt.max_bits;
    let mut pt_max_bits: libc::c_int = pt.max_bits;
    let mut state: libc::c_int = ds.state;
    's_43: loop {
        if state == ARCHIVE_LHA_DEFINED_PARAM.st_get_literal {
            current_block = 2868539653012386629;
        } else if state == ARCHIVE_LHA_DEFINED_PARAM.st_get_pos_1 {
            current_block = 11885127744888120434;
        } else if state == ARCHIVE_LHA_DEFINED_PARAM.st_get_pos_2 {
            current_block = 2708592659331960804;
        } else if state == ARCHIVE_LHA_DEFINED_PARAM.st_copy_data {
            current_block = 7343950298149844727;
        } else {
            continue;
        }
        loop {
            match current_block {
                2868539653012386629 => {
                    if blocks_avail == 0 as libc::c_int {
                        /* We have decoded all blocks.
                         * Let's handle next blocks. */
                        ds.state = ARCHIVE_LHA_DEFINED_PARAM.st_rd_block;
                        ds.br = bre;
                        ds.blocks_avail = 0 as libc::c_int;
                        ds.w_pos = w_pos;
                        ds.copy_pos = 0 as libc::c_int;
                        return 100 as libc::c_int;
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
                            current_block = 13987783605104790504;
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
                            ((bre.cache_buffer << lt_max_bits - bre.cache_avail) as uint16_t
                                as libc::c_int
                                & cache_masks[lt_max_bits as usize] as libc::c_int)
                                as libc::c_uint,
                        );
                        bre.cache_avail -= unsafe { *lt_bitlen.offset(c as isize) } as libc::c_int;
                        if !(bre.cache_avail >= 0 as libc::c_int) {
                            current_block = 5132186702048523172;
                            break 's_43;
                        }
                    } else {
                        c = lzh_decode_huffman(
                            lt,
                            ((bre.cache_buffer >> bre.cache_avail - lt_max_bits) as uint16_t
                                as libc::c_int
                                & cache_masks[lt_max_bits as usize] as libc::c_int)
                                as libc::c_uint,
                        );
                        bre.cache_avail -= unsafe { *lt_bitlen.offset(c as isize) } as libc::c_int
                    }
                    blocks_avail -= 1;
                    if c > ARCHIVE_LHA_DEFINED_PARAM.uchar_max {
                        /* Current block is a match data. */
                        /* 'c' is the length of a match pattern we have
                         * already extracted, which has be stored in
                         * window(ds->w_buff). */
                        copy_len = c - (ARCHIVE_LHA_DEFINED_PARAM.uchar_max + 1 as libc::c_int)
                            + ARCHIVE_LHA_DEFINED_PARAM.minmatch;
                        /* FALL THROUGH */
                        current_block = 11885127744888120434;
                    } else {
                        /*
                         * 'c' is exactly a literal code.
                         */
                        /* Save a decoded code to reference it
                         * afterward. */
                        unsafe {
                            *w_buff.offset(w_pos as isize) = c as libc::c_uchar;
                        }
                        w_pos += 1;
                        if !(w_pos >= w_size) {
                            current_block = 2868539653012386629;
                            continue;
                        }
                        w_pos = 0 as libc::c_int;
                        lzh_emit_window(strm_safe, w_size as size_t);
                        current_block = 13987783605104790504;
                        break 's_43;
                    }
                }
                2708592659331960804 =>
                /* FALL THROUGH */
                {
                    if copy_pos > 1 as libc::c_int {
                        /* We need an additional adjustment number to
                         * the position. */
                        let mut p: libc::c_int = copy_pos - 1 as libc::c_int; /* Truncated data.*/
                        if !(bre.cache_avail >= p
                            || lzh_br_fillup(strm_safe, &mut bre) != 0
                            || bre.cache_avail >= p)
                        {
                            if last != 0 {
                                current_block = 5132186702048523172;
                                break 's_43;
                            }
                            state = ARCHIVE_LHA_DEFINED_PARAM.st_get_pos_2;
                            ds.copy_len = copy_len;
                            ds.copy_pos = copy_pos;
                            current_block = 13987783605104790504;
                            break 's_43;
                        } else {
                            copy_pos = ((1 as libc::c_int) << p)
                                + ((bre.cache_buffer >> bre.cache_avail - p) as uint16_t
                                    as libc::c_int
                                    & cache_masks[p as usize] as libc::c_int);
                            bre.cache_avail -= p
                        }
                    }
                    /* The position is actually a distance from the last
                     * code we had extracted and thus we have to convert
                     * it to a position of the window. */
                    copy_pos = w_pos - copy_pos - 1 as libc::c_int & w_mask;
                    /* FALL THROUGH */
                    current_block = 7343950298149844727;
                }
                11885127744888120434 =>
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
                            current_block = 13987783605104790504;
                            break 's_43;
                        } else {
                            copy_pos = lzh_decode_huffman(
                                pt,
                                ((bre.cache_buffer << pt_max_bits - bre.cache_avail) as uint16_t
                                    as libc::c_int
                                    & cache_masks[pt_max_bits as usize] as libc::c_int)
                                    as libc::c_uint,
                            );
                            bre.cache_avail -=
                                unsafe { *pt_bitlen.offset(copy_pos as isize) } as libc::c_int;
                            if !(bre.cache_avail >= 0 as libc::c_int) {
                                current_block = 5132186702048523172;
                                break 's_43;
                            } else {
                                current_block = 2708592659331960804;
                            }
                        }
                    /* Over read. */
                    } else {
                        copy_pos = lzh_decode_huffman(
                            pt,
                            ((bre.cache_buffer >> bre.cache_avail - pt_max_bits) as uint16_t
                                as libc::c_int
                                & cache_masks[pt_max_bits as usize] as libc::c_int)
                                as libc::c_uint,
                        );
                        bre.cache_avail -=
                            unsafe { *pt_bitlen.offset(copy_pos as isize) } as libc::c_int;
                        current_block = 2708592659331960804;
                    }
                }
                _ =>
                /*
                 * Copy `copy_len' bytes as extracted data from
                 * the window into the output buffer.
                 */
                {
                    let mut l: libc::c_int = 0;
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
                        memcpy_safe(
                            unsafe { w_buff.offset(w_pos as isize) } as *mut libc::c_void,
                            unsafe { w_buff.offset(copy_pos as isize) } as *const libc::c_void,
                            l as libc::c_ulong,
                        );
                    } else {
                        let mut s: *const libc::c_uchar = 0 as *const libc::c_uchar;
                        let mut d: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
                        let mut li: libc::c_int = 0;
                        d = unsafe { w_buff.offset(w_pos as isize) };
                        s = unsafe { w_buff.offset(copy_pos as isize) };
                        li = 0 as libc::c_int;
                        while li < l - 1 as libc::c_int {
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
                        w_pos = 0 as libc::c_int;
                        lzh_emit_window(strm_safe, w_size as size_t);
                        if copy_len <= l {
                            state = ARCHIVE_LHA_DEFINED_PARAM.st_get_literal
                        } else {
                            state = ARCHIVE_LHA_DEFINED_PARAM.st_copy_data;
                            ds.copy_len = copy_len - l;
                            ds.copy_pos = copy_pos + l & w_mask
                        }
                        current_block = 13987783605104790504;
                        break 's_43;
                    } else if copy_len <= l {
                        /* A copy of current pattern ended. */
                        state = ARCHIVE_LHA_DEFINED_PARAM.st_get_literal;
                        break;
                    } else {
                        copy_len -= l;
                        copy_pos = copy_pos + l & w_mask;
                        current_block = 7343950298149844727;
                    }
                }
            }
        }
    }
    match current_block {
        5132186702048523172 => {
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

unsafe extern "C" fn lzh_huffman_init(
    mut hf: &mut huffman,
    mut len_size: size_t,
    mut tbl_bits: libc::c_int,
) -> libc::c_int {
    let mut bits: libc::c_int = 0;
    if hf.bitlen.is_null() {
        hf.bitlen = malloc_safe(
            len_size.wrapping_mul(::std::mem::size_of::<libc::c_uchar>() as libc::c_ulong),
        ) as *mut libc::c_uchar;
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
        hf.tbl = malloc_safe(
            ((1 as libc::c_int as size_t) << bits)
                .wrapping_mul(::std::mem::size_of::<uint16_t>() as libc::c_ulong),
        ) as *mut uint16_t;
        if hf.tbl.is_null() {
            return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
        }
    }
    if hf.tree.is_null() && tbl_bits > ARCHIVE_LHA_DEFINED_PARAM.htbl_bits {
        hf.tree_avail =
            (1 as libc::c_int) << tbl_bits - ARCHIVE_LHA_DEFINED_PARAM.htbl_bits + 4 as libc::c_int;
        hf.tree = malloc_safe(
            (hf.tree_avail as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<htree_t>() as libc::c_ulong),
        ) as *mut htree_t;
        if hf.tree.is_null() {
            return ARCHIVE_LHA_DEFINED_PARAM.archive_fatal;
        }
    }
    hf.len_size = len_size as libc::c_int;
    hf.tbl_bits = tbl_bits;
    return ARCHIVE_LHA_DEFINED_PARAM.archive_ok;
}

unsafe extern "C" fn lzh_huffman_free(mut hf: &mut huffman) {
    free_safe(hf.bitlen as *mut libc::c_void);
    free_safe(hf.tbl as *mut libc::c_void);
    free_safe(hf.tree as *mut libc::c_void);
}

static bitlen_tbl: [libc::c_char; 1024] = [
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

unsafe extern "C" fn lzh_read_pt_bitlen(
    mut strm: &mut lzh_stream,
    mut start: libc::c_int,
    mut end: libc::c_int,
) -> libc::c_int {
    let mut ds = unsafe { &mut *strm.ds };
    let mut br = &mut ds.br;
    let mut c: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    i = start;
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
        if !(br.cache_avail >= 3 as libc::c_int
            || lzh_br_fillup(strm, br) != 0
            || br.cache_avail >= 3 as libc::c_int)
        {
            return i;
        }
        c = (br.cache_buffer >> br.cache_avail - 3 as libc::c_int) as uint16_t as libc::c_int
            & cache_masks[3 as libc::c_int as usize] as libc::c_int;
        if c == 7 as libc::c_int {
            if !(br.cache_avail >= 13 as libc::c_int
                || lzh_br_fillup(strm, br) != 0
                || br.cache_avail >= 13 as libc::c_int)
            {
                return i;
            }
            c = bitlen_tbl[((br.cache_buffer >> br.cache_avail - 13 as libc::c_int) as uint16_t
                as libc::c_int
                & cache_masks[13 as libc::c_int as usize] as libc::c_int
                & 0x3ff as libc::c_int) as usize] as libc::c_int;
            if c != 0 {
                br.cache_avail -= c - 3 as libc::c_int
            } else {
                return -(1 as libc::c_int);
            }
            /* Invalid data. */
        } else {
            br.cache_avail -= 3 as libc::c_int
        }
        let fresh12 = i;
        i = i + 1;
        unsafe { *ds.pt.bitlen.offset(fresh12 as isize) = c as libc::c_uchar };
        ds.pt.freq[c as usize] += 1
    }
    return i;
}

unsafe extern "C" fn lzh_make_fake_table(mut hf: &mut huffman, mut c: uint16_t) -> libc::c_int {
    if c as libc::c_int >= hf.len_size {
        return 0 as libc::c_int;
    }
    unsafe {
        *hf.tbl.offset(0 as libc::c_int as isize) = c;
    }
    hf.max_bits = 0 as libc::c_int;
    hf.shift_bits = 0 as libc::c_int;
    unsafe {
        *hf.bitlen
            .offset(*hf.tbl.offset(0 as libc::c_int as isize) as isize) =
            0 as libc::c_int as libc::c_uchar;
    }
    return 1 as libc::c_int;
}

/*
 * Make a huffman coding table.
 */
unsafe extern "C" fn lzh_make_huffman_table(mut hf: &mut huffman) -> libc::c_int {
    let mut tbl: *mut uint16_t = 0 as *mut uint16_t;
    let mut bitlen: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut bitptn: [libc::c_int; 17] = [0; 17];
    let mut weight: [libc::c_int; 17] = [0; 17];
    let mut i: libc::c_int = 0;
    let mut maxbits: libc::c_int = 0 as libc::c_int;
    let mut ptn: libc::c_int = 0;
    let mut tbl_size: libc::c_int = 0;
    let mut w: libc::c_int = 0;
    let mut diffbits: libc::c_int = 0;
    let mut len_avail: libc::c_int = 0;
    /*
     * Initialize bit patterns.
     */
    ptn = 0 as libc::c_int; /* Invalid */
    i = 1 as libc::c_int;
    w = (1 as libc::c_int) << 15 as libc::c_int;
    while i <= 16 as libc::c_int {
        bitptn[i as usize] = ptn;
        weight[i as usize] = w;
        if hf.freq[i as usize] != 0 {
            ptn += hf.freq[i as usize] * w;
            maxbits = i
        }
        i += 1;
        w >>= 1 as libc::c_int
    }
    if ptn != 0x10000 as libc::c_int || maxbits > hf.tbl_bits {
        return 0 as libc::c_int;
    }
    hf.max_bits = maxbits;
    /*
     * Cut out extra bits which we won't house in the table.
     * This preparation reduces the same calculation in the for-loop
     * making the table.
     */
    if maxbits < 16 as libc::c_int {
        let mut ebits: libc::c_int = 16 as libc::c_int - maxbits;
        i = 1 as libc::c_int;
        while i <= maxbits {
            bitptn[i as usize] >>= ebits;
            weight[i as usize] >>= ebits;
            i += 1
        }
    }
    if maxbits > ARCHIVE_LHA_DEFINED_PARAM.htbl_bits {
        let mut htbl_max: libc::c_uint = 0;
        let mut p: *mut uint16_t = 0 as *mut uint16_t;
        diffbits = maxbits - ARCHIVE_LHA_DEFINED_PARAM.htbl_bits;
        i = 1 as libc::c_int;
        while i <= ARCHIVE_LHA_DEFINED_PARAM.htbl_bits {
            bitptn[i as usize] >>= diffbits;
            weight[i as usize] >>= diffbits;
            i += 1
        }
        htbl_max = (bitptn[ARCHIVE_LHA_DEFINED_PARAM.htbl_bits as usize]
            + weight[ARCHIVE_LHA_DEFINED_PARAM.htbl_bits as usize]
                * hf.freq[ARCHIVE_LHA_DEFINED_PARAM.htbl_bits as usize])
            as libc::c_uint;
        p = unsafe { &mut *hf.tbl.offset(htbl_max as isize) } as *mut uint16_t;
        while p < unsafe {
            &mut *hf
                .tbl
                .offset(((1 as libc::c_uint) << ARCHIVE_LHA_DEFINED_PARAM.htbl_bits) as isize)
        } as *mut uint16_t
        {
            let fresh13 = unsafe { &mut *p };
            unsafe {
                p = p.offset(1);
            }
            *fresh13 = 0 as libc::c_int as uint16_t
        }
    } else {
        diffbits = 0 as libc::c_int
    }
    hf.shift_bits = diffbits;
    /*
     * Make the table.
     */
    tbl_size = (1 as libc::c_int) << ARCHIVE_LHA_DEFINED_PARAM.htbl_bits;
    tbl = hf.tbl;
    bitlen = hf.bitlen;
    len_avail = hf.len_avail;
    hf.tree_used = 0 as libc::c_int;
    i = 0 as libc::c_int;
    while i < len_avail {
        let mut p_0: *mut uint16_t = 0 as *mut uint16_t;
        let mut len: libc::c_int = 0;
        let mut cnt: libc::c_int = 0;
        let mut bit: uint16_t = 0;
        let mut extlen: libc::c_int = 0;
        let mut ht = unsafe { &mut *(0 as *mut htree_t) };
        if !(unsafe { *bitlen.offset(i as isize) } as libc::c_int == 0 as libc::c_int) {
            /* Get a bit pattern */
            len = unsafe { *bitlen.offset(i as isize) } as libc::c_int;
            ptn = bitptn[len as usize];
            cnt = weight[len as usize];
            if len <= ARCHIVE_LHA_DEFINED_PARAM.htbl_bits {
                /* Calculate next bit pattern */
                bitptn[len as usize] = ptn + cnt; /* Invalid */
                if bitptn[len as usize] > tbl_size {
                    return 0 as libc::c_int;
                }
                /* Update the table */
                p_0 = unsafe { &mut *tbl.offset(ptn as isize) } as *mut uint16_t;
                if cnt > 7 as libc::c_int {
                    let mut pc: *mut uint16_t = 0 as *mut uint16_t;
                    cnt -= 8 as libc::c_int;
                    pc = unsafe { &mut *p_0.offset(cnt as isize) } as *mut uint16_t;
                    unsafe {
                        *pc.offset(0 as libc::c_int as isize) = i as uint16_t;
                        *pc.offset(1 as libc::c_int as isize) = i as uint16_t;
                        *pc.offset(2 as libc::c_int as isize) = i as uint16_t;
                        *pc.offset(3 as libc::c_int as isize) = i as uint16_t;
                        *pc.offset(4 as libc::c_int as isize) = i as uint16_t;
                        *pc.offset(5 as libc::c_int as isize) = i as uint16_t;
                        *pc.offset(6 as libc::c_int as isize) = i as uint16_t;
                        *pc.offset(7 as libc::c_int as isize) = i as uint16_t;
                    }
                    if cnt > 7 as libc::c_int {
                        cnt -= 8 as libc::c_int;
                        memcpy_safe(
                            unsafe { &mut *p_0.offset(cnt as isize) } as *mut uint16_t
                                as *mut libc::c_void,
                            pc as *const libc::c_void,
                            (8 as libc::c_int as libc::c_ulong)
                                .wrapping_mul(::std::mem::size_of::<uint16_t>() as libc::c_ulong),
                        );
                        pc = unsafe { &mut *p_0.offset(cnt as isize) } as *mut uint16_t;
                        while cnt > 15 as libc::c_int {
                            cnt -= 16 as libc::c_int;
                            memcpy_safe(
                                unsafe { &mut *p_0.offset(cnt as isize) } as *mut uint16_t
                                    as *mut libc::c_void,
                                pc as *const libc::c_void,
                                (16 as libc::c_int as libc::c_ulong).wrapping_mul(
                                    ::std::mem::size_of::<uint16_t>() as libc::c_ulong,
                                ),
                            );
                        }
                    }
                    if cnt != 0 {
                        memcpy_safe(
                            p_0 as *mut libc::c_void,
                            pc as *const libc::c_void,
                            (cnt as libc::c_ulong)
                                .wrapping_mul(::std::mem::size_of::<uint16_t>() as libc::c_ulong),
                        );
                    }
                } else {
                    while cnt > 1 as libc::c_int {
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
                bit = ((1 as libc::c_uint) << diffbits - 1 as libc::c_int) as uint16_t; /* Invalid */
                extlen = len - ARCHIVE_LHA_DEFINED_PARAM.htbl_bits; /* Invalid */
                p_0 = unsafe { &mut *tbl.offset((ptn >> diffbits) as isize) } as *mut uint16_t; /* Invalid */
                let safe_p_0 = unsafe { &mut *p_0 };
                if *safe_p_0 as libc::c_int == 0 as libc::c_int {
                    *safe_p_0 = (len_avail + hf.tree_used) as uint16_t; /* Invalid */
                    let fresh14 = hf.tree_used; /* Invalid */
                    hf.tree_used = hf.tree_used + 1;
                    ht = unsafe { &mut *(&mut *hf.tree.offset(fresh14 as isize) as *mut htree_t) };
                    if hf.tree_used > hf.tree_avail {
                        return 0 as libc::c_int;
                    }
                    ht.left = 0 as libc::c_int as uint16_t;
                    ht.right = 0 as libc::c_int as uint16_t
                } else {
                    if (*safe_p_0 as libc::c_int) < len_avail
                        || *safe_p_0 as libc::c_int >= len_avail + hf.tree_used
                    {
                        return 0 as libc::c_int;
                    }
                    ht = unsafe {
                        &mut *(&mut *hf
                            .tree
                            .offset((*safe_p_0 as libc::c_int - len_avail) as isize)
                            as *mut htree_t)
                    }
                }
                loop {
                    extlen -= 1;
                    if !(extlen > 0 as libc::c_int) {
                        break;
                    }
                    if ptn & bit as libc::c_int != 0 {
                        if (ht.left as libc::c_int) < len_avail {
                            ht.left = (len_avail + hf.tree_used) as uint16_t;
                            let fresh15 = hf.tree_used;
                            hf.tree_used = hf.tree_used + 1;
                            ht = unsafe {
                                &mut *(&mut *hf.tree.offset(fresh15 as isize) as *mut htree_t)
                            };
                            if hf.tree_used > hf.tree_avail {
                                return 0 as libc::c_int;
                            }
                            ht.left = 0 as libc::c_int as uint16_t;
                            ht.right = 0 as libc::c_int as uint16_t
                        } else {
                            ht = unsafe {
                                &mut *(&mut *hf
                                    .tree
                                    .offset((ht.left as libc::c_int - len_avail) as isize)
                                    as *mut htree_t)
                            }
                        }
                    } else if (ht.right as libc::c_int) < len_avail {
                        ht.right = (len_avail + hf.tree_used) as uint16_t;
                        let fresh16 = hf.tree_used;
                        hf.tree_used = hf.tree_used + 1;
                        ht = unsafe {
                            &mut *(&mut *hf.tree.offset(fresh16 as isize) as *mut htree_t)
                        };
                        if hf.tree_used > hf.tree_avail {
                            return 0 as libc::c_int;
                        }
                        ht.left = 0 as libc::c_int as uint16_t;
                        ht.right = 0 as libc::c_int as uint16_t
                    } else {
                        ht = unsafe {
                            &mut *(&mut *hf
                                .tree
                                .offset((ht.right as libc::c_int - len_avail) as isize)
                                as *mut htree_t)
                        }
                    }
                    bit = (bit as libc::c_int >> 1 as libc::c_int) as uint16_t
                }
                if ptn & bit as libc::c_int != 0 {
                    if ht.left as libc::c_int != 0 as libc::c_int {
                        return 0 as libc::c_int;
                    }
                    ht.left = i as uint16_t
                } else {
                    if ht.right as libc::c_int != 0 as libc::c_int {
                        return 0 as libc::c_int;
                    }
                    ht.right = i as uint16_t
                }
            }
        }
        i += 1
    }
    return 1 as libc::c_int;
}

unsafe extern "C" fn lzh_decode_huffman_tree(
    mut hf: &mut huffman,
    mut rbits: libc::c_uint,
    mut c: libc::c_int,
) -> libc::c_int {
    let hf_safe = unsafe { &mut *hf };
    let mut ht: *mut htree_t = 0 as *mut htree_t;
    let mut extlen: libc::c_int = 0;
    ht = hf_safe.tree;
    extlen = hf_safe.shift_bits;
    while c >= hf_safe.len_avail {
        c -= hf_safe.len_avail;
        let fresh17 = extlen;
        extlen = extlen - 1;
        if fresh17 <= 0 as libc::c_int || c >= hf_safe.tree_used {
            return 0 as libc::c_int;
        }
        if rbits & (1 as libc::c_uint) << extlen != 0 {
            c = (unsafe { *ht.offset(c as isize) }).left as libc::c_int
        } else {
            c = (unsafe { *ht.offset(c as isize) }).right as libc::c_int
        }
    }
    return c;
}

unsafe extern "C" fn lzh_decode_huffman(
    mut hf: &mut huffman,
    mut rbits: libc::c_uint,
) -> libc::c_int {
    let mut c: libc::c_int = 0;
    /*
     * At first search an index table for a bit pattern.
     * If it fails, search a huffman tree for.
     */
    c = unsafe { *hf.tbl.offset((rbits >> hf.shift_bits) as isize) } as libc::c_int;
    if c < hf.len_avail || hf.len_avail == 0 as libc::c_int {
        return c;
    }
    /* This bit pattern needs to be found out at a huffman tree. */
    return lzh_decode_huffman_tree(hf, rbits, c);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_archive_read_support_format_lha() {
    let mut archive_read: *mut archive_read = 0 as *mut archive_read;
    archive_read = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<archive_read>() as libc::c_ulong,
        )
    } as *mut archive_read;
    (*archive_read).archive.magic = ARCHIVE_AR_DEFINED_PARAM.archive_read_magic;
    (*archive_read).archive.state = ARCHIVE_AR_DEFINED_PARAM.archive_state_new;
    archive_read_support_format_lha(&mut (*archive_read).archive as *mut archive);
}

#[no_mangle]
unsafe extern "C" fn archive_test_lha_check_header_format(mut h: *const libc::c_void) {
    lha_check_header_format(h);
}

#[no_mangle]
unsafe extern "C" fn archive_test_archive_read_format_lha_options(
    mut _a: *mut archive,
    mut key: *const libc::c_char,
    mut val: *const libc::c_char,
) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    archive_read_format_lha_options(a, key, val);
}

#[no_mangle]
unsafe extern "C" fn archive_test_lha_skip_sfx(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    lha_skip_sfx(a);
    let mut archive_read_filter: *mut archive_read_filter = 0 as *mut archive_read_filter;
    archive_read_filter = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<archive_read_filter>() as libc::c_ulong,
        )
    } as *mut archive_read_filter;
    (*a).filter = archive_read_filter as *mut archive_read_filter;
    (*archive_read_filter).fatal = 'a' as libc::c_char;
    lha_skip_sfx(a);
}

#[no_mangle]
unsafe extern "C" fn archive_test_lha_read_data_none(mut _a: *mut archive) {
    let mut size: size_t = 2;
    let mut size2: *mut size_t = &size as *const size_t as *mut size_t;
    let mut offset: int64_t = 1;
    let mut offset2: *mut int64_t = &offset as *const int64_t as *mut int64_t;
    let mut buff: *mut libc::c_void = 0 as *const libc::c_void as *mut libc::c_void;
    let mut buff2: *mut *const libc::c_void = unsafe {
        &buff as *const *mut libc::c_void as *mut *mut libc::c_void as *mut *const libc::c_void
    };
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut lha: *mut lha = 0 as *mut lha;
    lha = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<lha>() as libc::c_ulong,
        )
    } as *mut lha;
    (*lha).entry_bytes_remaining = 0;
    (*(*a).format).data = lha as *mut libc::c_void;
    lha_read_data_none(a, buff2, size2, offset2);
}

#[no_mangle]
unsafe extern "C" fn archive_test_lha_read_data_lzh(mut _a: *mut archive) {
    let mut size: size_t = 2;
    let mut size2: *mut size_t = &size as *const size_t as *mut size_t;
    let mut offset: int64_t = 1;
    let mut offset2: *mut int64_t = &offset as *const int64_t as *mut int64_t;
    let mut buff: *mut libc::c_void = 0 as *const libc::c_void as *mut libc::c_void;
    let mut buff2: *mut *const libc::c_void = unsafe {
        &buff as *const *mut libc::c_void as *mut *mut libc::c_void as *mut *const libc::c_void
    };
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut lha: *mut lha = 0 as *mut lha;
    lha = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<lha>() as libc::c_ulong,
        )
    } as *mut lha;
    (*lha).decompress_init = 0;
    (*lha).method[0] = 'a' as libc::c_char;
    (*(*a).format).data = lha as *mut libc::c_void;
    lha_read_data_lzh(a, buff2, size2, offset2);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_lzh_emit_window() {
    let mut lzh_stream: *mut lzh_stream = 0 as *mut lzh_stream;
    lzh_stream = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<lzh_stream>() as libc::c_ulong,
        )
    } as *mut lzh_stream;
    let mut lzh_dec: *mut lzh_dec = 0 as *mut lzh_dec;
    lzh_dec = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<lzh_dec>() as libc::c_ulong,
        )
    } as *mut lzh_dec;
    (*lzh_stream).ds = lzh_dec as *mut lzh_dec;
    (*lzh_dec).w_buff = 1 as *mut libc::c_uchar;
    lzh_emit_window(lzh_stream, 1);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_lzh_decode_huffman_tree() {
    let mut huffman: *mut huffman = 0 as *mut huffman;
    huffman = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<huffman>() as libc::c_ulong,
        )
    } as *mut huffman;
    let mut htree_t: *mut htree_t = 0 as *mut htree_t;
    htree_t = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<htree_t>() as libc::c_ulong,
        )
    } as *mut htree_t;
    (*huffman).tree = htree_t as *mut htree_t;
    (*huffman).shift_bits = 1;
    (*huffman).len_avail = 1;
    (*huffman).tree_used = 2;
    lzh_decode_huffman_tree(huffman, 1, 2);
}

#[no_mangle]
unsafe extern "C" fn archive_test_truncated_error(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    truncated_error(a);
}

#[no_mangle]
unsafe extern "C" fn archive_test_lzh_decode_blocks() {
    let mut strm: *mut lzh_stream = 0 as *mut lzh_stream;
    strm = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<lzh_stream>() as libc::c_ulong,
        )
    } as *mut lzh_stream;
    let mut lzh_dec: *mut lzh_dec = 0 as *mut lzh_dec;
    lzh_dec = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<lzh_dec>() as libc::c_ulong,
        )
    } as *mut lzh_dec;
    (*strm).ds = lzh_dec as *mut lzh_dec;
    (*lzh_dec).state = 10;
    (*lzh_dec).br.cache_avail = -20;
    (*lzh_dec).copy_pos = 2;
    lzh_decode_blocks(strm, 0);
    (*lzh_dec).state = 11;
    lzh_decode_blocks(strm, 1);
    lzh_decode_blocks(strm, 0);
}

#[no_mangle]
unsafe extern "C" fn archive_test_lzh_read_blocks() {
    let mut strm: *mut lzh_stream = 0 as *mut lzh_stream;
    strm = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<lzh_stream>() as libc::c_ulong,
        )
    } as *mut lzh_stream;
    let mut lzh_dec: *mut lzh_dec = 0 as *mut lzh_dec;
    lzh_dec = unsafe {
        calloc_safe(
            1 as libc::c_int as libc::c_ulong,
            ::std::mem::size_of::<lzh_dec>() as libc::c_ulong,
        )
    } as *mut lzh_dec;
    (*strm).ds = lzh_dec as *mut lzh_dec;
    (*lzh_dec).pt.len_bits = 1;
    (*lzh_dec).lt.len_bits = 1;
    (*lzh_dec).pt.max_bits = 1;
    (*lzh_dec).state = 1;
    (*lzh_dec).br.cache_avail = -20;
    (*lzh_dec).copy_pos = 2;
    lzh_read_blocks(strm, 0);
    lzh_read_blocks(strm, 1);
    (*lzh_dec).state = 2;
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
    (*lzh_dec).state = 3;
    (*lzh_dec).loop_0 = 3;
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
    (*lzh_dec).state = 4;
    (*lzh_dec).pt.len_avail = 10000;
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
    (*lzh_dec).state = 5;
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
    (*lzh_dec).state = 6;
    (*lzh_dec).lt.len_avail = 0;
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
    (*lzh_dec).state = 7;
    (*lzh_dec).lt.len_avail = 4;
    lzh_read_blocks(strm, 1);
    lzh_read_blocks(strm, 0);
}
