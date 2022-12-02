use super::archive_string::archive_string_default_conversion_for_read;
use archive_core::archive_endian::*;
use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;
use std::mem::size_of;

/* Notify how many bits we consumed. */
static mut cache_masks: [uint32_t; 36] = [
    0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff, 0xfff, 0x1fff, 0x3fff,
    0x7fff, 0xffff, 0x1ffff, 0x3ffff, 0x7ffff, 0xfffff, 0x1fffff, 0x3fffff, 0x7fffff, 0xffffff,
    0x1ffffff, 0x3ffffff, 0x7ffffff, 0xfffffff, 0x1fffffff, 0x3fffffff, 0x7fffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff,
];
/*
 * Shift away used bits in the cache data and fill it up with following bits.
 * Call this when cache buffer does not have enough bits you need.
 *
 * Returns 1 if the cache buffer is full.
 * Returns 0 if the cache buffer is not full; input buffer is empty.
 */
fn rar_br_fillup(a: *mut archive_read, br: *mut rar_br) -> i32 {
    let safe_a = unsafe { &mut *a };
    let safe_br = unsafe { &mut *br };
    let rar: *mut rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    let mut n: i32 = (ARCHIVE_RAR_DEFINED_PARAM.cache_bits as u64)
        .wrapping_sub(safe_br.cache_avail as u64) as i32;
    loop {
        match n >> 3 {
            8 => unsafe {
                if safe_br.avail_in >= 8 {
                    safe_br.cache_buffer = (*(*br).next_in.offset(0) as uint64_t) << 56
                        | (*(*br).next_in.offset(1) as uint64_t) << 48
                        | (*(*br).next_in.offset(2) as uint64_t) << 40
                        | (*(*br).next_in.offset(3) as uint64_t) << 32
                        | ((*(*br).next_in.offset(4) as uint32_t) << 24) as u64
                        | ((*(*br).next_in.offset(5) as uint32_t) << 16) as u64
                        | ((*(*br).next_in.offset(6) as uint32_t) << 8) as u64
                        | *(*br).next_in.offset(7) as uint32_t as u64;
                    safe_br.next_in = safe_br.next_in.offset(8);
                    safe_br.avail_in -= 8;
                    safe_br.cache_avail += 8 * 8;
                    (*rar).bytes_unconsumed += 8;
                    (*rar).bytes_remaining -= 8;
                    return 1;
                }
            },
            7 => unsafe {
                if safe_br.avail_in >= 7 {
                    safe_br.cache_buffer = safe_br.cache_buffer << 56
                        | (*(*br).next_in.offset(0) as uint64_t) << 48
                        | (*(*br).next_in.offset(1) as uint64_t) << 40
                        | (*(*br).next_in.offset(2) as uint64_t) << 32
                        | ((*(*br).next_in.offset(3) as uint32_t) << 24) as u64
                        | ((*(*br).next_in.offset(4) as uint32_t) << 16) as u64
                        | ((*(*br).next_in.offset(5) as uint32_t) << 8) as u64
                        | *(*br).next_in.offset(6) as uint32_t as u64;
                    safe_br.next_in = safe_br.next_in.offset(7);
                    safe_br.avail_in -= 7;
                    safe_br.cache_avail += 7 * 8;
                    (*rar).bytes_unconsumed += 7;
                    (*rar).bytes_remaining -= 7;
                    return 1;
                }
            },
            6 => unsafe {
                if safe_br.avail_in >= 6 {
                    safe_br.cache_buffer = safe_br.cache_buffer << 48
                        | (*(*br).next_in.offset(0) as uint64_t) << 40
                        | (*(*br).next_in.offset(1) as uint64_t) << 32
                        | ((*(*br).next_in.offset(2) as uint32_t) << 24) as u64
                        | ((*(*br).next_in.offset(3) as uint32_t) << 16) as u64
                        | ((*(*br).next_in.offset(4) as uint32_t) << 8) as u64
                        | *(*br).next_in.offset(5) as uint32_t as u64;
                    safe_br.next_in = safe_br.next_in.offset(6);
                    safe_br.avail_in -= 6;
                    safe_br.cache_avail += 6 * 8;
                    (*rar).bytes_unconsumed += 6;
                    (*rar).bytes_remaining -= 6;
                    return 1;
                }
            },
            0 => {
                /* We have enough compressed data in
                 * the cache buffer.*/
                return 1;
            }
            _ => {}
        }
        if safe_br.avail_in <= 0 {
            if safe_rar.bytes_unconsumed > 0 {
                /* Consume as much as the decompressor
                 * actually used. */
                unsafe { __archive_read_consume_safe(a, safe_rar.bytes_unconsumed) };
                safe_rar.bytes_unconsumed = 0
            }
            safe_br.next_in = unsafe { rar_read_ahead(a, 1, &mut safe_br.avail_in) as *const u8 };
            if safe_br.next_in.is_null() {
                return 0;
            }
            if safe_br.avail_in == 0 {
                return 0;
            }
        }
        let fresh0 = safe_br.next_in;
        safe_br.next_in = unsafe { safe_br.next_in.offset(1) };
        safe_br.cache_buffer = unsafe { safe_br.cache_buffer << 8 | *fresh0 as u64 };
        safe_br.avail_in -= 1;
        safe_br.cache_avail += 8;
        n -= 8;
        safe_rar.bytes_unconsumed += 1;
        safe_rar.bytes_remaining -= 1
    }
}

fn rar_br_preparation(a: *mut archive_read, br: *mut rar_br) -> i32 {
    let rar: *mut rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    let safe_br = unsafe { &mut *br };
    if safe_rar.bytes_remaining > 0 {
        safe_br.next_in = unsafe { rar_read_ahead(a, 1, &mut safe_br.avail_in) as *const u8 };
        if safe_br.next_in.is_null() {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"Truncated RAR file data\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
        if safe_br.cache_avail == 0 {
            rar_br_fillup(a, br);
        }
    }
    return ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
}
/* Find last bit set */
#[inline]
fn rar_fls(mut word: u32) -> i32 {
    word |= word >> 1;
    word |= word >> 2;
    word |= word >> 4;
    word |= word >> 8;
    word |= word >> 16;
    return word.wrapping_sub(word >> 1) as i32;
}
/* LZSS functions */
#[inline]
fn lzss_position(lzss: *mut lzss) -> int64_t {
    let safe_lzss = unsafe { &mut *lzss };
    return safe_lzss.position;
}

#[inline]
fn lzss_mask(lzss: *mut lzss) -> i32 {
    let safe_lzss = unsafe { &mut *lzss };
    return safe_lzss.mask;
}

#[inline]
fn lzss_size(lzss: *mut lzss) -> i32 {
    let safe_lzss = unsafe { &mut *lzss };
    return safe_lzss.mask + 1;
}

#[inline]
fn lzss_offset_for_position(lzss: *mut lzss, pos: int64_t) -> i32 {
    let safe_lzss = unsafe { &mut *lzss };
    return (pos & safe_lzss.mask as i64) as i32;
}

#[inline]
fn lzss_pointer_for_position(lzss: *mut lzss, pos: int64_t) -> *mut u8 {
    unsafe {
        return &mut *(*lzss).window.offset((lzss_offset_for_position
            as unsafe fn(_: *mut lzss, _: int64_t) -> i32)(
            lzss, pos
        ) as isize) as *mut u8;
    }
}

#[inline]
fn lzss_current_offset(lzss: *mut lzss) -> i32 {
    let safe_lzss = unsafe { &mut *lzss };
    return lzss_offset_for_position(lzss, safe_lzss.position);
}

#[inline]
fn lzss_current_pointer(lzss: *mut lzss) -> *mut uint8_t {
    let safe_lzss = unsafe { &mut *lzss };
    return lzss_pointer_for_position(lzss, safe_lzss.position);
}

#[inline]
fn lzss_emit_literal(rar: *mut rar, literal: uint8_t) {
    let safe_rar = unsafe { &mut *rar };
    unsafe {
        *lzss_current_pointer(&mut safe_rar.lzss) = literal;
    }
    safe_rar.lzss.position += 1;
}

#[inline]
fn lzss_emit_match(rar: *mut rar, offset: i32, length: i32) {
    let safe_rar = unsafe { &mut *rar };
    let mut dstoffs: i32 = lzss_current_offset(&mut safe_rar.lzss);
    let mut srcoffs: i32 = dstoffs - offset & lzss_mask(&mut safe_rar.lzss);
    let mut l: i32 = 0;
    let mut li: i32 = 0;
    let mut remaining: i32 = 0;
    let mut d: *mut u8 = 0 as *mut u8;
    let mut s: *mut u8 = 0 as *mut u8;
    remaining = length;
    while remaining > 0 {
        l = remaining;
        if dstoffs > srcoffs {
            if l > lzss_size(&mut safe_rar.lzss) - dstoffs {
                l = lzss_size(&mut safe_rar.lzss) - dstoffs
            }
        } else if l > lzss_size(&mut safe_rar.lzss) - srcoffs {
            l = lzss_size(&mut safe_rar.lzss) - srcoffs
        }
        unsafe {
            d = &mut *(*rar).lzss.window.offset(dstoffs as isize) as *mut u8;
            s = &mut *(*rar).lzss.window.offset(srcoffs as isize) as *mut u8;
        }
        if dstoffs + l < srcoffs || srcoffs + l < dstoffs {
            unsafe { memcpy_safe(d as *mut (), s as *const (), l as u64) };
        } else {
            li = 0;
            while li < l {
                unsafe { *d.offset(li as isize) = *s.offset(li as isize) };
                li += 1
            }
        }
        remaining -= l;
        dstoffs = dstoffs + l & lzss_mask(&mut safe_rar.lzss);
        srcoffs = srcoffs + l & lzss_mask(&mut safe_rar.lzss)
    }
    safe_rar.lzss.position += length as i64;
}

fn ppmd_read(p: *mut ()) -> Byte {
    let safe_p = unsafe { *(p as *mut IByteIn) };
    let a: *mut archive_read = safe_p.a;
    let rar: *mut rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    let br: *mut rar_br = &mut safe_rar.br;
    let safe_br = unsafe { &mut *br };
    let mut b: Byte = 0;
    if !(safe_br.cache_avail >= 8 || rar_br_fillup(a, br) != 0 || safe_br.cache_avail >= 8) {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Truncated RAR file data\x00" as *const u8
        );
        safe_rar.valid = 0;
        return 0;
    }
    b = unsafe {
        ((safe_br.cache_buffer >> safe_br.cache_avail - 8) as uint32_t & cache_masks[8 as usize])
            as Byte
    };
    safe_br.cache_avail -= 8;
    return b;
}

#[no_mangle]
pub fn archive_read_support_format_rar(_a: *mut archive) -> i32 {
    let a: *mut archive_read = _a as *mut archive_read;
    let safe_a = unsafe { &mut *a };
    let mut rar: *mut rar = 0 as *mut rar;
    let mut r: i32 = 0;
    let magic_test: i32 = unsafe {
        __archive_check_magic_safe(
            _a,
            0xdeb0c5 as u32,
            1,
            b"archive_read_support_format_rar\x00" as *const u8,
        )
    };
    if magic_test == -(30 as i32) {
        return -(30 as i32);
    }
    rar = unsafe { calloc_safe(size_of::<rar>() as u64, 1) as *mut rar };
    if rar.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            12,
            b"Can\'t allocate rar data\x00" as *const u8
        );
        return -30;
    }
    /*
     * Until enough data has been read, we cannot tell about
     * any encrypted entries yet.
     */
    unsafe { (*rar).has_encrypted_entries = -(1) };
    r = unsafe {
        __archive_read_register_format_safe(
            a,
            rar as *mut (),
            b"rar\x00" as *const u8,
            Some(archive_read_format_rar_bid),
            Some(archive_read_format_rar_options),
            Some(archive_read_format_rar_read_header),
            Some(archive_read_format_rar_read_data),
            Some(archive_read_format_rar_read_data_skip),
            Some(archive_read_format_rar_seek_data),
            Some(archive_read_format_rar_cleanup),
            Some(archive_read_support_format_rar_capabilities),
            Some(archive_read_format_rar_has_encrypted_entries),
        )
    };
    if r != 0 {
        unsafe { free_safe(rar as *mut ()) };
    }
    return r;
}

fn archive_read_support_format_rar_capabilities(a: *mut archive_read) -> i32 {
    /* UNUSED */
    return ARCHIVE_RAR_DEFINED_PARAM.archive_read_format_caps_encrypt_data
        | ARCHIVE_RAR_DEFINED_PARAM.archive_read_format_caps_encrypt_metadata;
}

fn archive_read_format_rar_has_encrypted_entries(_a: *mut archive_read) -> i32 {
    let safe_a = unsafe { &mut *_a };
    if !_a.is_null() && !safe_a.format.is_null() {
        let rar: *mut rar = unsafe { (*(*_a).format).data as *mut rar };
        let safe_rar = unsafe { &mut *rar };
        if !rar.is_null() {
            return safe_rar.has_encrypted_entries;
        }
    }
    return ARCHIVE_RAR_DEFINED_PARAM.archive_read_format_encryption_dont_know;
}

fn archive_read_format_rar_bid(a: *mut archive_read, best_bid: i32) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    /* If there's already a bid > 30, we'll never win. */
    if best_bid > 30 {
        return -1;
    }
    p = unsafe { __archive_read_ahead_safe(a, 7, 0 as *mut ssize_t) as *const u8 };
    if p.is_null() {
        return -1;
    }
    if unsafe {
        memcmp_safe(
            p as *const (),
            b"Rar!\x1a\x07\x00\x00" as *const u8 as *const (),
            7,
        ) == 0
    } {
        return 30;
    }
    if unsafe { *p.offset(0) as i32 == 'M' as i32 && *p.offset(1) as i32 == 'Z' as i32 }
        || unsafe { memcmp_safe(p as *const (), b"\x7fELF\x00" as *const u8 as *const (), 4) == 0 }
    {
        /* This is a PE file */
        let mut offset: ssize_t = 0x10000;
        let mut window: ssize_t = 4096;
        let mut bytes_avail: ssize_t = 0;
        while offset + window <= (1024 * 128) as i64 {
            let buff: *const u8 = unsafe {
                __archive_read_ahead_safe(a, (offset + window) as size_t, &mut bytes_avail)
            } as *const u8;
            if buff.is_null() {
                /* Remaining bytes are less than window. */
                window >>= 1;
                if window < 0x40 {
                    return 0;
                }
            } else {
                unsafe { p = buff.offset(offset as isize) };
                while unsafe { p.offset(7) < buff.offset(bytes_avail as isize) } {
                    if unsafe {
                        memcmp_safe(
                            p as *const (),
                            b"Rar!\x1a\x07\x00\x00" as *const u8 as *const (),
                            7,
                        ) == 0
                    } {
                        return 30;
                    }
                    unsafe { p = p.offset(0x10 as i32 as isize) }
                    unsafe { offset = p.offset_from(buff) as i64 }
                }
            }
        }
    }
    return 0;
}

fn skip_sfx(a: *mut archive_read) -> i32 {
    let mut h: *const () = 0 as *const ();
    let mut p: *const u8 = 0 as *const u8;
    let mut q: *const u8 = 0 as *const u8;
    let mut skip: size_t = 0;
    let mut total: size_t = 0;
    let mut bytes: ssize_t = 0;
    let mut window: ssize_t = 0;
    total = 0;
    window = 4096;
    while total.wrapping_add(window as u64) <= (1024 * 128) as u64 {
        h = unsafe { __archive_read_ahead_safe(a, window as size_t, &mut bytes) };
        if h == 0 as *mut () {
            /* Remaining bytes are less than window. */
            window >>= 1;
            if window < 0x40 {
                break;
            }
        } else {
            if bytes < 0x40 {
                break;
            }
            p = h as *const u8;
            unsafe {
                q = p.offset(bytes as isize);
            }
            /*
             * Scan ahead until we find something that looks
             * like the RAR header.
             */
            while unsafe { p.offset(7) < q } {
                if unsafe {
                    memcmp_safe(
                        p as *const (),
                        b"Rar!\x1a\x07\x00\x00" as *const u8 as *const (),
                        7,
                    ) == 0
                } {
                    unsafe { skip = p.offset_from(h as *const u8) as i64 as size_t };
                    unsafe { __archive_read_consume_safe(a, skip as int64_t) };
                    return ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
                }
                unsafe { p = p.offset(0x10 as i32 as isize) }
            }
            unsafe { skip = p.offset_from(h as *const u8) as i64 as size_t };
            unsafe { __archive_read_consume_safe(a, skip as int64_t) };
            total = (total as u64).wrapping_add(skip) as size_t as size_t
        }
    }
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
        b"Couldn\'t find out RAR header\x00" as *const u8
    );
    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
}

fn archive_read_format_rar_options(a: *mut archive_read, key: *const u8, val: *const u8) -> i32 {
    let safe_a = unsafe { &mut *a };
    let mut rar: *mut rar = 0 as *mut rar;
    let mut ret: i32 = ARCHIVE_RAR_DEFINED_PARAM.archive_failed;
    rar = unsafe { (*(*a).format).data as *mut rar };
    if unsafe { strcmp_safe(key, b"hdrcharset\x00" as *const u8) == 0 } {
        if unsafe { val.is_null() || *val.offset(0) as i32 == 0 } {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_misc,
                b"rar: hdrcharset option needs a character-set name\x00" as *const u8
            );
        } else {
            unsafe {
                (*rar).opt_sconv =
                    archive_string_conversion_from_charset_safe(&mut safe_a.archive, val, 0)
            };
            if unsafe { !(*rar).opt_sconv.is_null() } {
                ret = ARCHIVE_RAR_DEFINED_PARAM.archive_ok
            } else {
                ret = ARCHIVE_RAR_DEFINED_PARAM.archive_fatal
            }
        }
        return ret;
    }
    /* Note: The "warn" return is just to inform the options
     * supervisor that we didn't handle it.  It will generate
     * a suitable error if no one used this option. */
    return ARCHIVE_RAR_DEFINED_PARAM.archive_warn;
}

fn archive_read_format_rar_read_header(a: *mut archive_read, entry: *mut archive_entry) -> i32 {
    let safe_a = unsafe { &mut *a };
    let mut h: *const () = 0 as *const ();
    let mut p: *const u8 = 0 as *const u8;
    let mut rar: *mut rar = 0 as *mut rar;
    let mut skip: size_t = 0;
    let mut head_type: u8 = 0;
    let mut ret: i32 = 0;
    let mut flags: u32 = 0;
    let mut crc32_expected: u64 = 0;
    safe_a.archive.archive_format = ARCHIVE_RAR_DEFINED_PARAM.archive_format_rar;
    if safe_a.archive.archive_format_name.is_null() {
        safe_a.archive.archive_format_name = b"RAR\x00" as *const u8
    }
    rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    /*
     * It should be sufficient to call archive_read_next_header() for
     * a reader to determine if an entry is encrypted or not. If the
     * encryption of an entry is only detectable when calling
     * archive_read_data(), so be it. We'll do the same check there
     * as well.
     */
    if safe_rar.has_encrypted_entries
        == ARCHIVE_RAR_DEFINED_PARAM.archive_read_format_encryption_dont_know
    {
        safe_rar.has_encrypted_entries = 0
    }
    /* RAR files can be generated without EOF headers, so return ARCHIVE_EOF if
     * this fails.
     */
    h = unsafe { __archive_read_ahead_safe(a, 7, 0 as *mut ssize_t) };
    if h == 0 as *mut () {
        return ARCHIVE_RAR_DEFINED_PARAM.archive_eof;
    }
    p = h as *const u8;
    if unsafe {
        (*rar).found_first_header == 0
            && (*p.offset(0) as i32 == 'M' as i32 && *p.offset(1) as i32 == 'Z' as i32
                || memcmp_safe(p as *const (), b"\x7fELF\x00" as *const u8 as *const (), 4) == 0)
    } {
        /* This is an executable ? Must be self-extracting... */
        ret = skip_sfx(a);
        if ret < ARCHIVE_RAR_DEFINED_PARAM.archive_warn {
            return ret;
        }
    }
    safe_rar.found_first_header = 1;
    loop {
        let mut crc32_val: u64 = 0;
        h = unsafe { __archive_read_ahead_safe(a, 7, 0 as *mut ssize_t) };
        if h == 0 as *mut () {
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
        p = h as *const u8;
        unsafe { head_type = *p.offset(2) };
        if head_type as i32 == ARCHIVE_RAR_DEFINED_PARAM.mark_head {
            if unsafe {
                memcmp_safe(
                    p as *const (),
                    b"Rar!\x1a\x07\x00\x00" as *const u8 as *const (),
                    7,
                ) != 0
            } {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                    b"Invalid marker header\x00" as *const u8
                );
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            unsafe { __archive_read_consume_safe(a, 7) };
        } else if head_type as i32 == ARCHIVE_RAR_DEFINED_PARAM.main_head {
            unsafe { safe_rar.main_flags = archive_le16dec(p.offset(3) as *const ()) as u32 };
            skip = archive_le16dec(unsafe { p.offset(5) as *const () }) as size_t;
            if skip < 7 + (size_of::<[u8; 2]>()) as u64 + (size_of::<[u8; 4]>()) as u64 {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                    b"Invalid header size\x00" as *const u8
                );
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            h = unsafe { __archive_read_ahead_safe(a, skip, 0 as *mut ssize_t) };
            if h == 0 as *mut () {
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            p = h as *const u8;
            unsafe {
                memcpy_safe(
                    safe_rar.reserved1.as_mut_ptr() as *mut (),
                    unsafe { p.offset(7) as *const () },
                    size_of::<[u8; 2]>() as u64,
                )
            };
            unsafe {
                memcpy_safe(
                    safe_rar.reserved2.as_mut_ptr() as *mut (),
                    unsafe {
                        p.offset(7).offset(size_of::<[u8; 2]>() as u64 as isize) as *const ()
                    },
                    size_of::<[u8; 4]>() as u64,
                )
            };
            if safe_rar.main_flags & ARCHIVE_RAR_DEFINED_PARAM.mhd_encryptver as u32 != 0 {
                if skip < 7 + size_of::<[u8; 2]>() as u64 + 1 {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                        b"Invalid header size\x00" as *const u8
                    );
                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                }
                unsafe {
                    (*rar).encryptver = *p
                        .offset(7)
                        .offset(size_of::<[u8; 2]>() as u64 as isize)
                        .offset(size_of::<[u8; 4]>() as u64 as isize)
                }
            }
            /* Main header is password encrypted, so we cannot read any
            file names or any other info about files from the header. */
            if safe_rar.main_flags & ARCHIVE_RAR_DEFINED_PARAM.mhd_password as u32 != 0 {
                unsafe {
                    archive_entry_set_is_metadata_encrypted_safe(entry, 1);
                    archive_entry_set_is_data_encrypted_safe(entry, 1);
                }
                safe_rar.has_encrypted_entries = 1;
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                    b"RAR encryption support unavailable.\x00" as *const u8
                );
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            crc32_val = unsafe {
                crc32_safe(
                    0,
                    unsafe { (p as *const u8).offset(2) },
                    (skip as u32).wrapping_sub(2),
                )
            };
            if crc32_val & 0xffff as i32 as u64 != archive_le16dec(p as *const ()) as u64 {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                    b"Header CRC error\x00" as *const u8
                );
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            unsafe { __archive_read_consume_safe(a, skip as int64_t) };
        } else if head_type as i32 == ARCHIVE_RAR_DEFINED_PARAM.file_head {
            return unsafe { read_header(a, entry, head_type) };
        } else if head_type as i32 == ARCHIVE_RAR_DEFINED_PARAM.comm_head
            || head_type as i32 == ARCHIVE_RAR_DEFINED_PARAM.av_head
            || head_type as i32 == ARCHIVE_RAR_DEFINED_PARAM.sub_head
            || head_type as i32 == ARCHIVE_RAR_DEFINED_PARAM.protect_head
            || head_type as i32 == ARCHIVE_RAR_DEFINED_PARAM.sign_head
            || head_type as i32 == ARCHIVE_RAR_DEFINED_PARAM.endarc_head
        {
            unsafe {
                flags = archive_le16dec(p.offset(3) as *const ()) as u32;
                skip = archive_le16dec(p.offset(5) as *const ()) as size_t;
            }
            if skip < 7 {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                    b"Invalid header size too small\x00" as *const u8
                );
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            if flags & ARCHIVE_RAR_DEFINED_PARAM.hd_add_size_present as u32 != 0 {
                if skip < (7 + 4) as u64 {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                        b"Invalid header size too small\x00" as *const u8
                    );
                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                }
                h = unsafe { __archive_read_ahead_safe(a, skip, 0 as *mut ssize_t) };
                if h == 0 as *mut () {
                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                }
                p = h as *const u8;
                unsafe {
                    skip = (skip as u64)
                        .wrapping_add(archive_le32dec(p.offset(7) as *const ()) as u64)
                        as size_t as size_t
                }
            }
            /* Skip over the 2-byte CRC at the beginning of the header. */
            crc32_expected = archive_le16dec(p as *const ()) as u64;
            unsafe { __archive_read_consume_safe(a, 2) };
            skip = (skip as u64).wrapping_sub(2) as size_t as size_t;
            /* Skim the entire header and compute the CRC. */
            crc32_val = 0;
            while skip > 0 {
                let mut to_read: size_t = skip;
                if to_read > (32 * 1024) as u64 {
                    to_read = (32 * 1024) as size_t
                }
                h = unsafe { __archive_read_ahead_safe(a, to_read, 0 as *mut ssize_t) };
                if h == 0 as *mut () {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                        b"Bad RAR file\x00" as *const u8
                    );
                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                }
                p = h as *const u8;
                unsafe {
                    crc32_val = crc32_safe(crc32_val, p as *const u8, to_read as uInt);
                    __archive_read_consume_safe(a, to_read as int64_t);
                }
                skip = (skip as u64).wrapping_sub(to_read) as size_t as size_t
            }
            if crc32_val & 0xffff as i32 as u64 != crc32_expected {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                    b"Header CRC error\x00" as *const u8
                );
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            if head_type as i32 == 0x7b as i32 {
                return ARCHIVE_RAR_DEFINED_PARAM.archive_eof;
            }
        } else if head_type as i32 == ARCHIVE_RAR_DEFINED_PARAM.newsub_head {
            ret = unsafe { read_header(a, entry, head_type) };
            if ret < ARCHIVE_RAR_DEFINED_PARAM.archive_warn {
                return ret;
            }
        } else {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"Bad RAR file\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
    }
}

fn archive_read_format_rar_read_data(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let rar: *mut rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    let safe_buff = unsafe { &mut *buff };
    let safe_size = unsafe { &mut *size };
    let safe_offset = unsafe { &mut *offset };
    let mut ret: i32 = 0;
    if safe_rar.has_encrypted_entries
        == ARCHIVE_RAR_DEFINED_PARAM.archive_read_format_encryption_dont_know
    {
        safe_rar.has_encrypted_entries = 0
    }
    if safe_rar.bytes_unconsumed > 0 {
        /* Consume as much as the decompressor actually used. */
        unsafe { __archive_read_consume_safe(a, safe_rar.bytes_unconsumed) };
        safe_rar.bytes_unconsumed = 0
    }
    *safe_buff = 0 as *const ();
    if unsafe { (*rar).entry_eof as i32 != 0 || (*rar).offset_seek >= (*rar).unp_size } {
        *safe_size = 0;
        *safe_offset = safe_rar.offset;
        if *safe_offset < safe_rar.unp_size {
            *safe_offset = safe_rar.unp_size
        }
        return ARCHIVE_RAR_DEFINED_PARAM.archive_eof;
    }
    if safe_rar.compression_method as i32 == ARCHIVE_RAR_DEFINED_PARAM.compress_method_store {
        ret = unsafe { read_data_stored(a, buff, size, offset) }
    } else if safe_rar.compression_method as i32
        == ARCHIVE_RAR_DEFINED_PARAM.compress_method_fastest
        || safe_rar.compression_method as i32 == ARCHIVE_RAR_DEFINED_PARAM.compress_method_fast
        || safe_rar.compression_method as i32 == ARCHIVE_RAR_DEFINED_PARAM.compress_method_normal
        || safe_rar.compression_method as i32 == ARCHIVE_RAR_DEFINED_PARAM.compress_method_good
        || safe_rar.compression_method as i32 == ARCHIVE_RAR_DEFINED_PARAM.compress_method_best
    {
        ret = unsafe { read_data_compressed(a, buff, size, offset, 0) };
        if ret != ARCHIVE_RAR_DEFINED_PARAM.archive_ok
            && ret != ARCHIVE_RAR_DEFINED_PARAM.archive_warn
        {
            unsafe {
                __archive_ppmd7_functions
                    .Ppmd7_Free
                    .expect("non-null function pointer")(&mut (*rar).ppmd7_context);
            }
            safe_rar.start_new_table = 1;
            safe_rar.ppmd_valid = 0
        }
    } else {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Unsupported compression method for RAR file.\x00" as *const u8
        );
        ret = ARCHIVE_RAR_DEFINED_PARAM.archive_fatal
    }
    return ret;
}

unsafe fn archive_read_format_rar_read_data_skip(a: *mut archive_read) -> i32 {
    let mut rar: *mut rar = 0 as *mut rar;
    let mut bytes_skipped: int64_t = 0;
    let mut ret: i32 = 0;
    rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_a = unsafe { &mut *a };
    let safe_rar = unsafe { &mut *rar };
    if safe_rar.bytes_unconsumed > 0 {
        /* Consume as much as the decompressor actually used. */
        __archive_read_consume_safe(a, safe_rar.bytes_unconsumed);
        safe_rar.bytes_unconsumed = 0
    }
    if safe_rar.bytes_remaining > 0 {
        bytes_skipped = __archive_read_consume_safe(a, safe_rar.bytes_remaining);
        if bytes_skipped < 0 {
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
    }
    /* Compressed data to skip must be read from each header in a multivolume
     * archive.
     */
    if safe_rar.main_flags & ARCHIVE_RAR_DEFINED_PARAM.mhd_volume as u32 != 0
        && safe_rar.file_flags & ARCHIVE_RAR_DEFINED_PARAM.fhd_split_after as u32 != 0
    {
        ret = archive_read_format_rar_read_header(a, safe_a.entry);
        if ret == ARCHIVE_RAR_DEFINED_PARAM.archive_eof {
            ret = archive_read_format_rar_read_header(a, safe_a.entry)
        }
        if ret != ARCHIVE_RAR_DEFINED_PARAM.archive_ok {
            return ret;
        }
        return archive_read_format_rar_read_data_skip(a);
    }
    return ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
}

fn archive_read_format_rar_seek_data(
    a: *mut archive_read,
    offset: int64_t,
    whence: i32,
) -> int64_t {
    let mut client_offset: int64_t = 0;
    let mut ret: int64_t = 0;
    let mut i: u32 = 0;
    let rar: *mut rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    let safe_a = unsafe { &mut *a };
    if safe_rar.compression_method as i32 == ARCHIVE_RAR_DEFINED_PARAM.compress_method_store {
        unsafe {
            /* Modify the offset for use with SEEK_SET */
            if whence == ARCHIVE_RAR_DEFINED_PARAM.seek_cur {
                client_offset = safe_rar.offset_seek
            } else if whence == ARCHIVE_RAR_DEFINED_PARAM.seek_end {
                client_offset = safe_rar.unp_size
            } else {
                client_offset = 0
            }
        }
        client_offset += offset;
        if client_offset < 0 {
            /* Can't seek past beginning of data block */
            return -(1) as int64_t;
        } else {
            if client_offset > safe_rar.unp_size {
                /*
                 * Set the returned offset but only seek to the end of
                 * the data block.
                 */
                unsafe { safe_rar.offset_seek = client_offset };
                client_offset = safe_rar.unp_size
            }
        }
        unsafe { client_offset += (*(*rar).dbo.offset(0)).start_offset };
        i = 0;
        while i < safe_rar.cursor {
            i = i.wrapping_add(1);
            unsafe {
                client_offset += (*(*rar).dbo.offset(i as isize)).start_offset
                    - (*(*rar).dbo.offset(i.wrapping_sub(1) as isize)).end_offset
            }
        }
        if safe_rar.main_flags & ARCHIVE_RAR_DEFINED_PARAM.mhd_volume as u32 != 0 {
            loop
            /* Find the appropriate offset among the multivolume archive */
            {
                if unsafe {
                    client_offset < (*(*rar).dbo.offset((*rar).cursor as isize)).start_offset
                        && safe_rar.file_flags & ARCHIVE_RAR_DEFINED_PARAM.fhd_split_before as u32
                            != 0
                } {
                    /* Search backwards for the correct data block */
                    if safe_rar.cursor == 0 {
                        archive_set_error_safe!(
                            &mut (*a).archive as *mut archive,
                            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_misc,
                            b"Attempt to seek past beginning of RAR data block\x00" as *const u8
                                as *const u8
                        );
                        return ARCHIVE_RAR_DEFINED_PARAM.archive_failed as int64_t;
                    }
                    safe_rar.cursor = safe_rar.cursor.wrapping_sub(1);
                    unsafe {
                        client_offset -=
                            (*(*rar).dbo.offset((*rar).cursor.wrapping_add(1) as isize))
                                .start_offset
                                - (*(*rar).dbo.offset((*rar).cursor as isize)).end_offset
                    };
                    if unsafe {
                        client_offset < (*(*rar).dbo.offset((*rar).cursor as isize)).start_offset
                    } {
                        continue;
                    }
                    ret = unsafe {
                        __archive_read_seek_safe(
                            a,
                            unsafe {
                                (*(*rar).dbo.offset(safe_rar.cursor as isize)).start_offset
                                    - (*(*rar).dbo.offset(safe_rar.cursor as isize)).header_size
                            },
                            0,
                        )
                    };
                    if ret < ARCHIVE_RAR_DEFINED_PARAM.archive_ok as int64_t {
                        return ret;
                    }
                    ret = archive_read_format_rar_read_header(a, safe_a.entry) as int64_t;
                    if ret != ARCHIVE_RAR_DEFINED_PARAM.archive_ok as int64_t {
                        archive_set_error_safe!(
                            &mut (*a).archive as *mut archive,
                            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_misc,
                            b"Error during seek of RAR file\x00" as *const u8
                        );
                        return ARCHIVE_RAR_DEFINED_PARAM.archive_failed as int64_t;
                    }
                    safe_rar.cursor = safe_rar.cursor.wrapping_sub(1);
                    break;
                } else {
                    if unsafe {
                        !(client_offset > (*(*rar).dbo.offset((*rar).cursor as isize)).end_offset
                            && (*rar).file_flags & ARCHIVE_RAR_DEFINED_PARAM.fhd_split_after as u32
                                != 0)
                    } {
                        break;
                    }
                    /* Search forward for the correct data block */
                    safe_rar.cursor = safe_rar.cursor.wrapping_add(1);
                    if unsafe {
                        safe_rar.cursor < safe_rar.nodes
                            && client_offset
                                > (*(*rar).dbo.offset(safe_rar.cursor as isize)).end_offset
                    } {
                        unsafe {
                            client_offset += (*(*rar).dbo.offset((*rar).cursor as isize))
                                .start_offset
                                - (*(*rar).dbo.offset((*rar).cursor.wrapping_sub(1) as isize))
                                    .end_offset
                        }
                    } else {
                        safe_rar.cursor = safe_rar.cursor.wrapping_sub(1);
                        ret = unsafe {
                            __archive_read_seek_safe(
                                a,
                                unsafe { (*(*rar).dbo.offset((*rar).cursor as isize)).end_offset },
                                0,
                            )
                        };
                        if ret < ARCHIVE_RAR_DEFINED_PARAM.archive_ok as int64_t {
                            return ret;
                        }
                        ret = archive_read_format_rar_read_header(a, safe_a.entry) as int64_t;
                        if ret == ARCHIVE_RAR_DEFINED_PARAM.archive_eof as i64 {
                            safe_rar.has_endarc_header = 1;
                            ret = archive_read_format_rar_read_header(a, safe_a.entry) as int64_t
                        }
                        if ret != ARCHIVE_RAR_DEFINED_PARAM.archive_ok as int64_t {
                            archive_set_error_safe!(
                                &mut (*a).archive as *mut archive,
                                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_misc,
                                b"Error during seek of RAR file\x00" as *const u8
                            );
                            return ARCHIVE_RAR_DEFINED_PARAM.archive_failed as int64_t;
                        }
                        unsafe {
                            client_offset += (*(*rar).dbo.offset((*rar).cursor as isize))
                                .start_offset
                                - (*(*rar).dbo.offset((*rar).cursor.wrapping_sub(1) as isize))
                                    .end_offset
                        }
                    }
                }
            }
        }
        ret = unsafe { __archive_read_seek_safe(a, client_offset, 0) };
        if ret < ARCHIVE_RAR_DEFINED_PARAM.archive_ok as int64_t {
            return ret;
        }
        unsafe {
            safe_rar.bytes_remaining =
                (*(*rar).dbo.offset(safe_rar.cursor as isize)).end_offset - ret
        };
        i = safe_rar.cursor;
        while i > 0 {
            i = i.wrapping_sub(1);
            unsafe {
                ret -= (*(*rar).dbo.offset(i.wrapping_add(1) as isize)).start_offset
                    - (*(*rar).dbo.offset(i as isize)).end_offset
            }
        }
        unsafe { ret -= (*(*rar).dbo.offset(0)).start_offset };
        /* Always restart reading the file after a seek */
        unsafe { __archive_reset_read_data_safe(&mut safe_a.archive) };
        safe_rar.bytes_unconsumed = 0;
        safe_rar.offset = 0;
        /*
         * If a seek past the end of file was requested, return the requested
         * offset.
         */
        {
            if ret == safe_rar.unp_size && safe_rar.offset_seek > safe_rar.unp_size {
                return safe_rar.offset_seek;
            }
            /* Return the new offset */
            safe_rar.offset_seek = ret;
            return safe_rar.offset_seek;
        }
    } else {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_misc,
            b"Seeking of compressed RAR files is unsupported\x00" as *const u8
        );
    }
    return ARCHIVE_RAR_DEFINED_PARAM.archive_failed as int64_t;
}

fn archive_read_format_rar_cleanup(a: *mut archive_read) -> i32 {
    let mut rar: *mut rar = 0 as *mut rar;
    rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    unsafe {
        free_codes(a);
        free_safe(safe_rar.filename as *mut ());
        free_safe(safe_rar.filename_save as *mut ());
        free_safe(safe_rar.dbo as *mut ());
        free_safe(safe_rar.unp_buffer as *mut ());
        free_safe(safe_rar.lzss.window as *mut ());
    }
    unsafe {
        __archive_ppmd7_functions
            .Ppmd7_Free
            .expect("non-null function pointer")(&mut safe_rar.ppmd7_context)
    };
    unsafe { free_safe(rar as *mut ()) };
    unsafe { (*(*a).format).data = 0 as *mut () };
    return ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
}
/* Support functions */
fn read_header(a: *mut archive_read, entry: *mut archive_entry, head_type: u8) -> i32 {
    let mut h: *const () = 0 as *const ();
    let mut p: *const u8 = 0 as *const u8;
    let mut endp: *const u8 = 0 as *const u8;
    let mut rar: *mut rar = 0 as *mut rar;
    let mut rar_header: rar_header = rar_header {
        crc: [0; 2],
        type_0: 0,
        flags: [0; 2],
        size: [0; 2],
    };
    let mut file_header: rar_file_header = rar_file_header {
        pack_size: [0; 4],
        unp_size: [0; 4],
        host_os: 0,
        file_crc: [0; 4],
        file_time: [0; 4],
        unp_ver: 0,
        method: 0,
        name_size: [0; 2],
        file_attr: [0; 4],
    };
    let mut header_size: int64_t = 0;
    let mut filename_size: u32 = 0;
    let mut end: u32 = 0;
    let mut filename: *mut u8 = 0 as *mut u8;
    let mut strp: *mut u8 = 0 as *mut u8;
    let mut packed_size: [u8; 8] = [0; 8];
    let mut unp_size: [u8; 8] = [0; 8];
    let mut ttime: i32 = 0;
    let mut sconv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    let mut fn_sconv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    let mut crc32_val: u64 = 0;
    let mut ret: i32 = ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
    let mut ret2: i32 = 0;
    rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    let safe_a = unsafe { &mut *a };
    /* Setup a string conversion object for non-rar-unicode filenames. */
    sconv = safe_rar.opt_sconv;
    if sconv.is_null() {
        if safe_rar.init_default_conversion == 0 {
            safe_rar.sconv_default =
                unsafe { archive_string_default_conversion_for_read(&mut safe_a.archive) };
            safe_rar.init_default_conversion = 1
        }
        sconv = safe_rar.sconv_default
    }
    h = unsafe { __archive_read_ahead_safe(a, 7, 0 as *mut ssize_t) };
    if h == 0 as *mut () {
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    p = h as *const u8;
    unsafe {
        memcpy_safe(
            &mut rar_header as *mut rar_header as *mut (),
            p as *const (),
            size_of::<rar_header>() as u64,
        )
    };
    safe_rar.file_flags = archive_le16dec(rar_header.flags.as_mut_ptr() as *const ()) as u32;
    header_size = archive_le16dec(rar_header.size.as_mut_ptr() as *const ()) as int64_t;
    if header_size < size_of::<rar_file_header>() as u64 as int64_t + 7 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid header size\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    crc32_val = unsafe { crc32_safe(0, (p as *const u8).offset(2), (7 - 2) as uInt) };
    unsafe { __archive_read_consume_safe(a, 7) };
    if safe_rar.file_flags & ARCHIVE_RAR_DEFINED_PARAM.fhd_solid as u32 == 0 {
        safe_rar.compression_method = 0;
        safe_rar.packed_size = 0;
        safe_rar.unp_size = 0;
        safe_rar.mtime = 0;
        safe_rar.ctime = 0;
        safe_rar.atime = 0;
        safe_rar.arctime = 0;
        safe_rar.mode = 0;
        unsafe {
            memset_safe(
                &mut safe_rar.salt as *mut [u8; 8] as *mut (),
                0,
                size_of::<[u8; 8]>() as u64,
            )
        };
        safe_rar.atime = 0;
        safe_rar.ansec = 0;
        safe_rar.ctime = 0;
        safe_rar.cnsec = 0;
        safe_rar.mtime = 0;
        safe_rar.mnsec = 0;
        safe_rar.arctime = 0;
        safe_rar.arcnsec = 0
    } else {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"RAR solid archive support unavailable.\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    h = unsafe {
        __archive_read_ahead_safe(
            a,
            (header_size as size_t).wrapping_sub(7),
            0 as *mut ssize_t,
        )
    };
    if h == 0 as *mut () {
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    /* File Header CRC check. */
    crc32_val = unsafe { crc32_safe(crc32_val, h as *const Bytef, (header_size - 7) as u32) };
    if crc32_val & 0xffff as i32 as u64
        != archive_le16dec(rar_header.crc.as_mut_ptr() as *const ()) as u64
    {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Header CRC error\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    /* If no CRC error, Go on parsing File Header. */
    p = h as *const u8;
    unsafe { endp = p.offset(header_size as isize).offset(-(7)) };
    unsafe {
        memcpy_safe(
            &mut file_header as *mut rar_file_header as *mut (),
            p as *const (),
            size_of::<rar_file_header>() as u64,
        )
    };
    unsafe { p = p.offset(size_of::<rar_file_header>() as u64 as isize) };
    safe_rar.compression_method = file_header.method;
    ttime = archive_le32dec(file_header.file_time.as_mut_ptr() as *const ()) as i32;
    safe_rar.mtime = unsafe { get_time(ttime) };
    safe_rar.file_crc = archive_le32dec(file_header.file_crc.as_mut_ptr() as *const ()) as u64;
    if safe_rar.file_flags & ARCHIVE_RAR_DEFINED_PARAM.fhd_password as u32 != 0 {
        unsafe { archive_entry_set_is_data_encrypted_safe(entry, 1) };
        safe_rar.has_encrypted_entries = 1;
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"RAR encryption support unavailable.\x00" as *const u8
        );
        /* Since it is only the data part itself that is encrypted we can at least
        extract information about the currently processed entry and don't need
        to return ARCHIVE_FATAL here. */
        /*return (ARCHIVE_FATAL);*/
    } /* High pack size */
    if safe_rar.file_flags & ARCHIVE_RAR_DEFINED_PARAM.fhd_large as u32 != 0 {
        unsafe {
            memcpy_safe(
                packed_size.as_mut_ptr() as *mut (),
                file_header.pack_size.as_mut_ptr() as *const (),
                4,
            ); /* High unpack size */
            memcpy_safe(
                unsafe { packed_size.as_mut_ptr().offset(4) as *mut () },
                p as *const (),
                4,
            );
        }
        unsafe { p = p.offset(4) };
        unsafe {
            memcpy_safe(
                unp_size.as_mut_ptr() as *mut (),
                file_header.unp_size.as_mut_ptr() as *const (),
                4,
            );
            memcpy_safe(
                unsafe { unp_size.as_mut_ptr().offset(4) as *mut () },
                p as *const (),
                4,
            );
        }
        unsafe { p = p.offset(4) };
        safe_rar.packed_size =
            archive_le64dec(&mut packed_size as *mut [u8; 8] as *const ()) as int64_t;
        safe_rar.unp_size = archive_le64dec(&mut unp_size as *mut [u8; 8] as *const ()) as int64_t
    } else {
        safe_rar.packed_size =
            archive_le32dec(file_header.pack_size.as_mut_ptr() as *const ()) as int64_t;
        safe_rar.unp_size =
            archive_le32dec(file_header.unp_size.as_mut_ptr() as *const ()) as int64_t
    }
    if safe_rar.packed_size < 0 || safe_rar.unp_size < 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid sizes specified.\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    safe_rar.bytes_remaining = safe_rar.packed_size;
    /* td RARv3 subblocks contain comments. For now the complete block is
     * consumed at the end.
     */
    if head_type as i32 == 0x7a as i32 {
        unsafe {
            let distance: size_t = p.offset_from(h as *const u8) as i64 as size_t;
            header_size += safe_rar.packed_size;
            /* Make sure we have the extended data. */
            h = __archive_read_ahead_safe(
                a,
                (header_size as size_t).wrapping_sub(7),
                0 as *mut ssize_t,
            );
            if h == 0 as *mut () {
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            p = h as *const u8;
            endp = p.offset(header_size as isize).offset(-(7));
            p = p.offset(distance as isize)
        }
    }
    filename_size = archive_le16dec(file_header.name_size.as_mut_ptr() as *const ()) as u32;
    if unsafe { p.offset(filename_size as isize) > endp } {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid filename size\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    if safe_rar.filename_allocated < filename_size.wrapping_mul(2).wrapping_add(2) as u64 {
        let mut newptr: *mut u8 = 0 as *mut u8;
        let newsize: size_t = filename_size.wrapping_mul(2).wrapping_add(2) as size_t;
        newptr = unsafe { realloc_safe(safe_rar.filename as *mut (), newsize) as *mut u8 };
        if newptr.is_null() {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.enomem,
                b"Couldn\'t allocate memory.\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
        safe_rar.filename = newptr;
        safe_rar.filename_allocated = newsize
    }
    filename = safe_rar.filename;
    unsafe { memcpy_safe(filename as *mut (), p as *const (), filename_size as u64) };
    unsafe { *filename.offset(filename_size as isize) = '\u{0}' as i32 as u8 };
    if safe_rar.file_flags & ARCHIVE_RAR_DEFINED_PARAM.fhd_unicode as u32 != 0 {
        if filename_size as u64 != unsafe { strlen_safe(filename) } {
            let mut highbyte: u8 = 0;
            let mut flagbits: u8 = 0;
            let mut flagbyte: u8 = 0;
            let mut fn_end: u32 = 0;
            let mut offset: u32 = 0;
            end = filename_size;
            fn_end = filename_size.wrapping_mul(2);
            filename_size = 0;
            offset = unsafe { (strlen_safe(filename) as u32).wrapping_add(1) };
            let fresh1 = offset;
            offset = offset.wrapping_add(1);
            unsafe { highbyte = *p.offset(fresh1 as isize) as u8 };
            flagbits = 0;
            flagbyte = 0;
            unsafe {
                while offset < end && filename_size < fn_end {
                    if flagbits == 0 {
                        let fresh2 = offset;
                        offset = offset.wrapping_add(1);
                        flagbyte = *p.offset(fresh2 as isize) as u8;
                        flagbits = 8
                    }
                    flagbits = (flagbits as i32 - 2) as u8;
                    match flagbyte as i32 >> flagbits as i32 & 3 {
                        0 => {
                            let fresh3 = filename_size;
                            filename_size = filename_size.wrapping_add(1);
                            *filename.offset(fresh3 as isize) = '\u{0}' as i32 as u8;
                            let fresh4 = offset;
                            offset = offset.wrapping_add(1);
                            let fresh5 = filename_size;
                            filename_size = filename_size.wrapping_add(1);
                            *filename.offset(fresh5 as isize) = *p.offset(fresh4 as isize)
                        }
                        1 => {
                            let fresh6 = filename_size;
                            filename_size = filename_size.wrapping_add(1);
                            *filename.offset(fresh6 as isize) = highbyte as u8;
                            let fresh7 = offset;
                            offset = offset.wrapping_add(1);
                            let fresh8 = filename_size;
                            filename_size = filename_size.wrapping_add(1);
                            *filename.offset(fresh8 as isize) = *p.offset(fresh7 as isize)
                        }
                        2 => {
                            let fresh9 = filename_size;
                            filename_size = filename_size.wrapping_add(1);
                            *filename.offset(fresh9 as isize) =
                                *p.offset(offset as isize).offset(1);
                            let fresh10 = filename_size;
                            filename_size = filename_size.wrapping_add(1);
                            *filename.offset(fresh10 as isize) = *p.offset(offset as isize);
                            offset = offset.wrapping_add(2)
                        }
                        3 => {
                            let mut extra: u8 = 0;
                            let mut high: u8 = 0;
                            let fresh11 = offset;
                            offset = offset.wrapping_add(1);
                            let mut length: uint8_t = *p.offset(fresh11 as isize) as uint8_t;
                            if length as i32 & 0x80 as i32 != 0 {
                                let fresh12 = offset;
                                offset = offset.wrapping_add(1);
                                extra = *p.offset(fresh12 as isize);
                                high = highbyte as u8
                            } else {
                                high = 0;
                                extra = high
                            }
                            length = ((length as i32 & 0x7f as i32) + 2) as uint8_t;
                            while length as i32 != 0 && filename_size < fn_end {
                                let cp: u32 = filename_size >> 1;
                                let fresh13 = filename_size;
                                filename_size = filename_size.wrapping_add(1);
                                *filename.offset(fresh13 as isize) = high;
                                let fresh14 = filename_size;
                                filename_size = filename_size.wrapping_add(1);
                                *filename.offset(fresh14 as isize) =
                                    (*p.offset(cp as isize) as i32 + extra as i32) as u8;
                                length = length.wrapping_sub(1)
                            }
                        }
                        _ => {}
                    }
                }
            }
            if filename_size > fn_end {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                    b"Invalid filename\x00" as *const u8
                );
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            let fresh15 = filename_size;
            filename_size = filename_size.wrapping_add(1);
            unsafe {
                *filename.offset(fresh15 as isize) = '\u{0}' as i32 as u8;
                /*
                 * Do not increment filename_size here as the computations below
                 * add the space for the terminating NUL explicitly.
                 */
                *filename.offset(filename_size as isize) = '\u{0}' as i32 as u8
            };
            /* Decoded unicode form is UTF-16BE, so we have to update a string
             * conversion object for it. */
            if safe_rar.sconv_utf16be.is_null() {
                safe_rar.sconv_utf16be = unsafe {
                    archive_string_conversion_from_charset_safe(
                        &mut safe_a.archive,
                        b"UTF-16BE\x00" as *const u8,
                        1,
                    )
                };
                if safe_rar.sconv_utf16be.is_null() {
                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                }
            }
            fn_sconv = safe_rar.sconv_utf16be;
            strp = filename;
            while unsafe {
                memcmp_safe(
                    strp as *const (),
                    b"\x00\x00\x00" as *const u8 as *const (),
                    2,
                )
            } != 0
            {
                if unsafe {
                    memcmp_safe(
                        strp as *const (),
                        b"\x00\\\x00" as *const u8 as *const (),
                        2,
                    ) == 0
                } {
                    unsafe { *strp.offset(1) = '/' as i32 as u8 }
                }
                unsafe { strp = strp.offset(2) }
            }
            unsafe { p = p.offset(offset as isize) }
        } else {
            /*
             * If FHD_UNICODE is set but no unicode data, this file name form
             * is UTF-8, so we have to update a string conversion object for
             * it accordingly.
             */
            if safe_rar.sconv_utf8.is_null() {
                safe_rar.sconv_utf8 = unsafe {
                    archive_string_conversion_from_charset_safe(
                        &mut safe_a.archive,
                        b"UTF-8\x00" as *const u8,
                        1,
                    )
                };
                if safe_rar.sconv_utf8.is_null() {
                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                }
            }
            fn_sconv = safe_rar.sconv_utf8;
            loop {
                strp = unsafe { strchr_safe(filename, '\\' as i32) };
                if strp.is_null() {
                    break;
                }
                unsafe { *strp = '/' as i32 as u8 }
            }
            unsafe { p = p.offset(filename_size as isize) }
        }
    } else {
        fn_sconv = sconv;
        loop {
            strp = unsafe { strchr_safe(filename, '\\' as i32) };
            if strp.is_null() {
                break;
            }
            unsafe { *strp = '/' as i32 as u8 }
        }
        unsafe { p = p.offset(filename_size as isize) }
    }
    /* Split file in multivolume RAR. No more need to process header. */
    if !safe_rar.filename_save.is_null()
        && filename_size as u64 == safe_rar.filename_save_size
        && unsafe {
            memcmp_safe(
                safe_rar.filename as *const (),
                safe_rar.filename_save as *const (),
                filename_size.wrapping_add(1) as u64,
            ) == 0
        }
    {
        unsafe { __archive_read_consume_safe(a, header_size - 7) };
        safe_rar.cursor = safe_rar.cursor.wrapping_add(1);
        if safe_rar.cursor >= safe_rar.nodes {
            safe_rar.nodes = safe_rar.nodes.wrapping_add(1);
            safe_rar.dbo = unsafe {
                realloc_safe(
                    safe_rar.dbo as *mut (),
                    (size_of::<data_block_offsets>() as u64).wrapping_mul(safe_rar.nodes as u64),
                )
            } as *mut data_block_offsets;
            if safe_rar.dbo.is_null() {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR_DEFINED_PARAM.enomem,
                    b"Couldn\'t allocate memory.\x00" as *const u8
                );
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            unsafe {
                (*(*rar).dbo.offset((*rar).cursor as isize)).header_size = header_size;
                (*(*rar).dbo.offset((*rar).cursor as isize)).start_offset = -(1) as int64_t;
                (*(*rar).dbo.offset((*rar).cursor as isize)).end_offset = -(1) as int64_t
            }
        }
        unsafe {
            if (*(*rar).dbo.offset((*rar).cursor as isize)).start_offset < 0 {
                (*(*rar).dbo.offset((*rar).cursor as isize)).start_offset = (*(*a).filter).position;
                (*(*rar).dbo.offset((*rar).cursor as isize)).end_offset =
                    (*(*rar).dbo.offset((*rar).cursor as isize)).start_offset + (*rar).packed_size
            }
        }
        return ret;
    } else {
        if safe_rar.filename_must_match != 0 {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"Mismatch of file parts split across multi-volume archive\x00" as *const u8
                    as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
    }
    safe_rar.filename_save = unsafe {
        realloc_safe(
            safe_rar.filename_save as *mut (),
            filename_size.wrapping_add(1) as u64,
        )
    } as *mut u8;
    unsafe {
        memcpy_safe(
            safe_rar.filename_save as *mut (),
            safe_rar.filename as *const (),
            filename_size.wrapping_add(1) as u64,
        )
    };
    safe_rar.filename_save_size = filename_size as size_t;
    /* Set info for seeking */
    unsafe { free_safe(safe_rar.dbo as *mut ()) };
    safe_rar.dbo = unsafe { calloc_safe(1, size_of::<data_block_offsets>() as u64) }
        as *mut data_block_offsets;
    if safe_rar.dbo.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.enomem,
            b"Couldn\'t allocate memory.\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    unsafe {
        (*(*rar).dbo.offset(0)).header_size = header_size;
        (*(*rar).dbo.offset(0)).start_offset = -(1) as int64_t;
        (*(*rar).dbo.offset(0)).end_offset = -(1) as int64_t;
    }
    safe_rar.cursor = 0;
    safe_rar.nodes = 1;
    if safe_rar.file_flags & 0x400 as i32 as u32 != 0 {
        if unsafe { p.offset(8) > endp } {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"Invalid header size\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
        unsafe {
            memcpy_safe(safe_rar.salt.as_mut_ptr() as *mut (), p as *const (), 8);
        }
        unsafe { p = p.offset(8) }
    }
    if safe_rar.file_flags & 0x1000 as i32 as u32 != 0 {
        if unsafe { read_exttime(p, rar, endp) } < 0 {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"Invalid header size\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
    }
    unsafe { __archive_read_consume_safe(a, header_size - 7) };
    unsafe {
        (*(*rar).dbo.offset(0)).start_offset = (*(*a).filter).position;
        (*(*rar).dbo.offset(0)).end_offset =
            (*(*rar).dbo.offset(0)).start_offset + (*rar).packed_size;
    }
    if file_header.host_os as i32 == ARCHIVE_RAR_DEFINED_PARAM.os_msdos
        || file_header.host_os as i32 == ARCHIVE_RAR_DEFINED_PARAM.os_os2
        || file_header.host_os as i32 == ARCHIVE_RAR_DEFINED_PARAM.os_win32
    {
        safe_rar.mode = archive_le32dec(file_header.file_attr.as_mut_ptr() as *const ());
        if safe_rar.mode & ARCHIVE_RAR_DEFINED_PARAM.file_attribute_directory as u32 != 0 {
            safe_rar.mode = ARCHIVE_RAR_DEFINED_PARAM.ae_ifdir as mode_t
                | ARCHIVE_RAR_DEFINED_PARAM.s_ixusr as u32
                | ARCHIVE_RAR_DEFINED_PARAM.s_ixgrp as u32
                | ARCHIVE_RAR_DEFINED_PARAM.s_ixoth as u32
        } else {
            safe_rar.mode = ARCHIVE_RAR_DEFINED_PARAM.ae_ifreg as mode_t
        }
        safe_rar.mode |= (ARCHIVE_RAR_DEFINED_PARAM.s_irusr
            | ARCHIVE_RAR_DEFINED_PARAM.s_iwusr
            | ARCHIVE_RAR_DEFINED_PARAM.s_irgrp
            | ARCHIVE_RAR_DEFINED_PARAM.s_iroth) as u32
    } else if file_header.host_os as i32 == ARCHIVE_RAR_DEFINED_PARAM.os_unix
        || file_header.host_os as i32 == ARCHIVE_RAR_DEFINED_PARAM.os_mac_os
        || file_header.host_os as i32 == ARCHIVE_RAR_DEFINED_PARAM.os_beos
    {
        safe_rar.mode = archive_le32dec(file_header.file_attr.as_mut_ptr() as *const ())
    } else {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Unknown file attributes from RAR file\'s host OS\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }

    safe_rar.bytes_unconsumed = 0;
    safe_rar.bytes_uncopied = safe_rar.bytes_unconsumed;
    safe_rar.offset = 0;
    safe_rar.lzss.position = safe_rar.offset;
    safe_rar.offset_seek = 0;
    safe_rar.dictionary_size = 0;
    safe_rar.offset_outgoing = 0;
    safe_rar.br.cache_avail = 0;
    safe_rar.br.avail_in = 0;
    safe_rar.crc_calculated = 0;
    safe_rar.entry_eof = 0;
    safe_rar.valid = 1;
    safe_rar.is_ppmd_block = 0;
    safe_rar.start_new_table = 1;
    unsafe { free_safe(safe_rar.unp_buffer as *mut ()) };
    safe_rar.unp_buffer = 0 as *mut u8;
    safe_rar.unp_offset = 0;
    safe_rar.unp_buffer_size = ARCHIVE_RAR_DEFINED_PARAM.unp_buffer_size as u32;
    unsafe {
        memset_safe(
            safe_rar.lengthtable.as_mut_ptr() as *mut (),
            0,
            size_of::<[u8; 404]>() as u64,
        )
    };
    unsafe {
        __archive_ppmd7_functions
            .Ppmd7_Free
            .expect("non-null function pointer")(&mut safe_rar.ppmd7_context);
    }
    safe_rar.ppmd_eod = 0;
    safe_rar.ppmd_valid = safe_rar.ppmd_eod;
    /* Don't set any archive entries for non-file header types */
    if head_type as i32 == 0x7a as i32 {
        return ret;
    }
    unsafe {
        archive_entry_set_mtime_safe(entry, safe_rar.mtime, safe_rar.mnsec);
        archive_entry_set_ctime_safe(entry, safe_rar.ctime, safe_rar.cnsec);
        archive_entry_set_atime_safe(entry, safe_rar.atime, safe_rar.ansec);
        archive_entry_set_size_safe(entry, safe_rar.unp_size);
        archive_entry_set_mode_safe(entry, safe_rar.mode);
    }
    if unsafe {
        _archive_entry_copy_pathname_l_safe(entry, filename, filename_size as size_t, fn_sconv) != 0
    } {
        if unsafe { *__errno_location() == ARCHIVE_RAR_DEFINED_PARAM.enomem } {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.enomem,
                b"Can\'t allocate memory for Pathname\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Pathname cannot be converted from %s to current locale.\x00" as *const u8
                as *const u8,
            archive_string_conversion_charset_name(fn_sconv)
        );
        ret = ARCHIVE_RAR_DEFINED_PARAM.archive_warn
    }
    if safe_rar.mode & ARCHIVE_RAR_DEFINED_PARAM.ae_ifmt as mode_t
        == ARCHIVE_RAR_DEFINED_PARAM.ae_iflnk as mode_t
    {
        /* Make sure a symbolic-link file does not have its body. */
        safe_rar.bytes_remaining = 0;
        unsafe { archive_entry_set_size_safe(entry, 0) };
        /* Read a symbolic-link name. */
        ret2 = unsafe { read_symlink_stored(a, entry, sconv) };
        if ret2 < ARCHIVE_RAR_DEFINED_PARAM.archive_warn {
            return ret2;
        }
        if ret > ret2 {
            ret = ret2
        }
    }
    if safe_rar.bytes_remaining == 0 {
        safe_rar.entry_eof = 1
    }
    return ret;
}

fn get_time(ttime: i32) -> time_t {
    let mut tm: tm = tm {
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
    };
    tm.tm_sec = 2 * (ttime & 0x1f);
    tm.tm_min = ttime >> 5 & 0x3f;
    tm.tm_hour = ttime >> 11 & 0x1f;
    tm.tm_mday = ttime >> 16 & 0x1f;
    tm.tm_mon = (ttime >> 21 & 0xf) - 1;
    tm.tm_year = (ttime >> 25 & 0x7f) + 80;
    tm.tm_isdst = -(1);
    return unsafe { mktime_safe(&mut tm) };
}

fn read_exttime(mut p: *const u8, rar: *mut rar, endp: *const u8) -> i32 {
    let mut rmode: u32 = 0;
    let mut flags: u32 = 0;
    let mut rem: u32 = 0;
    let mut j: u32 = 0;
    let mut count: u32 = 0;
    let mut ttime: i32 = 0;
    let mut i: i32 = 0;
    let mut tm: *mut tm = 0 as *mut tm;
    let mut t: time_t = 0;
    let mut nsec: i64 = 0;
    let safe_rar = unsafe { &mut *rar };
    #[cfg(any(HAVE_LOCALTIME_R, HAVE__LOCALTIME64_S))]
    let mut tmbuf: tm = tm {
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
    };

    match () {
        #[cfg(HAVE__LOCALTIME64_S)]
        _ => {
            let terr: errno_t = 0;
            let tmptime: __time64_t = 0;
        }
        #[cfg(not(HAVE__LOCALTIME64_S))]
        _ => {}
    }

    if unsafe { p.offset(2) > endp } {
        return -1;
    }
    flags = archive_le16dec(p as *const ()) as u32;
    unsafe { p = p.offset(2) };
    i = 3;
    while i >= 0 {
        t = 0;
        if i == 3 {
            t = safe_rar.mtime
        }
        rmode = flags >> i * 4;
        if rmode & 8 != 0 {
            if t == 0 {
                if unsafe { p.offset(4) > endp } {
                    return -(1);
                }
                ttime = archive_le32dec(p as *const ()) as i32;
                t = get_time(ttime);
                unsafe { p = p.offset(4) }
            }
            rem = 0;
            count = rmode & 3;
            if unsafe { p.offset(count as isize) > endp } {
                return -(1);
            }
            j = 0;
            while j < count {
                unsafe { rem = (*p as u8 as u32) << 16 | rem >> 8 };
                unsafe { p = p.offset(1) };
                j = j.wrapping_add(1)
            }

            match () {
                #[cfg(HAVE_LOCALTIME_R)]
                _ => {
                    tm = unsafe { localtime_r_safe(&mut t, &mut tmbuf) };
                }
                #[cfg(not(HAVE_LOCALTIME_R))]
                _ => {}

                #[cfg(HAVE__LOCALTIME64_S)]
                _ => {
                    tmptime = t;
                    terr = _localtime64_s(&tmbuf, &tmptime);
                    if terr == 0 {
                        tm = NULL;
                    } else {
                        tm = &mut tmbuf;
                    }
                }
                #[cfg(not(HAVE__LOCALTIME64_S))]
                _ => {}
            }
            unsafe {
                nsec = ((*tm).tm_sec as u32)
                    .wrapping_add(rem.wrapping_div(ARCHIVE_RAR_DEFINED_PARAM.ns_unit as u32))
                    as i64
            };
            if rmode & 4 != 0 {
                unsafe { (*tm).tm_sec += 1 };
                t = unsafe { mktime_safe(tm) }
            }
            if i == 3 {
                safe_rar.mtime = t;
                safe_rar.mnsec = nsec
            } else if i == 2 {
                safe_rar.ctime = t;
                safe_rar.cnsec = nsec
            } else if i == 1 {
                safe_rar.atime = t;
                safe_rar.ansec = nsec
            } else {
                safe_rar.arctime = t;
                safe_rar.arcnsec = nsec
            }
        }
        i -= 1
    }
    return 0;
}

fn read_symlink_stored(
    a: *mut archive_read,
    entry: *mut archive_entry,
    sconv: *mut archive_string_conv,
) -> i32 {
    let mut h: *const () = 0 as *const ();
    let mut p: *const u8 = 0 as *const u8;
    let mut rar: *mut rar = 0 as *mut rar;
    let mut ret: i32 = ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
    rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    h = unsafe { rar_read_ahead(a, safe_rar.packed_size as size_t, 0 as *mut ssize_t) };
    if h == 0 as *mut () {
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    p = h as *const u8;
    if unsafe {
        _archive_entry_copy_symlink_l_safe(entry, p, safe_rar.packed_size as size_t, sconv) != 0
    } {
        if unsafe { *__errno_location() == ARCHIVE_RAR_DEFINED_PARAM.enomem } {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.enomem,
                b"Can\'t allocate memory for link\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"link cannot be converted from %s to current locale.\x00" as *const u8,
            archive_string_conversion_charset_name(sconv)
        );
        ret = ARCHIVE_RAR_DEFINED_PARAM.archive_warn
    }
    unsafe { __archive_read_consume_safe(a, safe_rar.packed_size) };
    return ret;
}

fn read_data_stored(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let mut rar: *mut rar = 0 as *mut rar;
    let mut bytes_avail: ssize_t = 0;
    rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    let safe_buff = unsafe { &mut *buff };
    let safe_size = unsafe { &mut *size };
    let safe_offset = unsafe { &mut *offset };
    if safe_rar.bytes_remaining == 0
        && !(safe_rar.main_flags & ARCHIVE_RAR_DEFINED_PARAM.mhd_volume as u32 != 0
            && safe_rar.file_flags & ARCHIVE_RAR_DEFINED_PARAM.fhd_split_after as u32 != 0)
    {
        *safe_buff = 0 as *const ();
        *safe_size = 0;
        *safe_offset = safe_rar.offset;
        if safe_rar.file_crc != safe_rar.crc_calculated {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"File CRC error\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
        safe_rar.entry_eof = 1;
        return ARCHIVE_RAR_DEFINED_PARAM.archive_eof;
    }
    *safe_buff = unsafe { rar_read_ahead(a, 1, &mut bytes_avail) };
    if bytes_avail <= 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Truncated RAR file data\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    *safe_size = bytes_avail as size_t;
    *safe_offset = safe_rar.offset;
    safe_rar.offset += bytes_avail;
    safe_rar.offset_seek += bytes_avail;
    safe_rar.bytes_remaining -= bytes_avail;
    safe_rar.bytes_unconsumed = bytes_avail;
    /* Calculate File CRC. */
    unsafe {
        safe_rar.crc_calculated = crc32_safe(
            safe_rar.crc_calculated,
            *safe_buff as *const Bytef,
            bytes_avail as u32,
        )
    };
    return ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
}

fn read_data_compressed(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
    mut looper: size_t,
) -> i32 {
    let fresh16 = looper;
    looper = looper.wrapping_add(1);
    if fresh16 > ARCHIVE_RAR_DEFINED_PARAM.max_compress_depth as u64 {
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    let mut rar: *mut rar = 0 as *mut rar;
    let mut start: int64_t = 0;
    let mut end: int64_t = 0;
    let mut actualend: int64_t = 0;
    let mut bs: size_t = 0;
    let mut ret: i32 = ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
    let mut sym: i32 = 0;
    let mut code: i32 = 0;
    let mut lzss_offset: i32 = 0;
    let mut length: i32 = 0;
    let mut i: i32 = 0;
    rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    let safe_buff = unsafe { &mut *buff };
    let safe_size = unsafe { &mut *size };
    let safe_offset = unsafe { &mut *offset };
    let mut current_block: u64;
    loop {
        if safe_rar.valid == 0 {
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
        if unsafe {
            safe_rar.ppmd_eod as i32 != 0
                || safe_rar.dictionary_size != 0 && safe_rar.offset >= safe_rar.unp_size
        } {
            if safe_rar.unp_offset > 0 {
                /*
                 * If *buff is NULL, it means unp_buffer is not full.
                 * So we have to continue extracting a RAR file.
                 */
                /*
                 * We have unprocessed extracted data. write it out.
                 */
                *safe_buff = safe_rar.unp_buffer as *const ();
                *safe_size = safe_rar.unp_offset as size_t;
                *safe_offset = safe_rar.offset_outgoing;
                safe_rar.offset_outgoing = (safe_rar.offset_outgoing as u64)
                    .wrapping_add(*safe_size) as int64_t
                    as int64_t;
                /* Calculate File CRC. */
                safe_rar.crc_calculated = unsafe {
                    crc32_safe(
                        safe_rar.crc_calculated,
                        *safe_buff as *const Bytef,
                        *safe_size as u32,
                    )
                };
                safe_rar.unp_offset = 0;
                return ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
            }
            *safe_buff = 0 as *const ();
            *safe_size = 0;
            *safe_offset = safe_rar.offset;
            if safe_rar.file_crc != safe_rar.crc_calculated {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                    b"File CRC error\x00" as *const u8
                );
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            safe_rar.entry_eof = 1;
            return ARCHIVE_RAR_DEFINED_PARAM.archive_eof;
        }
        if safe_rar.is_ppmd_block == 0
            && safe_rar.dictionary_size != 0
            && safe_rar.bytes_uncopied > 0
        {
            if safe_rar.bytes_uncopied
                > safe_rar.unp_buffer_size.wrapping_sub(safe_rar.unp_offset) as i64
            {
                bs = safe_rar.unp_buffer_size.wrapping_sub(safe_rar.unp_offset) as size_t
            } else {
                bs = safe_rar.bytes_uncopied as size_t
            }
            ret = unsafe { copy_from_lzss_window(a, buff, safe_rar.offset, bs as i32) };
            if ret != ARCHIVE_RAR_DEFINED_PARAM.archive_ok {
                return ret;
            }
            safe_rar.offset = (safe_rar.offset as u64).wrapping_add(bs) as int64_t as int64_t;
            safe_rar.bytes_uncopied =
                (safe_rar.bytes_uncopied as u64).wrapping_sub(bs) as int64_t as int64_t;
            if *safe_buff != 0 as *mut () {
                safe_rar.unp_offset = 0;
                *safe_size = safe_rar.unp_buffer_size as size_t;
                *safe_offset = safe_rar.offset_outgoing;
                safe_rar.offset_outgoing = (safe_rar.offset_outgoing as u64)
                    .wrapping_add(*safe_size) as int64_t
                    as int64_t;
                /* Calculate File CRC. */
                safe_rar.crc_calculated = unsafe {
                    crc32_safe(
                        safe_rar.crc_calculated,
                        *safe_buff as *const Bytef,
                        *safe_size as u32,
                    )
                }; /* End Of ppmd Data. */
                return ret;
            }
        } else {
            if safe_rar.br.next_in.is_null() && {
                ret = rar_br_preparation(a, &mut safe_rar.br);
                (ret) < ARCHIVE_RAR_DEFINED_PARAM.archive_warn
            } {
                return ret;
            }
            if safe_rar.start_new_table as i32 != 0 && {
                ret = unsafe { parse_codes(a) };
                (ret) < ARCHIVE_RAR_DEFINED_PARAM.archive_warn
            } {
                return ret;
            }
            if safe_rar.is_ppmd_block != 0 {
                unsafe {
                    sym = __archive_ppmd7_functions
                        .Ppmd7_DecodeSymbol
                        .expect("non-null function pointer")(
                        &mut safe_rar.ppmd7_context,
                        &mut safe_rar.range_dec.p,
                    );
                }
                if sym < 0 {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                        b"Invalid symbol\x00" as *const u8
                    );
                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                }
                if sym != safe_rar.ppmd_escape {
                    lzss_emit_literal(rar, sym as uint8_t);
                    safe_rar.bytes_uncopied += 1;
                    current_block = 1;
                } else {
                    unsafe {
                        code = __archive_ppmd7_functions
                            .Ppmd7_DecodeSymbol
                            .expect("non-null function pointer")(
                            &mut safe_rar.ppmd7_context,
                            &mut safe_rar.range_dec.p,
                        );
                    }
                    if code < 0 {
                        archive_set_error_safe!(
                            &mut (*a).archive as *mut archive,
                            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                            b"Invalid symbol\x00" as *const u8
                        );
                        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                    }
                    match code {
                        0 => {
                            safe_rar.start_new_table = 1;
                            return read_data_compressed(a, buff, size, offset, looper);
                        }
                        2 => {
                            safe_rar.ppmd_eod = 1;
                            current_block = 0;
                        }
                        3 => {
                            archive_set_error_safe!(
                                &mut (*a).archive as *mut archive,
                                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_misc,
                                b"Parsing filters is unsupported.\x00" as *const u8
                            );
                            return ARCHIVE_RAR_DEFINED_PARAM.archive_failed;
                        }
                        4 => {
                            lzss_offset = 0;
                            i = 2;
                            while i >= 0 {
                                unsafe {
                                    code = __archive_ppmd7_functions
                                        .Ppmd7_DecodeSymbol
                                        .expect("non-null function pointer")(
                                        &mut safe_rar.ppmd7_context,
                                        &mut safe_rar.range_dec.p,
                                    );
                                }
                                if code < 0 {
                                    archive_set_error_safe!(
                                        &mut (*a).archive as *mut archive,
                                        ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                                        b"Invalid symbol\x00" as *const u8
                                    );
                                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                                }
                                lzss_offset |= code << i * 8;
                                i -= 1
                            }
                            unsafe {
                                length = __archive_ppmd7_functions
                                    .Ppmd7_DecodeSymbol
                                    .expect("non-null function pointer")(
                                    &mut safe_rar.ppmd7_context,
                                    &mut safe_rar.range_dec.p,
                                );
                            }
                            if length < 0 {
                                archive_set_error_safe!(
                                    &mut (*a).archive as *mut archive,
                                    ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                                    b"Invalid symbol\x00" as *const u8
                                );
                                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                            }
                            lzss_emit_match(rar, lzss_offset + 2, length + 32);
                            safe_rar.bytes_uncopied += (length + 32) as i64;
                            current_block = 1;
                        }
                        5 => {
                            unsafe {
                                length = __archive_ppmd7_functions
                                    .Ppmd7_DecodeSymbol
                                    .expect("non-null function pointer")(
                                    &mut safe_rar.ppmd7_context,
                                    &mut safe_rar.range_dec.p,
                                );
                            }
                            if length < 0 {
                                archive_set_error_safe!(
                                    &mut (*a).archive as *mut archive,
                                    ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                                    b"Invalid symbol\x00" as *const u8
                                );
                                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                            }
                            lzss_emit_match(rar, 1, length + 4);
                            safe_rar.bytes_uncopied += (length + 4) as i64;
                            current_block = 1;
                        }
                        _ => {
                            lzss_emit_literal(rar, sym as uint8_t);
                            safe_rar.bytes_uncopied += 1;
                            current_block = 1;
                        }
                    }
                }
            } else {
                start = safe_rar.offset;
                end = start + safe_rar.dictionary_size as i64;
                safe_rar.filterstart = ARCHIVE_RAR_DEFINED_PARAM.int64_max;
                actualend = unsafe { expand(a, end) };
                if actualend < 0 {
                    return actualend as i32;
                }
                safe_rar.bytes_uncopied = actualend - start;
                if safe_rar.bytes_uncopied == 0 {
                    /* Broken RAR files cause this case.
                     * NOTE: If this case were possible on a normal RAR file
                     * we would find out where it was actually bad and
                     * what we would do to solve it. */
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                        b"Internal error extracting RAR file\x00" as *const u8
                    );
                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                }
                current_block = 1;
            }
            match current_block {
                0 => {}
                _ => {
                    if safe_rar.bytes_uncopied
                        > safe_rar.unp_buffer_size.wrapping_sub(safe_rar.unp_offset) as i64
                    {
                        bs = safe_rar.unp_buffer_size.wrapping_sub(safe_rar.unp_offset) as size_t
                    } else {
                        bs = safe_rar.bytes_uncopied as size_t
                    }
                    ret = unsafe { copy_from_lzss_window(a, buff, safe_rar.offset, bs as i32) };
                    if ret != ARCHIVE_RAR_DEFINED_PARAM.archive_ok {
                        return ret;
                    }
                    safe_rar.offset =
                        (safe_rar.offset as u64).wrapping_add(bs) as int64_t as int64_t;
                    safe_rar.bytes_uncopied =
                        (safe_rar.bytes_uncopied as u64).wrapping_sub(bs) as int64_t as int64_t
                }
            }
        }
        if !(*safe_buff == 0 as *mut ()) {
            break;
        }
    }
    safe_rar.unp_offset = 0;
    *safe_size = safe_rar.unp_buffer_size as size_t;
    *safe_offset = safe_rar.offset_outgoing;
    safe_rar.offset_outgoing =
        (safe_rar.offset_outgoing as u64).wrapping_add(*safe_size) as int64_t as int64_t;
    /* Calculate File CRC. */
    safe_rar.crc_calculated = unsafe {
        crc32_safe(
            safe_rar.crc_calculated,
            *safe_buff as *const Bytef,
            *safe_size as u32,
        )
    };
    return ret;
}
fn parse_codes(a: *mut archive_read) -> i32 {
    let mut current_block: u64;
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut val: i32 = 0;
    let mut n: i32 = 0;
    let mut r: i32 = 0;
    let mut bitlengths: [u8; 20] = [0; 20];
    let mut zerocount: u8 = 0;
    let mut ppmd_flags: u8 = 0;
    let mut maxorder: u32 = 0;
    let mut precode: huffman_code = huffman_code {
        tree: 0 as *mut huffman_tree_node,
        numentries: 0,
        numallocatedentries: 0,
        minlength: 0,
        maxlength: 0,
        tablesize: 0,
        table: 0 as *mut huffman_table_entry,
    };
    let rar: *mut rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    let br: *mut rar_br = &mut safe_rar.br;
    let safe_br = unsafe { &mut *br };
    unsafe { free_codes(a) };
    /* Skip to the next byte */
    safe_br.cache_avail &= !(7);
    /* PPMd block flag */
    if safe_br.cache_avail >= 1 || rar_br_fillup(a, br) != 0 || safe_br.cache_avail >= 1 {
        unsafe {
            safe_rar.is_ppmd_block = ((safe_br.cache_buffer >> safe_br.cache_avail - 1) as uint32_t
                & cache_masks[1 as usize]) as u8
        };
        if safe_rar.is_ppmd_block as i32 != 0 {
            safe_br.cache_avail -= 1;
            if !(safe_br.cache_avail >= 7 || rar_br_fillup(a, br) != 0 || safe_br.cache_avail >= 7)
            {
                current_block = 1;
            } else {
                unsafe {
                    ppmd_flags = ((safe_br.cache_buffer >> safe_br.cache_avail - 7) as uint32_t
                        & cache_masks[7 as usize]) as u8
                };
                safe_br.cache_avail -= 7;
                /* Memory is allocated in MB */
                if ppmd_flags as i32 & 0x20 as i32 != 0 {
                    if !(safe_br.cache_avail >= 8
                        || rar_br_fillup(a, br) != 0
                        || safe_br.cache_avail >= 8)
                    {
                        current_block = 1;
                    } else {
                        unsafe {
                            safe_rar.dictionary_size =
                                ((safe_br.cache_buffer >> safe_br.cache_avail - 8) as uint32_t
                                    & cache_masks[8 as usize])
                                    .wrapping_add(1)
                                    << 20
                        };
                        safe_br.cache_avail -= 8;
                        current_block = 2;
                    }
                } else {
                    current_block = 2;
                }
                match current_block {
                    1 => {}
                    _ => {
                        if ppmd_flags as i32 & 0x40 as i32 != 0 {
                            if !(safe_br.cache_avail >= 8
                                || rar_br_fillup(a, br) != 0
                                || safe_br.cache_avail >= 8)
                            {
                                current_block = 1;
                            } else {
                                unsafe {
                                    safe_rar.ppmd7_context.InitEsc = (safe_br.cache_buffer
                                        >> safe_br.cache_avail - 8)
                                        as uint32_t
                                        & cache_masks[8 as usize]
                                };
                                safe_rar.ppmd_escape = safe_rar.ppmd7_context.InitEsc as i32;
                                safe_br.cache_avail -= 8;
                                current_block = 3;
                            }
                        } else {
                            safe_rar.ppmd_escape = 2;
                            current_block = 3;
                        }
                        match current_block {
                            1 => {}
                            _ => {
                                if ppmd_flags as i32 & 0x20 as i32 != 0 {
                                    maxorder = ((ppmd_flags as i32 & 0x1f as i32) + 1) as u32;
                                    if maxorder > 16 {
                                        maxorder = (16 as u32).wrapping_add(
                                            maxorder.wrapping_sub(16 as i32 as u32).wrapping_mul(3),
                                        )
                                    }
                                    if maxorder == 1 {
                                        archive_set_error_safe!(
                                            &mut (*a).archive as *mut archive,
                                            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                                            b"Truncated RAR file data\x00" as *const u8
                                                as *const u8
                                        );
                                        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                                    }
                                    /* Make sure ppmd7_contest is freed before Ppmd7_Construct
                                     * because reading a broken file cause this abnormal sequence. */
                                    unsafe {
                                        __archive_ppmd7_functions
                                            .Ppmd7_Free
                                            .expect("non-null function pointer")(
                                            &mut safe_rar.ppmd7_context,
                                        )
                                    };
                                    safe_rar.bytein.a = a;
                                    safe_rar.bytein.Read = Some(ppmd_read);
                                    unsafe {
                                        __archive_ppmd7_functions
                                            .PpmdRAR_RangeDec_CreateVTable
                                            .expect("non-null function pointer")(
                                            &mut safe_rar.range_dec,
                                        )
                                    };
                                    safe_rar.range_dec.Stream = &mut safe_rar.bytein;
                                    unsafe {
                                        __archive_ppmd7_functions
                                            .Ppmd7_Construct
                                            .expect("non-null function pointer")(
                                            &mut safe_rar.ppmd7_context,
                                        )
                                    };
                                    if safe_rar.dictionary_size == 0 {
                                        archive_set_error_safe!(
                                            &mut (*a).archive as *mut archive,
                                            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                                            b"Invalid zero dictionary size\x00" as *const u8
                                                as *const u8
                                        );
                                        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                                    }
                                    if unsafe {
                                        __archive_ppmd7_functions
                                            .Ppmd7_Alloc
                                            .expect("non-null function pointer")(
                                            &mut safe_rar.ppmd7_context,
                                            safe_rar.dictionary_size,
                                        ) == 0
                                    } {
                                        archive_set_error_safe!(
                                            &mut (*a).archive as *mut archive,
                                            ARCHIVE_RAR_DEFINED_PARAM.enomem,
                                            b"Out of memory\x00" as *const u8
                                        );
                                        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                                    }
                                    if unsafe {
                                        __archive_ppmd7_functions
                                            .PpmdRAR_RangeDec_Init
                                            .expect("non-null function pointer")(
                                            &mut safe_rar.range_dec,
                                        ) == 0
                                    } {
                                        archive_set_error_safe!(
                                            &mut (*a).archive as *mut archive,
                                            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                                            b"Unable to initialize PPMd range decoder\x00"
                                                as *const u8
                                                as *const u8
                                        );
                                        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                                    }
                                    unsafe {
                                        __archive_ppmd7_functions
                                            .Ppmd7_Init
                                            .expect("non-null function pointer")(
                                            &mut safe_rar.ppmd7_context,
                                            maxorder,
                                        )
                                    };
                                    safe_rar.ppmd_valid = 1
                                } else {
                                    if safe_rar.ppmd_valid == 0 {
                                        archive_set_error_safe!(
                                            &mut (*a).archive as *mut archive,
                                            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                                            b"Invalid PPMd sequence\x00" as *const u8
                                        );
                                        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                                    }
                                    if unsafe {
                                        __archive_ppmd7_functions
                                            .PpmdRAR_RangeDec_Init
                                            .expect("non-null function pointer")(
                                            &mut safe_rar.range_dec,
                                        ) == 0
                                    } {
                                        archive_set_error_safe!(
                                            &mut (*a).archive as *mut archive,
                                            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                                            b"Unable to initialize PPMd range decoder\x00"
                                                as *const u8
                                                as *const u8
                                        );
                                        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                                    }
                                }
                                current_block = 4;
                            }
                        }
                    }
                }
            }
        } else {
            safe_br.cache_avail -= 1;
            /* Keep existing table flag */
            if !(safe_br.cache_avail >= 1 || rar_br_fillup(a, br) != 0 || safe_br.cache_avail >= 1)
            {
                current_block = 1;
            } else {
                if unsafe {
                    (safe_br.cache_buffer >> safe_br.cache_avail - 1) as uint32_t
                        & cache_masks[1 as usize]
                        == 0
                } {
                    unsafe {
                        memset_safe(
                            safe_rar.lengthtable.as_mut_ptr() as *mut (),
                            0,
                            size_of::<[u8; 404]>() as u64,
                        )
                    };
                }
                safe_br.cache_avail -= 1;
                unsafe {
                    memset_safe(
                        &mut bitlengths as *mut [u8; 20] as *mut (),
                        0,
                        size_of::<[u8; 20]>() as u64,
                    )
                };
                i = 0;
                loop {
                    if !(i < ARCHIVE_RAR_DEFINED_PARAM.max_symbols) {
                        current_block = 5;
                        break;
                    }
                    if !(safe_br.cache_avail >= 4
                        || rar_br_fillup(a, br) != 0
                        || safe_br.cache_avail >= 4)
                    {
                        current_block = 1;
                        break;
                    }
                    let fresh17 = i;
                    i = i + 1;
                    unsafe {
                        bitlengths[fresh17 as usize] =
                            ((safe_br.cache_buffer >> safe_br.cache_avail - 4) as uint32_t
                                & cache_masks[4 as usize]) as u8
                    };
                    safe_br.cache_avail -= 4;
                    if !(bitlengths[(i - 1) as usize] as i32 == 0xf as i32) {
                        continue;
                    }
                    if !(safe_br.cache_avail >= 4
                        || rar_br_fillup(a, br) != 0
                        || safe_br.cache_avail >= 4)
                    {
                        current_block = 1;
                        break;
                    }
                    unsafe {
                        zerocount = ((safe_br.cache_buffer >> safe_br.cache_avail - 4) as uint32_t
                            & cache_masks[4 as usize]) as u8
                    };
                    safe_br.cache_avail -= 4;
                    if zerocount != 0 {
                        i -= 1;
                        j = 0;
                        while j < zerocount as i32 + 2 && i < ARCHIVE_RAR_DEFINED_PARAM.max_symbols
                        {
                            let fresh18 = i;
                            i = i + 1;
                            bitlengths[fresh18 as usize] = 0;
                            j += 1
                        }
                    }
                }
                match current_block {
                    1 => {}
                    _ => {
                        unsafe {
                            memset_safe(
                                &mut precode as *mut huffman_code as *mut (),
                                0,
                                size_of::<huffman_code>() as u64,
                            )
                        };
                        r = unsafe {
                            create_code(
                                a,
                                &mut precode,
                                bitlengths.as_mut_ptr(),
                                ARCHIVE_RAR_DEFINED_PARAM.max_symbols,
                                ARCHIVE_RAR_DEFINED_PARAM.max_symbol_length as u8,
                            )
                        };
                        if r != ARCHIVE_RAR_DEFINED_PARAM.archive_ok {
                            unsafe {
                                free_safe(precode.tree as *mut ());
                                free_safe(precode.table as *mut ());
                            }
                            return r;
                        }
                        i = 0;
                        loop {
                            if !(i < ARCHIVE_RAR_DEFINED_PARAM.huffman_table_size) {
                                current_block = 6;
                                break;
                            }
                            val = unsafe { read_next_symbol(a, &mut precode) };
                            if val < 0 {
                                unsafe {
                                    free_safe(precode.tree as *mut ());
                                    free_safe(precode.table as *mut ());
                                }
                                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                            }
                            if val < 16 {
                                safe_rar.lengthtable[i as usize] =
                                    (safe_rar.lengthtable[i as usize] as i32 + val & 0xf as i32)
                                        as u8;
                                i += 1
                            } else if val < 18 {
                                if i == 0 {
                                    unsafe {
                                        free_safe(precode.tree as *mut ());
                                        free_safe(precode.table as *mut ());
                                    }
                                    archive_set_error_safe!(
                                        &mut (*a).archive as *mut archive,
                                        ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                                        b"Internal error extracting RAR file.\x00" as *const u8
                                            as *const u8
                                    );
                                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                                }
                                if val == 16 {
                                    if !(safe_br.cache_avail >= 3
                                        || rar_br_fillup(a, br) != 0
                                        || safe_br.cache_avail >= 3)
                                    {
                                        unsafe {
                                            free_safe(precode.tree as *mut ());
                                            free_safe(precode.table as *mut ());
                                        }
                                        current_block = 1;
                                        break;
                                    } else {
                                        unsafe {
                                            n = ((safe_br.cache_buffer >> safe_br.cache_avail - 3)
                                                as uint32_t
                                                & cache_masks[3 as usize])
                                                .wrapping_add(3)
                                                as i32;
                                            safe_br.cache_avail -= 3
                                        }
                                    }
                                } else if !(safe_br.cache_avail >= 7
                                    || rar_br_fillup(a, br) != 0
                                    || safe_br.cache_avail >= 7)
                                {
                                    unsafe {
                                        free_safe(precode.tree as *mut ());
                                        free_safe(precode.table as *mut ());
                                    }
                                    current_block = 1;
                                    break;
                                } else {
                                    unsafe {
                                        n = ((safe_br.cache_buffer >> safe_br.cache_avail - 7)
                                            as uint32_t
                                            & cache_masks[7 as usize])
                                            .wrapping_add(11 as i32 as u32)
                                            as i32;
                                        safe_br.cache_avail -= 7
                                    }
                                }
                                j = 0;
                                while j < n && i < ARCHIVE_RAR_DEFINED_PARAM.huffman_table_size {
                                    safe_rar.lengthtable[i as usize] =
                                        safe_rar.lengthtable[(i - 1) as usize];
                                    i += 1;
                                    j += 1
                                }
                            } else {
                                if val == 18 {
                                    if !(safe_br.cache_avail >= 3
                                        || rar_br_fillup(a, br) != 0
                                        || safe_br.cache_avail >= 3)
                                    {
                                        unsafe {
                                            free_safe(precode.tree as *mut ());
                                            free_safe(precode.table as *mut ());
                                        }
                                        current_block = 1;
                                        break;
                                    } else {
                                        unsafe {
                                            n = ((safe_br.cache_buffer >> safe_br.cache_avail - 3)
                                                as uint32_t
                                                & cache_masks[3 as usize])
                                                .wrapping_add(3)
                                                as i32;
                                            safe_br.cache_avail -= 3
                                        }
                                    }
                                } else if !(safe_br.cache_avail >= 7
                                    || rar_br_fillup(a, br) != 0
                                    || safe_br.cache_avail >= 7)
                                {
                                    unsafe {
                                        free_safe(precode.tree as *mut ());
                                        free_safe(precode.table as *mut ());
                                    }
                                    current_block = 1;
                                    break;
                                } else {
                                    unsafe {
                                        n = ((safe_br.cache_buffer >> safe_br.cache_avail - 7)
                                            as uint32_t
                                            & cache_masks[7 as usize])
                                            .wrapping_add(11 as i32 as u32)
                                            as i32;
                                        safe_br.cache_avail -= 7
                                    }
                                }
                                j = 0;
                                while j < n && i < ARCHIVE_RAR_DEFINED_PARAM.huffman_table_size {
                                    let fresh19 = i;
                                    i = i + 1;
                                    safe_rar.lengthtable[fresh19 as usize] = 0;
                                    j += 1
                                }
                            }
                        }
                        match current_block {
                            1 => {}
                            _ => {
                                unsafe {
                                    free_safe(precode.tree as *mut ());
                                    free_safe(precode.table as *mut ());
                                }
                                r = unsafe {
                                    create_code(
                                        a,
                                        &mut safe_rar.maincode,
                                        unsafe { &mut *(*rar).lengthtable.as_mut_ptr().offset(0) },
                                        ARCHIVE_RAR_DEFINED_PARAM.maincode_size,
                                        ARCHIVE_RAR_DEFINED_PARAM.max_symbol_length as u8,
                                    )
                                };
                                if r != ARCHIVE_RAR_DEFINED_PARAM.archive_ok {
                                    return r;
                                }
                                unsafe {
                                    r = create_code(
                                        a,
                                        &mut (*rar).offsetcode,
                                        &mut *(*rar).lengthtable.as_mut_ptr().offset(
                                            ARCHIVE_RAR_DEFINED_PARAM.maincode_size as isize,
                                        ),
                                        ARCHIVE_RAR_DEFINED_PARAM.offsetcode_size,
                                        ARCHIVE_RAR_DEFINED_PARAM.max_symbol_length as u8,
                                    )
                                };
                                if r != ARCHIVE_RAR_DEFINED_PARAM.archive_ok {
                                    return r;
                                }
                                unsafe {
                                    r = create_code(
                                        a,
                                        &mut (*rar).lowoffsetcode,
                                        &mut *(*rar).lengthtable.as_mut_ptr().offset(
                                            (ARCHIVE_RAR_DEFINED_PARAM.maincode_size
                                                + ARCHIVE_RAR_DEFINED_PARAM.offsetcode_size)
                                                as isize,
                                        ),
                                        ARCHIVE_RAR_DEFINED_PARAM.lowoffsetcode_size,
                                        ARCHIVE_RAR_DEFINED_PARAM.max_symbol_length as u8,
                                    )
                                };
                                if r != ARCHIVE_RAR_DEFINED_PARAM.archive_ok {
                                    return r;
                                }
                                unsafe {
                                    r = create_code(
                                        a,
                                        &mut (*rar).lengthcode,
                                        &mut *(*rar).lengthtable.as_mut_ptr().offset(
                                            (ARCHIVE_RAR_DEFINED_PARAM.maincode_size
                                                + ARCHIVE_RAR_DEFINED_PARAM.offsetcode_size
                                                + ARCHIVE_RAR_DEFINED_PARAM.lowoffsetcode_size)
                                                as isize,
                                        ),
                                        ARCHIVE_RAR_DEFINED_PARAM.lengthcode_size,
                                        ARCHIVE_RAR_DEFINED_PARAM.max_symbol_length as u8,
                                    )
                                };
                                if r != ARCHIVE_RAR_DEFINED_PARAM.archive_ok {
                                    return r;
                                }
                                current_block = 4;
                            }
                        }
                    }
                }
            }
        }
        match current_block {
            1 => {}
            _ => {
                if safe_rar.dictionary_size == 0 || safe_rar.lzss.window.is_null() {
                    /* Seems as though dictionary sizes are not used. Even so, minimize
                     * memory usage as much as possible.
                     */
                    let mut new_window: *mut () = 0 as *mut ();
                    let mut new_size: u32 = 0;
                    if safe_rar.unp_size >= ARCHIVE_RAR_DEFINED_PARAM.dictionary_max_size as i64 {
                        new_size = ARCHIVE_RAR_DEFINED_PARAM.dictionary_max_size as u32
                    } else {
                        new_size = (rar_fls(safe_rar.unp_size as u32) << 1) as u32
                    }
                    if new_size == 0 {
                        archive_set_error_safe!(
                            &mut (*a).archive as *mut archive,
                            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                            b"Zero window size is invalid.\x00" as *const u8
                        );
                        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                    }
                    new_window =
                        unsafe { realloc_safe(safe_rar.lzss.window as *mut (), new_size as u64) };
                    if new_window.is_null() {
                        archive_set_error_safe!(
                            &mut (*a).archive as *mut archive,
                            ARCHIVE_RAR_DEFINED_PARAM.enomem,
                            b"Unable to allocate memory for uncompressed data.\x00" as *const u8
                                as *const u8
                        );
                        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                    }
                    safe_rar.lzss.window = new_window as *mut u8;
                    safe_rar.dictionary_size = new_size;
                    unsafe {
                        memset_safe(
                            safe_rar.lzss.window as *mut (),
                            0,
                            safe_rar.dictionary_size as u64,
                        )
                    };
                    safe_rar.lzss.mask = safe_rar.dictionary_size.wrapping_sub(1) as i32
                }
                safe_rar.start_new_table = 0;
                return ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
            }
        }
    }
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
        b"Truncated RAR file data\x00" as *const u8
    );
    safe_rar.valid = 0;
    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
}

fn free_codes(a: *mut archive_read) {
    let rar: *mut rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    unsafe {
        free_safe(safe_rar.maincode.tree as *mut ());
        free_safe(safe_rar.offsetcode.tree as *mut ());
        free_safe(safe_rar.lowoffsetcode.tree as *mut ());
        free_safe(safe_rar.lengthcode.tree as *mut ());
        free_safe(safe_rar.maincode.table as *mut ());
        free_safe(safe_rar.offsetcode.table as *mut ());
        free_safe(safe_rar.lowoffsetcode.table as *mut ());
        free_safe(safe_rar.lengthcode.table as *mut ());
    }
    unsafe {
        memset_safe(
            &mut safe_rar.maincode as *mut huffman_code as *mut (),
            0,
            size_of::<huffman_code>() as u64,
        );
        memset_safe(
            &mut safe_rar.offsetcode as *mut huffman_code as *mut (),
            0,
            size_of::<huffman_code>() as u64,
        );
        memset_safe(
            &mut safe_rar.lowoffsetcode as *mut huffman_code as *mut (),
            0,
            size_of::<huffman_code>() as u64,
        );
        memset_safe(
            &mut safe_rar.lengthcode as *mut huffman_code as *mut (),
            0,
            size_of::<huffman_code>() as u64,
        )
    };
}

fn read_next_symbol(a: *mut archive_read, code: *mut huffman_code) -> i32 {
    let mut bit: u8 = 0;
    let mut bits: u32 = 0;
    let mut length: i32 = 0;
    let mut value: i32 = 0;
    let mut node: i32 = 0;
    let mut rar: *mut rar = 0 as *mut rar;
    let mut br: *mut rar_br = 0 as *mut rar_br;
    let safe_code = unsafe { &mut *code };
    if safe_code.table.is_null() {
        if unsafe { make_table(a, code) } != ARCHIVE_RAR_DEFINED_PARAM.archive_ok {
            return -(1);
        }
    }
    rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    br = &mut safe_rar.br;
    let safe_br = unsafe { &mut *br };
    /* Look ahead (peek) at bits */
    if !(safe_br.cache_avail >= safe_code.tablesize
        || rar_br_fillup(a, br) != 0
        || safe_br.cache_avail >= safe_code.tablesize)
    {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Truncated RAR file data\x00" as *const u8
        );
        safe_rar.valid = 0;
        return -(1);
    }
    unsafe {
        bits = (safe_br.cache_buffer >> safe_br.cache_avail - safe_code.tablesize) as uint32_t
            & cache_masks[safe_code.tablesize as usize]
    };
    unsafe {
        length = (*(*code).table.offset(bits as isize)).length as i32;
        value = (*(*code).table.offset(bits as isize)).value;
    }
    if length < 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid prefix code in bitstream\x00" as *const u8
        );
        return -(1);
    }
    if length <= safe_code.tablesize {
        /* Skip length bits */
        safe_br.cache_avail -= length;
        return value;
    }
    /* Skip tablesize bits */
    safe_br.cache_avail -= safe_code.tablesize;
    node = value;
    while unsafe {
        !((*(*code).tree.offset(node as isize)).branches[0 as usize]
            == (*(*code).tree.offset(node as isize)).branches[1 as usize])
    } {
        if !(safe_br.cache_avail >= 1 || rar_br_fillup(a, br) != 0 || safe_br.cache_avail >= 1) {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"Truncated RAR file data\x00" as *const u8
            );
            safe_rar.valid = 0;
            return -(1);
        }
        unsafe {
            bit = ((safe_br.cache_buffer >> safe_br.cache_avail - 1) as uint32_t
                & cache_masks[1 as usize]) as u8
        };
        safe_br.cache_avail -= 1;
        if unsafe { (*(*code).tree.offset(node as isize)).branches[bit as usize] < 0 } {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"Invalid prefix code in bitstream\x00" as *const u8
            );
            return -(1);
        }
        unsafe { node = (*(*code).tree.offset(node as isize)).branches[bit as usize] }
    }
    return unsafe { (*(*code).tree.offset(node as isize)).branches[0 as usize] };
}

fn create_code(
    a: *mut archive_read,
    code: *mut huffman_code,
    lengths: *mut u8,
    numsymbols: i32,
    maxlength: u8,
) -> i32 {
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut codebits: i32 = 0;
    let mut symbolsleft: i32 = numsymbols;
    let safe_code = unsafe { &mut *code };
    safe_code.numentries = 0;
    safe_code.numallocatedentries = 0;
    if unsafe { new_node(code) } < 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.enomem,
            b"Unable to allocate memory for node data.\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    safe_code.numentries = 1;
    safe_code.minlength = 21474836472 as i64 as i32;
    safe_code.maxlength = -2147483647 - 1;
    codebits = 0;
    i = 1;
    while i <= maxlength as i32 {
        j = 0;
        while j < numsymbols {
            if unsafe { !(*lengths.offset(j as isize) as i32 != i) } {
                if unsafe {
                    add_value(a, code, j, codebits, i) != ARCHIVE_RAR_DEFINED_PARAM.archive_ok
                } {
                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
                }
                codebits += 1;
                symbolsleft -= 1;
                if symbolsleft <= 0 {
                    break;
                }
            }
            j += 1
        }
        if symbolsleft <= 0 {
            break;
        }
        codebits <<= 1;
        i += 1
    }
    return ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
}

fn add_value(
    a: *mut archive_read,
    code: *mut huffman_code,
    value: i32,
    codebits: i32,
    length: i32,
) -> i32 {
    let mut lastnode: i32 = 0;
    let mut bitpos: i32 = 0;
    let mut bit: i32 = 0;
    let safe_code = unsafe { &mut *code };
    /* int repeatpos, repeatnode, nextnode; */
    unsafe { free_safe(safe_code.table as *mut ()) };
    safe_code.table = 0 as *mut huffman_table_entry;
    if length > safe_code.maxlength {
        safe_code.maxlength = length
    }
    if length < safe_code.minlength {
        safe_code.minlength = length
    }
    /*
     * Dead code, repeatpos was is -1
     *
    repeatpos = -1;
    if (repeatpos == 0 || (repeatpos >= 0
      && (((codebits >> (repeatpos - 1)) & 3) == 0
      || ((codebits >> (repeatpos - 1)) & 3) == 3)))
    {
      archive_set_error_safe!(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
                        "Invalid repeat position");
      return (ARCHIVE_FATAL);
    }
    */
    lastnode = 0;
    bitpos = length - 1;
    while bitpos >= 0 {
        bit = codebits >> bitpos & 1;
        /* } */
        if unsafe {
            (*(*code).tree.offset(lastnode as isize)).branches[0 as usize]
                == (*(*code).tree.offset(lastnode as isize)).branches[1 as usize]
        } {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"Prefix found\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
        if unsafe { (*(*code).tree.offset(lastnode as isize)).branches[bit as usize] < 0 } {
            if unsafe { new_node(code) } < 0 {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR_DEFINED_PARAM.enomem,
                    b"Unable to allocate memory for node data.\x00" as *const u8
                );
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
            }
            let fresh20 = safe_code.numentries;
            safe_code.numentries = safe_code.numentries + 1;
            unsafe { (*(*code).tree.offset(lastnode as isize)).branches[bit as usize] = fresh20 }
        }
        unsafe { lastnode = (*(*code).tree.offset(lastnode as isize)).branches[bit as usize] };
        bitpos -= 1
    }
    if unsafe {
        !((*(*code).tree.offset(lastnode as isize)).branches[0 as usize] == -(1)
            && (*(*code).tree.offset(lastnode as isize)).branches[1 as usize] == -(2))
    } {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Prefix found\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    /* Leaf node check */
    /*
     * Dead code, repeatpos was -1, bitpos >=0
     *
    if (bitpos == repeatpos)
    {
      * Open branch check *
      if (!(code->tree[lastnode].branches[bit] < 0))
      {
        archive_set_error_safe!(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
                          "Invalid repeating code");
        return (ARCHIVE_FATAL);
      }

      if ((repeatnode = new_node(code)) < 0) {
        archive_set_error_safe!(&a->archive, ENOMEM,
                          "Unable to allocate memory for node data.");
        return (ARCHIVE_FATAL);
      }
      if ((nextnode = new_node(code)) < 0) {
        archive_set_error_safe!(&a->archive, ENOMEM,
                          "Unable to allocate memory for node data.");
        return (ARCHIVE_FATAL);
      }

      * Set branches *
      code->tree[lastnode].branches[bit] = repeatnode;
      code->tree[repeatnode].branches[bit] = repeatnode;
      code->tree[repeatnode].branches[bit^1] = nextnode;
      lastnode = nextnode;

      bitpos++; * terminating bit already handled, skip it *
    }
    else
    {
    */
    /* Open branch check */
    /* set to branch */
    /* Set leaf value */
    unsafe {
        (*(*code).tree.offset(lastnode as isize)).branches[0 as usize] = value;
        (*(*code).tree.offset(lastnode as isize)).branches[1 as usize] = value;
    }
    return ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
}

fn new_node(code: *mut huffman_code) -> i32 {
    let mut new_tree: *mut () = 0 as *mut ();
    let safe_code = unsafe { &mut *code };
    if safe_code.numallocatedentries == safe_code.numentries {
        let mut new_num_entries: i32 = 256;
        if safe_code.numentries > 0 {
            new_num_entries = safe_code.numentries * 2
        }
        new_tree = unsafe {
            realloc_safe(
                safe_code.tree as *mut (),
                (new_num_entries as u64).wrapping_mul(size_of::<huffman_tree_node>() as u64),
            )
        };
        if new_tree.is_null() {
            return -1;
        }
        safe_code.tree = new_tree as *mut huffman_tree_node;
        safe_code.numallocatedentries = new_num_entries
    }
    unsafe {
        (*(*code).tree.offset((*code).numentries as isize)).branches[0 as usize] = -(1);
        (*(*code).tree.offset((*code).numentries as isize)).branches[1 as usize] = -(2);
    }
    return 1;
}

fn make_table(a: *mut archive_read, code: *mut huffman_code) -> i32 {
    let safe_code = unsafe { &mut *code };
    if safe_code.maxlength < safe_code.minlength || safe_code.maxlength > 10 {
        safe_code.tablesize = 10
    } else {
        safe_code.tablesize = safe_code.maxlength
    }
    safe_code.table = unsafe {
        calloc_safe(
            1,
            (size_of::<huffman_table_entry>() as u64).wrapping_mul((1) << safe_code.tablesize),
        ) as *mut huffman_table_entry
    };
    return unsafe { make_table_recurse(a, code, 0, safe_code.table, 0, safe_code.tablesize) };
}

fn make_table_recurse(
    a: *mut archive_read,
    code: *mut huffman_code,
    node: i32,
    table: *mut huffman_table_entry,
    depth: i32,
    maxdepth: i32,
) -> i32 {
    let mut currtablesize: i32 = 0;
    let mut i: i32 = 0;
    let mut ret: i32 = ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
    let safe_code = unsafe { &mut *code };
    if safe_code.tree.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Huffman tree was not created.\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    if node < 0 || node >= safe_code.numentries {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid location to Huffman tree specified.\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    currtablesize = (1) << maxdepth - depth;
    if unsafe {
        (*(*code).tree.offset(node as isize)).branches[0 as usize]
            == (*(*code).tree.offset(node as isize)).branches[1 as usize]
    } {
        i = 0;
        while i < currtablesize {
            unsafe {
                (*table.offset(i as isize)).length = depth as u32;
                (*table.offset(i as isize)).value =
                    (*(*code).tree.offset(node as isize)).branches[0 as usize];
            }
            i += 1
        }
    } else if depth == maxdepth {
        unsafe {
            (*table.offset(0)).length = (maxdepth + 1) as u32;
            (*table.offset(0)).value = node
        }
    } else {
        ret |= make_table_recurse(
            a,
            code,
            unsafe { (*(*code).tree.offset(node as isize)).branches[0 as usize] },
            table,
            depth + 1,
            maxdepth,
        );
        ret |= make_table_recurse(
            a,
            code,
            unsafe { (*(*code).tree.offset(node as isize)).branches[1 as usize] },
            unsafe { table.offset((currtablesize / 2) as isize) },
            depth + 1,
            maxdepth,
        )
    }
    return ret;
}
/*
 * Dead code, node >= 0
 *
else if (node < 0)
{
  for(i = 0; i < currtablesize; i++)
    table[i].length = -1;
}
 */
// Initialized in run_static_initializers
static mut lengthb_min: i32 = 0;
// Initialized in run_static_initializers
static mut offsetb_min: i32 = 0;

fn expand(a: *mut archive_read, mut end: int64_t) -> int64_t {
    let current_block: u64;
    static mut lengthbases: [u8; 28] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112,
        128, 160, 192, 224,
    ];
    static mut lengthbits: [u8; 28] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
    ];
    static mut offsetbases: [u32; 60] = [
        0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
        2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072,
        196608, 262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968,
        917504, 983040, 1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584,
        3145728, 3407872, 3670016, 3932160,
    ];
    static mut offsetbits: [u8; 60] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18,
        18, 18, 18, 18, 18, 18, 18, 18, 18,
    ];
    static mut shortbases: [u8; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
    static mut shortbits: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];
    let mut symbol: i32 = 0;
    let mut offs: i32 = 0;
    let mut len: i32 = 0;
    let mut offsindex: i32 = 0;
    let mut lensymbol: i32 = 0;
    let mut i: i32 = 0;
    let mut offssymbol: i32 = 0;
    let mut lowoffsetsymbol: i32 = 0;
    let mut newfile: u8 = 0;
    let rar: *mut rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    let br: *mut rar_br = &mut safe_rar.br;
    let safe_br = unsafe { &mut *br };
    if safe_rar.filterstart < end {
        end = safe_rar.filterstart
    }
    loop {
        if safe_rar.output_last_match as i32 != 0
            && lzss_position(&mut safe_rar.lzss) + safe_rar.lastlength as i64 <= end
        {
            lzss_emit_match(rar, safe_rar.lastoffset as i32, safe_rar.lastlength as i32);
            safe_rar.output_last_match = 0
        }
        if safe_rar.is_ppmd_block as i32 != 0
            || safe_rar.output_last_match as i32 != 0
            || lzss_position(&mut safe_rar.lzss) >= end
        {
            return lzss_position(&mut safe_rar.lzss);
        }
        symbol = read_next_symbol(a, &mut safe_rar.maincode);
        if symbol < 0 {
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal as int64_t;
        }
        safe_rar.output_last_match = 0;
        if symbol < 256 {
            lzss_emit_literal(rar, symbol as uint8_t);
        } else if symbol == 256 {
            if !(safe_br.cache_avail >= 1 || rar_br_fillup(a, br) != 0 || safe_br.cache_avail >= 1)
            {
                current_block = 1;
                break;
            }
            unsafe {
                newfile = ((safe_br.cache_buffer >> safe_br.cache_avail - 1) as uint32_t
                    & cache_masks[1 as usize]
                    == 0) as i32 as u8
            };
            safe_br.cache_avail -= 1;
            if newfile != 0 {
                safe_rar.start_new_block = 1;
                if !(safe_br.cache_avail >= 1
                    || rar_br_fillup(a, br) != 0
                    || safe_br.cache_avail >= 1)
                {
                    current_block = 1;
                    break;
                }
                unsafe {
                    safe_rar.start_new_table =
                        ((safe_br.cache_buffer >> safe_br.cache_avail - 1) as uint32_t
                            & cache_masks[1 as usize]) as u8
                };
                safe_br.cache_avail -= 1;
                return lzss_position(&mut safe_rar.lzss);
            } else if parse_codes(a) != ARCHIVE_RAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal as int64_t;
            }
        } else if symbol == 257 {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_misc,
                b"Parsing filters is unsupported.\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_failed as int64_t;
        } else {
            if symbol == 258 {
                if safe_rar.lastlength == 0 {
                    continue;
                }
                offs = safe_rar.lastoffset as i32;
                len = safe_rar.lastlength as i32
            } else if symbol <= 262 {
                offsindex = symbol - 259;
                offs = safe_rar.oldoffset[offsindex as usize] as i32;
                lensymbol = read_next_symbol(a, &mut safe_rar.lengthcode);
                if lensymbol < 0 {
                    current_block = 2;
                    break;
                }
                if unsafe { lensymbol > lengthb_min } {
                    current_block = 2;
                    break;
                }
                unsafe { len = lengthbases[lensymbol as usize] as i32 + 2 };
                if unsafe { lengthbits[lensymbol as usize] as i32 > 0 } {
                    if unsafe {
                        !(safe_br.cache_avail >= lengthbits[lensymbol as usize] as i32
                            || rar_br_fillup(a, br) != 0
                            || safe_br.cache_avail >= lengthbits[lensymbol as usize] as i32)
                    } {
                        current_block = 1;
                        break;
                    }
                    unsafe {
                        len = (len as u32).wrapping_add(
                            (safe_br.cache_buffer
                                >> safe_br.cache_avail - lengthbits[lensymbol as usize] as i32)
                                as uint32_t
                                & cache_masks[lengthbits[lensymbol as usize] as usize],
                        ) as i32 as i32
                    };
                    unsafe { safe_br.cache_avail -= lengthbits[lensymbol as usize] as i32 }
                }
                i = offsindex;
                while i > 0 {
                    unsafe {
                        safe_rar.oldoffset[i as usize] = safe_rar.oldoffset[(i - 1) as usize]
                    };
                    i -= 1
                }
                unsafe { safe_rar.oldoffset[0 as usize] = offs as u32 }
            } else if symbol <= 270 {
                unsafe { offs = shortbases[(symbol - 263) as usize] as i32 + 1 };
                if unsafe { shortbits[(symbol - 263) as usize] as i32 > 0 } {
                    if unsafe {
                        !(safe_br.cache_avail >= shortbits[(symbol - 263) as usize] as i32
                            || rar_br_fillup(a, br) != 0
                            || safe_br.cache_avail >= shortbits[(symbol - 263) as usize] as i32)
                    } {
                        current_block = 1;
                        break;
                    }
                    unsafe {
                        offs = (offs as u32).wrapping_add(
                            (safe_br.cache_buffer
                                >> safe_br.cache_avail - shortbits[(symbol - 263) as usize] as i32)
                                as uint32_t
                                & cache_masks[shortbits[(symbol - 263) as usize] as usize],
                        ) as i32 as i32
                    };
                    unsafe { safe_br.cache_avail -= shortbits[(symbol - 263) as usize] as i32 }
                }
                len = 2;
                i = 3;
                while i > 0 {
                    safe_rar.oldoffset[i as usize] = safe_rar.oldoffset[(i - 1) as usize];
                    i -= 1
                }
                safe_rar.oldoffset[0 as usize] = offs as u32
            } else {
                if unsafe { symbol - 271 > lengthb_min } {
                    current_block = 2;
                    break;
                }
                unsafe { len = lengthbases[(symbol - 271) as usize] as i32 + 3 };
                if unsafe { lengthbits[(symbol - 271) as usize] as i32 > 0 } {
                    if unsafe {
                        !(safe_br.cache_avail >= lengthbits[(symbol - 271) as usize] as i32
                            || rar_br_fillup(a, br) != 0
                            || (*br).cache_avail >= lengthbits[(symbol - 271) as usize] as i32)
                    } {
                        current_block = 1;
                        break;
                    }
                    unsafe {
                        len = (len as u32).wrapping_add(
                            (safe_br.cache_buffer
                                >> safe_br.cache_avail - lengthbits[(symbol - 271) as usize] as i32)
                                as uint32_t
                                & cache_masks[lengthbits[(symbol - 271) as usize] as usize],
                        ) as i32 as i32
                    };
                    unsafe { safe_br.cache_avail -= lengthbits[(symbol - 271) as usize] as i32 }
                }
                offssymbol = read_next_symbol(a, &mut safe_rar.offsetcode);
                if offssymbol < 0 {
                    current_block = 2;
                    break;
                }
                if unsafe { offssymbol > offsetb_min } {
                    current_block = 2;
                    break;
                }
                unsafe { offs = offsetbases[offssymbol as usize].wrapping_add(1) as i32 };
                unsafe {
                    if offsetbits[offssymbol as usize] as i32 > 0 {
                        if offssymbol > 9 {
                            if offsetbits[offssymbol as usize] as i32 > 4 {
                                if !(safe_br.cache_avail
                                    >= offsetbits[offssymbol as usize] as i32 - 4
                                    || rar_br_fillup(a, br) != 0
                                    || safe_br.cache_avail
                                        >= offsetbits[offssymbol as usize] as i32 - 4)
                                {
                                    current_block = 1;
                                    break;
                                }
                                offs = (offs as u32).wrapping_add(
                                    ((safe_br.cache_buffer
                                        >> safe_br.cache_avail
                                            - (offsetbits[offssymbol as usize] as i32 - 4))
                                        as uint32_t
                                        & cache_masks[(offsetbits[offssymbol as usize] as i32 - 4)
                                            as usize])
                                        << 4,
                                ) as i32 as i32;
                                safe_br.cache_avail -= offsetbits[offssymbol as usize] as i32 - 4
                            }
                            if safe_rar.numlowoffsetrepeats > 0 {
                                safe_rar.numlowoffsetrepeats =
                                    safe_rar.numlowoffsetrepeats.wrapping_sub(1);
                                offs =
                                    (offs as u32).wrapping_add(safe_rar.lastlowoffset) as i32 as i32
                            } else {
                                lowoffsetsymbol = read_next_symbol(a, &mut safe_rar.lowoffsetcode);
                                if lowoffsetsymbol < 0 {
                                    return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal as int64_t;
                                }
                                if lowoffsetsymbol == 16 {
                                    safe_rar.numlowoffsetrepeats = 15;
                                    offs = (offs as u32).wrapping_add(safe_rar.lastlowoffset) as i32
                                        as i32
                                } else {
                                    offs += lowoffsetsymbol;
                                    safe_rar.lastlowoffset = lowoffsetsymbol as u32
                                }
                            }
                        } else {
                            if !(safe_br.cache_avail >= offsetbits[offssymbol as usize] as i32
                                || rar_br_fillup(a, br) != 0
                                || safe_br.cache_avail >= offsetbits[offssymbol as usize] as i32)
                            {
                                current_block = 1;
                                break;
                            }
                            offs = (offs as u32).wrapping_add(
                                (safe_br.cache_buffer
                                    >> safe_br.cache_avail - offsetbits[offssymbol as usize] as i32)
                                    as uint32_t
                                    & cache_masks[offsetbits[offssymbol as usize] as usize],
                            ) as i32 as i32;
                            safe_br.cache_avail -= offsetbits[offssymbol as usize] as i32
                        }
                    }
                }
                if offs >= 0x40000 as i32 {
                    len += 1
                }
                if offs >= 0x2000 as i32 {
                    len += 1
                }
                i = 3;
                while i > 0 {
                    safe_rar.oldoffset[i as usize] = safe_rar.oldoffset[(i - 1) as usize];
                    i -= 1
                }
                safe_rar.oldoffset[0 as usize] = offs as u32
            }
            safe_rar.lastoffset = offs as u32;
            safe_rar.lastlength = len as u32;
            safe_rar.output_last_match = 1
        }
    }
    match current_block {
        2 => {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"Bad RAR file data\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal as int64_t;
        }
        _ => {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"Truncated RAR file data\x00" as *const u8
            );
            safe_rar.valid = 0;
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal as int64_t;
        }
    };
}

fn copy_from_lzss_window(
    a: *mut archive_read,
    buffer: *mut *const (),
    startpos: int64_t,
    length: i32,
) -> i32 {
    let mut windowoffs: i32 = 0;
    let mut firstpart: i32 = 0;
    let rar: *mut rar = unsafe { (*(*a).format).data as *mut rar };
    let safe_rar = unsafe { &mut *rar };
    let safe_buffer = unsafe { &mut *buffer };
    if safe_rar.unp_buffer.is_null() {
        safe_rar.unp_buffer = unsafe { malloc_safe(safe_rar.unp_buffer_size as u64) as *mut u8 };
        if safe_rar.unp_buffer.is_null() {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.enomem,
                b"Unable to allocate memory for uncompressed data.\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
    }
    windowoffs = lzss_offset_for_position(&mut safe_rar.lzss, startpos);
    if windowoffs + length <= lzss_size(&mut safe_rar.lzss) {
        unsafe {
            memcpy_safe(
                unsafe {
                    &mut *(*rar).unp_buffer.offset(safe_rar.unp_offset as isize) as *mut u8
                        as *mut ()
                },
                unsafe {
                    &mut *(*rar).lzss.window.offset(windowoffs as isize) as *mut u8 as *const ()
                },
                length as u64,
            )
        };
    } else if length <= lzss_size(&mut safe_rar.lzss) {
        firstpart = lzss_size(&mut safe_rar.lzss) - windowoffs;
        if firstpart < 0 {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
                b"Bad RAR file data\x00" as *const u8
            );
            return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
        }
        if firstpart < length {
            unsafe {
                memcpy_safe(
                    unsafe {
                        &mut *(*rar).unp_buffer.offset(safe_rar.unp_offset as isize) as *mut u8
                            as *mut ()
                    },
                    unsafe {
                        &mut *(*rar).lzss.window.offset(windowoffs as isize) as *mut u8 as *const ()
                    },
                    firstpart as u64,
                );
                memcpy_safe(
                    unsafe {
                        &mut *(*rar)
                            .unp_buffer
                            .offset(safe_rar.unp_offset.wrapping_add(firstpart as u32) as isize)
                            as *mut u8 as *mut ()
                    },
                    unsafe { &mut *(*rar).lzss.window.offset(0) as *mut u8 as *const () },
                    (length - firstpart) as u64,
                );
            }
        } else {
            unsafe {
                memcpy_safe(
                    unsafe {
                        &mut *(*rar).unp_buffer.offset(safe_rar.unp_offset as isize) as *mut u8
                            as *mut ()
                    },
                    unsafe {
                        &mut *(*rar).lzss.window.offset(windowoffs as isize) as *mut u8 as *const ()
                    },
                    length as u64,
                )
            };
        }
    } else {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR_DEFINED_PARAM.archive_errno_file_format,
            b"Bad RAR file data\x00" as *const u8
        );
        return ARCHIVE_RAR_DEFINED_PARAM.archive_fatal;
    }
    safe_rar.unp_offset = safe_rar.unp_offset.wrapping_add(length as u32);
    if safe_rar.unp_offset >= safe_rar.unp_buffer_size {
        *safe_buffer = safe_rar.unp_buffer as *const ()
    } else {
        *safe_buffer = 0 as *const ()
    }
    return ARCHIVE_RAR_DEFINED_PARAM.archive_ok;
}

fn rar_read_ahead(a: *mut archive_read, min: size_t, avail: *mut ssize_t) -> *const () {
    let rar: *mut rar = unsafe { (*(*a).format).data as *mut rar };
    let h: *const () = unsafe { __archive_read_ahead_safe(a, min, avail) };
    let mut ret: i32 = 0;
    let safe_a = unsafe { &mut *a };
    let safe_rar = unsafe { &mut *rar };
    let safe_avail = unsafe { &mut *avail };
    if !avail.is_null() {
        if safe_a.archive.read_data_is_posix_read as i32 != 0
            && *safe_avail > safe_a.archive.read_data_requested as ssize_t
        {
            *safe_avail = safe_a.archive.read_data_requested as ssize_t
        }
        if *safe_avail > safe_rar.bytes_remaining {
            *safe_avail = safe_rar.bytes_remaining
        }
        if *safe_avail < 0 {
            return 0 as *const ();
        } else {
            if *safe_avail == 0
                && safe_rar.main_flags & ARCHIVE_RAR_DEFINED_PARAM.mhd_volume as u32 != 0
                && safe_rar.file_flags & ARCHIVE_RAR_DEFINED_PARAM.fhd_split_after as u32 != 0
            {
                safe_rar.filename_must_match = 1;
                ret = archive_read_format_rar_read_header(a, safe_a.entry);
                if ret == ARCHIVE_RAR_DEFINED_PARAM.archive_eof {
                    safe_rar.has_endarc_header = 1;
                    ret = archive_read_format_rar_read_header(a, safe_a.entry)
                }
                safe_rar.filename_must_match = 0;
                if ret != ARCHIVE_RAR_DEFINED_PARAM.archive_ok {
                    return 0 as *const ();
                }
                return rar_read_ahead(a, min, avail);
            }
        }
    }
    return h;
}

fn run_static_initializers() {
    unsafe {
        lengthb_min = (size_of::<[u8; 28]>() as u64).wrapping_div(size_of::<u8>() as u64) as i32
    }
    unsafe {
        offsetb_min = if ((size_of::<[u32; 60]>() as u64).wrapping_div(size_of::<u32>() as u64)
            as i32)
            < (size_of::<[u8; 60]>() as u64).wrapping_div(size_of::<u8>() as u64) as i32
        {
            (size_of::<[u32; 60]>() as u64).wrapping_div(size_of::<u32>() as u64) as i32
        } else {
            (size_of::<[u8; 60]>() as u64).wrapping_div(size_of::<u8>() as u64) as i32
        }
    }
}

#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe fn(); 1] = [run_static_initializers];

#[no_mangle]
fn archive_test_make_table_recurse(_a: *mut archive) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut huffman_code: *mut huffman_code = 0 as *mut huffman_code;
    huffman_code = unsafe { calloc_safe(1, size_of::<huffman_code>() as u64) } as *mut huffman_code;
    let mut huffman_table_entry: *mut huffman_table_entry = 0 as *mut huffman_table_entry;
    huffman_table_entry = unsafe { calloc_safe(1, size_of::<huffman_table_entry>() as u64) }
        as *mut huffman_table_entry;
    make_table_recurse(a, huffman_code, 0, huffman_table_entry, 0, 0);
}

#[no_mangle]
fn archive_test_rar_br_preparation(_a: *mut archive) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut rar: *mut rar = 0 as *mut rar;
    rar = unsafe { calloc_safe(1, size_of::<rar>() as u64) } as *mut rar;
    unsafe {
        (*rar).bytes_remaining = 1;
    }
    let mut rar_br: *mut rar_br = 0 as *mut rar_br;
    rar_br = unsafe { calloc_safe(1, size_of::<rar_br>() as u64) } as *mut rar_br;
    unsafe {
        (*rar_br).avail_in = -1;
    }
    unsafe {
        (*(*a).format).data = rar as *mut ();
    }
    rar_br_preparation(a, rar_br);
}

#[no_mangle]
fn archive_test_rar_skip_sfx(_a: *mut archive) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut archive_read_filter: *mut archive_read_filter = 0 as *mut archive_read_filter;
    archive_read_filter = unsafe { calloc_safe(1, size_of::<archive_read_filter>() as u64) }
        as *mut archive_read_filter;
    unsafe {
        (*archive_read_filter).fatal = 'a' as u8;
    }
    unsafe {
        (*a).filter = archive_read_filter as *mut archive_read_filter;
    }
    skip_sfx(a);
}

#[no_mangle]
fn archive_test_archive_read_format_rar_options(_a: *mut archive) {
    let a: *mut archive_read = _a as *mut archive_read;
    archive_read_format_rar_options(
        a,
        b"hdrcharset\x00" as *const u8,
        b"hdrcharset\x00" as *const u8,
    );
}

#[no_mangle]
fn archive_test_archive_read_format_rar_read_data(
    _a: *mut archive,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut rar: *mut rar = 0 as *mut rar;
    rar = unsafe { calloc_safe(1, size_of::<rar>() as u64) } as *mut rar;
    unsafe {
        (*(*a).format).data = rar as *mut ();
    }
    archive_read_format_rar_read_data(a, buff, size, offset);
    unsafe {
        (*rar).offset_seek = 1;
    }
    unsafe {
        (*rar).unp_size = 2;
    }
    unsafe {
        (*(*a).format).data = rar as *mut ();
    }
    archive_read_format_rar_read_data(a, buff, size, offset);
}

#[no_mangle]
fn archive_test_archive_read_format_rar_seek_data(_a: *mut archive) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut rar: *mut rar = 0 as *mut rar;
    rar = unsafe { calloc_safe(1, size_of::<rar>() as u64) } as *mut rar;
    unsafe {
        (*rar).compression_method = 0x31;
    }
    unsafe {
        (*(*a).format).data = rar as *mut ();
    }
    archive_read_format_rar_seek_data(a, 1, 1);
}

#[no_mangle]
fn archive_test_read_data_stored(
    _a: *mut archive,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut rar: *mut rar = 0 as *mut rar;
    rar = unsafe { calloc_safe(1, size_of::<rar>() as u64) } as *mut rar;
    unsafe {
        (*rar).bytes_remaining = 0;
    }
    unsafe {
        (*rar).main_flags = 1;
    }
    unsafe {
        (*(*a).format).data = rar as *mut ();
    }
    read_data_stored(a, buff, size, offset);
    unsafe {
        (*rar).file_crc = 1;
    }
    unsafe {
        (*rar).crc_calculated = 2;
    }
    unsafe {
        (*(*a).format).data = rar as *mut ();
    }
    read_data_stored(a, buff, size, offset);
}

#[no_mangle]
fn archive_test_copy_from_lzss_window(
    _a: *mut archive,
    buffer: *mut *const (),
    startpos: int64_t,
    length: i32,
) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut rar: *mut rar = 0 as *mut rar;
    rar = unsafe { calloc_safe(1, size_of::<rar>() as u64) } as *mut rar;
    unsafe {
        (*rar).lzss.mask = 1;
    }
    copy_from_lzss_window(a, buffer, startpos, length);
}
