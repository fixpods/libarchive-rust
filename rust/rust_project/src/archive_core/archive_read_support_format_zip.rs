use super::archive_string::archive_string_default_conversion_for_read;
use archive_core::archive_endian::*;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;
use std::mem::size_of;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct obj0 {
    pub first: *mut archive_read_passphrase,
    pub last: *mut *mut archive_read_passphrase,
    pub candidate: i32,
    pub callback: Option<archive_passphrase_callback>,
    pub client_data: *mut (),
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct zip {
    pub format_name: archive_string,
    pub central_directory_offset: int64_t,
    pub central_directory_offset_adjusted: int64_t,
    pub central_directory_entries_total: size_t,
    pub central_directory_entries_on_this_disk: size_t,
    pub has_encrypted_entries: i32,
    pub zip_entries: *mut zip_entry,
    pub tree: archive_rb_tree,
    pub tree_rsrc: archive_rb_tree,
    pub unconsumed: size_t,
    pub entry: *mut zip_entry,
    pub entry_bytes_remaining: int64_t,
    pub entry_compressed_bytes_read: int64_t,
    pub entry_uncompressed_bytes_read: int64_t,
    pub entry_crc32: u64,
    pub crc32func: Option<unsafe fn(_: u64, _: *const (), _: size_t) -> u64>,
    pub ignore_crc32: u8,
    pub decompress_init: u8,
    pub end_of_entry: u8,
    pub uncompressed_buffer: *mut u8,
    pub uncompressed_buffer_size: size_t,

    #[cfg(HAVE_ZLIB_H)]
    pub stream: z_stream,
    #[cfg(HAVE_ZLIB_H)]
    pub stream_valid: u8,
    #[cfg(all(HAVE_ZLIB_H, HAVE_LIBLZMA))]
    pub zipx_lzma_stream: lzma_stream,
    #[cfg(all(HAVE_ZLIB_H, HAVE_LIBLZMA))]
    pub zipx_lzma_valid: u8,
    #[cfg(HAVE_BZLIB_H)]
    pub bzstream: bz_stream,
    #[cfg(HAVE_BZLIB_H)]
    pub bzstream_valid: u8,

    pub zipx_ppmd_stream: IByteIn,
    pub zipx_ppmd_read_compressed: ssize_t,
    pub ppmd8: CPpmd8,
    pub ppmd8_valid: u8,
    pub ppmd8_stream_failed: u8,
    pub sconv: *mut archive_string_conv,
    pub sconv_default: *mut archive_string_conv,
    pub sconv_utf8: *mut archive_string_conv,
    pub init_default_conversion: i32,
    pub process_mac_extensions: i32,
    pub init_decryption: u8,
    pub decrypted_buffer: *mut u8,
    pub decrypted_ptr: *mut u8,
    pub decrypted_buffer_size: size_t,
    pub decrypted_bytes_remaining: size_t,
    pub decrypted_unconsumed_bytes: size_t,
    pub tctx: trad_enc_ctx,
    pub tctx_valid: u8,
    pub cctx: archive_crypto_ctx,
    pub cctx_valid: u8,
    pub hctx: archive_hmac_sha1_ctx,
    pub hctx_valid: u8,
    pub iv_size: u32,
    pub alg_id: u32,
    pub bit_len: u32,
    pub flags: u32,
    pub erd_size: u32,
    pub v_size: u32,
    pub v_crc32: u32,
    pub iv: *mut uint8_t,
    pub erd: *mut uint8_t,
    pub v_data: *mut uint8_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct obj2 {
    pub id: i32,
    pub name: *const u8,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct _alone_header {
    pub bytes: [uint8_t; 5],
    pub uncompressed_size: uint64_t,
}

fn ppmd_read(p: *mut ()) -> Byte {
    /* Get the handle to current decompression context. */

    let a: *mut archive_read = unsafe { (*(p as *mut IByteIn)).a };
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let safe_p = unsafe { &mut *p };
    let safe_zip = unsafe { &mut *zip };
    let mut bytes_avail: ssize_t = 0;
    /* Fetch next byte. */
    let data: *const uint8_t =
        unsafe { __archive_read_ahead_safe(a, 1, &mut bytes_avail) as *const uint8_t };
    if bytes_avail < 1 {
        safe_zip.ppmd8_stream_failed = 1;
        return 0;
    }
    unsafe { __archive_read_consume_safe(a, 1) };
    /* Increment the counter. */
    safe_zip.zipx_ppmd_read_compressed += 1;
    /* Return the next compressed byte. */
    unsafe { return *data.offset(0 as isize) };
}

fn trad_enc_update_keys(ctx: *mut trad_enc_ctx, mut c: uint8_t) {
    let mut t: uint8_t;
    let safe_ctx = unsafe { &mut *ctx };
    safe_ctx.keys[0] = unsafe {
        (crc32_safe(safe_ctx.keys[0] as u64 ^ 0xffffffff, &mut c, 1) ^ 0xffffffff) as uint32_t
    };
    safe_ctx.keys[1] =
        ((safe_ctx.keys[1] + (safe_ctx.keys[0] & 0xff)) as i64 * 134775813 + 1) as uint32_t;
    t = (safe_ctx.keys[1] >> 24 as i32 & 0xff) as uint8_t;
    safe_ctx.keys[2] = unsafe {
        (crc32_safe(safe_ctx.keys[2] as u64 ^ 0xffffffff, &mut t, 1) ^ 0xffffffff) as uint32_t
    };
}
fn trad_enc_decrypt_byte(ctx: *mut trad_enc_ctx) -> uint8_t {
    let safe_ctx = unsafe { &mut *ctx };
    let temp: u32 = safe_ctx.keys[2] | 2;
    return ((temp * (temp ^ 1) >> 8) as i32 & 0xff) as uint8_t;
}
fn trad_enc_decrypt_update(
    ctx: *mut trad_enc_ctx,
    in_0: *const uint8_t,
    in_len: size_t,
    out: *mut uint8_t,
    out_len: size_t,
) {
    let mut i: u32;
    let max: u32;
    max = if in_len < out_len { in_len } else { out_len } as u32;
    i = 0;
    unsafe {
        while i < max {
            let t: uint8_t =
                (*in_0.offset(i as isize) as i32 ^ trad_enc_decrypt_byte(ctx) as i32) as uint8_t;
            *out.offset(i as isize) = t;
            trad_enc_update_keys(ctx, t);
            i = i + 1
        }
    }
}
fn trad_enc_init(
    ctx: *mut trad_enc_ctx,
    mut pw: *const u8,
    mut pw_len: size_t,
    key: *const uint8_t,
    key_len: size_t,
    crcchk: *mut uint8_t,
) -> i32 {
    let mut header: [uint8_t; 12] = [0; 12];
    let safe_crcchk = unsafe { &mut *crcchk };
    let safe_ctx = unsafe { &mut *ctx };
    if key_len < 12 {
        *safe_crcchk = 0xff;
        return -(1);
    }
    safe_ctx.keys[0] = 305419896;
    safe_ctx.keys[1] = 591751049;
    safe_ctx.keys[2] = 878082192;
    while pw_len != 0 {
        let fresh0 = pw;
        let safe_fresh0 = unsafe { &*fresh0 };
        unsafe {
            pw = pw.offset(1 as isize);
        }
        trad_enc_update_keys(ctx, *safe_fresh0 as uint8_t);
        pw_len = pw_len - 1
    }
    trad_enc_decrypt_update(ctx, key, 12, header.as_mut_ptr(), 12);
    /* Return the last byte for CRC check. */
    *safe_crcchk = header[11];
    return 0;
}
/*
* Common code for streaming or seeking modes.
*
* Includes code to read local file headers, decompress data
* from entry bodies, and common API.
*/
fn real_crc32(crc: u64, buff: *const (), len: size_t) -> u64 {
    return unsafe { crc32_safe(crc, buff as *const Bytef, len as u32) };
}
/* Used by "ignorecrc32" option to speed up tests. */
fn fake_crc32(crc: u64, buff: *const (), len: size_t) -> u64 {
    /* UNUSED */
    return 0;
}
static mut compression_methods: [obj2; 25] = [
    obj2 {
        id: 0,
        name: b"uncompressed\x00" as *const u8,
    },
    obj2 {
        id: 1,
        name: b"shrinking\x00" as *const u8,
    },
    obj2 {
        id: 2,
        name: b"reduced-1\x00" as *const u8,
    },
    obj2 {
        id: 3,
        name: b"reduced-2\x00" as *const u8,
    },
    obj2 {
        id: 4,
        name: b"reduced-3\x00" as *const u8,
    },
    obj2 {
        id: 5,
        name: b"reduced-4\x00" as *const u8,
    },
    obj2 {
        id: 6,
        name: b"imploded\x00" as *const u8,
    },
    obj2 {
        id: 7,
        name: b"reserved\x00" as *const u8,
    },
    obj2 {
        id: 8,
        name: b"deflation\x00" as *const u8,
    },
    obj2 {
        id: 9,
        name: b"deflation-64-bit\x00" as *const u8,
    },
    obj2 {
        id: 10,
        name: b"ibm-terse\x00" as *const u8,
    },
    obj2 {
        id: 11,
        name: b"reserved\x00" as *const u8,
    },
    obj2 {
        id: 12,
        name: b"bzip\x00" as *const u8,
    },
    obj2 {
        id: 13,
        name: b"reserved\x00" as *const u8,
    },
    obj2 {
        id: 14,
        name: b"lzma\x00" as *const u8,
    },
    obj2 {
        id: 15,
        name: b"reserved\x00" as *const u8,
    },
    obj2 {
        id: 16,
        name: b"reserved\x00" as *const u8,
    },
    obj2 {
        id: 17,
        name: b"reserved\x00" as *const u8,
    },
    obj2 {
        id: 18,
        name: b"ibm-terse-new\x00" as *const u8,
    },
    obj2 {
        id: 19,
        name: b"ibm-lz777\x00" as *const u8,
    },
    obj2 {
        id: 95,
        name: b"xz\x00" as *const u8,
    },
    obj2 {
        id: 96,
        name: b"jpeg\x00" as *const u8,
    },
    obj2 {
        id: 97,
        name: b"wav-pack\x00" as *const u8,
    },
    obj2 {
        id: 98,
        name: b"ppmd-1\x00" as *const u8,
    },
    obj2 {
        id: 99,
        name: b"aes\x00" as *const u8,
    },
];
// Initialized in run_static_initializers
static mut num_compression_methods: i32 = 0;
fn compression_name(compression: i32) -> *const u8 {
    let mut i: i32 = 0;
    unsafe {
        while compression >= 0 && i < num_compression_methods {
            if compression_methods[i as usize].id == compression {
                return compression_methods[i as usize].name;
            }
            i += 1
        }
    }
    return b"??\x00" as *const u8;
}
/* Convert an MSDOS-style date/time into Unix-style time. */
fn zip_time(p: *const u8) -> time_t {
    let msTime: i32; /* Years since 1900. */
    let msDate: i32; /* Month number. */
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
    }; /* Day of month. */
    unsafe {
        msTime = ((0xff & *p.offset(0 as isize) as u32)
            + 256 * (0xff & *p.offset(1 as isize) as u32)) as i32;
    }
    unsafe {
        msDate = ((0xff & *p.offset(2 as isize) as u32)
            + 256 * (0xff & *p.offset(3 as isize) as u32)) as i32;
    }
    unsafe { memset_safe(&mut ts as *mut tm as *mut (), 0, size_of::<tm>() as u64) };
    ts.tm_year = (msDate >> 9 & 0x7f) + 80;
    ts.tm_mon = (msDate >> 5 & 0xf) - 1;
    ts.tm_mday = msDate & 0x1f;
    ts.tm_hour = msTime >> 11 & 0x1f;
    ts.tm_min = msTime >> 5 & 0x3f;
    ts.tm_sec = msTime << 1 & 0x3e;
    ts.tm_isdst = -1;
    return unsafe { mktime_safe(&mut ts) };
}
/*
* The extra data is stored as a list of
*	id1+size1+data1 + id2+size2+data2 ...
*  triplets.  id and size are 2 bytes each.
*/
fn process_extra(
    a: *mut archive_read,
    entry: *mut archive_entry,
    p: *const u8,
    extra_length: size_t,
    zip_entry: *mut zip_entry,
) -> i32 {
    let mut offset: u32 = 0;
    let mut zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let safe_zip = unsafe { &mut *zip };
    let safe_a = unsafe { &mut *a };
    let safe_zip_entry = unsafe { &mut *zip_entry };
    if extra_length == 0 {
        return 0;
    }
    if extra_length < 4 {
        let mut i: size_t = 0;
        /* Some ZIP files may have trailing 0 bytes. Let's check they
         * are all 0 and ignore them instead of returning an error.
         *
         * This is not technically correct, but some ZIP files look
         * like this and other tools support those files - so let's
         * also  support them.
         */
        while i < extra_length {
            if unsafe { *p.offset(i as isize) as i32 != 0 } {
                unsafe {
                    archive_set_error(
                        &mut safe_a.archive as *mut archive,
                        84,
                        b"Too-small extra data: Need at least 4 bytes, but only found %d bytes\x00"
                            as *const u8,
                        extra_length as i32,
                    );
                }
                return -25;
            }
            i = i + 1
        }
        return 0;
    }
    while offset as u64 <= extra_length - 4 {
        let headerid: u16 = archive_le16dec(unsafe { p.offset(offset as isize) as *const () });
        let mut datasize: u16 =
            archive_le16dec(unsafe { p.offset(offset as isize).offset(2 as isize) as *const () });
        offset = offset + 4;
        if (offset + datasize as u32) as u64 > extra_length {
            unsafe {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    84,
                    b"Extra data overflow: Need %d bytes but only found %d bytes\x00" as *const u8
                        as *const u8,
                    datasize as i32,
                    (extra_length - offset as u64) as i32,
                );
            }
            return -25;
        }
        let mut current_block: u64;
        match headerid as i32 {
            1 => {
                /* Zip64 extended information extra field. */
                safe_zip_entry.flags = (safe_zip_entry.flags as i32 | 1 << 0) as u8;
                if safe_zip_entry.uncompressed_size == 0xffffffff {
                    let mut t: uint64_t = 0;
                    if datasize < 8 || {
                        t = archive_le64dec(unsafe { p.offset(offset as isize) as *const () });
                        (t) > 9223372036854775807 as u64
                    } {
                        unsafe {
                            archive_set_error(
                                &mut safe_a.archive as *mut archive,
                                84,
                                b"Malformed 64-bit uncompressed size\x00" as *const u8,
                            );
                        }
                        return -25;
                    }
                    safe_zip_entry.uncompressed_size = t as int64_t;
                    offset = offset + 8;
                    datasize = (datasize - 8) as u16
                }
                if safe_zip_entry.compressed_size == 0xffffffff {
                    let mut t_0: uint64_t = 0;
                    if datasize < 8 || {
                        t_0 = archive_le64dec(unsafe { p.offset(offset as isize) as *const () });
                        (t_0) > 9223372036854775807
                    } {
                        unsafe {
                            archive_set_error(
                                &mut (*a).archive as *mut archive,
                                84,
                                b"Malformed 64-bit compressed size\x00" as *const u8,
                            );
                        }
                        return -25;
                    }
                    safe_zip_entry.compressed_size = t_0 as int64_t;
                    offset = offset + 8;
                    datasize = (datasize - 8) as u16
                }
                if safe_zip_entry.local_header_offset == 0xffffffff {
                    let mut t_1: uint64_t = 0;
                    if datasize < 8 || {
                        t_1 = archive_le64dec(unsafe { p.offset(offset as isize) as *const () });
                        (t_1) > 9223372036854775807
                    } {
                        unsafe {
                            archive_set_error(
                                &mut safe_a.archive as *mut archive,
                                84,
                                b"Malformed 64-bit local header offset\x00" as *const u8
                                    as *const u8,
                            );
                        }
                        return -25;
                    }
                    safe_zip_entry.local_header_offset = t_1 as int64_t;
                    offset = offset + 8;
                    datasize = (datasize - 8) as u16
                }
            }
            21589 => {
                /* Extended time field "UT". */
                let flags: i32;
                if datasize as i32 == 0 {
                    unsafe {
                        archive_set_error(
                            &mut (*a).archive as *mut archive,
                            84,
                            b"Incomplete extended time field\x00" as *const u8,
                        );
                    }
                    return -25;
                }
                flags = unsafe { *p.offset(offset as isize) as i32 };
                offset = offset + 1;
                datasize = datasize - 1;
                /* Flag bits indicate which dates are present. */
                if flags & 0x1 != 0 {
                    if datasize < 4 {
                        current_block = 1;
                    } else {
                        safe_zip_entry.mtime =
                            archive_le32dec(unsafe { p.offset(offset as isize) as *const () })
                                as time_t;
                        offset = offset + 4;
                        datasize = (datasize - 4) as u16;
                        current_block = 2;
                    }
                } else {
                    current_block = 2;
                }
                match current_block {
                    1 => {}
                    _ => {
                        if flags & 0x2 != 0 {
                            if datasize < 4 {
                                current_block = 1;
                            } else {
                                safe_zip_entry.atime = archive_le32dec(unsafe {
                                    p.offset(offset as isize) as *const ()
                                }) as time_t;
                                offset = offset + 4;
                                datasize = (datasize - 4) as u16;
                                current_block = 3;
                            }
                        } else {
                            current_block = 3;
                        }
                        match current_block {
                            1 => {}
                            _ => {
                                if flags & 0x4 as i32 != 0 {
                                    if !(datasize < 4) {
                                        safe_zip_entry.ctime = archive_le32dec(unsafe {
                                            p.offset(offset as isize) as *const ()
                                        })
                                            as time_t;
                                        offset = offset + 4;
                                        datasize = (datasize - 4) as u16
                                    }
                                }
                            }
                        }
                    }
                }
            }
            22613 => {
                /* Info-ZIP Unix Extra Field (old version) "UX". */
                if datasize as i32 >= 8 {
                    safe_zip_entry.atime =
                        archive_le32dec(unsafe { p.offset(offset as isize) as *const () })
                            as time_t;
                    safe_zip_entry.mtime =
                        archive_le32dec(
                            unsafe { p.offset(offset as isize).offset(4 as isize) } as *const ()
                        ) as time_t
                }
                if datasize as i32 >= 12 {
                    safe_zip_entry.uid = archive_le16dec(unsafe {
                        p.offset(offset as isize).offset(8 as isize) as *const ()
                    }) as int64_t;
                    safe_zip_entry.gid = archive_le16dec(unsafe {
                        p.offset(offset as isize).offset(10 as isize) as *const ()
                    }) as int64_t
                }
            }
            27768 => {
                /* Experimental 'xl' field */
                /*
                 * Introduced Dec 2013 to provide a way to
                 * include external file attributes (and other
                 * fields that ordinarily appear only in
                 * central directory) in local file header.
                 * This provides file type and permission
                 * information necessary to support full
                 * streaming extraction.  Currently being
                 * discussed with other Zip developers
                 * ... subject to change.
                 *
                 * Format:
                 *  The field starts with a bitmap that specifies
                 *  which additional fields are included.  The
                 *  bitmap is variable length and can be extended in
                 *  the future.
                 *
                 *  n bytes - feature bitmap: first byte has low-order
                 *    7 bits.  If high-order bit is set, a subsequent
                 *    byte holds the next 7 bits, etc.
                 *
                 *  if bitmap & 1, 2 byte "version made by"
                 *  if bitmap & 2, 2 byte "internal file attributes"
                 *  if bitmap & 4, 4 byte "external file attributes"
                 *  if bitmap & 8, 2 byte comment length + n byte
                 *  comment
                 */
                let bitmap: i32;
                let mut bitmap_last: i32;
                if !(datasize < 1) {
                    unsafe {
                        bitmap = 0xff & *p.offset(offset as isize) as i32;
                    }
                    bitmap_last = bitmap;
                    offset = offset + 1;
                    datasize = (datasize - 1) as u16;
                    /* We only support first 7 bits of bitmap; skip rest. */
                    while bitmap_last & 0x80 != 0 && datasize as i32 >= 1 {
                        bitmap_last = unsafe { *p.offset(offset as isize) as i32 };
                        offset = offset + 1;
                        datasize = (datasize - 1) as u16
                    }
                    if bitmap & 1 != 0 {
                        /* 2 byte "version made by" */
                        if datasize < 2 {
                            current_block = 1;
                        } else {
                            safe_zip_entry.system =
                                (archive_le16dec(unsafe { p.offset(offset as isize) as *const () })
                                    as i32
                                    >> 8) as u8;
                            offset = offset + 2;
                            datasize = (datasize - 2) as u16;
                            current_block = 4;
                        }
                    } else {
                        current_block = 4;
                    }
                    match current_block {
                        1 => {}
                        _ => {
                            if bitmap & 2 != 0 {
                                /* 2 byte "internal file attributes" */
                                let mut internal_attributes: uint32_t = 0;
                                if datasize < 2 {
                                    current_block = 1;
                                } else {
                                    internal_attributes = archive_le16dec(unsafe {
                                        p.offset(offset as isize) as *const ()
                                    })
                                        as uint32_t;
                                    /* Not used by libarchive at present. */
                                    /* UNUSED */
                                    offset = offset + 2;
                                    datasize = (datasize - 2) as u16;
                                    current_block = 5;
                                }
                            } else {
                                current_block = 5;
                            }
                            match current_block {
                                1 => {}
                                _ => {
                                    if bitmap & 4 as i32 != 0 {
                                        /* 4 byte "external file attributes" */
                                        let mut external_attributes: uint32_t = 0;
                                        if datasize < 4 {
                                            current_block = 1;
                                        } else {
                                            external_attributes = archive_le32dec(unsafe {
                                                p.offset(offset as isize) as *const ()
                                            });
                                            if safe_zip_entry.system as i32 == 3 {
                                                safe_zip_entry.mode =
                                                    (external_attributes >> 16) as uint16_t
                                            } else if safe_zip_entry.system as i32 == 0 {
                                                // Interpret MSDOS directory bit
                                                if 0x10 == external_attributes & 0x10 {
                                                    safe_zip_entry.mode =
                                                        (0o40000 | 0o775) as uint16_t
                                                } else {
                                                    safe_zip_entry.mode =
                                                        (0o100000 | 0o664) as uint16_t
                                                }
                                                if 0x1 == external_attributes & 0x1 {
                                                    /* Read-only bit;
                                                     * strip write permissions */
                                                    safe_zip_entry.mode =
                                                        (safe_zip_entry.mode & 0o555) as uint16_t
                                                }
                                            } else {
                                                safe_zip_entry.mode = 0
                                            }
                                            offset = offset + 4;
                                            datasize = (datasize - 4) as u16;
                                            current_block = 6;
                                        }
                                    } else {
                                        current_block = 6;
                                    }
                                    match current_block {
                                        1 => {}
                                        _ => {
                                            if bitmap & 8 != 0 {
                                                /* 2 byte comment length + comment */
                                                let mut comment_length: uint32_t = 0;
                                                if !(datasize < 2) {
                                                    comment_length = archive_le16dec(unsafe {
                                                        p.offset(offset as isize) as *const ()
                                                    })
                                                        as uint32_t;
                                                    offset = offset + 2;
                                                    datasize = (datasize - 2) as u16;
                                                    if !((datasize as u32) < comment_length) {
                                                        /* Comment is not supported by libarchive */
                                                        offset = offset + comment_length;
                                                        datasize = (datasize as u32
                                                            - comment_length)
                                                            as u16
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            28789 => {
                /* Info-ZIP Unicode Path Extra Field. */
                if !(datasize < 5 || entry.is_null()) {
                    offset = offset + 5;
                    datasize = (datasize - 5) as u16;
                    /* The path name in this field is always encoded
                     * in UTF-8. */
                    if safe_zip.sconv_utf8.is_null() {
                        safe_zip.sconv_utf8 = unsafe {
                            archive_string_conversion_from_charset_safe(
                                &mut safe_a.archive,
                                b"UTF-8\x00" as *const u8,
                                1,
                            )
                        };
                        /* If the converter from UTF-8 is not
                         * available, then the path name from the main
                         * field will more likely be correct. */
                        if safe_zip.sconv_utf8.is_null() {
                            current_block = 1;
                        } else {
                            current_block = 7;
                        }
                    } else {
                        current_block = 7;
                    }
                    match current_block {
                        1 => {}
                        _ =>
                        /* Make sure the CRC32 of the filename matches. */
                        {
                            if safe_zip.ignore_crc32 == 0 {
                                let mut cp: *const u8 =
                                    unsafe { archive_entry_pathname_safe(entry) };
                                if !cp.is_null() {
                                    let mut file_crc: u64 = unsafe {
                                        safe_zip.crc32func.expect("non-null function pointer")(
                                            0,
                                            cp as *const (),
                                            strlen_safe(cp),
                                        )
                                    };
                                    let mut utf_crc: u64 = archive_le32dec(unsafe {
                                        p.offset(offset as isize - 4) as *const ()
                                    })
                                        as u64;
                                    if file_crc != utf_crc {
                                        current_block = 1;
                                    } else {
                                        current_block = 8;
                                    }
                                } else {
                                    current_block = 8;
                                }
                            } else {
                                current_block = 8;
                            }
                            match current_block {
                                1 => {}
                                _ => {
                                    unsafe {
                                        (_archive_entry_copy_pathname_l_safe(
                                            entry,
                                            p.offset(offset as isize),
                                            datasize as size_t,
                                            safe_zip.sconv_utf8,
                                        )) != 0
                                    };
                                }
                            }
                        }
                    }
                }
            }
            30805 => {
                /* Info-ZIP Unix Extra Field (type 2) "Ux". */
                if datasize >= 2 {
                    safe_zip_entry.uid =
                        archive_le16dec(unsafe { p.offset(offset as isize) as *const () })
                            as int64_t
                }
                if datasize >= 4 {
                    safe_zip_entry.gid = archive_le16dec(unsafe {
                        p.offset(offset as isize).offset(2 as isize) as *const ()
                    }) as int64_t
                }
            }
            30837 => {
                /* Info-Zip Unix Extra Field (type 3) "ux". */
                let mut uidsize: i32 = 0;
                let mut gidsize: i32 = 0;
                /* TODO: support arbitrary uidsize/gidsize. */
                if unsafe { datasize >= 1 && *p.offset(offset as isize) as i32 == 1 } {
                    /* version=1 */
                    if datasize >= 4 {
                        /* get a uid size. */
                        unsafe {
                            uidsize = 0xff & *p.offset(offset as isize + 1) as i32;
                        }
                        if uidsize == 2 {
                            safe_zip_entry.uid = archive_le16dec(unsafe {
                                p.offset(offset as isize).offset(2 as isize) as *const ()
                            }) as int64_t
                        } else if uidsize == 4 as i32 && datasize as i32 >= 6 as i32 {
                            safe_zip_entry.uid = archive_le32dec(unsafe {
                                p.offset(offset as isize).offset(2 as isize) as *const ()
                            }) as int64_t
                        }
                    }
                    if datasize as i32 >= 2 + uidsize + 3 {
                        /* get a gid size. */
                        unsafe {
                            gidsize =
                                0xff & *p.offset(offset as isize + uidsize as isize + 2) as i32;
                        }
                        if gidsize == 2 {
                            unsafe {
                                safe_zip_entry.gid = archive_le16dec(
                                    p.offset(offset as isize)
                                        .offset(2 as isize)
                                        .offset(uidsize as isize)
                                        .offset(1 as isize)
                                        as *const (),
                                ) as int64_t
                            }
                        } else if gidsize == 4 && datasize as i32 >= 2 + uidsize + 5 {
                            unsafe {
                                safe_zip_entry.gid = archive_le32dec(
                                    p.offset(offset as isize)
                                        .offset(2 as isize)
                                        .offset(uidsize as isize)
                                        .offset(1 as isize)
                                        as *const (),
                                ) as int64_t
                            }
                        }
                    }
                }
            }
            39169 => {
                /* WinZip AES extra data field. */
                if datasize < 6 {
                    unsafe {
                        archive_set_error(
                            &mut safe_a.archive as *mut archive,
                            84,
                            b"Incomplete AES field\x00" as *const u8,
                        );
                    }
                    return -25;
                }
                if unsafe {
                    *p.offset(offset as isize + 2) as i32 == 'A' as i32
                        && *p.offset(offset as isize + 3) as i32 == 'E' as i32
                } {
                    /* Vendor version. */
                    safe_zip_entry.aes_extra.vendor =
                        archive_le16dec(unsafe { p.offset(offset as isize) as *const () }) as u32;
                    /* AES encryption strength. */
                    safe_zip_entry.aes_extra.strength =
                        unsafe { *p.offset(offset as isize + 4) as u32 };
                    /* Actual compression method. */
                    safe_zip_entry.aes_extra.compression =
                        unsafe { *p.offset(offset as isize + 5) as u8 }
                }
            }
            _ => {}
        }
        offset = offset + datasize as u32
    }
    return 0;
}
/*
* Assumes file pointer is at beginning of local file header.
*/
fn zip_read_local_file_header(
    a: *mut archive_read,
    entry: *mut archive_entry,
    zip: *mut zip,
) -> i32 {
    let safe_a = unsafe { &mut *a };
    let safe_entry = unsafe { &mut *entry };
    let safe_zip = unsafe { &mut *zip };
    let mut p: *const u8 = 0 as *const u8;
    let safe_p = unsafe { &*p };
    let mut h: *const ();
    let mut wp: *const wchar_t = 0 as *const wchar_t;
    let mut cp: *const u8;
    let mut len: size_t;
    let filename_length: size_t;
    let extra_length: size_t;
    let mut sconv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    let zip_entry: *mut zip_entry = safe_zip.entry;
    let safe_sconv = unsafe { &mut *sconv };
    let safe_zip_entry = unsafe { &mut *zip_entry };
    let mut zip_entry_central_dir: zip_entry = zip_entry {
        node: archive_rb_node {
            rb_nodes: [0 as *mut archive_rb_node; 2],
            rb_info: 0,
        },
        next: 0 as *mut zip_entry,
        local_header_offset: 0,
        compressed_size: 0,
        uncompressed_size: 0,
        gid: 0,
        uid: 0,
        rsrcname: archive_string {
            s: 0 as *mut u8,
            length: 0,
            buffer_length: 0,
        },
        mtime: 0,
        atime: 0,
        ctime: 0,
        crc32: 0,
        mode: 0,
        zip_flags: 0,
        compression: 0,
        system: 0,
        flags: 0,
        decdat: 0,
        aes_extra: obj1_zip {
            vendor: 0,
            strength: 0,
            compression: 0,
        },
    };
    let mut ret: i32 = 0;
    let mut version: u8 = 0;
    /* Save a copy of the original for consistency checks. */
    zip_entry_central_dir = *safe_zip_entry;
    safe_zip.decompress_init = 0;
    safe_zip.end_of_entry = 0;
    safe_zip.entry_uncompressed_bytes_read = 0;
    safe_zip.entry_compressed_bytes_read = 0;
    unsafe {
        safe_zip.entry_crc32 =
            safe_zip.crc32func.expect("non-null function pointer")(0, 0 as *const (), 0)
    };
    /* Setup default conversion. */
    if safe_zip.sconv.is_null() && safe_zip.init_default_conversion == 0 {
        safe_zip.sconv_default =
            unsafe { archive_string_default_conversion_for_read(&mut safe_a.archive) };
        safe_zip.init_default_conversion = 1
    }
    p = unsafe { __archive_read_ahead_safe(a, 30, 0 as *mut ssize_t) as *const u8 };
    if p.is_null() {
        unsafe {
            archive_set_error(
                &mut safe_a.archive as *mut archive,
                84,
                b"Truncated ZIP file header\x00" as *const u8,
            )
        };
        return -30;
    }
    if unsafe {
        memcmp_safe(
            p as *const (),
            b"PK\x03\x04\x00" as *const u8 as *const (),
            4,
        )
    } != 0
    {
        unsafe {
            archive_set_error(
                &mut safe_a.archive as *mut archive,
                -1,
                b"Damaged Zip archive\x00" as *const u8,
            )
        };
        return -30;
    }
    version = unsafe { *p.offset(4 as isize) };
    safe_zip_entry.system = unsafe { *p.offset(5 as isize) as u8 };
    safe_zip_entry.zip_flags = archive_le16dec(unsafe { p.offset(6 as isize) as *const () });
    if safe_zip_entry.zip_flags as i32 & ((1) << 0 | (1 << 6)) != 0 {
        safe_zip.has_encrypted_entries = 1;
        unsafe { archive_entry_set_is_data_encrypted_safe(entry, 1 as u8) };
        if safe_zip_entry.zip_flags as i32 & (1 << 13) as i32 != 0
            && safe_zip_entry.zip_flags as i32 & (1 << 0) as i32 != 0
            && safe_zip_entry.zip_flags as i32 & (1 << 6) as i32 != 0
        {
            unsafe { archive_entry_set_is_metadata_encrypted_safe(entry, 1) };
            return -30;
        }
    }
    safe_zip.init_decryption = (safe_zip_entry.zip_flags as i32 & (1 << 0) as i32) as u8;
    safe_zip_entry.compression =
        archive_le16dec(unsafe { p.offset(8 as isize) as *const () }) as u8;
    safe_zip_entry.mtime = zip_time(unsafe { p.offset(10 as isize) });
    safe_zip_entry.crc32 = archive_le32dec(unsafe { p.offset(14 as isize) as *const () });
    if safe_zip_entry.zip_flags as i32 & (1 << 3) as i32 != 0 {
        safe_zip_entry.decdat = unsafe { *p.offset(11 as isize) as u8 }
    } else {
        safe_zip_entry.decdat = unsafe { *p.offset(17 as isize) as u8 }
    }
    safe_zip_entry.compressed_size =
        archive_le32dec(unsafe { p.offset(18 as isize) as *const () }) as int64_t;
    safe_zip_entry.uncompressed_size =
        archive_le32dec(unsafe { p.offset(22 as isize) as *const () }) as int64_t;
    filename_length = archive_le16dec(unsafe { p.offset(26 as isize) as *const () }) as size_t;
    extra_length = archive_le16dec(unsafe { p.offset(28 as isize) as *const () }) as size_t;
    unsafe { __archive_read_consume_safe(a, 30) };
    /* Read the filename. */
    h = unsafe { __archive_read_ahead_safe(a, filename_length, 0 as *mut ssize_t) };
    if h == 0 as *mut () {
        unsafe {
            archive_set_error(
                &mut safe_a.archive as *mut archive,
                84,
                b"Truncated ZIP file header\x00" as *const u8,
            )
        };
        return -30;
    }
    if safe_zip_entry.zip_flags as i32 & (1 << 11) as i32 != 0 {
        /* The filename is stored to be UTF-8. */
        if safe_zip.sconv_utf8.is_null() {
            safe_zip.sconv_utf8 = unsafe {
                archive_string_conversion_from_charset_safe(
                    &mut safe_a.archive,
                    b"UTF-8\x00" as *const u8,
                    1,
                )
            };
            if safe_zip.sconv_utf8.is_null() {
                return -30;
            }
        }
        sconv = safe_zip.sconv_utf8
    } else if !(safe_zip).sconv.is_null() {
        sconv = (safe_zip).sconv
    } else {
        sconv = (safe_zip).sconv_default
    }
    if unsafe { _archive_entry_copy_pathname_l_safe(entry, h as *const u8, filename_length, sconv) }
        != 0
    {
        unsafe {
            if *__errno_location() == 12 {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    12,
                    b"Can\'t allocate memory for Pathname\x00" as *const u8,
                );
                return -30;
            }
            archive_set_error(
                &mut safe_a.archive as *mut archive,
                84,
                b"Pathname cannot be converted from %s to current locale.\x00" as *const u8
                    as *const u8,
                archive_string_conversion_charset_name_safe(sconv),
            );
        }
        ret = -20
    }
    unsafe { __archive_read_consume_safe(a, filename_length as int64_t) };
    /* Read the extra data. */
    h = unsafe { __archive_read_ahead_safe(a, extra_length, 0 as *mut ssize_t) };
    if h == 0 as *mut () {
        unsafe {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                84,
                b"Truncated ZIP file header\x00" as *const u8,
            )
        };
        return -30;
    }
    if 0 != process_extra(a, entry, h as *const u8, extra_length, zip_entry) {
        return -30;
    }
    unsafe { __archive_read_consume_safe(a, extra_length as int64_t) };
    /* Work around a bug in Info-Zip: When reading from a pipe, it
     * stats the pipe instead of synthesizing a file entry. */
    if safe_zip_entry.mode as u32 & 0o170000 as mode_t == 0o10000 as mode_t {
        safe_zip_entry.mode = (safe_zip_entry.mode as u32 & !(0o170000 as mode_t)) as uint16_t;
        safe_zip_entry.mode = (safe_zip_entry.mode as u32 | 0o100000 as mode_t) as uint16_t
    }
    /* If the mode is totally empty, set some sane default. */
    if safe_zip_entry.mode as i32 == 0 {
        safe_zip_entry.mode = (safe_zip_entry.mode as i32 | 0o664 as i32) as uint16_t
    }
    /* Windows archivers sometimes use backslash as the directory
     * separator. Normalize to slash. */
    if safe_zip_entry.system as i32 == 0 && {
        wp = unsafe { archive_entry_pathname_w_safe(entry) };
        !wp.is_null()
    } {
        if unsafe {
            wcschr_safe(wp, '/' as wchar_t).is_null() && !wcschr_safe(wp, '\\' as wchar_t).is_null()
        } {
            let mut i: size_t;
            let mut s: archive_wstring = archive_wstring {
                s: 0 as *mut wchar_t,
                length: 0,
                buffer_length: 0,
            };
            s.s = 0 as *mut wchar_t;
            s.length = 0;
            s.buffer_length = 0;
            s.length = 0;
            unsafe {
                archive_wstrncat_safe(&mut s, wp, (if wp.is_null() { 0 } else { wcslen_safe(wp) }))
            };
            i = 0;
            unsafe {
                while i < s.length {
                    if *s.s.offset(i as isize) == '\\' as wchar_t {
                        *s.s.offset(i as isize) = '/' as wchar_t
                    }
                    i = i + 1
                }
            }
            unsafe {
                archive_entry_copy_pathname_w_safe(entry, s.s);
                archive_wstring_free_safe(&mut s)
            };
        }
    }
    /* Make sure that entries with a trailing '/' are marked as directories
     * even if the External File Attributes contains bogus values.  If this
     * is not a directory and there is no type, assume a regular file. */
    if safe_zip_entry.mode as u32 & 0o170000 as mode_t != 0o10000 as mode_t {
        let has_slash: i32;
        wp = unsafe { archive_entry_pathname_w_safe(entry) };
        if !wp.is_null() {
            len = unsafe { wcslen_safe(wp) };
            has_slash =
                unsafe { (len > 0 && *wp.offset(len as isize - 1) == '/' as wchar_t) as i32 }
        } else {
            cp = unsafe { archive_entry_pathname_safe(entry) };
            len = if !cp.is_null() {
                unsafe { strlen_safe(cp) }
            } else {
                0
            };
            unsafe {
                has_slash = (len > 0 && *cp.offset(len as isize - 1) as i32 == '/' as i32) as i32
            }
        }
        /* Correct file type as needed. */
        if has_slash != 0 {
            safe_zip_entry.mode = (safe_zip_entry.mode as u32 & !(0o170000 as mode_t)) as uint16_t;
            safe_zip_entry.mode = (safe_zip_entry.mode as u32 | 0o40000 as mode_t) as uint16_t;
            safe_zip_entry.mode = (safe_zip_entry.mode as i32 | 0o111) as uint16_t
        } else if safe_zip_entry.mode as u32 & 0o170000 as mode_t == 0 {
            safe_zip_entry.mode = (safe_zip_entry.mode as u32 | 0o100000 as mode_t) as uint16_t
        }
    }
    /* Make sure directories end in '/' */
    if safe_zip_entry.mode as u32 & 0o170000 as mode_t == 0o40000 as mode_t {
        wp = unsafe { archive_entry_pathname_w_safe(entry) };
        if !wp.is_null() {
            len = unsafe { wcslen_safe(wp) };
            if unsafe { len > 0 && *wp.offset(len as isize - 1) != '/' as wchar_t } {
                let mut s_0: archive_wstring = archive_wstring {
                    s: 0 as *mut wchar_t,
                    length: 0,
                    buffer_length: 0,
                };
                s_0.s = 0 as *mut wchar_t;
                s_0.length = 0;
                s_0.buffer_length = 0;
                unsafe {
                    archive_wstrcat_safe(&mut s_0, wp);
                    archive_wstrappend_wchar_safe(&mut s_0, '/' as wchar_t);
                    archive_entry_copy_pathname_w_safe(entry, s_0.s);
                    archive_wstring_free_safe(&mut s_0)
                };
            }
        } else {
            cp = unsafe { archive_entry_pathname_safe(entry) };
            len = if !cp.is_null() {
                unsafe { strlen_safe(cp) }
            } else {
                0
            };
            if unsafe { len > 0 && *cp.offset(len as isize - 1) as i32 != '/' as i32 } {
                let mut s_1: archive_string = archive_string {
                    s: 0 as *mut u8,
                    length: 0,
                    buffer_length: 0,
                };
                s_1.s = 0 as *mut u8;
                s_1.length = 0;
                s_1.buffer_length = 0;
                unsafe {
                    archive_strcat_safe(&mut s_1, cp as *const ());
                    archive_strappend_char_safe(&mut s_1, '/' as u8);
                    archive_entry_set_pathname_safe(entry, s_1.s);
                    archive_string_free_safe(&mut s_1)
                };
            }
        }
    }
    if safe_zip_entry.flags as i32 & (1 << 1) as i32 != 0 {
        /* If this came from the central dir, its size info
         * is definitive, so ignore the length-at-end flag. */
        safe_zip_entry.zip_flags = (safe_zip_entry.zip_flags as i32 & !(1 << 3)) as uint16_t;
        /* If local header is missing a value, use the one from
        the central directory.  If both have it, warn about
        mismatches. */
        if safe_zip_entry.crc32 == 0 {
            safe_zip_entry.crc32 = zip_entry_central_dir.crc32
        } else if safe_zip.ignore_crc32 == 0 && safe_zip_entry.crc32 != zip_entry_central_dir.crc32
        {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    84,
                    b"Inconsistent CRC32 values\x00" as *const u8,
                )
            };
            ret = -20
        }
        if safe_zip_entry.compressed_size == 0 {
            safe_zip_entry.compressed_size = zip_entry_central_dir.compressed_size
        } else if safe_zip_entry.compressed_size != zip_entry_central_dir.compressed_size {
            unsafe {
                archive_set_error(
                &mut safe_a.archive as *mut archive,
                84,
                b"Inconsistent compressed size: %jd in central directory, %jd in local header\x00"
                    as *const u8,
                zip_entry_central_dir.compressed_size,
                safe_zip_entry.compressed_size,
            )
            };
            ret = -20
        }
        if safe_zip_entry.uncompressed_size == 0 {
            safe_zip_entry.uncompressed_size = zip_entry_central_dir.uncompressed_size
        } else if safe_zip_entry.uncompressed_size != zip_entry_central_dir.uncompressed_size {
            unsafe {
                archive_set_error(
                &mut safe_a.archive as *mut archive,
                84,
                b"Inconsistent uncompressed size: %jd in central directory, %jd in local header\x00"
                    as *const u8,
                zip_entry_central_dir.uncompressed_size,
                safe_zip_entry.uncompressed_size,
            )
            };
            ret = -20
        }
    }
    /* Populate some additional entry fields: */
    unsafe {
        archive_entry_set_mode_safe(entry, safe_zip_entry.mode as mode_t);
        archive_entry_set_uid_safe(entry, safe_zip_entry.uid);
        archive_entry_set_gid_safe(entry, safe_zip_entry.gid);
        archive_entry_set_mtime_safe(entry, safe_zip_entry.mtime, 0);
        archive_entry_set_ctime_safe(entry, safe_zip_entry.ctime, 0);
        archive_entry_set_atime_safe(entry, safe_zip_entry.atime, 0)
    };
    if unsafe { (*(safe_zip).entry).mode as u32 & 0o170000 as mode_t == 0o120000 as mode_t } {
        let mut linkname_length: size_t = 0;
        if safe_zip_entry.compressed_size > (64 * 1024) as i64 {
            unsafe {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -1,
                    b"Zip file with oversized link entry\x00" as *const u8,
                )
            };
            return -30;
        }
        linkname_length = safe_zip_entry.compressed_size as size_t;
        unsafe { archive_entry_set_size_safe(entry, 0) };
        // take into account link compression if any
        let mut linkname_full_length: size_t = linkname_length;
        if unsafe { (*(safe_zip).entry).compression as i32 != 0 } {
            // symlink target string appeared to be compressed
            let mut status: i32 = -30;
            let mut uncompressed_buffer: *const () = 0 as *const ();
            match unsafe { (*(safe_zip).entry).compression as i32 } {
                #[cfg(HAVE_ZLIB_H)]
                8 => {
                    /* Deflate compression. */
                    safe_zip.entry_bytes_remaining = safe_zip_entry.compressed_size;
                    status = unsafe {
                        zip_read_data_deflate(
                            a,
                            &mut uncompressed_buffer,
                            &mut linkname_full_length,
                            0 as *mut int64_t,
                        )
                    }
                }
                #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
                14 => {
                    /* ZIPx LZMA compression. */
                    /*(see zip file format specification, section 4.4.5)*/
                    safe_zip.entry_bytes_remaining = safe_zip_entry.compressed_size;
                    status = unsafe {
                        zip_read_data_zipx_lzma_alone(
                            a,
                            &mut uncompressed_buffer,
                            &mut linkname_full_length,
                            0 as *mut int64_t,
                        )
                    }
                }
                _ => {}
            }
            if status == 0 {
                p = uncompressed_buffer as *const u8
            } else {
                unsafe {
                    archive_set_error(&mut safe_a.archive as *mut archive,
                        84,
                             b"Unsupported ZIP compression method during decompression of link entry (%d: %s)\x00"
                                 as *const u8,
                             (*(safe_zip).entry).compression as i32,
                             compression_name((*(safe_zip).entry).compression
                                                  as i32))
                };
                return -25;
            }
        } else {
            p = unsafe { __archive_read_ahead_safe(a, linkname_length, 0 as *mut ssize_t) }
                as *const u8
        }
        if p.is_null() {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    -1,
                    b"Truncated Zip file\x00" as *const u8,
                )
            };
            return -30;
        }
        sconv = safe_zip.sconv;
        if unsafe { sconv.is_null() && (*(safe_zip).entry).zip_flags as i32 & (1) << 11 != 0 } {
            sconv = (safe_zip).sconv_utf8
        }
        if sconv.is_null() {
            sconv = safe_zip.sconv_default
        }
        if unsafe { _archive_entry_copy_symlink_l_safe(entry, p, linkname_full_length, sconv) != 0 }
        {
            if unsafe {
                *__errno_location() != 12
                    && sconv == safe_zip.sconv_utf8
                    && (*(safe_zip).entry).zip_flags as i32 & (1) << 11 != 0
            } {
                unsafe {
                    _archive_entry_copy_symlink_l_safe(
                        entry,
                        p,
                        linkname_full_length,
                        0 as *mut archive_string_conv,
                    )
                };
            }
            unsafe {
                if *__errno_location() == 12 {
                    archive_set_error(
                        &mut safe_a.archive as *mut archive,
                        12,
                        b"Can\'t allocate memory for Symlink\x00" as *const u8,
                    );
                    return -30;
                }
            }
            /*
             * Since there is no character-set regulation for
             * symlink name, do not report the conversion error
             * in an automatic conversion.
             */
            if unsafe {
                sconv != safe_zip.sconv_utf8
                    || (*(safe_zip).entry).zip_flags as i32
                        & ARCHIVE_ZIP_DEFINED_PARAM.zip_utf8_name as i32
                        == 0
            } {
                unsafe {
                    archive_set_error(
                        &mut (*a).archive as *mut archive,
                        84,
                        b"Symlink cannot be converted from %s to current locale.\x00" as *const u8
                            as *const u8,
                        archive_string_conversion_charset_name(sconv),
                    )
                };
                ret = -20
            }
        }
        safe_zip_entry.compressed_size = 0;
        safe_zip_entry.uncompressed_size = safe_zip_entry.compressed_size;
        if unsafe { __archive_read_consume_safe(a, linkname_length as int64_t) < 0 } {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    -1,
                    b"Read error skipping symlink target name\x00" as *const u8,
                )
            };
            return -30;
        }
    } else if 0 == safe_zip_entry.zip_flags as i32 & (1 << 3)
        || safe_zip_entry.uncompressed_size > 0
    {
        /* Set the size only if it's meaningful. */
        unsafe { archive_entry_set_size_safe(entry, safe_zip_entry.uncompressed_size) };
    }
    safe_zip.entry_bytes_remaining = safe_zip_entry.compressed_size;
    /* If there's no body, force read_data() to return EOF immediately. */
    if 0 == safe_zip_entry.zip_flags as i32 & (1 << 3) && safe_zip.entry_bytes_remaining < 1 {
        safe_zip.end_of_entry = 1
    }
    /* Set up a more descriptive format name. */
    safe_zip.format_name.length = 0;
    unsafe {
        archive_string_sprintf(
            &mut safe_zip.format_name as *mut archive_string,
            b"ZIP %d.%d (%s)\x00" as *const u8,
            version as i32 / 10,
            version as i32 % 10,
            compression_name((*(safe_zip).entry).compression as i32),
        )
    };
    safe_a.archive.archive_format_name = safe_zip.format_name.s;
    return ret;
}

fn check_authentication_code(mut a: *mut archive_read, mut _p: *const ()) -> i32 {
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let safe_a = unsafe { &mut *a };
    let mut safe__p = unsafe { &*_p };
    let safe_zip = unsafe { &mut *zip };

    /* Check authentication code. */
    if safe_zip.hctx_valid != 0 {
        let mut p: *const () = 0 as *const ();
        let mut hmac: [uint8_t; 20] = [0; 20];
        let mut hmac_len: size_t = 20;
        let mut cmp: i32 = 0;
        unsafe {
            __archive_hmac
                .__hmac_sha1_final
                .expect("non-null function pointer")(
                &mut safe_zip.hctx,
                hmac.as_mut_ptr(),
                &mut hmac_len,
            )
        };
        if _p == 0 as *mut () {
            /* Read authentication code. */
            p = unsafe { __archive_read_ahead_safe(a, 10, 0 as *mut ssize_t) };
            if p == 0 as *mut () {
                unsafe {
                    archive_set_error(
                        &mut safe_a.archive as *mut archive,
                        84,
                        b"Truncated ZIP file data\x00" as *const u8,
                    )
                };
                return -30;
            }
        } else {
            p = _p
        }
        cmp = unsafe { memcmp_safe(hmac.as_mut_ptr() as *const (), p, 10) };
        unsafe { __archive_read_consume_safe(a, 10) };
        if cmp != 0 {
            unsafe {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -1,
                    b"ZIP bad Authentication code\x00" as *const u8,
                )
            };
            return -20;
        }
    }
    return 0;
}

fn zip_read_data_none(
    a: *mut archive_read,
    _buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    unsafe {
        let zip: *mut zip;
        let mut buff: *const u8;
        let mut bytes_avail: ssize_t = 0;
        let r: i32;
        /* UNUSED */
        zip = (*(*a).format).data as *mut zip;
        if (*(*zip).entry).zip_flags as i32 & (1 << 3) != 0 {
            let mut p: *const u8;
            let mut grabbing_bytes: ssize_t = 24 as ssize_t;
            if (*zip).hctx_valid != 0 {
                grabbing_bytes += 10
            }
            /* Grab at least 24 bytes. */
            buff = __archive_read_ahead(a, grabbing_bytes as size_t, &mut bytes_avail) as *const u8;
            if bytes_avail < grabbing_bytes {
                /* Zip archives have end-of-archive markers
                that are longer than this, so a failure to get at
                least 24 bytes really does indicate a truncated
                file. */
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    84,
                    b"Truncated ZIP file data\x00" as *const u8,
                );
                return -30;
            }
            /* Check for a complete PK\007\010 signature, followed
             * by the correct 4-byte CRC. */
            p = buff;
            if (*zip).hctx_valid != 0 {
                p = p.offset(10 as isize)
            }
            if *p.offset(0 as isize) as i32 == 'P' as i32
                && *p.offset(1 as isize) as i32 == 'K' as i32
                && *p.offset(2 as isize) as i32 == '\u{7}' as i32
                && *p.offset(3 as isize) as i32 == '\u{8}' as i32
                && (archive_le32dec(p.offset(4 as isize) as *const ()) as u64 == (*zip).entry_crc32
                    || (*zip).ignore_crc32 != 0
                    || (*zip).hctx_valid as i32 != 0 && (*(*zip).entry).aes_extra.vendor == 0x2)
            {
                if (*(*zip).entry).flags as i32 & (1 << 0) != 0 {
                    let mut compressed: uint64_t;
                    let mut uncompressed: uint64_t;
                    (*(*zip).entry).crc32 = archive_le32dec(p.offset(4 as isize) as *const ());
                    compressed = archive_le64dec(p.offset(8 as isize) as *const ());
                    uncompressed = archive_le64dec(p.offset(16 as isize) as *const ());
                    if compressed > 9223372036854775807 || uncompressed > 9223372036854775807 {
                        archive_set_error(
                            &mut (*a).archive as *mut archive,
                            84,
                            b"Overflow of 64-bit file sizes\x00" as *const u8,
                        );
                        return -25;
                    }
                    (*(*zip).entry).compressed_size = compressed as int64_t;
                    (*(*zip).entry).uncompressed_size = uncompressed as int64_t;
                    (*zip).unconsumed = 24 as size_t
                } else {
                    (*(*zip).entry).crc32 = archive_le32dec(p.offset(4 as isize) as *const ());
                    (*(*zip).entry).compressed_size =
                        archive_le32dec(p.offset(8 as isize) as *const ()) as int64_t;
                    (*(*zip).entry).uncompressed_size =
                        archive_le32dec(p.offset(12 as isize) as *const ()) as int64_t;
                    (*zip).unconsumed = 16 as size_t
                }
                if (*zip).hctx_valid != 0 {
                    r = check_authentication_code(a, buff as *const ());
                    if r != 0 {
                        return r;
                    }
                }
                (*zip).end_of_entry = 1;
                return 0;
            }
            /* If not at EOF, ensure we consume at least one byte. */
            p = p.offset(1 as isize);
            /* Scan forward until we see where a PK\007\010 signature
             * might be. */
            /* Return bytes up until that point.  On the next call,
             * the code above will verify the data descriptor. */
            while p < buff.offset(bytes_avail as isize - 4) {
                if *p.offset(3 as isize) as i32 == 'P' as i32 {
                    p = p.offset(3 as isize)
                } else if *p.offset(3 as isize) as i32 == 'K' as i32 {
                    p = p.offset(2 as isize)
                } else if *p.offset(3 as isize) as i32 == '\u{7}' as i32 {
                    p = p.offset(1 as isize)
                } else if *p.offset(3 as isize) as i32 == '\u{8}' as i32
                    && *p.offset(2 as isize) as i32 == '\u{7}' as i32
                    && *p.offset(1 as isize) as i32 == 'K' as i32
                    && *p.offset(0 as isize) as i32 == 'P' as i32
                {
                    if (*zip).hctx_valid != 0 {
                        p = p.offset(-(10 as isize))
                    }
                    break;
                } else {
                    p = p.offset(4 as isize)
                }
            }
            bytes_avail = p.offset_from(buff) as i64
        } else {
            if (*zip).entry_bytes_remaining == 0 {
                (*zip).end_of_entry = 1;
                if (*zip).hctx_valid != 0 {
                    r = check_authentication_code(a, 0 as *const ());
                    if r != 0 {
                        return r;
                    }
                }
                return 0;
            }
            /* Grab a bunch of bytes. */
            buff = __archive_read_ahead(a, 1 as size_t, &mut bytes_avail) as *const u8;
            if bytes_avail <= 0 {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    84,
                    b"Truncated ZIP file data\x00" as *const u8,
                );
                return -30;
            }
            if bytes_avail > (*zip).entry_bytes_remaining {
                bytes_avail = (*zip).entry_bytes_remaining
            }
        }
        if (*zip).tctx_valid as i32 != 0 || (*zip).cctx_valid as i32 != 0 {
            let mut dec_size: size_t = bytes_avail as size_t;
            if dec_size > (*zip).decrypted_buffer_size {
                dec_size = (*zip).decrypted_buffer_size
            }
            if (*zip).tctx_valid != 0 {
                trad_enc_decrypt_update(
                    &mut (*zip).tctx,
                    buff as *const uint8_t,
                    dec_size,
                    (*zip).decrypted_buffer,
                    dec_size,
                );
            } else {
                let mut dsize: size_t = dec_size;
                __archive_hmac
                    .__hmac_sha1_update
                    .expect("non-null function pointer")(
                    &mut (*zip).hctx,
                    buff as *const uint8_t,
                    dec_size,
                );
                __archive_cryptor
                    .decrypto_aes_ctr_update
                    .expect("non-null function pointer")(
                    &mut (*zip).cctx,
                    buff as *const uint8_t,
                    dec_size,
                    (*zip).decrypted_buffer,
                    &mut dsize,
                );
            }
            bytes_avail = dec_size as ssize_t;
            buff = (*zip).decrypted_buffer as *const u8
        }
        *size = bytes_avail as size_t;
        (*zip).entry_bytes_remaining -= bytes_avail;
        (*zip).entry_uncompressed_bytes_read += bytes_avail;
        (*zip).entry_compressed_bytes_read += bytes_avail;
        (*zip).unconsumed = ((*zip).unconsumed as u64) + (bytes_avail as u64) as size_t;
        *_buff = buff as *const ();
        return 0;
    }
}

fn consume_optional_marker(a: *mut archive_read, zip: *mut zip) -> i32 {
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };

    if unsafe {
        safe_zip.end_of_entry as i32 != 0 && (*safe_zip.entry).zip_flags as i32 & (1 << 3) != 0
    } {
        let mut p: *const u8;
        p = unsafe { __archive_read_ahead_safe(a, 24 as size_t, 0 as *mut ssize_t) as *const u8 };
        if p.is_null() {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    84,
                    b"Truncated ZIP end-of-file record\x00" as *const u8,
                )
            };
            return -30;
        }
        /* Consume the optional PK\007\010 marker. */
        if unsafe {
            *p.offset(0 as isize) as i32 == 'P' as i32
                && *p.offset(1 as isize) as i32 == 'K' as i32
                && *p.offset(2 as isize) as i32 == '\u{7}' as i32
                && *p.offset(3 as isize) as i32 == '\u{8}' as i32
        } {
            unsafe { p = p.offset(4 as isize) };
            safe_zip.unconsumed = 4 as size_t
        }
        if unsafe { (*(safe_zip).entry).flags as i32 & (1) << 0 != 0 } {
            let mut compressed: uint64_t = 0;
            let mut uncompressed: uint64_t = 0;
            unsafe { (*(safe_zip).entry).crc32 = archive_le32dec(p as *const ()) };
            compressed = archive_le64dec(unsafe { p.offset(4 as isize) as *const () });
            uncompressed = archive_le64dec(unsafe { p.offset(12 as isize) as *const () });
            if compressed > 9223372036854775807 || uncompressed > 9223372036854775807 {
                unsafe {
                    archive_set_error(
                        &mut (*a).archive as *mut archive,
                        84,
                        b"Overflow of 64-bit file sizes\x00" as *const u8,
                    )
                };
                return -25;
            }
            unsafe {
                (*(safe_zip).entry).compressed_size = compressed as int64_t;
                (*(safe_zip).entry).uncompressed_size = uncompressed as int64_t;
            }
            safe_zip.unconsumed = safe_zip.unconsumed as u64 + 20
        } else {
            unsafe {
                (*safe_zip.entry).crc32 = archive_le32dec(p as *const ());
                (*safe_zip.entry).compressed_size =
                    archive_le32dec(p.offset(4 as isize) as *const ()) as int64_t;
                (*safe_zip.entry).uncompressed_size =
                    archive_le32dec(p.offset(8 as isize) as *const ()) as int64_t;
                safe_zip.unconsumed = safe_zip.unconsumed as u64 + 12
            }
        }
    }
    return 0;
}

#[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
fn zipx_xz_init(a: *mut archive_read, zip: *mut zip) -> i32 {
    let mut r: lzma_ret = LZMA_OK;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };

    if safe_zip.zipx_lzma_valid != 0 {
        unsafe { lzma_end_safe(&mut safe_zip.zipx_lzma_stream) };
        safe_zip.zipx_lzma_valid = 0
    }
    unsafe {
        memset_safe(
            &mut safe_zip.zipx_lzma_stream as *mut lzma_stream as *mut (),
            0,
            size_of::<lzma_stream>() as u64,
        )
    };
    r = unsafe {
        lzma_stream_decoder_safe(
            &mut safe_zip.zipx_lzma_stream,
            18446744073709551615,
            0 as uint32_t,
        )
    };
    if r as u32 != LZMA_OK as u32 {
        unsafe {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                -1,
                b"xz initialization failed(%d)\x00" as *const u8,
                r as u32,
            )
        };
        return -25;
    }
    safe_zip.zipx_lzma_valid = 1;
    unsafe { free_safe(safe_zip.uncompressed_buffer as *mut ()) };
    safe_zip.uncompressed_buffer_size = (256 * 1024) as size_t;
    safe_zip.uncompressed_buffer =
        unsafe { malloc_safe(safe_zip.uncompressed_buffer_size) as *mut uint8_t };
    if safe_zip.uncompressed_buffer.is_null() {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                12,
                b"No memory for xz decompression\x00" as *const u8,
            )
        };
        return -30;
    }
    safe_zip.decompress_init = 1;
    return 0;
}
fn zipx_lzma_alone_init(a: *mut archive_read, zip: *mut zip) -> i32 {
    unsafe {
        let safe_a = unsafe { &mut *a };
        let safe_zip = unsafe { &mut *zip };

        let mut r: lzma_ret = LZMA_OK;
        let mut p: *const uint8_t = 0 as *const uint8_t;
        let mut alone_header: _alone_header = _alone_header {
            bytes: [0; 5],
            uncompressed_size: 0,
        };
        if safe_zip.zipx_lzma_valid != 0 {
            lzma_end(&mut safe_zip.zipx_lzma_stream);
            safe_zip.zipx_lzma_valid = 0
        }

        memset_safe(
            &mut safe_zip.zipx_lzma_stream as *mut lzma_stream as *mut (),
            0,
            size_of::<lzma_stream>() as u64,
        );
        r = lzma_alone_decoder_safe(&mut safe_zip.zipx_lzma_stream, 18446744073709551615);
        if r as u32 != LZMA_OK as u32 {
            unsafe {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -1,
                    b"lzma initialization failed(%d)\x00" as *const u8,
                    r as u32,
                )
            };
            return -25;
        }

        (safe_zip).zipx_lzma_valid = 1;

        p = __archive_read_ahead_safe(a, 9, 0 as *mut ssize_t) as *const uint8_t;
        if p.is_null() {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    84,
                    b"Truncated lzma data\x00" as *const u8,
                )
            };
            return -30;
        }
        if unsafe { *p.offset(2 as isize) as i32 != 0x5 || *p.offset(3 as isize) as i32 != 0 } {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    84,
                    b"Invalid lzma data\x00" as *const u8,
                )
            };
            return -30;
        }
        /* Prepare an lzma alone header: copy the lzma_params blob into
         * a proper place into the lzma alone header. */
        memcpy_safe(
            &mut *alone_header.bytes.as_mut_ptr().offset(0 as isize) as *mut uint8_t as *mut (),
            p.offset(4 as isize) as *const (),
            5,
        );
        /* Initialize the 'uncompressed size' field to unknown; we'll manually
         * monitor how many bytes there are still to be uncompressed. */
        alone_header.uncompressed_size = 18446744073709551615;
        if (safe_zip).uncompressed_buffer.is_null() {
            (safe_zip).uncompressed_buffer_size = (256 * 1024) as size_t;
            (safe_zip).uncompressed_buffer =
                malloc_safe((safe_zip).uncompressed_buffer_size) as *mut uint8_t;
            if (safe_zip).uncompressed_buffer.is_null() {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        12,
                        b"No memory for lzma decompression\x00" as *const u8,
                    )
                };
                return -30;
            }
        }
        safe_zip.zipx_lzma_stream.next_in =
            &mut alone_header as *mut _alone_header as *mut () as *const uint8_t;
        safe_zip.zipx_lzma_stream.avail_in = size_of::<_alone_header>() as u64;
        safe_zip.zipx_lzma_stream.total_in = 0;
        safe_zip.zipx_lzma_stream.next_out = safe_zip.uncompressed_buffer;
        safe_zip.zipx_lzma_stream.avail_out = safe_zip.uncompressed_buffer_size;
        safe_zip.zipx_lzma_stream.total_out = 0;
        /* Feed only the header into the lzma alone decoder. This will
         * effectively initialize the decoder, and will not produce any
         * output bytes yet. */
        r = lzma_code(&mut safe_zip.zipx_lzma_stream, LZMA_RUN);
        if r as u32 != LZMA_OK as u32 {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                22,
                b"lzma stream initialization error\x00" as *const u8,
            );
            return -30;
        }
        /* We've already consumed some bytes, so take this into account. */
        __archive_read_consume_safe(a, 9);
        safe_zip.entry_bytes_remaining -= 9;
        safe_zip.entry_compressed_bytes_read += 9;
        safe_zip.decompress_init = 1;
        return 0;
    }
}
fn zip_read_data_zipx_xz(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let safe_a = unsafe { &mut *a };
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let safe_zip = unsafe { &mut *zip };
    let mut ret: i32 = 0;
    let mut lz_ret: lzma_ret = LZMA_OK;
    let mut compressed_buf: *const () = 0 as *const ();
    let mut bytes_avail: ssize_t = 0;
    let mut in_bytes: ssize_t = 0;
    let mut to_consume: ssize_t = 0;
    /* UNUSED */
    /* Initialize decompressor if not yet initialized. */
    if safe_zip.decompress_init == 0 {
        ret = zipx_xz_init(a, zip);
        if ret != 0 {
            return ret;
        }
    }
    compressed_buf = unsafe { __archive_read_ahead_safe(a, 1 as size_t, &mut bytes_avail) };
    if bytes_avail < 0 {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84,
                b"Truncated xz file body\x00" as *const u8,
            )
        };
        return -30;
    }
    in_bytes = if safe_zip.entry_bytes_remaining < bytes_avail {
        safe_zip.entry_bytes_remaining
    } else {
        bytes_avail
    };
    safe_zip.zipx_lzma_stream.next_in = compressed_buf as *const uint8_t;
    safe_zip.zipx_lzma_stream.avail_in = in_bytes as size_t;
    safe_zip.zipx_lzma_stream.total_in = 0;
    safe_zip.zipx_lzma_stream.next_out = safe_zip.uncompressed_buffer;
    safe_zip.zipx_lzma_stream.avail_out = safe_zip.uncompressed_buffer_size;
    safe_zip.zipx_lzma_stream.total_out = 0;
    /* Perform the decompression. */
    lz_ret = unsafe { lzma_code_safe(&mut safe_zip.zipx_lzma_stream, LZMA_RUN) };
    match lz_ret as u32 {
        9 => {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -1,
                    b"xz data error (error %d)\x00" as *const u8,
                    lz_ret as i32,
                )
            };
            return -30;
        }
        2 | 0 => {}
        1 => {
            unsafe { lzma_end_safe(&mut (safe_zip).zipx_lzma_stream) };
            safe_zip.zipx_lzma_valid = 0;
            if safe_zip.zipx_lzma_stream.total_in as int64_t != safe_zip.entry_bytes_remaining {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -1,
                        b"xz premature end of stream\x00" as *const u8,
                    )
                };
                return -30;
            }
            safe_zip.end_of_entry = 1
        }
        _ => {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    -1,
                    b"xz unknown error %d\x00" as *const u8,
                    lz_ret as i32,
                )
            };
            return -30;
        }
    }
    to_consume = safe_zip.zipx_lzma_stream.total_in as ssize_t;
    unsafe { __archive_read_consume_safe(a, to_consume) };
    safe_zip.entry_bytes_remaining -= to_consume;
    safe_zip.entry_compressed_bytes_read += to_consume;
    safe_zip.entry_uncompressed_bytes_read = (safe_zip.entry_uncompressed_bytes_read as int64_t)
        + (safe_zip.zipx_lzma_stream.total_out) as int64_t;
    unsafe { *size = safe_zip.zipx_lzma_stream.total_out };
    unsafe { *buff = safe_zip.uncompressed_buffer as *const () };
    ret = consume_optional_marker(a, zip);
    if ret != 0 {
        return ret;
    }
    return 0;
}

#[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
fn zip_read_data_zipx_lzma_alone(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };

    let mut ret: i32 = 0;
    let mut lz_ret: lzma_ret = LZMA_OK;
    let mut compressed_buf: *const () = 0 as *const ();
    let mut bytes_avail: ssize_t = 0;
    let mut in_bytes: ssize_t = 0;
    let mut to_consume: ssize_t = 0;

    if safe_zip.decompress_init == 0 {
        ret = zipx_lzma_alone_init(a, zip);
        if ret != 0 {
            return ret;
        }
    }

    compressed_buf = unsafe { __archive_read_ahead_safe(a, 1, &mut bytes_avail) };
    if bytes_avail < 0 {
        unsafe {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                84,
                b"Truncated lzma file body\x00" as *const u8,
            )
        };
        return -30;
    }
    /* Set decompressor parameters. */
    in_bytes = if safe_zip.entry_bytes_remaining < bytes_avail {
        safe_zip.entry_bytes_remaining
    } else {
        bytes_avail
    };
    safe_zip.zipx_lzma_stream.next_in = compressed_buf as *const uint8_t;
    safe_zip.zipx_lzma_stream.avail_in = in_bytes as size_t;
    safe_zip.zipx_lzma_stream.total_in = 0;
    safe_zip.zipx_lzma_stream.next_out = safe_zip.uncompressed_buffer;
    safe_zip.zipx_lzma_stream.avail_out = if unsafe {
        (safe_zip.uncompressed_buffer_size as int64_t)
            < (*safe_zip.entry).uncompressed_size - safe_zip.entry_uncompressed_bytes_read
    } {
        safe_zip.uncompressed_buffer_size as int64_t
    } else {
        unsafe { ((*safe_zip.entry).uncompressed_size) - safe_zip.entry_uncompressed_bytes_read }
    } as size_t;
    safe_zip.zipx_lzma_stream.total_out = 0;
    /* Perform the decompression. */
    lz_ret = unsafe { lzma_code_safe(&mut safe_zip.zipx_lzma_stream, LZMA_RUN) };
    match lz_ret as u32 {
        9 => {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    -1,
                    b"lzma data error (error %d)\x00" as *const u8,
                    lz_ret as i32,
                )
            };
            return -30;
        }
        1 => {
            /* This case is optional in lzma alone format. It can happen,
             * but most of the files don't have it. (GitHub #1257) */
            unsafe { lzma_end_safe(&mut safe_zip.zipx_lzma_stream) };
            safe_zip.zipx_lzma_valid = 0;
            if safe_zip.zipx_lzma_stream.total_in as int64_t != safe_zip.entry_bytes_remaining {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -1,
                        b"lzma alone premature end of stream\x00" as *const u8,
                    )
                };
                return -30;
            }
            safe_zip.end_of_entry = 1
        }
        0 => {}
        _ => {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -1,
                    b"lzma unknown error %d\x00" as *const u8,
                    lz_ret as i32,
                )
            };
            return -30;
        }
    }
    to_consume = (safe_zip).zipx_lzma_stream.total_in as ssize_t;
    /* Update pointers. */
    unsafe { __archive_read_consume_safe(a, to_consume) };
    safe_zip.entry_bytes_remaining -= to_consume;
    safe_zip.entry_compressed_bytes_read += to_consume;
    safe_zip.entry_uncompressed_bytes_read = (safe_zip.entry_uncompressed_bytes_read as int64_t)
        + (safe_zip.zipx_lzma_stream.total_out) as int64_t;
    if safe_zip.entry_bytes_remaining == 0 {
        safe_zip.end_of_entry = 1
    }
    /* Return values. */
    unsafe {
        *size = safe_zip.zipx_lzma_stream.total_out;
        *buff = safe_zip.uncompressed_buffer as *const ();
    }
    /* Behave the same way as during deflate decompression. */
    ret = consume_optional_marker(a, zip);
    if ret != 0 {
        return ret;
    }
    /* Free lzma decoder handle because we'll no longer need it. */
    if safe_zip.end_of_entry != 0 {
        unsafe { lzma_end_safe(&mut safe_zip.zipx_lzma_stream) };
        safe_zip.zipx_lzma_valid = 0
    }
    /* If we're here, then we're good! */
    return 0;
}
/* HAVE_LZMA_H && HAVE_LIBLZMA */
fn zipx_ppmd8_init(a: *mut archive_read, zip: *mut zip) -> i32 {
    let mut p: *const () = 0 as *const ();
    let mut val: uint32_t = 0;
    let mut order: uint32_t = 0;
    let mut mem: uint32_t = 0;
    let mut restore_method: uint32_t = 0;

    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    /* Remove previous decompression context if it exists. */
    if (safe_zip).ppmd8_valid != 0 {
        unsafe {
            __archive_ppmd8_functions
                .Ppmd8_Free
                .expect("non-null function pointer")(&mut (safe_zip).ppmd8);
            (safe_zip).ppmd8_valid = 0
        }
    }
    /* Create a new decompression context. */
    unsafe {
        __archive_ppmd8_functions
            .Ppmd8_Construct
            .expect("non-null function pointer")(&mut (*zip).ppmd8)
    };
    safe_zip.ppmd8_stream_failed = 0;
    /* Setup function pointers required by Ppmd8 decompressor. The
     * 'ppmd_read' function will feed new bytes to the decompressor,
     * and will increment the 'zip->zipx_ppmd_read_compressed' counter. */
    safe_zip.ppmd8.Stream.In = &mut safe_zip.zipx_ppmd_stream;
    safe_zip.zipx_ppmd_stream.a = a;
    safe_zip.zipx_ppmd_stream.Read = Some(ppmd_read);
    /* Reset number of read bytes to 0. */
    safe_zip.zipx_ppmd_read_compressed = 0;
    /* Read Ppmd8 header (2 bytes). */
    p = unsafe { __archive_read_ahead_safe(a, 2 as size_t, 0 as *mut ssize_t) };
    if p.is_null() {
        unsafe {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                84,
                b"Truncated file data in PPMd8 stream\x00" as *const u8,
            )
        };
        return -30;
    }
    unsafe { __archive_read_consume_safe(a, 2) };
    /* Decode the stream's compression parameters. */
    val = archive_le16dec(p) as uint32_t;
    order = (val & 15) + 1;
    mem = (val >> 4 & 0xff) + 1;
    restore_method = val >> 12;
    if order < 2 || restore_method > 2 {
        unsafe {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                84,
                b"Invalid parameter set in PPMd8 stream (order=%d, restore=%d)\x00" as *const u8
                    as *const u8,
                order,
                restore_method,
            )
        };
        return -25;
    }
    /* Allocate the memory needed to properly decompress the file. */
    if unsafe {
        __archive_ppmd8_functions
            .Ppmd8_Alloc
            .expect("non-null function pointer")(&mut (safe_zip).ppmd8, mem << 20)
            == 0
    } {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                12,
                b"Unable to allocate memory for PPMd8 stream: %d bytes\x00" as *const u8
                    as *const u8,
                mem << 20,
            )
        };
        return -30;
    }
    /* Signal the cleanup function to release Ppmd8 context in the
     * cleanup phase. */
    (safe_zip).ppmd8_valid = 1;
    /* Perform further Ppmd8 initialization. */
    if unsafe {
        __archive_ppmd8_functions
            .Ppmd8_RangeDec_Init
            .expect("non-null function pointer")(&mut (*zip).ppmd8)
            == 0
    } {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                22,
                b"PPMd8 stream range decoder initialization error\x00" as *const u8,
            )
        };
        return -30;
    }
    unsafe {
        __archive_ppmd8_functions
            .Ppmd8_Init
            .expect("non-null function pointer")(&mut (*zip).ppmd8, order, restore_method)
    };
    /* Allocate the buffer that will hold uncompressed data. */
    unsafe { free_safe((safe_zip).uncompressed_buffer as *mut ()) };
    safe_zip.uncompressed_buffer_size = (256 * 1024) as size_t;
    safe_zip.uncompressed_buffer =
        unsafe { malloc_safe(safe_zip.uncompressed_buffer_size) as *mut uint8_t };
    if safe_zip.uncompressed_buffer.is_null() {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                12,
                b"No memory for PPMd8 decompression\x00" as *const u8,
            )
        };
        return -30;
    }
    /* Ppmd8 initialization is done. */
    (safe_zip).decompress_init = 1;
    /* We've already read 2 bytes in the output stream. Additionally,
     * Ppmd8 initialization code could read some data as well. So we
     * are advancing the stream by 2 bytes plus whatever number of
     * bytes Ppmd8 init function used. */
    (safe_zip).entry_compressed_bytes_read += 2 + (safe_zip).zipx_ppmd_read_compressed;
    return 0;
}
fn zip_read_data_zipx_ppmd(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    let mut ret: i32 = 0;
    let mut consumed_bytes: size_t = 0 as size_t;
    let mut bytes_avail: ssize_t = 0 as ssize_t;
    /* UNUSED */
    /* If we're here for the first time, initialize Ppmd8 decompression
     * context first. */
    if safe_zip.decompress_init == 0 {
        ret = zipx_ppmd8_init(a, zip);
        if ret != 0 {
            return ret;
        }
    }
    /* Fetch for more data. We're reading 1 byte here, but libarchive
     * should prefetch more bytes. */
    unsafe { __archive_read_ahead_safe(a, 1, &mut bytes_avail) };
    if bytes_avail < 0 {
        unsafe {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                84,
                b"Truncated PPMd8 file body\x00" as *const u8,
            )
        };
        return -30;
    }
    /* This counter will be updated inside ppmd_read(), which at one
     * point will be called by Ppmd8_DecodeSymbol. */
    safe_zip.zipx_ppmd_read_compressed = 0;
    loop
    /* Decompression loop. */
    {
        let mut sym: i32 = unsafe {
            __archive_ppmd8_functions
                .Ppmd8_DecodeSymbol
                .expect("non-null function pointer")(&mut (*zip).ppmd8)
        };

        if sym < 0 {
            safe_zip.end_of_entry = 1;
            break;
        } else {
            /* This field is set by ppmd_read() when there was no more data
             * to be read. */
            if safe_zip.ppmd8_stream_failed != 0 {
                unsafe {
                    archive_set_error(
                        &mut safe_a.archive as *mut archive,
                        84,
                        b"Truncated PPMd8 file body\x00" as *const u8,
                    )
                };
                return -30;
            }
            unsafe {
                *(safe_zip)
                    .uncompressed_buffer
                    .offset(consumed_bytes as isize) = sym as uint8_t
            };
            consumed_bytes = consumed_bytes + 1;
            if !(consumed_bytes < safe_zip.uncompressed_buffer_size) {
                break;
            }
        }
    }
    /* Update pointers for libarchive. */
    unsafe {
        *buff = safe_zip.uncompressed_buffer as *const ();
        *size = consumed_bytes;
    }
    /* Update pointers so we can continue decompression in another call. */
    (safe_zip).entry_bytes_remaining -= safe_zip.zipx_ppmd_read_compressed;
    (safe_zip).entry_compressed_bytes_read += safe_zip.zipx_ppmd_read_compressed;
    safe_zip.entry_uncompressed_bytes_read =
        (safe_zip.entry_uncompressed_bytes_read as int64_t) + consumed_bytes as int64_t;
    /* If we're at the end of stream, deinitialize Ppmd8 context. */
    if safe_zip.end_of_entry != 0 {
        unsafe {
            __archive_ppmd8_functions
                .Ppmd8_Free
                .expect("non-null function pointer")(&mut safe_zip.ppmd8);
            safe_zip.ppmd8_valid = 0
        }
    }
    /* Seek for optional marker, same way as in each zip entry. */
    ret = consume_optional_marker(a, zip);
    if ret != 0 {
        return ret;
    }
    return 0;
}

#[cfg(HAVE_BZLIB_H)]
fn zipx_bzip2_init(a: *mut archive_read, zip: *mut zip) -> i32 {
    let mut r: i32 = 0;
    /* Deallocate already existing BZ2 decompression context if it
     * exists. */

    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };

    if safe_zip.bzstream_valid != 0 {
        unsafe { BZ2_bzDecompressEnd_safe(&mut safe_zip.bzstream) };
        safe_zip.bzstream_valid = 0
    }
    /* Allocate a new BZ2 decompression context. */
    unsafe {
        memset_safe(
            &mut safe_zip.bzstream as *mut bz_stream as *mut (),
            0,
            size_of::<bz_stream>() as u64,
        )
    };
    r = unsafe { BZ2_bzDecompressInit_safe(&mut (safe_zip).bzstream, 0, 1) };
    if r != 0 {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -1,
                b"bzip2 initialization failed(%d)\x00" as *const u8,
                r,
            )
        };
        return -25;
    }
    /* Mark the bzstream field to be released in cleanup phase. */
    safe_zip.bzstream_valid = 1;
    /* (Re)allocate the buffer that will contain decompressed bytes. */
    unsafe { free_safe(safe_zip.uncompressed_buffer as *mut ()) };
    safe_zip.uncompressed_buffer_size = (256 * 1024) as size_t;
    safe_zip.uncompressed_buffer =
        unsafe { malloc_safe(safe_zip.uncompressed_buffer_size) as *mut uint8_t };
    if safe_zip.uncompressed_buffer.is_null() {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                12,
                b"No memory for bzip2 decompression\x00" as *const u8,
            )
        };
        return -30;
    }
    /* Initialization done. */
    safe_zip.decompress_init = 1;
    return 0;
}
fn zip_read_data_zipx_bzip2(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };

    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };

    let mut bytes_avail: ssize_t = 0 as ssize_t;
    let mut in_bytes: ssize_t = 0;
    let mut to_consume: ssize_t = 0;
    let mut compressed_buff: *const () = 0 as *const ();
    let mut r: i32 = 0;
    let mut total_out: uint64_t = 0;
    /* UNUSED */
    /* Initialize decompression context if we're here for the first time. */
    if safe_zip.decompress_init == 0 {
        r = zipx_bzip2_init(a, zip);
        if r != 0 {
            return r;
        }
    }
    /* Fetch more compressed bytes. */
    compressed_buff = unsafe { __archive_read_ahead_safe(a, 1, &mut bytes_avail) };
    if bytes_avail < 0 {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84,
                b"Truncated bzip2 file body\x00" as *const u8,
            )
        };
        return -30;
    }
    in_bytes = if (safe_zip).entry_bytes_remaining < bytes_avail {
        safe_zip.entry_bytes_remaining
    } else {
        bytes_avail
    };
    if in_bytes < 1 {
        /* libbz2 doesn't complain when caller feeds avail_in == 0.
         * It will actually return success in this case, which is
         * undesirable. This is why we need to make this check
         * manually. */
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84,
                b"Truncated bzip2 file body\x00" as *const u8,
            )
        };
        return -30;
    }
    /* Setup buffer boundaries. */
    safe_zip.bzstream.next_in = compressed_buff as uintptr_t as *mut u8;
    safe_zip.bzstream.avail_in = in_bytes as u32;
    safe_zip.bzstream.total_in_hi32 = 0;
    safe_zip.bzstream.total_in_lo32 = 0;
    safe_zip.bzstream.next_out = safe_zip.uncompressed_buffer as *mut u8;
    safe_zip.bzstream.avail_out = safe_zip.uncompressed_buffer_size as u32;
    safe_zip.bzstream.total_out_hi32 = 0;
    safe_zip.bzstream.total_out_lo32 = 0;
    /* Perform the decompression. */
    r = unsafe { BZ2_bzDecompress_safe(&mut safe_zip.bzstream) };
    match r {
        4 => {
            /* If we're at the end of the stream, deinitialize the
             * decompression context now. */
            match unsafe { BZ2_bzDecompressEnd_safe(&mut (safe_zip).bzstream) } {
                0 => {}
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -1,
                            b"Failed to clean up bzip2 decompressor\x00" as *const u8,
                        )
                    };
                    return -30;
                }
            }
            (safe_zip).end_of_entry = 1
        }
        0 => {}
        _ => {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -1,
                    b"bzip2 decompression failed\x00" as *const u8,
                )
            };
            return -30;
        }
    }
    /* Update the pointers so decompressor can continue decoding. */
    to_consume = (safe_zip).bzstream.total_in_lo32 as ssize_t;
    unsafe { __archive_read_consume_safe(a, to_consume) };
    total_out = (((safe_zip).bzstream.total_out_hi32 as uint64_t) << 32)
        + (safe_zip).bzstream.total_out_lo32 as u64;
    safe_zip.entry_bytes_remaining -= to_consume;
    safe_zip.entry_compressed_bytes_read += to_consume;
    safe_zip.entry_uncompressed_bytes_read =
        (safe_zip.entry_uncompressed_bytes_read as i64) + total_out as int64_t;
    /* Give libarchive its due. */
    unsafe {
        *size = total_out;
        *buff = (safe_zip).uncompressed_buffer as *const ();
    }
    /* Seek for optional marker, like in other entries. */
    r = consume_optional_marker(a, zip);
    if r != 0 {
        return r;
    }
    return 0;
}

#[cfg(HAVE_ZLIB_H)]
fn zip_deflate_init(a: *mut archive_read, zip: *mut zip) -> i32 {
    let mut r: i32 = 0;
    /* If we haven't yet read any data, initialize the decompressor. */
    let safe_zip = unsafe { &mut *zip };
    if safe_zip.decompress_init == 0 {
        if safe_zip.stream_valid != 0 {
            r = unsafe { inflateReset_safe(&mut safe_zip.stream) }
        } else {
            r = unsafe {
                inflateInit2__safe(
                    &mut safe_zip.stream,
                    -15,
                    b"1.2.11\x00" as *const u8,
                    size_of::<z_stream>() as u64 as i32,
                )
            }
        }
        /* Don't check for zlib header */
        if r != 0 {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    -1,
                    b"Can\'t initialize ZIP decompression.\x00" as *const u8,
                )
            };
            return -30;
        }
        /* Stream structure has been set up. */
        (safe_zip).stream_valid = 1;
        /* We've initialized decompression for this stream. */
        (safe_zip).decompress_init = 1
    }
    return 0;
}

#[cfg(HAVE_ZLIB_H)]
fn zip_read_data_deflate(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    unsafe {
        let mut zip: *mut zip = 0 as *mut zip;
        let mut bytes_avail: ssize_t = 0;
        let mut compressed_buff: *const () = 0 as *const ();
        let mut sp: *const () = 0 as *const ();
        let mut r: i32 = 0;
        /* UNUSED */
        zip = (*(*a).format).data as *mut zip;
        /* If the buffer hasn't been allocated, allocate it now. */
        if (*zip).uncompressed_buffer.is_null() {
            (*zip).uncompressed_buffer_size = (256 * 1024) as size_t;
            (*zip).uncompressed_buffer = malloc((*zip).uncompressed_buffer_size) as *mut u8;
            if (*zip).uncompressed_buffer.is_null() {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    12,
                    b"No memory for ZIP decompression\x00" as *const u8,
                );
                return -30;
            }
        }
        r = zip_deflate_init(a, zip);
        if r != 0 {
            return r;
        }
        /*
         * Note: '1' here is a performance optimization.
         * Recall that the decompression layer returns a count of
         * available bytes; asking for more than that forces the
         * decompressor to combine reads by copying data.
         */
        sp = __archive_read_ahead(a, 1 as size_t, &mut bytes_avail);
        compressed_buff = sp;
        if 0 == (*(*zip).entry).zip_flags as i32 & (1 << 3)
            && bytes_avail > (*zip).entry_bytes_remaining
        {
            bytes_avail = (*zip).entry_bytes_remaining
        }
        if bytes_avail < 0 {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                84,
                b"Truncated ZIP file body\x00" as *const u8,
            );
            return -30;
        }
        if (*zip).tctx_valid as i32 != 0 || (*zip).cctx_valid as i32 != 0 {
            if (*zip).decrypted_bytes_remaining < bytes_avail as size_t {
                let mut buff_remaining: size_t = (*zip)
                    .decrypted_buffer
                    .offset((*zip).decrypted_buffer_size as isize)
                    .offset_from(
                        (*zip)
                            .decrypted_ptr
                            .offset((*zip).decrypted_bytes_remaining as isize),
                    ) as size_t;
                if buff_remaining > bytes_avail as size_t {
                    buff_remaining = bytes_avail as size_t
                }
                if 0 == (*(*zip).entry).zip_flags as i32 & (1 << 3)
                    && (*zip).entry_bytes_remaining > 0
                {
                    if ((*zip).decrypted_bytes_remaining as int64_t + buff_remaining as int64_t)
                        > (*zip).entry_bytes_remaining
                    {
                        if (*zip).entry_bytes_remaining
                            < (*zip).decrypted_bytes_remaining as int64_t
                        {
                            buff_remaining = 0 as size_t
                        } else {
                            buff_remaining = ((*zip).entry_bytes_remaining as size_t)
                                - (*zip).decrypted_bytes_remaining
                        }
                    }
                }
                if buff_remaining > 0 {
                    if (*zip).tctx_valid != 0 {
                        trad_enc_decrypt_update(
                            &mut (*zip).tctx,
                            compressed_buff as *const uint8_t,
                            buff_remaining,
                            (*zip)
                                .decrypted_ptr
                                .offset((*zip).decrypted_bytes_remaining as isize),
                            buff_remaining,
                        );
                    } else {
                        let mut dsize: size_t = buff_remaining;
                        __archive_cryptor
                            .decrypto_aes_ctr_update
                            .expect("non-null function pointer")(
                            &mut (*zip).cctx,
                            compressed_buff as *const uint8_t,
                            buff_remaining,
                            (*zip)
                                .decrypted_ptr
                                .offset((*zip).decrypted_bytes_remaining as isize),
                            &mut dsize,
                        );
                    }
                    (*zip).decrypted_bytes_remaining =
                        ((*zip).decrypted_bytes_remaining as u64) + buff_remaining as size_t
                }
            }
            bytes_avail = (*zip).decrypted_bytes_remaining as ssize_t;
            compressed_buff = (*zip).decrypted_ptr as *const u8 as *const ()
        }
        /*
         * A bug in zlib.h: stream.next_in should be marked 'const'
         * but isn't (the library never alters data through the
         * next_in pointer, only reads it).  The result: this ugly
         * cast to remove 'const'.
         */
        (*zip).stream.next_in = compressed_buff as uintptr_t as *mut Bytef;
        (*zip).stream.avail_in = bytes_avail as uInt;
        (*zip).stream.total_in = 0;
        (*zip).stream.next_out = (*zip).uncompressed_buffer;
        (*zip).stream.avail_out = (*zip).uncompressed_buffer_size as uInt;
        (*zip).stream.total_out = 0;
        r = inflate(&mut (*zip).stream, 0);
        match r {
            0 => {}
            1 => (*zip).end_of_entry = 1,
            -4 => {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    12,
                    b"Out of memory for ZIP decompression\x00" as *const u8,
                );
                return -30;
            }
            _ => {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    -1,
                    b"ZIP decompression failed (%d)\x00" as *const u8,
                    r,
                );
                return -30;
            }
        }
        /* Consume as much as the compressor actually used. */
        bytes_avail = (*zip).stream.total_in as ssize_t;
        if (*zip).tctx_valid as i32 != 0 || (*zip).cctx_valid as i32 != 0 {
            (*zip).decrypted_bytes_remaining =
                ((*zip).decrypted_bytes_remaining as u64) - bytes_avail as u64;
            if (*zip).decrypted_bytes_remaining == 0 {
                (*zip).decrypted_ptr = (*zip).decrypted_buffer
            } else {
                (*zip).decrypted_ptr = (*zip).decrypted_ptr.offset(bytes_avail as isize)
            }
        }
        /* Calculate compressed data as much as we used.*/
        if (*zip).hctx_valid != 0 {
            __archive_hmac
                .__hmac_sha1_update
                .expect("non-null function pointer")(
                &mut (*zip).hctx,
                sp as *const uint8_t,
                bytes_avail as size_t,
            );
        }
        __archive_read_consume(a, bytes_avail);
        (*zip).entry_bytes_remaining -= bytes_avail;
        (*zip).entry_compressed_bytes_read += bytes_avail;
        *size = (*zip).stream.total_out;
        (*zip).entry_uncompressed_bytes_read =
            ((*zip).entry_uncompressed_bytes_read as int64_t) + (*zip).stream.total_out as int64_t;
        *buff = (*zip).uncompressed_buffer as *const ();
        if (*zip).end_of_entry as i32 != 0 && (*zip).hctx_valid as i32 != 0 {
            r = check_authentication_code(a, 0 as *const ());
            if r != 0 {
                return r;
            }
        }
        r = consume_optional_marker(a, zip);
        if r != 0 {
            return r;
        }
        return 0;
    }
}

fn read_decryption_header(a: *mut archive_read) -> i32 {
    let mut current_block: u64;
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let mut p: *const u8;
    let remaining_size: u32;
    let mut ts: u32;

    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    /*
     * Read an initialization vector data field.
     */
    p = unsafe { __archive_read_ahead_safe(a, 2, 0 as *mut ssize_t) as *const u8 };
    if !p.is_null() {
        ts = safe_zip.iv_size;
        safe_zip.iv_size = archive_le16dec(p as *const ()) as u32;
        unsafe { __archive_read_consume_safe(a, 2) };
        if ts < safe_zip.iv_size {
            unsafe { free_safe(safe_zip.iv as *mut ()) };
            safe_zip.iv = 0 as *mut uint8_t
        }
        p = unsafe { __archive_read_ahead_safe(a, safe_zip.iv_size as size_t, 0 as *mut ssize_t) }
            as *const u8;
        if !p.is_null() {
            if safe_zip.iv.is_null() {
                safe_zip.iv = unsafe { malloc_safe(safe_zip.iv_size as u64) as *mut uint8_t };
                if safe_zip.iv.is_null() {
                    current_block = 1;
                } else {
                    current_block = 2;
                }
            } else {
                current_block = 2;
            }
            match current_block {
                2 => {
                    unsafe {
                        memcpy_safe(
                            safe_zip.iv as *mut (),
                            p as *const (),
                            safe_zip.iv_size as u64,
                        )
                    };
                    unsafe { __archive_read_consume_safe(a, safe_zip.iv_size as int64_t) };
                    /*
                     * Read a size of remaining decryption header field.
                     */
                    p = unsafe { __archive_read_ahead_safe(a, 14 as size_t, 0 as *mut ssize_t) }
                        as *const u8;
                    if p.is_null() {
                        current_block = 3;
                    } else {
                        remaining_size = archive_le32dec(p as *const ());
                        if remaining_size < 16 || remaining_size > (1 << 18) as u32 {
                            current_block = 4;
                        } else {
                            /* Check if format version is supported. */
                            if archive_le16dec(unsafe { p.offset(4 as isize) as *const () }) as i32
                                != 3
                            {
                                unsafe {
                                    archive_set_error(
                                        &mut (safe_a).archive as *mut archive,
                                        84,
                                        b"Unsupported encryption format version: %u\x00"
                                            as *const u8
                                            as *const u8,
                                        archive_le16dec(p.offset(4 as isize) as *const ()) as i32,
                                    )
                                };
                                return -25;
                            }
                            /*
                             * Read an encryption algorithm field.
                             */
                            (safe_zip).alg_id =
                                archive_le16dec(unsafe { p.offset(6 as isize) as *const () })
                                    as u32;
                            match (safe_zip).alg_id {
                                26113 | 26114 | 26115 | 26121 | 26126 | 26127 | 26128 | 26370
                                | 26400 | 26401 | 26625 => {}
                                _ => {
                                    unsafe {
                                        archive_set_error(
                                            &mut (safe_a).archive as *mut archive,
                                            84,
                                            b"Unknown encryption algorithm: %u\x00" as *const u8
                                                as *const u8,
                                            (safe_zip).alg_id,
                                        )
                                    };
                                    return -25;
                                }
                            }
                            /*
                             * Read a bit length field.
                             */
                            (safe_zip).bit_len =
                                archive_le16dec(unsafe { p.offset(8 as isize) as *const () })
                                    as u32;
                            /*
                             * Read a flags field.
                             */
                            (safe_zip).flags =
                                archive_le16dec(unsafe { p.offset(10 as isize) as *const () })
                                    as u32;
                            let mut current_block: u64;
                            match (safe_zip).flags & 0xf000 {
                                1 | 2 | 3 => {}
                                _ => {
                                    unsafe {
                                        archive_set_error(
                                            &mut (safe_a).archive as *mut archive,
                                            84,
                                            b"Unknown encryption flag: %u\x00" as *const u8
                                                as *const u8,
                                            (safe_zip).flags,
                                        )
                                    };
                                    return -25;
                                }
                            }
                            if (safe_zip).flags & 0xf000 == 0
                                || (safe_zip).flags & 0xf000 == 0x4000 as u32
                            {
                                unsafe {
                                    archive_set_error(
                                        &mut (safe_a).archive as *mut archive,
                                        84,
                                        b"Unknown encryption flag: %u\x00" as *const u8
                                            as *const u8,
                                        (safe_zip).flags,
                                    )
                                };
                                return -25;
                            }
                            /*
                             * Read an encrypted random data field.
                             */
                            ts = (safe_zip).erd_size;
                            (safe_zip).erd_size =
                                archive_le16dec(unsafe { p.offset(12 as isize) as *const () })
                                    as u32;
                            unsafe { __archive_read_consume_safe(a, 14) };
                            if (safe_zip).erd_size & 0xf != 0
                                || (safe_zip).erd_size + 16 > remaining_size
                                || (safe_zip).erd_size + 16 < (safe_zip).erd_size
                            {
                                current_block = 4;
                            } else {
                                if ts < (safe_zip).erd_size {
                                    unsafe { free_safe((safe_zip).erd as *mut ()) };
                                    (safe_zip).erd = 0 as *mut uint8_t
                                }
                                p = unsafe {
                                    __archive_read_ahead_safe(
                                        a,
                                        (safe_zip).erd_size as size_t,
                                        0 as *mut ssize_t,
                                    )
                                } as *const u8;
                                if p.is_null() {
                                    current_block = 3;
                                } else {
                                    if (safe_zip).erd.is_null() {
                                        (safe_zip).erd = unsafe {
                                            malloc_safe((safe_zip).erd_size as u64) as *mut uint8_t
                                        };
                                        if (safe_zip).erd.is_null() {
                                            current_block = 1;
                                        } else {
                                            current_block = 5;
                                        }
                                    } else {
                                        current_block = 5;
                                    }
                                    match current_block {
                                        1 => {}
                                        _ => {
                                            unsafe {
                                                memcpy_safe(
                                                    (safe_zip).erd as *mut (),
                                                    p as *const (),
                                                    (safe_zip).erd_size as u64,
                                                );
                                                __archive_read_consume_safe(
                                                    a,
                                                    (safe_zip).erd_size as int64_t,
                                                )
                                            };
                                            /*
                                             * Read a reserved data field.
                                             */
                                            p = unsafe {
                                                __archive_read_ahead_safe(a, 4, 0 as *mut ssize_t)
                                            }
                                                as *const u8;
                                            if p.is_null() {
                                                current_block = 3;
                                            } else if archive_le32dec(p as *const ()) != 0 {
                                                current_block = 4;
                                            } else {
                                                unsafe { __archive_read_consume_safe(a, 4) };
                                                /* Reserved data size should be zero. */
                                                /*
                                                 * Read a password validation data field.
                                                 */
                                                p = unsafe {
                                                    __archive_read_ahead_safe(
                                                        a,
                                                        2,
                                                        0 as *mut ssize_t,
                                                    )
                                                        as *const u8
                                                };
                                                if p.is_null() {
                                                    current_block = 3;
                                                } else {
                                                    ts = (safe_zip).v_size;
                                                    (safe_zip).v_size =
                                                        archive_le16dec(p as *const ()) as u32;
                                                    unsafe { __archive_read_consume_safe(a, 2) };
                                                    if (safe_zip).v_size & 0xf != 0
                                                        || (safe_zip).erd_size
                                                            + (safe_zip).v_size
                                                            + 16
                                                            > remaining_size
                                                        || (safe_zip).erd_size
                                                            + (safe_zip).v_size
                                                            + 16
                                                            < (safe_zip).erd_size + safe_zip.v_size
                                                    {
                                                        current_block = 4;
                                                    } else {
                                                        if ts < safe_zip.v_size {
                                                            unsafe {
                                                                free_safe(
                                                                    safe_zip.v_data as *mut (),
                                                                )
                                                            };
                                                            safe_zip.v_data = 0 as *mut uint8_t
                                                        }
                                                        p = unsafe {
                                                            __archive_read_ahead_safe(
                                                                a,
                                                                safe_zip.v_size as size_t,
                                                                0 as *mut ssize_t,
                                                            )
                                                        }
                                                            as *const u8;
                                                        if p.is_null() {
                                                            current_block = 3;
                                                        } else {
                                                            if safe_zip.v_data.is_null() {
                                                                safe_zip.v_data = unsafe {
                                                                    malloc_safe(
                                                                        safe_zip.v_size as u64,
                                                                    )
                                                                }
                                                                    as *mut uint8_t;
                                                                if safe_zip.v_data.is_null() {
                                                                    current_block = 1;
                                                                } else {
                                                                    current_block = 6;
                                                                }
                                                            } else {
                                                                current_block = 6;
                                                            }
                                                            match current_block {
                                                                1 => {}
                                                                _ => {
                                                                    unsafe {
                                                                        memcpy_safe(
                                                                            safe_zip.v_data
                                                                                as *mut (),
                                                                            p as *const (),
                                                                            safe_zip.v_size as u64,
                                                                        );
                                                                        __archive_read_consume_safe(
                                                                            a,
                                                                            safe_zip.v_size
                                                                                as int64_t,
                                                                        );
                                                                        p = __archive_read_ahead_safe(
                                                                        a,
                                                                        4,
                                                                        0 as *mut ssize_t,
                                                                    )
                                                                        as *const u8
                                                                    };
                                                                    if p.is_null() {
                                                                        current_block = 3;
                                                                    } else {
                                                                        safe_zip.v_crc32 =
                                                                            archive_le32dec(
                                                                                p as *const (),
                                                                            );
                                                                        unsafe {
                                                                            __archive_read_consume_safe(
                                                                            a,
                                                                            4,
                                                                        )
                                                                        };
                                                                        /*return (ARCHIVE_OK);
                                                                         * This is not fully implemented yet.*/
                                                                        unsafe {
                                                                            archive_set_error(&mut (*a).archive
                                                                                         as
                                                                                         *mut archive,
                                                                                     84
                                                                                         as
                                                                                         i32,
                                                                                     b"Encrypted file is unsupported\x00"
                                                                                         as
                                                                                         *const u8
                                                                                         as
                                                                                         *const u8)
                                                                        };
                                                                        return -25;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        match current_block {
                            3 => {}
                            1 => {}
                            _ => {
                                unsafe {
                                    archive_set_error(
                                        &mut (safe_a).archive as *mut archive,
                                        84,
                                        b"Corrupted ZIP file data\x00" as *const u8,
                                    )
                                };
                                return -30;
                            }
                        }
                    }
                }
                _ => {}
            }
            match current_block {
                3 => {}
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            12,
                            b"No memory for ZIP decryption\x00" as *const u8,
                        )
                    };
                    return -30;
                }
            }
        }
    }
    unsafe {
        archive_set_error(
            &mut (safe_a).archive as *mut archive,
            84,
            b"Truncated ZIP file data\x00" as *const u8,
        )
    };
    return -30;
}
fn zip_alloc_decryption_buffer(a: *mut archive_read) -> i32 {
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let bs: size_t = (256 * 1024) as size_t;

    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };

    if safe_zip.decrypted_buffer.is_null() {
        safe_zip.decrypted_buffer_size = bs;
        safe_zip.decrypted_buffer = unsafe { malloc_safe(bs) as *mut u8 };
        if safe_zip.decrypted_buffer.is_null() {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    12,
                    b"No memory for ZIP decryption\x00" as *const u8,
                )
            };
            return -30;
        }
    }
    safe_zip.decrypted_ptr = safe_zip.decrypted_buffer;
    return 0;
}
fn init_traditional_PKWARE_decryption(a: *mut archive_read) -> i32 {
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let mut p: *const () = 0 as *const ();
    let mut retry: i32 = 0;
    let mut r: i32 = 0;

    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };

    if safe_zip.tctx_valid != 0 {
        return 0;
    }
    /*
      Read the 12 bytes encryption header stored at
      the start of the data area.
    */
    if unsafe {
        0 == (*safe_zip.entry).zip_flags as i32 & (1 << 3) && safe_zip.entry_bytes_remaining < 12
    } {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84,
                b"Truncated Zip encrypted body: only %jd bytes available\x00" as *const u8
                    as *const u8,
                safe_zip.entry_bytes_remaining,
            )
        };
        return -30;
    }
    p = unsafe { __archive_read_ahead_safe(a, 12, 0 as *mut ssize_t) };
    if p == 0 as *mut () {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84,
                b"Truncated ZIP file data\x00" as *const u8,
            )
        };
        return -30;
    }
    retry = 0;
    loop {
        let mut passphrase: *const u8;
        let mut crcchk: uint8_t = 0;
        passphrase = unsafe { __archive_read_next_passphrase_safe(a) };
        if passphrase.is_null() {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -1,
                    if retry > 0 {
                        b"Incorrect passphrase\x00" as *const u8
                    } else {
                        b"Passphrase required for this entry\x00" as *const u8
                    },
                )
            };
            return -25;
        }
        /*
         * Initialize ctx for Traditional PKWARE Decryption.
         */
        r = trad_enc_init(
            &mut (safe_zip).tctx,
            passphrase,
            unsafe { strlen_safe(passphrase) },
            p as *const uint8_t,
            12,
            &mut crcchk,
        ); /* The passphrase is OK. */
        if unsafe { r == 0 && crcchk as i32 == (*(safe_zip).entry).decdat as i32 } {
            break;
        }
        if retry > 10000 {
            /* Avoid infinity loop. */
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -1,
                    b"Too many incorrect passphrases\x00" as *const u8,
                )
            };
            return -25;
        }
        retry += 1
    }
    unsafe { __archive_read_consume_safe(a, 12) };
    (safe_zip).tctx_valid = 1;
    if unsafe { 0 == (*(safe_zip).entry).zip_flags as i32 & (1 << 3) } {
        safe_zip.entry_bytes_remaining -= 12
    }
    /*zip->entry_uncompressed_bytes_read += ENC_HEADER_SIZE;*/
    safe_zip.entry_compressed_bytes_read += 12;
    safe_zip.decrypted_bytes_remaining = 0;
    return zip_alloc_decryption_buffer(a);
}
fn init_WinZip_AES_decryption(a: *mut archive_read) -> i32 {
    let current_block: u64;
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let mut p: *const () = 0 as *const ();
    let mut pv: *const uint8_t = 0 as *const uint8_t;
    let mut key_len: size_t = 0;
    let mut salt_len: size_t = 0;
    let mut derived_key: [uint8_t; 66] = [0; 66];
    let mut retry: i32;
    let mut r: i32;

    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };

    if safe_zip.cctx_valid as i32 != 0 || safe_zip.hctx_valid as i32 != 0 {
        return 0;
    }
    match unsafe { (*safe_zip.entry).aes_extra.strength } {
        1 => {
            salt_len = 8;
            key_len = 16;
            current_block = 1;
        }
        2 => {
            salt_len = 12;
            key_len = 24;
            current_block = 2;
        }
        3 => {
            salt_len = 16;
            key_len = 32;
            current_block = 3;
        }
        _ => {
            current_block = 0;
        }
    }
    match current_block {
        1 | 2 | 3 => {
            p = unsafe { __archive_read_ahead_safe(a, salt_len + 2, 0 as *mut ssize_t) };
            if p == 0 as *mut () {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        84,
                        b"Truncated ZIP file data\x00" as *const u8,
                    )
                };
                return -30;
            } else {
                retry = 0;
                loop {
                    let mut passphrase: *const u8 = 0 as *const u8;
                    passphrase = unsafe { __archive_read_next_passphrase_safe(a) };
                    if passphrase.is_null() {
                        unsafe {
                            archive_set_error(
                                &mut (safe_a).archive as *mut archive,
                                -1,
                                if retry > 0 {
                                    b"Incorrect passphrase\x00" as *const u8
                                } else {
                                    b"Passphrase required for this entry\x00" as *const u8
                                        as *const u8
                                },
                            )
                        };
                        return -25;
                    }
                    unsafe {
                        memset_safe(
                            derived_key.as_mut_ptr() as *mut (),
                            0,
                            size_of::<[uint8_t; 66]>() as u64,
                        )
                    };
                    r = unsafe {
                        __archive_cryptor
                            .pbkdf2sha1
                            .expect("non-null function pointer")(
                            passphrase,
                            strlen_safe(passphrase),
                            p as *const uint8_t,
                            salt_len,
                            1000,
                            derived_key.as_mut_ptr(),
                            key_len * 2 + 2,
                        )
                    };
                    if r != 0 {
                        unsafe {
                            archive_set_error(
                                &mut (safe_a).archive as *mut archive,
                                -1,
                                b"Decryption is unsupported due to lack of crypto library\x00"
                                    as *const u8,
                            )
                        };
                        return -25;
                    }
                    /* Check password verification value. */
                    pv = unsafe { (p as *const uint8_t).offset(salt_len as isize) }; /* The passphrase is OK. */
                    if unsafe {
                        derived_key[(key_len * 2) as usize] as i32 == *pv.offset(0 as isize) as i32
                            && derived_key[(key_len * 2 + 1) as usize] as i32
                                == *pv.offset(1 as isize) as i32
                    } {
                        break;
                    }
                    if retry > 10000 {
                        /* Avoid infinity loop. */
                        unsafe {
                            archive_set_error(
                                &mut (*a).archive as *mut archive,
                                -1,
                                b"Too many incorrect passphrases\x00" as *const u8,
                            )
                        };
                        return -25;
                    }
                    retry += 1
                }
                r = unsafe {
                    __archive_cryptor
                        .decrypto_aes_ctr_init
                        .expect("non-null function pointer")(
                        &mut (*zip).cctx,
                        derived_key.as_mut_ptr(),
                        key_len,
                    )
                };
                if r != 0 {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -1,
                            b"Decryption is unsupported due to lack of crypto library\x00"
                                as *const u8,
                        )
                    };
                    return -25;
                }
                r = unsafe {
                    __archive_hmac
                        .__hmac_sha1_init
                        .expect("non-null function pointer")(
                        &mut (*zip).hctx,
                        derived_key.as_mut_ptr().offset(key_len as isize),
                        key_len,
                    )
                };
                if r != 0 {
                    unsafe {
                        __archive_cryptor
                            .decrypto_aes_ctr_release
                            .expect("non-null function pointer")(
                            &mut (safe_zip).cctx
                        );

                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -1,
                            b"Failed to initialize HMAC-SHA1\x00" as *const u8,
                        );
                        return -25;
                    }
                }
                (safe_zip).hctx_valid = 1;
                (safe_zip).cctx_valid = (safe_zip).hctx_valid;
                unsafe { __archive_read_consume_safe(a, salt_len as i64 + 2) };
                (safe_zip).entry_bytes_remaining = unsafe {
                    ((safe_zip).entry_bytes_remaining as int64_t) - (salt_len + 2 + 10) as int64_t
                };
                if unsafe {
                    !(0 == (*(safe_zip).entry).zip_flags as i32 & (1 << 3)
                        && (safe_zip).entry_bytes_remaining < 0)
                } {
                    (safe_zip).entry_compressed_bytes_read = ((safe_zip).entry_compressed_bytes_read
                        as int64_t)
                        + (salt_len + 2 + 10) as int64_t;
                    (safe_zip).decrypted_bytes_remaining = 0;
                    unsafe {
                        (*(safe_zip).entry).compression = (*(safe_zip).entry).aes_extra.compression
                    };
                    return zip_alloc_decryption_buffer(a);
                }
            }
        }
        _ => {}
    }
    unsafe {
        archive_set_error(
            &mut (safe_a).archive as *mut archive,
            84,
            b"Corrupted ZIP file data\x00" as *const u8,
        )
    };
    return -30;
}
fn archive_read_format_zip_read_data(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let mut r: i32;
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };

    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };

    if safe_zip.has_encrypted_entries == -1 {
        safe_zip.has_encrypted_entries = 0
    }
    unsafe {
        *offset = safe_zip.entry_uncompressed_bytes_read;
        *size = 0 as size_t;
        *buff = 0 as *const ();
    }
    /* If we hit end-of-entry last time, return ARCHIVE_EOF. */
    if safe_zip.end_of_entry != 0 {
        return 1;
    }
    /* Return EOF immediately if this is a non-regular file. */
    if unsafe { 0o100000 as mode_t != (*(safe_zip).entry).mode as u32 & 0o170000 as mode_t } {
        return 1;
    }
    unsafe { __archive_read_consume_safe(a, (safe_zip).unconsumed as int64_t) };
    (safe_zip).unconsumed = 0 as size_t;
    if (safe_zip).init_decryption != 0 {
        (safe_zip).has_encrypted_entries = 1;
        if unsafe { (*(safe_zip).entry).zip_flags as i32 & (1 << 6) != 0 } {
            r = read_decryption_header(a)
        } else if unsafe { (*(safe_zip).entry).compression as i32 == 99 } {
            r = init_WinZip_AES_decryption(a)
        } else {
            r = init_traditional_PKWARE_decryption(a)
        }
        if r != 0 {
            return r;
        }
        (safe_zip).init_decryption = 0
    }
    match unsafe { (*(safe_zip).entry).compression as i32 } {
        0 => {
            /* No compression. */
            r = zip_read_data_none(a, buff, size, offset)
        }
        #[cfg(HAVE_BZLIB_H)]
        12 => {
            /* ZIPx bzip2 compression. */
            r = zip_read_data_zipx_bzip2(a, buff, size, offset)
        }
        #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
        14 => {
            /* ZIPx LZMA compression. */
            r = zip_read_data_zipx_lzma_alone(a, buff, size, offset)
        }
        #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
        95 => {
            /* ZIPx XZ compression. */
            r = zip_read_data_zipx_xz(a, buff, size, offset)
        }
        98 => {
            /* PPMd support is built-in, so we don't need any #if guards. */
            /* ZIPx PPMd compression. */
            r = zip_read_data_zipx_ppmd(a, buff, size, offset)
        }
        #[cfg(HAVE_ZLIB_H)]
        8 => {
            /* Deflate compression. */
            r = zip_read_data_deflate(a, buff, size, offset)
        }
        _ => {
            /* Unsupported compression. */
            /* Return a warning. */
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    84,
                    b"Unsupported ZIP compression method (%d: %s)\x00" as *const u8,
                    (*(safe_zip).entry).compression as i32,
                    compression_name((*(safe_zip).entry).compression as i32),
                )
            };
            /* We can't decompress this entry, but we will
             * be able to skip() it and try the next entry. */
            return -25;
        }
    }
    if r != 0 {
        return r;
    }
    /* Update checksum */
    unsafe {
        if *size != 0 {
            safe_zip.entry_crc32 = safe_zip.crc32func.expect("non-null function pointer")(
                safe_zip.entry_crc32,
                *buff,
                *size as u32 as size_t,
            )
        }
    }
    /* If we hit the end, swallow any end-of-data marker. */
    if (safe_zip).end_of_entry != 0 {
        /* Check file size, CRC against these values. */
        unsafe {
            if (*(safe_zip).entry).compressed_size != (safe_zip).entry_compressed_bytes_read {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -1,
                    b"ZIP compressed data is wrong size (read %jd, expected %jd)\x00" as *const u8
                        as *const u8,
                    (safe_zip).entry_compressed_bytes_read,
                    (*(safe_zip).entry).compressed_size,
                );
                return -20;
            }
        }
        /* Size field only stores the lower 32 bits of the actual
         * size. */
        unsafe {
            if (*(safe_zip).entry).uncompressed_size & 4294967295
                != (safe_zip).entry_uncompressed_bytes_read & 4294967295
            {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -1,
                    b"ZIP uncompressed data is wrong size (read %jd, expected %jd)\n\x00"
                        as *const u8,
                    (safe_zip).entry_uncompressed_bytes_read,
                    (*(safe_zip).entry).uncompressed_size,
                );
                return -20;
            }
        }
        /* Check computed CRC against header */
        unsafe {
            if ((safe_zip).hctx_valid == 0 || (*(safe_zip).entry).aes_extra.vendor != 0x2)
                && (*(safe_zip).entry).crc32 as u64 != (safe_zip).entry_crc32
                && (safe_zip).ignore_crc32 == 0
            {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -1,
                    b"ZIP bad CRC: 0x%lx should be 0x%lx\x00" as *const u8,
                    (safe_zip).entry_crc32,
                    (*(safe_zip).entry).crc32 as u64,
                );
                return -20;
            }
        }
    }
    return 0;
}

fn archive_read_format_zip_cleanup(a: *mut archive_read) -> i32 {
    unsafe {
        let mut zip: *mut zip = 0 as *mut zip;
        let mut zip_entry: *mut zip_entry = 0 as *mut zip_entry;
        let mut next_zip_entry: *mut zip_entry = 0 as *mut zip_entry;
        zip = (*(*a).format).data as *mut zip;
        #[cfg(HAVE_ZLIB_H)]
        if (*zip).stream_valid != 0 {
            inflateEnd(&mut (*zip).stream);
        }
        #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
        if (*zip).zipx_lzma_valid != 0 {
            lzma_end(&mut (*zip).zipx_lzma_stream);
        }
        #[cfg(HAVE_BZLIB_H)]
        if (*zip).bzstream_valid != 0 {
            BZ2_bzDecompressEnd(&mut (*zip).bzstream);
        }
        free((*zip).uncompressed_buffer as *mut ());
        if (*zip).ppmd8_valid != 0 {
            __archive_ppmd8_functions
                .Ppmd8_Free
                .expect("non-null function pointer")(&mut (*zip).ppmd8);
        }
        if !(*zip).zip_entries.is_null() {
            zip_entry = (*zip).zip_entries;
            while !zip_entry.is_null() {
                next_zip_entry = (*zip_entry).next;
                archive_string_free(&mut (*zip_entry).rsrcname);
                free(zip_entry as *mut ());
                zip_entry = next_zip_entry
            }
        }
        free((*zip).decrypted_buffer as *mut ());
        if (*zip).cctx_valid != 0 {
            __archive_cryptor
                .decrypto_aes_ctr_release
                .expect("non-null function pointer")(&mut (*zip).cctx);
        }
        if (*zip).hctx_valid != 0 {
            __archive_hmac
                .__hmac_sha1_cleanup
                .expect("non-null function pointer")(&mut (*zip).hctx);
        }
        free((*zip).iv as *mut ());
        free((*zip).erd as *mut ());
        free((*zip).v_data as *mut ());
        archive_string_free(&mut (*zip).format_name);
        free(zip as *mut ());
        (*(*a).format).data = 0 as *mut ();
        return 0;
    }
}

fn archive_read_format_zip_has_encrypted_entries(_a: *mut archive_read) -> i32 {
    let safe__a = unsafe { &mut *_a };

    if !_a.is_null() && !(safe__a).format.is_null() {
        let zip: *mut zip = unsafe { (*(safe__a).format).data as *mut zip };
        let safe_zip = unsafe { &mut *zip };
        if !zip.is_null() {
            return (safe_zip).has_encrypted_entries;
        }
    }
    return -1;
}

fn archive_read_format_zip_options(a: *mut archive_read, key: *const u8, val: *const u8) -> i32 {
    let mut zip: *mut zip = 0 as *mut zip;
    let mut ret: i32 = -25;
    zip = unsafe { (*(*a).format).data as *mut zip };

    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };

    if unsafe { strcmp_safe(key, b"compat-2x\x00" as *const u8) } == 0 {
        /* Handle filenames as libarchive 2.x */
        (safe_zip).init_default_conversion = if !val.is_null() { 1 } else { 0 };
        return 0;
    } else {
        if unsafe { strcmp_safe(key, b"hdrcharset\x00" as *const u8) } == 0 {
            if unsafe { val.is_null() || *val.offset(0 as isize) as i32 == 0 } {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -1,
                        b"zip: hdrcharset option needs a character-set name\x00" as *const u8
                            as *const u8,
                    )
                };
            } else {
                (safe_zip).sconv = unsafe {
                    archive_string_conversion_from_charset_safe(&mut (safe_a).archive, val, 0)
                };
                if !(safe_zip).sconv.is_null() {
                    if unsafe { strcmp_safe(val, b"UTF-8\x00" as *const u8) } == 0 {
                        (safe_zip).sconv_utf8 = (safe_zip).sconv
                    }
                    ret = 0
                } else {
                    ret = -30
                }
            }
            return ret;
        } else {
            if unsafe { strcmp_safe(key, b"ignorecrc32\x00" as *const u8) } == 0 {
                /* Mostly useful for testing. */
                if unsafe { val.is_null() || *val.offset(0 as isize) as i32 == 0 } {
                    (safe_zip).crc32func = Some(real_crc32);
                    (safe_zip).ignore_crc32 = 0
                } else {
                    (safe_zip).crc32func = Some(fake_crc32);
                    (safe_zip).ignore_crc32 = 1
                }
                return 0;
            } else {
                if unsafe { strcmp_safe(key, b"mac-ext\x00" as *const u8) } == 0 {
                    unsafe {
                        (safe_zip).process_mac_extensions =
                            (!val.is_null() && *val.offset(0 as isize) as i32 != 0) as i32;
                    }
                    return 0;
                }
            }
        }
    }
    /* Note: The "warn" return is just to inform the options
     * supervisor that we didn't handle it.  It will generate
     * a suitable error if no one used this option. */
    return -20;
}

pub fn archive_read_support_format_zip(a: *mut archive) -> i32 {
    let mut r: i32 = 0;
    r = unsafe { archive_read_support_format_zip_streamable(a) };
    if r != 0 {
        return r;
    }
    return unsafe { archive_read_support_format_zip_seekable(a) };
}
/* ------------------------------------------------------------------------ */
/*
* Streaming-mode support
*/
fn archive_read_support_format_zip_capabilities_streamable(a: *mut archive_read) -> i32 {
    /* UNUSED */
    return (1 << 0) | (1 << 1);
}
fn archive_read_format_zip_streamable_bid(a: *mut archive_read, best_bid: i32) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    /* UNUSED */
    p = unsafe { __archive_read_ahead_safe(a, 4 as size_t, 0 as *mut ssize_t) as *const u8 };
    if p.is_null() {
        return -1;
    }
    /*
     * Bid of 29 here comes from:
     *  + 16 bits for "PK",
     *  + next 16-bit field has 6 options so contributes
     *    about 16 - log_2(6) ~= 16 - 2.6 ~= 13 bits
     *
     * So we've effectively verified ~29 total bits of check data.
     */
    unsafe {
        if *p.offset(0 as isize) as i32 == 'P' as i32 && *p.offset(1 as isize) as i32 == 'K' as i32
        {
            if *p.offset(2 as isize) as i32 == '\u{1}' as i32
                && *p.offset(3 as isize) as i32 == '\u{2}' as i32
                || *p.offset(2 as isize) as i32 == '\u{3}' as i32
                    && *p.offset(3 as isize) as i32 == '\u{4}' as i32
                || *p.offset(2 as isize) as i32 == '\u{5}' as i32
                    && *p.offset(3 as isize) as i32 == '\u{6}' as i32
                || *p.offset(2 as isize) as i32 == '\u{6}' as i32
                    && *p.offset(3 as isize) as i32 == '\u{6}' as i32
                || *p.offset(2 as isize) as i32 == '\u{7}' as i32
                    && *p.offset(3 as isize) as i32 == '\u{8}' as i32
                || *p.offset(2 as isize) as i32 == '0' as i32
                    && *p.offset(3 as isize) as i32 == '0' as i32
            {
                return 29 as i32;
            }
        }
        /* TODO: It's worth looking ahead a little bit for a valid
         * PK signature.  In particular, that would make it possible
         * to read some UUEncoded SFX files or SFX files coming from
         * a network socket. */
        return 0;
    }
}

fn archive_read_format_zip_streamable_read_header(
    a: *mut archive_read,
    entry: *mut archive_entry,
) -> i32 {
    let mut zip: *mut zip = 0 as *mut zip;

    let safe_a = unsafe { &mut *a };

    let safe_entry = unsafe { &mut *entry };

    (safe_a).archive.archive_format = 0x50000;
    if (safe_a).archive.archive_format_name.is_null() {
        (safe_a).archive.archive_format_name = b"ZIP\x00" as *const u8
    }
    zip = unsafe { (*(safe_a).format).data as *mut zip };
    let safe_zip = unsafe { &mut *zip };
    /*
     * It should be sufficient to call archive_read_next_header() for
     * a reader to determine if an entry is encrypted or not. If the
     * encryption of an entry is only detectable when calling
     * archive_read_data(), so be it. We'll do the same check there
     * as well.
     */
    if (safe_zip).has_encrypted_entries == -1 {
        (safe_zip).has_encrypted_entries = 0
    }
    /* Make sure we have a zip_entry structure to use. */
    if (safe_zip).zip_entries.is_null() {
        (safe_zip).zip_entries =
            unsafe { malloc_safe(size_of::<zip_entry>() as u64) as *mut zip_entry };
        if (safe_zip).zip_entries.is_null() {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    12,
                    b"Out  of memory\x00" as *const u8,
                )
            };
            return -30;
        }
    }
    (safe_zip).entry = (safe_zip).zip_entries;
    unsafe {
        memset_safe(
            (safe_zip).entry as *mut (),
            0,
            size_of::<zip_entry>() as u64,
        )
    };
    if (safe_zip).cctx_valid != 0 {
        unsafe {
            __archive_cryptor
                .decrypto_aes_ctr_release
                .expect("non-null function pointer")(&mut (*zip).cctx)
        };
    }
    if (safe_zip).hctx_valid != 0 {
        unsafe {
            __archive_hmac
                .__hmac_sha1_cleanup
                .expect("non-null function pointer")(&mut (safe_zip).hctx)
        };
    }
    safe_zip.hctx_valid = 0;
    safe_zip.cctx_valid = safe_zip.hctx_valid;
    safe_zip.tctx_valid = safe_zip.cctx_valid;
    unsafe { __archive_read_reset_passphrase_safe(a) };
    /* Search ahead for the next local file header. */
    unsafe { __archive_read_consume_safe(a, safe_zip.unconsumed as int64_t) };
    safe_zip.unconsumed = 0;
    loop {
        let mut skipped: int64_t = 0;
        let mut p: *const u8 = 0 as *const u8;
        let mut end: *const u8 = 0 as *const u8;
        let mut bytes: ssize_t = 0;
        p = unsafe { __archive_read_ahead_safe(a, 4, &mut bytes) as *const u8 };
        if p.is_null() {
            return -30;
        }
        end = unsafe { p.offset(bytes as isize) };
        unsafe {
            while p.offset(4 as isize) <= end {
                if *p.offset(0 as isize) as i32 == 'P' as i32
                    && *p.offset(1 as isize) as i32 == 'K' as i32
                {
                    if *p.offset(2 as isize) as i32 == '\u{3}' as i32
                        && *p.offset(3 as isize) as i32 == '\u{4}' as i32
                    {
                        /* Regular file entry. */
                        __archive_read_consume_safe(a, skipped);
                        return zip_read_local_file_header(a, entry, zip);
                    }
                    /*
                     * TODO: We cannot restore permissions
                     * based only on the local file headers.
                     * Consider scanning the central
                     * directory and returning additional
                     * entries for at least directories.
                     * This would allow us to properly set
                     * directory permissions.
                     *
                     * This won't help us fix symlinks
                     * and may not help with regular file
                     * permissions, either.  <sigh>
                     */
                    if *p.offset(2 as isize) as i32 == '\u{1}' as i32
                        && *p.offset(3 as isize) as i32 == '\u{2}' as i32
                    {
                        return 1;
                    }
                    /* End of central directory?  Must be an
                     * empty archive. */
                    if *p.offset(2 as isize) as i32 == '\u{5}' as i32
                        && *p.offset(3 as isize) as i32 == '\u{6}' as i32
                        || *p.offset(2) as i32 == '\u{6}' as i32
                            && *p.offset(3) as i32 == '\u{6}' as i32
                    {
                        return 1;
                    }
                }
                p = p.offset(1 as isize);
                skipped += 1
            }
        }
        unsafe { __archive_read_consume_safe(a, skipped) };
    }
}

fn archive_read_format_zip_read_data_skip_streamable(a: *mut archive_read) -> i32 {
    let mut zip: *mut zip = 0 as *mut zip;
    let mut bytes_skipped: int64_t;
    zip = unsafe { (*(*a).format).data as *mut zip };

    let safe_a = unsafe { &mut *a };
    let mut safe_zip = unsafe { &mut *zip };

    bytes_skipped = unsafe { __archive_read_consume_safe(a, (safe_zip).unconsumed as int64_t) };

    (safe_zip).unconsumed = 0;
    if bytes_skipped < 0 {
        return -30;
    }
    /* If we've already read to end of data, we're done. */
    if (safe_zip).end_of_entry != 0 {
        return 0;
    }
    /* So we know we're streaming... */
    if unsafe {
        0 == (*(safe_zip).entry).zip_flags as i32 & (1 << 3)
            || (*(safe_zip).entry).compressed_size > 0
    } {
        /* We know the compressed length, so we can just skip. */
        bytes_skipped = unsafe { __archive_read_consume_safe(a, (safe_zip).entry_bytes_remaining) };
        if bytes_skipped < 0 {
            return -30;
        }
        return 0;
    }
    if (safe_zip).init_decryption != 0 {
        let mut r: i32 = 0;
        (safe_zip).has_encrypted_entries = 1;
        if unsafe { (*(safe_zip).entry).zip_flags as i32 & (1 << 6) != 0 } {
            r = read_decryption_header(a)
        } else if unsafe { (*(safe_zip).entry).compression as i32 == 99 } {
            r = init_WinZip_AES_decryption(a)
        } else {
            r = init_traditional_PKWARE_decryption(a)
        }
        if r != 0 {
            return r;
        }
        (safe_zip).init_decryption = 0
    }
    /* We're streaming and we don't know the length. */
    /* If the body is compressed and we know the format, we can
     * find an exact end-of-entry by decompressing it. */
    match unsafe { (*(safe_zip).entry).compression as i32 } {
        #[cfg(HAVE_ZLIB_H)]
        8 => {
            /* Deflate compression. */
            while (safe_zip).end_of_entry == 0 {
                let mut offset: int64_t = 0;
                let mut buff: *const () = 0 as *const ();
                let mut size: size_t = 0;
                let mut r_0: i32 = 0;
                r_0 = zip_read_data_deflate(a, &mut buff, &mut size, &mut offset);
                if r_0 != 0 {
                    return r_0;
                }
                safe_zip = unsafe { &mut *((*(*a).format).data as *mut zip) }
            }
            return 0;
        }
        _ => {
            loop
            /* Uncompressed or unknown. */
            /* Scan for a PK\007\010 signature. */
            {
                let mut p: *const u8 = 0 as *const u8;
                let mut buff_0: *const u8 = 0 as *const u8;
                let mut bytes_avail: ssize_t = 0;
                buff_0 = unsafe { __archive_read_ahead_safe(a, 16 as size_t, &mut bytes_avail) }
                    as *const u8;
                if bytes_avail < 16 {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            84,
                            b"Truncated ZIP file data\x00" as *const u8,
                        )
                    };
                    return -30;
                }
                p = buff_0;
                unsafe {
                    while p <= buff_0.offset(bytes_avail as isize).offset(-(16)) {
                        if *p.offset(3 as isize) as i32 == 'P' as i32 {
                            p = p.offset(3 as isize)
                        } else if *p.offset(3 as isize) as i32 == 'K' as i32 {
                            p = p.offset(2 as isize)
                        } else if *p.offset(3 as isize) as i32 == '\u{7}' as i32 {
                            p = p.offset(1 as isize)
                        } else if *p.offset(3 as isize) as i32 == '\u{8}' as i32
                            && *p.offset(2 as isize) as i32 == '\u{7}' as i32
                            && *p.offset(1 as isize) as i32 == 'K' as i32
                            && *p.offset(0 as isize) as i32 == 'P' as i32
                        {
                            if (*(*zip).entry).flags as i32 & (1 << 0) != 0 {
                                __archive_read_consume(a, p.offset_from(buff_0) as i64 + 24);
                            } else {
                                __archive_read_consume(a, p.offset_from(buff_0) as i64 + 16);
                            }
                            return 0;
                        } else {
                            p = p.offset(4 as isize)
                        }
                    }
                }
                unsafe { __archive_read_consume_safe(a, unsafe { p.offset_from(buff_0) as i64 }) };
            }
        }
    };
}
#[no_mangle]
pub fn archive_read_support_format_zip_streamable(_a: *mut archive) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut zip = 0 as *mut zip;
    let safe_a = unsafe { &mut *a };
    let mut r: i32;
    let mut magic_test: i32 = unsafe {
        __archive_check_magic_safe(
            _a,
            0xdeb0c5,
            1,
            b"archive_read_support_format_zip\x00" as *const u8,
        )
    };
    if magic_test == -30 {
        return -30;
    }
    zip = unsafe { calloc_safe(1, size_of::<zip>() as u64) as *mut zip };

    let safe_zip = unsafe { &mut *zip };

    if zip.is_null() {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                12,
                b"Can\'t allocate zip data\x00" as *const u8,
            )
        };
        return -30;
    }
    /* Streamable reader doesn't support mac extensions. */
    (safe_zip).process_mac_extensions = 0;
    /*
     * Until enough data has been read, we cannot tell about
     * any encrypted entries yet.
     */
    (safe_zip).has_encrypted_entries = -1;
    (safe_zip).crc32func = Some(real_crc32);
    r = unsafe {
        __archive_read_register_format_safe(
            a,
            zip as *mut (),
            b"zip\x00" as *const u8,
            Some(archive_read_format_zip_streamable_bid),
            Some(archive_read_format_zip_options),
            Some(archive_read_format_zip_streamable_read_header),
            Some(archive_read_format_zip_read_data),
            Some(archive_read_format_zip_read_data_skip_streamable),
            None,
            Some(archive_read_format_zip_cleanup),
            Some(archive_read_support_format_zip_capabilities_streamable),
            Some(archive_read_format_zip_has_encrypted_entries),
        )
    };
    if r != 0 {
        unsafe { free_safe(zip as *mut ()) };
    }
    return 0;
}
/* ------------------------------------------------------------------------ */
/*
* Seeking-mode support
*/
fn archive_read_support_format_zip_capabilities_seekable(a: *mut archive_read) -> i32 {
    /* UNUSED */
    return (1 << 0) | (1 << 1);
}
/*
* TODO: This is a performance sink because it forces the read core to
* drop buffered data from the start of file, which will then have to
* be re-read again if this bidder loses.
*
* We workaround this a little by passing in the best bid so far so
* that later bidders can do nothing if they know they'll never
* outbid.  But we can certainly do better...
*/
unsafe fn read_eocd(zip: *mut zip, p: *const u8, current_offset: int64_t) -> i32 {
    let safe_p = unsafe { &*p };
    let safe_zip = unsafe { &mut *zip };
    let disk_num: uint16_t;
    let cd_size: uint32_t;
    let cd_offset: uint32_t;
    disk_num = archive_le16dec(unsafe { p.offset(4 as isize) as *const () });
    cd_size = archive_le32dec(unsafe { p.offset(12 as isize) as *const () });
    cd_offset = archive_le32dec(unsafe { p.offset(16 as isize) as *const () });
    /* Sanity-check the EOCD we've found. */
    /* This must be the first volume. */
    if disk_num as i32 != 0 {
        return 0;
    }
    /* Central directory must be on this volume. */
    if disk_num as i32 != archive_le16dec(unsafe { p.offset(6 as isize) as *const () }) as i32 {
        return 0;
    }
    /* All central directory entries must be on this volume. */
    if archive_le16dec(unsafe { p.offset(10 as isize) as *const () }) as i32
        != archive_le16dec(unsafe { p.offset(8 as isize) as *const () }) as i32
    {
        return 0;
    }
    /* Central directory can't extend beyond start of EOCD record. */
    if cd_offset as i64 + cd_size as i64 > current_offset {
        return 0;
    }
    /* Save the central directory location for later use. */
    (safe_zip).central_directory_offset = cd_offset as int64_t;
    (safe_zip).central_directory_offset_adjusted = current_offset - cd_size as i64;
    /* This is just a tiny bit higher than the maximum
    returned by the streaming Zip bidder.  This ensures
    that the more accurate seeking Zip parser wins
    whenever seek is available. */
    return 32;
}
/*
* Examine Zip64 EOCD locator:  If it's valid, store the information
* from it.
*/
fn read_zip64_eocd(a: *mut archive_read, zip: *mut zip, mut p: *const u8) -> i32 {
    let mut eocd64_offset: int64_t = 0;
    let mut eocd64_size: int64_t = 0;
    let safe_p = unsafe { &*p };
    let safe_zip = unsafe { &mut *zip };
    /* Sanity-check the locator record. */
    /* Central dir must be on first volume. */
    if archive_le32dec(unsafe { p.offset(4 as isize) as *const () }) != 0 {
        return 0;
    }
    /* Must be only a single volume. */
    if archive_le32dec(unsafe { p.offset(16 as isize) as *const () }) != 1 {
        return 0;
    }
    /* Find the Zip64 EOCD record. */
    eocd64_offset = archive_le64dec(unsafe { p.offset(8 as isize) as *const () }) as int64_t;
    if unsafe { __archive_read_seek_safe(a, eocd64_offset, 0) < 0 } {
        return 0;
    }
    p = unsafe { __archive_read_ahead_safe(a, 56, 0 as *mut ssize_t) as *const u8 };
    if p.is_null() {
        return 0;
    }
    /* Make sure we can read all of it. */
    eocd64_size =
        archive_le64dec(unsafe { p.offset(4 as isize) as *const () }) as int64_t + 12 as int64_t;
    if eocd64_size < 56 || eocd64_size > 16384 {
        return 0;
    }
    p = unsafe {
        __archive_read_ahead_safe(a, eocd64_size as size_t, 0 as *mut ssize_t) as *const u8
    };
    if p.is_null() {
        return 0;
    }
    /* Sanity-check the EOCD64 */
    if archive_le32dec(unsafe { p.offset(16 as isize) as *const () }) != 0 {
        /* Must be disk #0 */
        return 0;
    }
    if archive_le32dec(unsafe { p.offset(20 as isize) as *const () }) != 0 {
        /* CD must be on disk #0 */
        return 0;
    }
    /* CD can't be split. */
    if archive_le64dec(unsafe { p.offset(24 as isize) as *const () })
        != archive_le64dec(unsafe { p.offset(32 as isize) as *const () })
    {
        return 0;
    }
    /* Save the central directory offset for later use. */
    (safe_zip).central_directory_offset =
        archive_le64dec(unsafe { p.offset(48 as isize) as *const () }) as int64_t;
    /* TODO: Needs scanning backwards to find the eocd64 instead of assuming */
    (safe_zip).central_directory_offset_adjusted = (safe_zip).central_directory_offset;
    return 32;
}
fn archive_read_format_zip_seekable_bid(a: *mut archive_read, best_bid: i32) -> i32 {
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let file_size: int64_t;
    let current_offset: int64_t;
    let mut p: *const u8 = 0 as *const u8;
    let mut i: i32;
    let tail: i32;

    let safe_zip = unsafe { &mut *zip };
    /* If someone has already bid more than 32, then avoid
    trashing the look-ahead buffers with a seek. */
    if best_bid > 32 {
        return -1;
    }
    file_size = unsafe { __archive_read_seek_safe(a, 0, 2) };
    if file_size <= 0 {
        return 0;
    }
    /* Search last 16k of file for end-of-central-directory
     * record (which starts with PK\005\006) */
    tail = if ((1024 * 16) as i64) < file_size {
        (1024 * 16) as i64
    } else {
        file_size
    } as i32;
    current_offset = unsafe { __archive_read_seek_safe(a, -tail as int64_t, 2) };
    if current_offset < 0 {
        return 0;
    }
    p = unsafe { __archive_read_ahead_safe(a, tail as size_t, 0 as *mut ssize_t) as *const u8 };
    if p.is_null() {
        return 0;
    }
    /* Boyer-Moore search backwards from the end, since we want
     * to match the last EOCD in the file (there can be more than
     * one if there is an uncompressed Zip archive as a member
     * within this Zip archive). */
    i = tail - 22;
    unsafe {
        while i > 0 {
            match *p.offset(i as isize) as i32 {
                80 => {
                    if memcmp_safe(
                        p.offset(i as isize) as *const (),
                        b"PK\x05\x06\x00" as *const u8 as *const (),
                        4,
                    ) == 0
                    {
                        let mut ret: i32 =
                            read_eocd(zip, p.offset(i as isize), current_offset + i as i64);
                        /* Zip64 EOCD locator precedes
                         * regular EOCD if present. */
                        if i >= 20
                            && memcmp_safe(
                                p.offset(i as isize).offset(-(20)) as *const (),
                                b"PK\x06\x07\x00" as *const u8 as *const (),
                                4 as u64,
                            ) == 0
                        {
                            let mut ret_zip64: i32 =
                                read_zip64_eocd(a, zip, p.offset(i as isize).offset(-(20)));
                            if ret_zip64 > ret {
                                ret = ret_zip64
                            }
                        }
                        return ret;
                    }
                    i -= 4
                }
                75 => i -= 1,
                5 => i -= 2,
                6 => i -= 3,
                _ => i -= 4,
            }
        }
    }
    return 0;
}
/* The red-black trees are only used in seeking mode to manage
* the in-memory copy of the central directory. */
fn cmp_node(n1: *const archive_rb_node, n2: *const archive_rb_node) -> i32 {
    let e1: *const zip_entry = n1 as *const zip_entry;
    let e2: *const zip_entry = n2 as *const zip_entry;
    let safe_e1 = unsafe { &*e1 };
    let safe_e2 = unsafe { &*e2 };
    if (safe_e1).local_header_offset > (safe_e2).local_header_offset {
        return -1;
    }
    if (safe_e1).local_header_offset < (safe_e2).local_header_offset {
        return 1;
    }
    return 0;
}
fn cmp_key(n: *const archive_rb_node, key: *const ()) -> i32 {
    /* This function won't be called */
    /* UNUSED */
    return 1;
}
static mut rb_ops: archive_rb_tree_ops = {
    let init = archive_rb_tree_ops {
        rbto_compare_nodes: Some(cmp_node),
        rbto_compare_key: Some(cmp_key),
    };
    init
};
fn rsrc_cmp_node(n1: *const archive_rb_node, n2: *const archive_rb_node) -> i32 {
    let e1: *const zip_entry = n1 as *const zip_entry;
    let e2: *const zip_entry = n2 as *const zip_entry;
    let safe_e1 = unsafe { &*e1 };
    let safe_e2 = unsafe { &*e2 };
    return unsafe { strcmp_safe(safe_e2.rsrcname.s, safe_e1.rsrcname.s) };
}
fn rsrc_cmp_key(n: *const archive_rb_node, key: *const ()) -> i32 {
    let e: *const zip_entry = n as *const zip_entry;
    let safe_e = unsafe { &*e };
    return unsafe { strcmp_safe(key as *const u8, safe_e.rsrcname.s) };
}
static mut rb_rsrc_ops: archive_rb_tree_ops = {
    let mut init = archive_rb_tree_ops {
        rbto_compare_nodes: Some(rsrc_cmp_node),
        rbto_compare_key: Some(rsrc_cmp_key),
    };
    init
};
fn rsrc_basename(name: *const u8, name_length: size_t) -> *const u8 {
    let mut s: *const u8 = 0 as *const u8;
    let mut r: *const u8 = 0 as *const u8;
    s = name;
    r = s;
    loop {
        s = unsafe {
            memchr_safe(
                s as *const (),
                '/' as i32,
                name_length - (unsafe { s.offset_from(name) as u64 }),
            )
        } as *const u8;
        if s.is_null() {
            break;
        }
        s = unsafe { s.offset(1 as isize) };
        r = s
    }
    return r;
}
fn expose_parent_dirs(zip: *mut zip, name: *const u8, name_length: size_t) {
    let mut str: archive_string = archive_string {
        s: 0 as *mut u8,
        length: 0,
        buffer_length: 0,
    };
    let mut dir: *mut zip_entry = 0 as *mut zip_entry;
    let mut s: *mut u8 = 0 as *mut u8;
    str.s as *mut u8;
    str.length as size_t;
    str.buffer_length as size_t;
    str.length as size_t;
    unsafe { archive_strncat_safe(&mut str, name as *const (), name_length) };
    let safe_zip = unsafe { &mut *zip };
    let safe_dir = unsafe { &mut *dir };
    loop {
        s = unsafe { strrchr_safe(str.s, '/' as i32) };
        if s.is_null() {
            break;
        }
        unsafe { *s = '\u{0}' as u8 };
        /* Transfer the parent directory from zip->tree_rsrc RB
         * tree to zip->tree RB tree to expose. */
        dir = unsafe {
            __archive_rb_tree_find_node_safe(&mut safe_zip.tree_rsrc, str.s as *const ())
        } as *mut zip_entry;
        if dir.is_null() {
            break;
        }
        unsafe {
            __archive_rb_tree_remove_node_safe(&mut safe_zip.tree_rsrc, &mut (safe_dir).node);
            archive_string_free_safe(&mut (safe_dir).rsrcname);
            __archive_rb_tree_insert_node_safe(&mut safe_zip.tree, &mut (safe_dir).node)
        };
    }
    unsafe { archive_string_free_safe(&mut str) };
}
fn slurp_central_directory(a: *mut archive_read, entry: *mut archive_entry, zip: *mut zip) -> i32 {
    let mut i: ssize_t = 0;
    let mut found: u32 = 0;
    let mut correction: int64_t = 0;
    let mut bytes_avail: ssize_t = 0;
    let mut p: *const u8 = 0 as *const u8;

    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    /*
     * Find the start of the central directory.  The end-of-CD
     * record has our starting point, but there are lots of
     * Zip archives which have had other data prepended to the
     * file, which makes the recorded offsets all too small.
     * So we search forward from the specified offset until we
     * find the real start of the central directory.  Then we
     * know the correction we need to apply to account for leading
     * padding.
     */
    if unsafe { __archive_read_seek_safe(a, safe_zip.central_directory_offset_adjusted, 0) } < 0 {
        return -30;
    }
    found = 0;
    while found == 0 {
        p = unsafe { __archive_read_ahead_safe(a, 20 as size_t, &mut bytes_avail) as *const u8 };
        if p.is_null() {
            return -30;
        }
        found = 0;
        i = 0 as ssize_t;
        while found == 0 && i < bytes_avail - 4 as i64 {
            match unsafe { *p.offset((i + 3 as i64) as isize) as i32 } {
                80 => i += 3 as i64,
                75 => i += 2 as i64,
                1 => i += 1 as i64,
                2 => {
                    if unsafe {
                        memcmp_safe(
                            unsafe { p.offset(i as isize) as *const () },
                            b"PK\x01\x02\x00" as *const u8 as *const (),
                            4 as u64,
                        )
                    } == 0
                    {
                        unsafe { p = p.offset(i as isize) };
                        found = 1 as u32
                    } else {
                        i += 4 as i64
                    }
                }
                5 => i += 1 as i64,
                6 => {
                    if unsafe {
                        memcmp_safe(
                            unsafe { p.offset(i as isize) as *const () },
                            b"PK\x05\x06\x00" as *const u8 as *const (),
                            4 as u64,
                        )
                    } == 0
                        || unsafe {
                            memcmp_safe(
                                unsafe { p.offset(i as isize) as *const () },
                                b"PK\x06\x06\x00" as *const u8 as *const (),
                                4 as u64,
                            )
                        } == 0
                    {
                        unsafe { p = p.offset(i as isize) };
                        found = 1 as u32
                    } else {
                        i += 1 as i64
                    }
                }
                _ => i += 4 as i64,
            }
        }
        unsafe { __archive_read_consume_safe(a, i) };
    }
    correction = unsafe {
        archive_filter_bytes_safe(&mut (safe_a).archive, 0) - (safe_zip).central_directory_offset
    };
    unsafe {
        __archive_rb_tree_init_safe(&mut (safe_zip).tree, &rb_ops);
        __archive_rb_tree_init_safe(&mut (safe_zip).tree_rsrc, &rb_rsrc_ops);
    }
    (safe_zip).central_directory_entries_total = 0 as size_t;
    loop {
        let mut zip_entry: *mut zip_entry = 0 as *mut zip_entry;
        let mut filename_length: size_t = 0;
        let mut extra_length: size_t = 0;
        let mut comment_length: size_t = 0;
        let mut external_attributes: uint32_t = 0;
        let mut name: *const u8 = 0 as *const u8;
        let mut r: *const u8 = 0 as *const u8;
        p = unsafe { __archive_read_ahead_safe(a, 4 as size_t, 0 as *mut ssize_t) as *const u8 };
        if p.is_null() {
            return -30;
        }
        if unsafe {
            memcmp_safe(
                p as *const (),
                b"PK\x06\x06\x00" as *const u8 as *const (),
                4 as u64,
            )
        } == 0
            || unsafe {
                memcmp_safe(
                    p as *const (),
                    b"PK\x05\x06\x00" as *const u8 as *const (),
                    4 as u64,
                )
            } == 0
        {
            break;
        }
        if unsafe {
            memcmp_safe(
                p as *const (),
                b"PK\x01\x02\x00" as *const u8 as *const (),
                4 as u64,
            )
        } != 0
        {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -1,
                    b"Invalid central directory signature\x00" as *const u8,
                )
            };
            return -30;
        }
        p = unsafe { __archive_read_ahead_safe(a, 46 as size_t, 0 as *mut ssize_t) as *const u8 };
        if p.is_null() {
            return -30;
        }
        zip_entry =
            unsafe { calloc_safe(1 as u64, size_of::<zip_entry>() as u64) } as *mut zip_entry;
        let safe_zip_entry = unsafe { &mut *zip_entry };
        if zip_entry.is_null() {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    12,
                    b"Can\'t allocate zip entry\x00" as *const u8,
                )
            };
            return -30;
        }

        safe_zip_entry.next = (safe_zip).zip_entries;
        safe_zip_entry.flags = (safe_zip_entry.flags as i32 | (1 << 1)) as u8;
        (safe_zip).zip_entries = zip_entry;
        (safe_zip).central_directory_entries_total = (safe_zip).central_directory_entries_total + 1;
        /* version = p[4]; */
        safe_zip_entry.system = unsafe { *p.offset(5 as isize) as u8 };
        /* version_required = archive_le16dec(p + 6); */
        safe_zip_entry.zip_flags = archive_le16dec(unsafe { p.offset(8 as isize) as *const () });
        if safe_zip_entry.zip_flags as i32 & ((1 << 0) | (1 << 6)) != 0 {
            (safe_zip).has_encrypted_entries = 1
        }
        safe_zip_entry.compression =
            archive_le16dec(unsafe { p.offset(10 as isize) as *const () }) as u8 as u8;
        safe_zip_entry.mtime = zip_time(unsafe { p.offset(12 as isize) });
        safe_zip_entry.crc32 = archive_le32dec(unsafe { p.offset(16 as isize) as *const () });
        if safe_zip_entry.zip_flags as i32 & (1 << 3) != 0 {
            safe_zip_entry.decdat = unsafe { *p.offset(13 as isize) as u8 }
        } else {
            safe_zip_entry.decdat = unsafe { *p.offset(19 as isize) as u8 }
        }
        safe_zip_entry.compressed_size =
            archive_le32dec(unsafe { p.offset(20 as isize) as *const () }) as int64_t;
        safe_zip_entry.uncompressed_size =
            archive_le32dec(unsafe { p.offset(24 as isize) as *const () }) as int64_t;
        filename_length = archive_le16dec(unsafe { p.offset(28 as isize) as *const () }) as size_t;
        extra_length = archive_le16dec(unsafe { p.offset(30 as isize) as *const () }) as size_t;
        comment_length = archive_le16dec(unsafe { p.offset(32 as isize) as *const () }) as size_t;
        /* disk_start = archive_le16dec(p + 34);
         *   Better be zero.
         * internal_attributes = archive_le16dec(p + 36);
         *   text bit */
        external_attributes = archive_le32dec(unsafe { p.offset(38 as isize) as *const () });
        safe_zip_entry.local_header_offset =
            archive_le32dec(unsafe { p.offset(42 as isize) as *const () }) as i64 + correction;
        /* If we can't guess the mode, leave it zero here;
        when we read the local file header we might get
        more information. */
        if safe_zip_entry.system as i32 == 3 {
            safe_zip_entry.mode = (external_attributes >> 16) as uint16_t
        } else if safe_zip_entry.system as i32 == 0 {
            // Interpret MSDOS directory bit
            if 0x10 == external_attributes & 0x10 {
                safe_zip_entry.mode = (0o40000 as mode_t | 0o775 as u32) as uint16_t
            } else {
                safe_zip_entry.mode = (0o100000 as mode_t | 0o664 as u32) as uint16_t
            }
            if 0x1 == external_attributes & 0x1 {
                // Read-only bit; strip write permissions
                safe_zip_entry.mode = (safe_zip_entry.mode as i32 & 0o555 as i32) as uint16_t
            }
        } else {
            safe_zip_entry.mode = 0
        }
        /* We're done with the regular data; get the filename and
         * extra data. */
        unsafe { __archive_read_consume_safe(a, 46 as int64_t) };
        p = unsafe {
            __archive_read_ahead_safe(a, filename_length + (extra_length), 0 as *mut ssize_t)
                as *const u8
        };
        if p.is_null() {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    84,
                    b"Truncated ZIP file header\x00" as *const u8,
                )
            };
            return -30;
        }
        if 0 != process_extra(
            a,
            entry,
            unsafe { p.offset(filename_length as isize) },
            extra_length,
            zip_entry,
        ) {
            return -30;
        }
        /*
         * Mac resource fork files are stored under the
         * "__MACOSX/" directory, so we should check if
         * it is.
         */
        if (safe_zip).process_mac_extensions == 0 {
            /* Treat every entry as a regular entry. */
            unsafe {
                __archive_rb_tree_insert_node_safe(&mut (safe_zip).tree, &mut (safe_zip_entry).node)
            };
        } else {
            name = p;
            r = rsrc_basename(name, filename_length);
            if filename_length >= 9 as u64
                && unsafe { strncmp_safe(b"__MACOSX/\x00" as *const u8, name, 9 as u64) } == 0
            {
                /* If this file is not a resource fork nor
                 * a directory. We should treat it as a non
                 * resource fork file to expose it. */
                if unsafe {
                    *name.offset((filename_length - 1 as u64) as isize) as i32 != '/' as i32
                        && ((r.offset_from(name) as i64) < 3 as i64
                            || *r.offset(0 as isize) as i32 != '.' as i32
                            || *r.offset(1 as isize) as i32 != '_' as i32)
                } {
                    unsafe {
                        __archive_rb_tree_insert_node_safe(
                            &mut (safe_zip).tree,
                            &mut (safe_zip_entry).node,
                        )
                    };
                    /* Expose its parent directories. */
                    expose_parent_dirs(zip, name, filename_length);
                } else {
                    /* This file is a resource fork file or
                     * a directory. */
                    (safe_zip_entry).rsrcname.length = 0 as size_t;
                    unsafe {
                        archive_strncat_safe(
                            &mut (safe_zip_entry).rsrcname,
                            name as *const (),
                            filename_length,
                        )
                    };
                    unsafe {
                        __archive_rb_tree_insert_node_safe(
                            &mut (safe_zip).tree_rsrc,
                            &mut (safe_zip_entry).node,
                        )
                    };
                }
            } else {
                /* Generate resource fork name to find its
                 * resource file at zip->tree_rsrc. */
                (safe_zip_entry).rsrcname.length = 0 as size_t;
                unsafe {
                    archive_strncat_safe(
                        &mut (safe_zip_entry).rsrcname,
                        b"__MACOSX/\x00" as *const u8 as *const (),
                        (if (b"__MACOSX/\x00" as *const u8).is_null() {
                            0
                        } else {
                            strlen_safe(b"__MACOSX/\x00" as *const u8)
                        }),
                    )
                };
                unsafe {
                    archive_strncat_safe(
                        &mut (safe_zip_entry).rsrcname,
                        name as *const (),
                        unsafe { r.offset_from(name) as size_t },
                    )
                };
                unsafe {
                    archive_strcat_safe(
                        &mut (safe_zip_entry).rsrcname,
                        b"._\x00" as *const u8 as *const (),
                    )
                };
                unsafe {
                    archive_strncat_safe(
                        &mut (safe_zip_entry).rsrcname,
                        name.offset(r.offset_from(name) as i64 as isize) as *const (),
                        filename_length - (r.offset_from(name) as u64),
                    )
                };
                /* Register an entry to RB tree to sort it by
                 * file offset. */
                unsafe {
                    __archive_rb_tree_insert_node_safe(
                        &mut (safe_zip).tree,
                        &mut (safe_zip_entry).node,
                    )
                };
            }
        }
        /* Skip the comment too ... */
        unsafe {
            __archive_read_consume_safe(
                a,
                (filename_length + (extra_length) + (comment_length)) as int64_t,
            )
        };
    }
    return 0;
}

fn zip_get_local_file_header_size(a: *mut archive_read, extra: size_t) -> ssize_t {
    let mut p: *const u8 = 0 as *const u8;
    let filename_length: ssize_t;
    let extra_length: ssize_t;
    p = unsafe { __archive_read_ahead_safe(a, extra + 30, 0 as *mut ssize_t) } as *const u8;
    let safe_a = unsafe { &mut *a };
    if p.is_null() {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84,
                b"Truncated ZIP file header\x00" as *const u8,
            )
        };
        return -20;
    }
    unsafe { p = p.offset(extra as isize) };
    if unsafe {
        memcmp_safe(
            p as *const (),
            b"PK\x03\x04\x00" as *const u8 as *const (),
            4,
        )
    } != 0
    {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -1,
                b"Damaged Zip archive\x00" as *const u8,
            )
        };
        return -20;
    }
    filename_length = archive_le16dec(unsafe { p.offset(26 as isize) as *const () }) as ssize_t;
    extra_length = archive_le16dec(unsafe { p.offset(28 as isize) as *const () }) as ssize_t;
    return 30 + filename_length + extra_length;
}

fn zip_read_mac_metadata(
    a: *mut archive_read,
    entry: *mut archive_entry,
    rsrc: *mut zip_entry,
) -> i32 {
    unsafe {
        let current_block: u64;
        let zip: *mut zip = (*(*a).format).data as *mut zip;
        let mut metadata: *mut u8 = 0 as *mut u8;
        let mut mp: *mut u8 = 0 as *mut u8;
        let mut offset: int64_t = archive_filter_bytes(&mut (*a).archive, 0);
        let mut remaining_bytes: size_t;
        let mut metadata_bytes: size_t;
        let mut hsize: ssize_t;
        let mut ret: i32 = 0;
        let mut eof: i32;
        let safe_a = unsafe { &mut *a };
        let safe_zip = unsafe { &mut *zip };
        let safe_rsrc = unsafe { &mut *rsrc };
        match safe_rsrc.compression as i32 {
            0 => {
                /* No compression. */
                if safe_rsrc.uncompressed_size != safe_rsrc.compressed_size {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            84,
                            b"Malformed OS X metadata entry: inconsistent size\x00" as *const u8
                                as *const u8,
                        )
                    };
                    return -30;
                }
            }
            #[cfg(HAVE_ZLIB_H)]
            8 => {}
            _ => {
                /* Unsupported compression. */
                /* Return a warning. */
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        84,
                        b"Unsupported ZIP compression method (%s)\x00" as *const u8,
                        compression_name((*rsrc).compression as i32),
                    )
                };
                /* We can't decompress this entry, but we will
                 * be able to skip() it and try the next entry. */
                return -20;
            }
        }
        if (safe_rsrc).uncompressed_size > (4 * 1024 * 1024) as i64 {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    84,
                    b"Mac metadata is too large: %jd > 4M bytes\x00" as *const u8,
                    (*rsrc).uncompressed_size,
                )
            };
            return -20;
        }
        if (safe_rsrc).compressed_size > (4 * 1024 * 1024) as i64 {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    84,
                    b"Mac metadata is too large: %jd > 4M bytes\x00" as *const u8,
                    (safe_rsrc).compressed_size,
                )
            };
            return -20;
        }
        metadata = malloc_safe((safe_rsrc).uncompressed_size as size_t) as *mut u8;
        if metadata.is_null() {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    12,
                    b"Can\'t allocate memory for Mac metadata\x00" as *const u8,
                )
            };
            return -30;
        }
        if offset < (safe_rsrc).local_header_offset {
            __archive_read_consume_safe(a, (safe_rsrc).local_header_offset - offset);
        } else if offset != (safe_rsrc).local_header_offset {
            __archive_read_seek(a, (safe_rsrc).local_header_offset, 0);
        }
        hsize = zip_get_local_file_header_size(a, 0);
        __archive_read_consume_safe(a, hsize);
        remaining_bytes = (safe_rsrc).compressed_size as size_t;
        metadata_bytes = (safe_rsrc).uncompressed_size as size_t;
        mp = metadata;
        eof = 0;
        loop {
            if !(eof == 0 && remaining_bytes != 0) {
                current_block = 1;
                break;
            }
            let mut p: *const u8 = 0 as *const u8;
            let mut bytes_avail: ssize_t = 0;
            let mut bytes_used: size_t = 0;
            p = __archive_read_ahead_safe(a, 1 as size_t, &mut bytes_avail) as *const u8;
            if p.is_null() {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        84,
                        b"Truncated ZIP file header\x00" as *const u8,
                    )
                };
                ret = -20;
                current_block = 2;
                break;
            } else {
                if bytes_avail as size_t > remaining_bytes {
                    bytes_avail = remaining_bytes as ssize_t
                }
                match (safe_rsrc).compression as i32 {
                    0 => {
                        /* No compression. */
                        if bytes_avail as size_t > metadata_bytes {
                            bytes_avail = metadata_bytes as ssize_t
                        }
                        memcpy_safe(mp as *mut (), p as *const (), bytes_avail as u64);
                        bytes_used = bytes_avail as size_t;
                        metadata_bytes = ((metadata_bytes as u64) - (bytes_used)) as size_t;
                        mp = unsafe { mp.offset(bytes_used as isize) };
                        if metadata_bytes == 0 {
                            eof = 1
                        }
                    }
                    #[cfg(HAVE_ZLIB_H)]
                    8 => {
                        /* Deflate compression. */
                        let mut r: i32 = 0;
                        ret = zip_deflate_init(a, zip);
                        if ret != 0 {
                            current_block = 2;
                            break;
                        }
                        (safe_zip).stream.next_in = p as *const () as uintptr_t as *mut Bytef;
                        (safe_zip).stream.avail_in = bytes_avail as uInt;
                        (safe_zip).stream.total_in = 0;
                        (safe_zip).stream.next_out = mp;
                        (safe_zip).stream.avail_out = metadata_bytes as uInt;
                        (safe_zip).stream.total_out = 0;
                        r = inflate_safe(&mut (safe_zip).stream, 0);
                        match r {
                            0 => {}
                            1 => eof = 1,
                            -4 => {
                                unsafe {
                                    archive_set_error(
                                        &mut (safe_a).archive as *mut archive,
                                        12,
                                        b"Out of memory for ZIP decompression\x00" as *const u8
                                            as *const u8,
                                    )
                                };
                                ret = -30;
                                current_block = 2;
                                break;
                            }
                            _ => {
                                unsafe {
                                    archive_set_error(
                                        &mut (safe_a).archive as *mut archive,
                                        -1,
                                        b"ZIP decompression failed (%d)\x00" as *const u8
                                            as *const u8,
                                        r,
                                    )
                                };
                                ret = -30;
                                current_block = 2;
                                break;
                            }
                        }
                        bytes_used = (safe_zip).stream.total_in;
                        metadata_bytes =
                            ((metadata_bytes as u64) - ((*zip).stream.total_out)) as size_t;
                        mp = mp.offset((safe_zip).stream.total_out as isize)
                    }
                    _ => bytes_used = 0 as size_t,
                }
                __archive_read_consume_safe(a, bytes_used as int64_t);
                remaining_bytes = ((remaining_bytes as u64) - (bytes_used)) as size_t
            }
        }
        match current_block {
            1 => {
                archive_entry_copy_mac_metadata(
                    entry,
                    metadata as *const (),
                    ((*rsrc).uncompressed_size as size_t) - (metadata_bytes),
                );
            }
            _ => {}
        }
        __archive_read_seek_safe(a, offset, 0);
        (safe_zip).decompress_init = 0;
        free_safe(metadata as *mut ());
        return ret;
    }
}
unsafe fn archive_read_format_zip_seekable_read_header(
    a: *mut archive_read,
    entry: *mut archive_entry,
) -> i32 {
    let zip: *mut zip = unsafe { (*(*a).format).data as *mut zip };
    let mut rsrc: *mut zip_entry = 0 as *mut zip_entry;
    let mut offset: int64_t;
    let mut r: i32;
    let mut ret: i32 = 0;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    /*
     * It should be sufficient to call archive_read_next_header() for
     * a reader to determine if an entry is encrypted or not. If the
     * encryption of an entry is only detectable when calling
     * archive_read_data(), so be it. We'll do the same check there
     * as well.
     */
    if safe_zip.has_encrypted_entries == -1 {
        safe_zip.has_encrypted_entries = 0
    }
    (safe_a).archive.archive_format = 0x50000;
    if safe_a.archive.archive_format_name.is_null() {
        safe_a.archive.archive_format_name = b"ZIP\x00" as *const u8
    }
    if safe_zip.zip_entries.is_null() {
        r = slurp_central_directory(a, entry, zip);
        if r != 0 {
            return r;
        }
        /* Get first entry whose local header offset is lower than
         * other entries in the archive file. */
        safe_zip.entry = unsafe {
            __archive_rb_tree_iterate_safe(&mut safe_zip.tree, 0 as *mut archive_rb_node, 0 as u32)
        } as *mut zip_entry
    } else if !safe_zip.entry.is_null() {
        /* Get next entry in local header offset order. */
        unsafe {
            safe_zip.entry =
                __archive_rb_tree_iterate(&mut safe_zip.tree, &mut (*safe_zip.entry).node, 1)
                    as *mut zip_entry
        }
    }
    if (safe_zip).entry.is_null() {
        return 1;
    }
    unsafe {
        if !(*(safe_zip).entry).rsrcname.s.is_null() {
            rsrc = __archive_rb_tree_find_node_safe(
                &mut safe_zip.tree_rsrc,
                (*safe_zip.entry).rsrcname.s as *const (),
            ) as *mut zip_entry
        } else {
            rsrc = 0 as *mut zip_entry
        }
    }
    if safe_zip.cctx_valid != 0 {
        unsafe {
            __archive_cryptor
                .decrypto_aes_ctr_release
                .expect("non-null function pointer")(&mut safe_zip.cctx)
        };
    }
    if safe_zip.hctx_valid != 0 {
        unsafe {
            __archive_hmac
                .__hmac_sha1_cleanup
                .expect("non-null function pointer")(&mut safe_zip.hctx)
        };
    }
    safe_zip.hctx_valid = 0;
    safe_zip.cctx_valid = safe_zip.hctx_valid;
    safe_zip.tctx_valid = safe_zip.cctx_valid;
    unsafe { __archive_read_reset_passphrase_safe(a) };
    /* File entries are sorted by the header offset, we should mostly
     * use __archive_read_consume to advance a read point to avoid
     * redundant data reading.  */
    offset = unsafe { archive_filter_bytes_safe(&mut (safe_a).archive, 0) };
    unsafe {
        if offset < (*(safe_zip).entry).local_header_offset {
            __archive_read_consume_safe(a, (*(safe_zip).entry).local_header_offset - offset);
        } else if offset != (*(safe_zip).entry).local_header_offset {
            __archive_read_seek_safe(a, (*(safe_zip).entry).local_header_offset, 0);
        }
    }
    safe_zip.unconsumed = 0 as size_t;
    r = zip_read_local_file_header(a, entry, zip);
    if r != 0 {
        return r;
    }
    if !rsrc.is_null() {
        let mut ret2: i32 = zip_read_mac_metadata(a, entry, rsrc);
        if ret2 < ret {
            ret = ret2
        }
    }
    return ret;
}
/*
* We're going to seek for the next header anyway, so we don't
* need to bother doing anything here.
*/
fn archive_read_format_zip_read_data_skip_seekable(a: *mut archive_read) -> i32 {
    let mut zip: *mut zip = 0 as *mut zip;
    zip = unsafe { (*(*a).format).data as *mut zip };
    let safe_zip = unsafe { &mut *zip };
    (safe_zip).unconsumed = 0;
    return 0;
}

#[no_mangle]
pub fn archive_read_support_format_zip_seekable(_a: *mut archive) -> i32 {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut zip = 0 as *mut zip;
    let r: i32;
    let magic_test: i32 = unsafe {
        __archive_check_magic_safe(
            _a,
            0xdeb0c5,
            1,
            b"archive_read_support_format_zip_seekable\x00" as *const u8,
        )
    };
    if magic_test == -30 {
        return -30;
    }
    zip = unsafe { calloc_safe(1, size_of::<zip>() as u64) } as *mut zip;

    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };

    if zip.is_null() {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                12,
                b"Can\'t allocate zip data\x00" as *const u8,
            )
        };
        return -30;
    }

    match () {
        #[cfg(HAVE_COPYFILE_H)]
        _ => {
            (safe_zip).process_mac_extensions = 1;
        }
        #[cfg(not(HAVE_COPYFILE_H))]
        _ => {}
    }

    /*
     * Until enough data has been read, we cannot tell about
     * any encrypted entries yet.
     */
    (safe_zip).has_encrypted_entries = -1;
    (safe_zip).crc32func = Some(real_crc32);
    r = unsafe {
        __archive_read_register_format_safe(
            a,
            zip as *mut (),
            b"zip\x00" as *const u8,
            Some(archive_read_format_zip_seekable_bid),
            Some(archive_read_format_zip_options),
            Some(archive_read_format_zip_seekable_read_header),
            Some(archive_read_format_zip_read_data),
            Some(archive_read_format_zip_read_data_skip_seekable),
            None,
            Some(archive_read_format_zip_cleanup),
            Some(archive_read_support_format_zip_capabilities_seekable),
            Some(archive_read_format_zip_has_encrypted_entries),
        )
    };
    if r != 0 {
        unsafe { free_safe(zip as *mut ()) };
    }
    return 0;
}
fn run_static_initializers() {
    unsafe {
        num_compression_methods =
            ((size_of::<[obj2; 25]>() as u64) / (size_of::<obj2>() as u64)) as i32
    }
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe fn(); 1] = [run_static_initializers];
/*# vim:set noet:*/

#[no_mangle]
pub fn archive_test_trad_enc_init(_a: *mut archive, key: *const uint8_t, crcchk: *mut uint8_t) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut trad_enc_ctx: *mut trad_enc_ctx = 0 as *mut trad_enc_ctx;
    trad_enc_ctx = unsafe { calloc_safe(1, size_of::<trad_enc_ctx>() as u64) } as *mut trad_enc_ctx;
    trad_enc_init(
        trad_enc_ctx,
        b"11" as *const u8,
        20,
        key,
        10 as size_t,
        crcchk,
    );
}

#[no_mangle]
pub fn archive_test_zip_read_mac_metadata(_a: *mut archive, entry: *mut archive_entry) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut zip_entry: *mut zip_entry = 0 as *mut zip_entry;
    zip_entry = unsafe { calloc_safe(1, size_of::<zip_entry>() as u64) } as *mut zip_entry;
    unsafe { (*(zip_entry)).uncompressed_size = (5 * 1024 * 1024) as int64_t };
    unsafe { (*(zip_entry)).compressed_size = (6 * 1024 * 1024) as int64_t };
    zip_read_mac_metadata(a, entry, zip_entry);
    unsafe { (*(zip_entry)).compressed_size = (5 * 1024 * 1024) as int64_t };
    zip_read_mac_metadata(a, entry, zip_entry);
}

#[no_mangle]
pub fn archive_test_expose_parent_dirs(_a: *mut archive, name: *const u8, name_length: size_t) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut zip = 0 as *mut zip;
    zip = unsafe { (*(*a).format).data as *mut zip };
    expose_parent_dirs(zip, name, name_length);
}

#[no_mangle]
pub fn archive_test_check_authentication_code(_a: *mut archive, _p: *const ()) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut zip = 0 as *mut zip;
    zip = unsafe { calloc_safe(1, size_of::<zip>() as u64) } as *mut zip;
    unsafe { (*(*a).format).data = zip as *mut () };
    check_authentication_code(a, _p);
}

#[no_mangle]
pub fn archive_test_archive_read_format_zip_options(
    _a: *mut archive,
    key: *const u8,
    val: *const u8,
) {
    let a: *mut archive_read = _a as *mut archive_read;
    archive_read_format_zip_options(a, key, val);
}

#[no_mangle]
pub fn archive_test_zipx_ppmd8_init(mut _a: *mut archive) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut zip = 0 as *mut zip;
    zip = unsafe { calloc_safe(1, size_of::<zip>() as u64) } as *mut zip;
    unsafe { (*zip).ppmd8_valid = 'a' as u8 };
    zipx_ppmd8_init(a, zip);
}

#[no_mangle]
pub fn archive_test_cmp_key(n: *const archive_rb_node, key: *const ()) {
    let mut archive_rb_node: *mut archive_rb_node = 0 as *mut archive_rb_node;
    archive_rb_node =
        unsafe { calloc_safe(1, size_of::<archive_rb_node>() as u64) } as *mut archive_rb_node;
    cmp_key(archive_rb_node, key);
}

#[no_mangle]
pub fn archive_test_read_format_zip_read_data(_a: *mut archive) {
    let a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut zip = 0 as *mut zip;
    zip = unsafe { calloc_safe(1, size_of::<zip>() as u64) } as *mut zip;
    unsafe { (*zip).has_encrypted_entries = -1 };
    unsafe { (*zip).entry_uncompressed_bytes_read = 0 };
    unsafe { (*zip).end_of_entry = 'a' as u8 };
    unsafe { (*(*a).format).data = zip as *mut () };
    let mut size: size_t = 0;
    let mut size2: *mut size_t = &size as *const size_t as *mut size_t;
    let mut offset: int64_t = 0;
    let mut offset2: *mut int64_t = &offset as *const int64_t as *mut int64_t;
    let mut buff: *mut () = 0 as *const () as *mut ();
    let mut buff2: *mut *const () =
        unsafe { &buff as *const *mut () as *mut *mut () as *mut *const () };
    archive_read_format_zip_read_data(a, buff2, size2, offset2);
}
