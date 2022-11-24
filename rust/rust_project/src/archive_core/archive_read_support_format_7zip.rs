use archive_core::archive_endian::*;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;
use std::mem::size_of;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7zip {
    pub si: _7z_stream_info,
    pub header_is_being_read: i32,
    pub header_is_encoded: i32,
    pub header_bytes_remaining: uint64_t,
    pub header_crc32: u64,
    pub header_offset: uint64_t,
    pub seek_base: uint64_t,
    pub entries_remaining: size_t,
    pub numFiles: uint64_t,
    pub entries: *mut _7zip_entry,
    pub entry: *mut _7zip_entry,
    pub entry_names: *mut u8,
    pub entry_offset: int64_t,
    pub entry_bytes_remaining: uint64_t,
    pub entry_crc32: u64,
    pub end_of_entry: u8,
    pub uncompressed_buffer: *mut u8,
    pub uncompressed_buffer_pointer: *mut u8,
    pub uncompressed_buffer_size: size_t,
    pub uncompressed_buffer_bytes_remaining: size_t,
    pub stream_offset: int64_t,
    pub folder_index: u32,
    pub folder_outbytes_remaining: uint64_t,
    pub pack_stream_index: u32,
    pub pack_stream_remaining: u32,
    pub pack_stream_inbytes_remaining: uint64_t,
    pub pack_stream_bytes_unconsumed: size_t,
    pub codec: u64,
    pub codec2: u64,
    #[cfg(HAVE_LZMA_H)]
    pub lzstream: lzma_stream,
    #[cfg(HAVE_LZMA_H)]
    pub lzstream_valid: i32,
    #[cfg(all(HAVE_ZLIB_H, BZ_CONFIG_ERROR))]
    pub bzstream: bz_stream,
    #[cfg(all(HAVE_ZLIB_H, BZ_CONFIG_ERROR))]
    pub bzstream_valid: i32,
    #[cfg(HAVE_ZLIB_H)]
    pub stream: z_stream,
    #[cfg(HAVE_ZLIB_H)]
    pub stream_valid: i32,
    pub ppmd7_stat: i32,
    pub ppmd7_context: CPpmd7,
    pub range_dec: CPpmd7z_RangeDec,
    pub bytein: IByteIn,
    pub ppstream: obj,
    pub ppmd7_valid: i32,
    pub bcj_state: uint32_t,
    pub odd_bcj_size: size_t,
    pub odd_bcj: [u8; 4],
    pub bcj_prevPosT: size_t,
    pub bcj_prevMask: uint32_t,
    pub bcj_ip: uint32_t,
    pub main_stream_bytes_remaining: size_t,
    pub sub_stream_buff: [*mut u8; 3],
    pub sub_stream_size: [size_t; 3],
    pub sub_stream_bytes_remaining: [size_t; 3],
    pub tmp_stream_buff: *mut u8,
    pub tmp_stream_buff_size: size_t,
    pub tmp_stream_bytes_avail: size_t,
    pub tmp_stream_bytes_remaining: size_t,
    pub bcj2_p: [uint16_t; 258],
    pub bcj2_prevByte: uint8_t,
    pub bcj2_range: uint32_t,
    pub bcj2_code: uint32_t,
    pub bcj2_outPos: uint64_t,
    pub sconv: *mut archive_string_conv,
    pub format_name: [u8; 64],
    pub has_encrypted_entries: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct obj {
    pub next_in: *const u8,
    pub avail_in: int64_t,
    pub total_in: int64_t,
    pub next_out: *mut u8,
    pub avail_out: int64_t,
    pub total_out: int64_t,
    pub overconsumed: i32,
}

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
pub struct _7zip_entry {
    pub name_len: size_t,
    pub utf16name: *mut u8,

    #[cfg_attr(_WIN32, _DEBUG, cfg(not(HAVE_TIMEGM)))]
    pub wname: *const wchar_t,

    pub folderIndex: uint32_t,
    pub ssIndex: uint32_t,
    pub flg: u32,
    pub mtime: time_t,
    pub atime: time_t,
    pub ctime: time_t,
    pub mtime_ns: i64,
    pub atime_ns: i64,
    pub ctime_ns: i64,
    pub mode: uint32_t,
    pub attr: uint32_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7z_stream_info {
    pub pi: _7z_pack_info,
    pub ci: _7z_coders_info,
    pub ss: _7z_substream_info,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7z_substream_info {
    pub unpack_streams: size_t,
    pub unpackSizes: *mut uint64_t,
    pub digestsDefined: *mut u8,
    pub digests: *mut uint32_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7z_coders_info {
    pub numFolders: uint64_t,
    pub folders: *mut _7z_folder,
    pub dataStreamIndex: uint64_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7z_folder {
    pub numCoders: uint64_t,
    pub coders: *mut _7z_coder,
    pub numBindPairs: uint64_t,
    pub bindPairs: *mut obj1,
    pub numPackedStreams: uint64_t,
    pub packedStreams: *mut uint64_t,
    pub numInStreams: uint64_t,
    pub numOutStreams: uint64_t,
    pub unPackSize: *mut uint64_t,
    pub digest_defined: u8,
    pub digest: uint32_t,
    pub numUnpackStreams: uint64_t,
    pub packIndex: uint32_t,
    pub skipped_bytes: uint64_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct obj1 {
    pub inIndex: uint64_t,
    pub outIndex: uint64_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7z_coder {
    pub codec: u64,
    pub numInStreams: uint64_t,
    pub numOutStreams: uint64_t,
    pub propertiesSize: uint64_t,
    pub properties: *mut u8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7z_pack_info {
    pub pos: uint64_t,
    pub numPackStreams: uint64_t,
    pub sizes: *mut uint64_t,
    pub digest: _7z_digests,
    pub positions: *mut uint64_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7z_digests {
    pub defineds: *mut u8,
    pub digests: *mut uint32_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7z_header_info {
    pub dataIndex: uint64_t,
    pub emptyStreamBools: *mut u8,
    pub emptyFileBools: *mut u8,
    pub antiBools: *mut u8,
    pub attrBools: *mut u8,
}

#[no_mangle]
pub unsafe fn archive_read_support_format_7zip(mut _a: *mut archive) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    let mut r: i32 = 0;
    let mut magic_test: i32 = __archive_check_magic_safe(
        _a,
        0xdeb0c5 as u32,
        1 as u32,
        b"archive_read_support_format_7zip\x00" as *const u8,
    );
    if magic_test == -(30 as i32) {
        return -(30 as i32);
    }
    zip = calloc_safe(1 as i32 as u64, size_of::<_7zip>() as u64) as *mut _7zip;
    let safe_zip = unsafe { &mut *zip };
    let safe_a = unsafe { &mut *a };

    if zip.is_null() {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                12 as i32,
                b"Can\'t allocate 7zip data\x00" as *const u8,
            )
        };
        return -(30 as i32);
    }
    /*
     * Until enough data has been read, we cannot tell about
     * any encrypted entries yet.
     */
    (safe_zip).has_encrypted_entries = -(1 as i32);
    r = __archive_read_register_format_safe(
        a,
        zip as *mut (),
        b"7zip\x00" as *const u8,
        Some(archive_read_format_7zip_bid),
        None,
        Some(archive_read_format_7zip_read_header),
        Some(archive_read_format_7zip_read_data),
        Some(archive_read_format_7zip_read_data_skip),
        None,
        Some(archive_read_format_7zip_cleanup),
        Some(archive_read_support_format_7zip_capabilities),
        Some(archive_read_format_7zip_has_encrypted_entries),
    );
    if r != 0 as i32 {
        free_safe(zip as *mut ());
    }
    return 0 as i32;
}
unsafe fn archive_read_support_format_7zip_capabilities(mut a: *mut archive_read) -> i32 {
    /* UNUSED */
    return (1 as i32) << 0 as i32 | (1 as i32) << 1 as i32;
}
/* Maximum entry size. This limitation prevents reading intentional
* corrupted 7-zip files on assuming there are not so many entries in
* the files. */
unsafe fn archive_read_format_7zip_has_encrypted_entries(mut _a: *mut archive_read) -> i32 {
    let safe__a = unsafe { &mut *_a };
    if !_a.is_null() && !safe__a.format.is_null() {
        let mut zip: *mut _7zip = unsafe { (*safe__a.format).data as *mut _7zip };
        let safe_zip = unsafe { &mut *zip };
        if !zip.is_null() {
            return safe_zip.has_encrypted_entries;
        }
    }
    return -(1 as i32);
}
unsafe fn archive_read_format_7zip_bid(mut a: *mut archive_read, mut best_bid: i32) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    /* If someone has already bid more than 32, then avoid
    trashing the look-ahead buffers with a seek. */
    if best_bid > 32 as i32 {
        return -(1 as i32);
    }
    p = __archive_read_ahead_safe(a, 6 as i32 as size_t, 0 as *mut ssize_t) as *const u8;
    if p.is_null() {
        return 0 as i32;
    }
    /* If first six bytes are the 7-Zip signature,
     * return the bid right now. */
    if memcmp_safe(
        p as *const (),
        b"7z\xbc\xaf\'\x1c\x00" as *const u8 as *const (),
        6 as i32 as u64,
    ) == 0 as i32
    {
        return 48 as i32;
    }
    /*
     * It may a 7-Zip SFX archive file. If first two bytes are
     * 'M' and 'Z' available on Windows or first four bytes are
     * "\x7F\x45LF" available on posix like system, seek the 7-Zip
     * signature. Although we will perform a seek when reading
     * a header, what we do not use __archive_read_seek() here is
     * due to a bidding performance.
     */
    if unsafe {
        *p.offset(0 as i32 as isize) as i32 == 'M' as i32
            && *p.offset(1 as i32 as isize) as i32 == 'Z' as i32
            || memcmp_safe(
                p as *const (),
                b"\x7fELF\x00" as *const u8 as *const (),
                4 as i32 as u64,
            ) == 0 as i32
    } {
        let mut offset: ssize_t = 0x27000 as i32 as ssize_t;
        let mut window: ssize_t = 4096 as i32 as ssize_t;
        let mut bytes_avail: ssize_t = 0;
        while offset + window <= 0x60000 as i32 as i64 {
            let mut buff: *const u8 =
                __archive_read_ahead_safe(a, (offset + window) as size_t, &mut bytes_avail)
                    as *const u8;
            if buff.is_null() {
                /* Remaining bytes are less than window. */
                window >>= 1 as i32;
                if window < 0x40 as i32 as i64 {
                    return 0 as i32;
                }
            } else {
                unsafe {
                    p = buff.offset(offset as isize);
                    while p.offset(32 as i32 as isize) < buff.offset(bytes_avail as isize) {
                        let mut step: i32 = check_7zip_header_in_sfx(p);
                        if step == 0 as i32 {
                            return 48 as i32;
                        }
                        p = p.offset(step as isize)
                    }
                    offset = p.offset_from(buff) as i64
                }
            }
        }
    }
    return 0 as i32;
}
unsafe fn check_7zip_header_in_sfx(mut p: *const u8) -> i32 {
    match unsafe { *p.offset(5 as i32 as isize) as u8 as i32 } {
        28 => {
            if memcmp_safe(
                p as *const (),
                b"7z\xbc\xaf\'\x1c\x00" as *const u8 as *const (),
                6 as i32 as u64,
            ) != 0 as i32
            {
                return 6 as i32;
            }
            /*
             * Test the CRC because its extraction code has 7-Zip
             * Magic Code, so we should do this in order not to
             * make a mis-detection.
             */
            if unsafe {
                crc32_safe(
                    0 as i32 as uLong,
                    (p as *const u8).offset(12 as i32 as isize),
                    20 as i32 as uInt,
                ) != archive_le32dec(p.offset(8 as i32 as isize) as *const ()) as u64
            } {
                return 6 as i32;
            }
            /* Hit the header! */
            return 0 as i32;
        }
        55 => return 5 as i32,
        122 => return 4 as i32,
        188 => return 3 as i32,
        175 => return 2 as i32,
        39 => return 1 as i32,
        _ => return 6 as i32,
    };
}
unsafe fn skip_sfx(mut a: *mut archive_read, mut bytes_avail: ssize_t) -> i32 {
    let mut h: *const () = 0 as *const ();
    let mut p: *const u8 = 0 as *const u8;
    let mut q: *const u8 = 0 as *const u8;
    let mut skip: size_t = 0;
    let mut offset: size_t = 0;
    let mut bytes: ssize_t = 0;
    let mut window: ssize_t = 0;
    let safe_a = unsafe { &mut *a };
    /*
     * If bytes_avail > SFX_MIN_ADDR we do not have to call
     * __archive_read_seek() at this time since we have
     * already had enough data.
     */
    if bytes_avail > 0x27000 as i32 as i64 {
        __archive_read_consume_safe(a, 0x27000 as i32 as int64_t);
    } else if __archive_read_seek_safe(a, 0x27000 as i32 as int64_t, 0 as i32) < 0 as i32 as i64 {
        return -(30 as i32);
    }
    offset = 0 as i32 as size_t;
    window = 1 as i32 as ssize_t;
    while offset.wrapping_add(window as u64) <= (0x60000 as i32 - 0x27000 as i32) as u64 {
        h = __archive_read_ahead_safe(a, window as size_t, &mut bytes);
        if h == 0 as *mut () {
            /* Remaining bytes are less than window. */
            window >>= 1 as i32;
            if window < 0x40 as i32 as i64 {
                break;
            }
        } else if bytes < 6 as i32 as i64 {
            /* This case might happen when window == 1. */
            window = 4096 as i32 as ssize_t
        } else {
            p = h as *const u8;
            q = unsafe { p.offset(bytes as isize) };
            /*
             * Scan ahead until we find something that looks
             * like the 7-Zip header.
             */
            unsafe {
                while p.offset(32 as i32 as isize) < q {
                    let mut step: i32 = check_7zip_header_in_sfx(p);
                    if step == 0 as i32 {
                        let mut zip: *mut _7zip = (*(*a).format).data as *mut _7zip;
                        skip = p.offset_from(h as *const u8) as i64 as size_t;
                        __archive_read_consume(a, skip as int64_t);
                        (*zip).seek_base = (0x27000 as i32 as u64)
                            .wrapping_add(offset)
                            .wrapping_add(skip);
                        return 0 as i32;
                    }
                    p = p.offset(step as isize)
                }
            }
            skip = unsafe { p.offset_from(h as *const u8) as i64 as size_t };
            __archive_read_consume_safe(a, skip as int64_t);
            offset = (offset as u64).wrapping_add(skip) as size_t as size_t;
            if window == 1 as i32 as i64 {
                window = 4096 as i32 as ssize_t
            }
        }
    }
    unsafe {
        archive_set_error(
            &mut (safe_a).archive as *mut archive,
            84 as i32,
            b"Couldn\'t find out 7-Zip header\x00" as *const u8,
        )
    };
    return -(30 as i32);
}
unsafe fn archive_read_format_7zip_read_header(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
) -> i32 {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut zip_entry: *mut _7zip_entry = 0 as *mut _7zip_entry;
    let mut r: i32 = 0;
    let mut ret: i32 = 0 as i32;
    let mut folder: *mut _7z_folder = 0 as *mut _7z_folder;
    let mut fidx: uint64_t = 0 as i32 as uint64_t;
    let safe_a = unsafe { &mut *a };
    let mut safe_zip = unsafe { &mut *zip };

    if safe_zip.has_encrypted_entries == -(1 as i32) {
        safe_zip.has_encrypted_entries = 0 as i32
    }
    safe_a.archive.archive_format = 0xe0000 as i32;
    if safe_a.archive.archive_format_name.is_null() {
        safe_a.archive.archive_format_name = b"7-Zip\x00" as *const u8
    }
    if safe_zip.entries.is_null() {
        let mut header: _7z_header_info = _7z_header_info {
            dataIndex: 0,
            emptyStreamBools: 0 as *mut u8,
            emptyFileBools: 0 as *mut u8,
            antiBools: 0 as *mut u8,
            attrBools: 0 as *mut u8,
        };
        memset_safe(
            &mut header as *mut _7z_header_info as *mut (),
            0 as i32,
            size_of::<_7z_header_info>() as u64,
        );
        r = slurp_central_directory(a, zip, &mut header);
        free_Header(&mut header);
        if r != 0 as i32 {
            return r;
        }
        (safe_zip).entries_remaining = (safe_zip).numFiles;
        (safe_zip).entry = (safe_zip).entries
    } else {
        (safe_zip).entry = unsafe { (safe_zip).entry.offset(1) }
    }
    zip_entry = (safe_zip).entry;
    let safe_zip_entry = unsafe { &mut *zip_entry };
    if (safe_zip).entries_remaining <= 0 as i32 as u64 || zip_entry.is_null() {
        return 1 as i32;
    }
    (safe_zip).entries_remaining = (safe_zip).entries_remaining.wrapping_sub(1);
    (safe_zip).entry_offset = 0 as i32 as int64_t;
    (safe_zip).end_of_entry = 0 as i32 as u8;
    (safe_zip).entry_crc32 = crc32_safe(0 as i32 as uLong, 0 as *const Bytef, 0 as i32 as uInt);
    /* Setup a string conversion for a filename. */
    if (safe_zip).sconv.is_null() {
        (safe_zip).sconv = archive_string_conversion_from_charset_safe(
            &mut (safe_a).archive,
            b"UTF-16LE\x00" as *const u8,
            1 as i32,
        );
        if (safe_zip).sconv.is_null() {
            return -(30 as i32);
        }
    }

    if !zip_entry.is_null() && ((safe_zip_entry).folderIndex as u64) < (safe_zip).si.ci.numFolders {
        folder = unsafe {
            &mut *(safe_zip)
                .si
                .ci
                .folders
                .offset((safe_zip_entry).folderIndex as isize) as *mut _7z_folder
        };
        fidx = 0 as i32 as uint64_t;
        unsafe {
            while !folder.is_null() && fidx < (*folder).numCoders {
                match (*(*folder).coders.offset(fidx as isize)).codec {
                    116457729 | 116458243 | 116459265 => {
                        archive_entry_set_is_data_encrypted(entry, 1 as i32 as u8);
                        (safe_zip).has_encrypted_entries = 1 as i32
                    }
                    _ => {}
                }
                fidx = fidx.wrapping_add(1)
            }
        }
    }

    if (safe_zip).has_encrypted_entries == -(1 as i32) {
        (safe_zip).has_encrypted_entries = 0 as i32
    }
    if _archive_entry_copy_pathname_l_safe(
        entry,
        (safe_zip_entry).utf16name as *const u8,
        (safe_zip_entry).name_len,
        (safe_zip).sconv,
    ) != 0 as i32
    {
        if unsafe { *__errno_location() == 12 as i32 } {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    12 as i32,
                    b"Can\'t allocate memory for Pathname\x00" as *const u8,
                )
            };
            return -(30 as i32);
        }
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84 as i32,
                b"Pathname cannot be converted from %s to current locale.\x00" as *const u8
                    as *const u8,
                archive_string_conversion_charset_name((safe_zip).sconv),
            )
        };
        ret = -(20 as i32)
    }
    /* Populate some additional entry fields: */
    archive_entry_set_mode_safe(entry, (safe_zip_entry).mode);
    if (safe_zip_entry).flg & ((1 as i32) << 0 as i32) as u32 != 0 {
        archive_entry_set_mtime_safe(entry, (safe_zip_entry).mtime, (safe_zip_entry).mtime_ns);
    }
    if (safe_zip_entry).flg & ((1 as i32) << 2 as i32) as u32 != 0 {
        archive_entry_set_ctime_safe(entry, (safe_zip_entry).ctime, (safe_zip_entry).ctime_ns);
    }
    if (safe_zip_entry).flg & ((1 as i32) << 1 as i32) as u32 != 0 {
        archive_entry_set_atime_safe(entry, (safe_zip_entry).atime, (safe_zip_entry).atime_ns);
    }
    if (safe_zip_entry).ssIndex != -(1 as i32) as uint32_t {
        (safe_zip).entry_bytes_remaining = unsafe {
            *(safe_zip)
                .si
                .ss
                .unpackSizes
                .offset((safe_zip_entry).ssIndex as isize)
        };
        archive_entry_set_size_safe(entry, (safe_zip).entry_bytes_remaining as la_int64_t);
    } else {
        (safe_zip).entry_bytes_remaining = 0 as i32 as uint64_t;
        archive_entry_set_size_safe(entry, 0 as i32 as la_int64_t);
    }
    /* If there's no body, force read_data() to return EOF immediately. */
    if (safe_zip).entry_bytes_remaining < 1 as i32 as u64 {
        (safe_zip).end_of_entry = 1 as i32 as u8
    }
    if (safe_zip_entry).mode & 0o170000 as i32 as mode_t == 0o120000 as i32 as mode_t {
        let mut symname: *mut u8 = 0 as *mut u8;
        let mut symsize: size_t = 0 as i32 as size_t;

        while (safe_zip).entry_bytes_remaining > 0 as i32 as u64 {
            let mut buff: *const () = 0 as *const ();
            let mut mem: *mut u8 = 0 as *mut u8;
            let mut size: size_t = 0;
            let mut offset: int64_t = 0;
            r = archive_read_format_7zip_read_data(a, &mut buff, &mut size, &mut offset);
            if r < -(20 as i32) {
                free_safe(symname as *mut ());
                return r;
            }
            mem = realloc_safe(
                symname as *mut (),
                symsize.wrapping_add(size).wrapping_add(1 as i32 as u64),
            ) as *mut u8;
            if mem.is_null() {
                free_safe(symname as *mut ());
                unsafe {
                    archive_set_error(
                        &mut (*a).archive as *mut archive,
                        12 as i32,
                        b"Can\'t allocate memory for Symname\x00" as *const u8,
                    )
                };
                return -(30 as i32);
            }
            symname = mem;
            memcpy_safe(
                unsafe { symname.offset(symsize as isize) as *mut () },
                buff,
                size,
            );
            symsize = (symsize as u64).wrapping_add(size) as size_t as size_t;
            safe_zip = unsafe { &mut *((*(*a).format).data as *mut _7zip) };
        }
        if symsize == 0 as i32 as u64 {
            /* If there is no symname, handle it as a regular
             * file. */
            (safe_zip_entry).mode &= !(0o170000 as i32 as mode_t);
            (safe_zip_entry).mode |= 0o100000 as i32 as mode_t;
            archive_entry_set_mode_safe(entry, (safe_zip_entry).mode);
        } else {
            unsafe { *symname.offset(symsize as isize) = '\u{0}' as i32 as u8 };
            archive_entry_copy_symlink_safe(entry, symname as *const u8);
        }
        free_safe(symname as *mut ());
        archive_entry_set_size_safe(entry, 0 as i32 as la_int64_t);
    }
    /* Set up a more descriptive format name. */
    unsafe {
        sprintf(
            (safe_zip).format_name.as_mut_ptr(),
            b"7-Zip\x00" as *const u8,
        )
    };
    (safe_a).archive.archive_format_name = (safe_zip).format_name.as_mut_ptr();
    return ret;
}
unsafe fn archive_read_format_7zip_read_data(
    mut a: *mut archive_read,
    mut buff: *mut *const (),
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) -> i32 {
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    let mut bytes: ssize_t = 0;
    let mut ret: i32 = 0 as i32;
    let safe_a = unsafe { &mut *a };
    zip = unsafe { (*(safe_a).format).data as *mut _7zip };
    let safe_zip = unsafe { &mut *zip };
    if safe_zip.has_encrypted_entries == -(1 as i32) {
        safe_zip.has_encrypted_entries = 0 as i32
    }
    if safe_zip.pack_stream_bytes_unconsumed != 0 {
        read_consume(a);
    }
    unsafe {
        *offset = (safe_zip).entry_offset;
        *size = 0 as i32 as size_t;
        *buff = 0 as *const ();
    }

    if safe_zip.end_of_entry != 0 {
        return 1 as i32;
    } // Don't try to read more than 16 MB at a time
    let max_read_size: uint64_t = (16 as i32 * 1024 as i32 * 1024 as i32) as uint64_t;
    let mut bytes_to_read: size_t = max_read_size;
    if bytes_to_read > safe_zip.entry_bytes_remaining {
        bytes_to_read = safe_zip.entry_bytes_remaining
    }
    bytes = read_stream(a, buff, bytes_to_read, 0 as i32 as size_t);
    if bytes < 0 as i32 as i64 {
        return bytes as i32;
    }
    if bytes == 0 as i32 as i64 {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84 as i32,
                b"Truncated 7-Zip file body\x00" as *const u8,
            )
        };
        return -(30 as i32);
    }
    (safe_zip).entry_bytes_remaining =
        (safe_zip.entry_bytes_remaining as u64).wrapping_sub(bytes as u64) as uint64_t as uint64_t;
    if safe_zip.entry_bytes_remaining == 0 as i32 as u64 {
        safe_zip.end_of_entry = 1 as i32 as u8
    }
    /* Update checksum */
    if unsafe { (*safe_zip.entry).flg & ((1 as i32) << 3 as i32) as u32 != 0 && bytes != 0 } {
        safe_zip.entry_crc32 = crc32_safe(
            safe_zip.entry_crc32,
            unsafe { *buff as *const Bytef },
            bytes as u32,
        )
    }
    /* If we hit the end, swallow any end-of-data marker. */
    if (safe_zip).end_of_entry != 0 {
        /* Check computed CRC against file contents. */
        if unsafe {
            (*safe_zip.entry).flg & ((1 as i32) << 3 as i32) as u32 != 0
                && *safe_zip
                    .si
                    .ss
                    .digests
                    .offset((*safe_zip.entry).ssIndex as isize) as u64
                    != safe_zip.entry_crc32
        } {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"7-Zip bad CRC: 0x%lx should be 0x%lx\x00" as *const u8,
                    safe_zip.entry_crc32,
                    *safe_zip
                        .si
                        .ss
                        .digests
                        .offset((*safe_zip.entry).ssIndex as isize) as u64,
                )
            };
            ret = -(20 as i32)
        }
    }
    unsafe {
        *size = bytes as size_t;
        *offset = (*zip).entry_offset;
    }
    (safe_zip).entry_offset += bytes;
    return ret;
}
unsafe fn archive_read_format_7zip_read_data_skip(mut a: *mut archive_read) -> i32 {
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    let mut bytes_skipped: int64_t = 0;
    zip = unsafe { (*(*a).format).data as *mut _7zip };
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    if safe_zip.pack_stream_bytes_unconsumed != 0 {
        read_consume(a);
    }
    /* If we've already read to end of data, we're done. */
    if safe_zip.end_of_entry != 0 {
        return 0 as i32;
    }
    /*
     * If the length is at the beginning, we can skip the
     * compressed data much more quickly.
     */
    bytes_skipped = skip_stream(a, safe_zip.entry_bytes_remaining);
    if bytes_skipped < 0 as i32 as i64 {
        return -(30 as i32);
    }
    safe_zip.entry_bytes_remaining = 0 as i32 as uint64_t;
    /* This entry is finished and done. */
    safe_zip.end_of_entry = 1 as i32 as u8;
    return 0 as i32;
}
unsafe fn archive_read_format_7zip_cleanup(mut a: *mut archive_read) -> i32 {
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    zip = unsafe { (*(*a).format).data as *mut _7zip };
    let safe_zip = unsafe { &mut *zip };
    free_StreamsInfo(&mut safe_zip.si);
    free_safe(safe_zip.entries as *mut ());
    free_safe(safe_zip.entry_names as *mut ());
    free_decompression(a, zip);
    free_safe(safe_zip.uncompressed_buffer as *mut ());
    free_safe(safe_zip.sub_stream_buff[0 as i32 as usize] as *mut ());
    free_safe(safe_zip.sub_stream_buff[1 as i32 as usize] as *mut ());
    free_safe(safe_zip.sub_stream_buff[2 as i32 as usize] as *mut ());
    free_safe(safe_zip.tmp_stream_buff as *mut ());
    free_safe(zip as *mut ());
    unsafe { (*(*a).format).data = 0 as *mut () };
    return 0 as i32;
}
unsafe fn read_consume(mut a: *mut archive_read) {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let safe_zip = unsafe { &mut *zip };
    if safe_zip.pack_stream_bytes_unconsumed != 0 {
        __archive_read_consume_safe(a, safe_zip.pack_stream_bytes_unconsumed as int64_t);
        safe_zip.stream_offset = (safe_zip.stream_offset as u64)
            .wrapping_add(safe_zip.pack_stream_bytes_unconsumed)
            as int64_t as int64_t;
        safe_zip.pack_stream_bytes_unconsumed = 0 as i32 as size_t
    };
}
/*
* Set an error code and choose an error message for liblzma.
*/
#[cfg(HAVE_LZMA_H)]
unsafe fn set_error(mut a: *mut archive_read, mut ret: i32) {
    let safe_a = unsafe { &mut *a };
    unsafe {
        match ret {
            1 => {}
            0 => {}
            5 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    12 as i32,
                    b"Lzma library error: Cannot allocate memory\x00" as *const u8,
                );
            }
            6 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    12 as i32,
                    b"Lzma library error: Out of memory\x00" as *const u8,
                );
            }
            7 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -(1 as i32),
                    b"Lzma library error: format not recognized\x00" as *const u8,
                );
            }
            8 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -(1 as i32),
                    b"Lzma library error: Invalid options\x00" as *const u8,
                );
            }
            9 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -(1 as i32),
                    b"Lzma library error: Corrupted input data\x00" as *const u8,
                );
            }
            10 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -(1 as i32),
                    b"Lzma library error:  No progress is possible\x00" as *const u8,
                );
            }
            _ => {
                /* Return an error. */
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -(1 as i32),
                    b"Lzma decompression failed:  Unknown error\x00" as *const u8,
                );
            }
        };
    }
}
unsafe fn decode_codec_id(mut codecId: *const u8, mut id_size: size_t) -> u64 {
    let mut i: u32 = 0;
    let mut id: u64 = 0 as i32 as u64;
    i = 0 as i32 as u32;
    while (i as u64) < id_size {
        id <<= 8 as i32;
        id = unsafe { id.wrapping_add(*codecId.offset(i as isize) as u64) };
        i = i.wrapping_add(1)
    }
    return id;
}
unsafe fn ppmd_read(mut p: *mut ()) -> Byte {
    let mut a: *mut archive_read = unsafe { (*(p as *mut IByteIn)).a };
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut b: Byte = 0;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    if safe_zip.ppstream.avail_in == 0 as i32 as i64 {
        unsafe {
            archive_set_error(
                &mut safe_a.archive as *mut archive,
                84 as i32,
                b"Truncated RAR file data\x00" as *const u8,
            )
        };
        safe_zip.ppstream.overconsumed = 1 as i32;
        return 0 as i32 as Byte;
    }
    let fresh0 = safe_zip.ppstream.next_in;
    safe_zip.ppstream.next_in = unsafe { safe_zip.ppstream.next_in.offset(1) };
    b = unsafe { *fresh0 };
    safe_zip.ppstream.avail_in -= 1;
    safe_zip.ppstream.total_in += 1;
    return b;
}
unsafe fn init_decompression(
    mut a: *mut archive_read,
    mut zip: *mut _7zip,
    mut coder1: *const _7z_coder,
    mut coder2: *const _7z_coder,
) -> i32 {
    let mut r: i32 = 0;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    let safe_coder1 = unsafe { &*coder1 };
    safe_zip.codec = (safe_coder1).codec;
    safe_zip.codec2 = -(1 as i32) as u64;
    let safe_coder2 = unsafe { &*coder2 };
    match safe_zip.codec {
        0 | 262658 | 262408 | 197633 => {
            if !coder2.is_null() {
                if safe_coder2.codec != 0x3030103 as i32 as u64
                    && safe_coder2.codec != 0x303011b as i32 as u64
                {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as i32),
                            b"Unsupported filter %lx for %lx\x00" as *const u8,
                            safe_coder2.codec,
                            safe_coder1.codec,
                        )
                    };
                    return -(25 as i32);
                }
                safe_zip.codec2 = safe_coder2.codec;
                safe_zip.bcj_state = 0 as i32 as uint32_t;
                if safe_coder2.codec == 0x3030103 as i32 as u64 {
                    x86_Init(zip);
                }
            }
        }
        _ => {}
    }
    match (safe_zip).codec {
        0 => {}

        196865 | 33 => {
            match () {
                #[cfg(HAVE_LZMA_H)]
                _ => {
                    {
                        /* Effectively disable the limiter. */
                        let mut delta_opt: lzma_options_delta = lzma_options_delta {
                            type_0: LZMA_DELTA_TYPE_BYTE,
                            dist: 0,
                            reserved_int1: 0,
                            reserved_int2: 0,
                            reserved_int3: 0,
                            reserved_int4: 0,
                            reserved_ptr1: 0 as *mut (),
                            reserved_ptr2: 0 as *mut (),
                        };
                        let mut filters: [lzma_filter; 4] = [lzma_filter {
                            id: 0,
                            options: 0 as *mut (),
                        }; 4];
                        let mut ff: *mut lzma_filter = 0 as *mut lzma_filter;
                        let mut fi: i32 = 0 as i32;
                        if (safe_zip).lzstream_valid != 0 {
                            lzma_end_safe(&mut (safe_zip).lzstream);
                            (safe_zip).lzstream_valid = 0 as i32
                        }

                        if !coder2.is_null() {
                            (safe_zip).codec2 = (safe_coder2).codec;
                            filters[fi as usize].options = 0 as *mut ();
                            match (safe_zip).codec2 {
                                50528515 => {
                                    if (safe_zip).codec == 0x21 as i32 as u64 {
                                        filters[fi as usize].id = 0x4 as u64;
                                        fi += 1
                                    } else {
                                        /* Use our filter. */
                                        x86_Init(zip);
                                    }
                                }
                                50528539 => {
                                    /* Use our filter. */
                                    (safe_zip).bcj_state = 0 as i32 as uint32_t
                                }
                                3 => {
                                    if (safe_coder2).propertiesSize != 1 as i32 as u64 {
                                        unsafe {
                                            archive_set_error(
                                                &mut (safe_a).archive as *mut archive,
                                                -(1 as i32),
                                                b"Invalid Delta parameter\x00" as *const u8
                                                    as *const u8,
                                            )
                                        };
                                        return -(25 as i32);
                                    }
                                    filters[fi as usize].id = 0x3 as u64;
                                    memset_safe(
                                        &mut delta_opt as *mut lzma_options_delta as *mut (),
                                        0 as i32,
                                        size_of::<lzma_options_delta>() as u64,
                                    );
                                    delta_opt.type_0 = LZMA_DELTA_TYPE_BYTE;
                                    delta_opt.dist = unsafe {
                                        (*(safe_coder2).properties.offset(0 as i32 as isize)
                                            as uint32_t)
                                            .wrapping_add(1 as i32 as u32)
                                    };
                                    filters[fi as usize].options =
                                        &mut delta_opt as *mut lzma_options_delta as *mut ();
                                    fi += 1
                                }
                                50528773 => {
                                    /* Following filters have not been tested yet. */
                                    filters[fi as usize].id = 0x5 as u64;
                                    fi += 1
                                }
                                50529281 => {
                                    filters[fi as usize].id = 0x6 as u64;
                                    fi += 1
                                }
                                50529537 => {
                                    filters[fi as usize].id = 0x7 as u64;
                                    fi += 1
                                }
                                50530049 => {
                                    filters[fi as usize].id = 0x8 as u64;
                                    fi += 1
                                }
                                50530309 => {
                                    filters[fi as usize].id = 0x9 as u64;
                                    fi += 1
                                }
                                _ => {
                                    unsafe {
                                        archive_set_error(
                                            &mut (safe_a).archive as *mut archive,
                                            -(1 as i32),
                                            b"Unexpected codec ID: %lX\x00" as *const u8
                                                as *const u8,
                                            (safe_zip).codec2,
                                        )
                                    };
                                    return -(25 as i32);
                                }
                            }
                        }
                        if (safe_zip).codec == 0x21 as i32 as u64 {
                            filters[fi as usize].id = 0x21 as u64
                        } else {
                            filters[fi as usize].id = 0x4000000000000001 as u64
                        }
                        filters[fi as usize].options = 0 as *mut ();
                        ff = unsafe {
                            &mut *filters.as_mut_ptr().offset(fi as isize) as *mut lzma_filter
                        };
                        r = lzma_properties_decode_safe(
                            unsafe { &mut *filters.as_mut_ptr().offset(fi as isize) },
                            0 as *const lzma_allocator,
                            (safe_coder1).properties,
                            (safe_coder1).propertiesSize,
                        ) as i32;
                        if r != LZMA_OK as i32 {
                            set_error(a, r);
                            return -(25 as i32);
                        }
                        fi += 1;
                        filters[fi as usize].id = 18446744073709551615 as u64;
                        filters[fi as usize].options = 0 as *mut ();
                        r = lzma_raw_decoder_safe(&mut (safe_zip).lzstream, filters.as_mut_ptr())
                            as i32;
                        unsafe { free((*ff).options) };
                        if r != LZMA_OK as i32 {
                            set_error(a, r);
                            return -(25 as i32);
                        }
                        (safe_zip).lzstream_valid = 1 as i32;
                        (safe_zip).lzstream.total_in = 0 as i32 as uint64_t;
                        (safe_zip).lzstream.total_out = 0 as i32 as uint64_t
                    }
                }

                #[cfg(not(HAVE_LZMA_H))]
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as i32),
                            b"LZMA codec is unsupported.\x00" as *const u8,
                        )
                    };
                    return -25;
                }
            }
        }

        262658 => match () {
            #[cfg(all(HAVE_BZLIB_H, BZ_CONFIG_ERROR))]
            _ => {
                if (safe_zip).bzstream_valid != 0 {
                    BZ2_bzDecompressEnd_safe(&mut (safe_zip).bzstream);
                    (safe_zip).bzstream_valid = 0 as i32
                }
                r = BZ2_bzDecompressInit_safe(&mut (safe_zip).bzstream, 0 as i32, 0 as i32);
                if r == -(3 as i32) {
                    r = BZ2_bzDecompressInit_safe(&mut (safe_zip).bzstream, 0 as i32, 1 as i32)
                }
                if r != 0 as i32 {
                    let mut err: i32 = -(1 as i32);
                    let mut detail: *const u8 = 0 as *const u8;
                    match r {
                        -2 => detail = b"invalid setup parameter\x00" as *const u8,
                        -3 => {
                            err = 12 as i32;
                            detail = b"out of memory\x00" as *const u8
                        }
                        -9 => detail = b"mis-compiled library\x00" as *const u8,
                        _ => {}
                    }
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            err,
                            b"Internal error initializing decompressor: %s\x00" as *const u8
                                as *const u8,
                            if !detail.is_null() {
                                detail
                            } else {
                                b"??\x00" as *const u8
                            },
                        )
                    };
                    (safe_zip).bzstream_valid = 0 as i32;
                    return -(25 as i32);
                }
                safe_zip.bzstream_valid = 1 as i32;
                safe_zip.bzstream.total_in_lo32 = 0 as i32 as u32;
                safe_zip.bzstream.total_in_hi32 = 0 as i32 as u32;
                safe_zip.bzstream.total_out_lo32 = 0 as i32 as u32;
                safe_zip.bzstream.total_out_hi32 = 0 as i32 as u32
            }

            #[cfg(not(all(HAVE_BZLIB_H, BZ_CONFIG_ERROR)))]
            _ => {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as i32),
                        b"BZ2 codec is unsupported\x00" as *const u8,
                    )
                };
                return -25;
            }
        },

        262408 => {
            match () {
                #[cfg(HAVE_ZLIB_H)]
                _ => {
                    {
                        if (safe_zip).stream_valid != 0 {
                            r = inflateReset_safe(&mut (safe_zip).stream)
                        } else {
                            r = inflateInit2__safe(
                                &mut (safe_zip).stream,
                                -(15 as i32),
                                b"1.2.11\x00" as *const u8,
                                size_of::<z_stream>() as u64 as i32,
                            )
                        }
                        /* Don't check for zlib header */
                        if r != 0 as i32 {
                            unsafe {
                                archive_set_error(
                                    &mut (safe_a).archive as *mut archive,
                                    -(1 as i32),
                                    b"Couldn\'t initialize zlib stream.\x00" as *const u8
                                        as *const u8,
                                )
                            };
                            return -(25 as i32);
                        }
                        (safe_zip).stream_valid = 1 as i32;
                        (safe_zip).stream.total_in = 0 as i32 as uLong;
                        (safe_zip).stream.total_out = 0 as i32 as uLong
                    }
                }

                #[cfg(not(HAVE_ZLIB_H))]
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as i32),
                            b"DEFLATE codec is unsupported\x00" as *const u8,
                        )
                    };
                    return -25;
                }
            }
        }

        197633 => {
            let mut order: u32 = 0;
            let mut msize: uint32_t = 0;
            if (safe_zip).ppmd7_valid != 0 {
                unsafe {
                    __archive_ppmd7_functions
                        .Ppmd7_Free
                        .expect("non-null function pointer")(
                        &mut (*zip).ppmd7_context
                    )
                };
                (safe_zip).ppmd7_valid = 0 as i32
            }
            if (safe_coder1).propertiesSize < 5 as i32 as u64 {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as i32),
                        b"Malformed PPMd parameter\x00" as *const u8,
                    )
                };
                return -(25 as i32);
            }
            order = unsafe { *(safe_coder1).properties.offset(0 as i32 as isize) as u32 };
            msize = archive_le32dec(unsafe {
                &mut *(safe_coder1).properties.offset(1 as i32 as isize) as *mut u8 as *const ()
            });
            if order < 2 as i32 as u32
                || order > 64 as i32 as u32
                || msize < ((1 as i32) << 11 as i32) as u32
                || msize > (0xffffffff as u32).wrapping_sub((12 as i32 * 3 as i32) as u32)
            {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as i32),
                        b"Malformed PPMd parameter\x00" as *const u8,
                    )
                };
                return -(25 as i32);
            }
            unsafe {
                __archive_ppmd7_functions
                    .Ppmd7_Construct
                    .expect("non-null function pointer")(&mut (*zip).ppmd7_context)
            };
            r = unsafe {
                __archive_ppmd7_functions
                    .Ppmd7_Alloc
                    .expect("non-null function pointer")(
                    &mut (safe_zip).ppmd7_context, msize
                )
            };
            if r == 0 as i32 {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        12 as i32,
                        b"Coludn\'t allocate memory for PPMd\x00" as *const u8,
                    )
                };
                return -(30 as i32);
            }
            unsafe {
                __archive_ppmd7_functions
                    .Ppmd7_Init
                    .expect("non-null function pointer")(
                    &mut (safe_zip).ppmd7_context, order
                )
            };
            unsafe {
                __archive_ppmd7_functions
                    .Ppmd7z_RangeDec_CreateVTable
                    .expect("non-null function pointer")(&mut (safe_zip).range_dec)
            };
            (safe_zip).ppmd7_valid = 1 as i32;
            (safe_zip).ppmd7_stat = 0 as i32;
            (safe_zip).ppstream.overconsumed = 0 as i32;
            (safe_zip).ppstream.total_in = 0 as i32 as int64_t;
            (safe_zip).ppstream.total_out = 0 as i32 as int64_t
        }
        50528515 | 50528539 | 50528773 | 50529281 | 50529537 | 50530049 | 50530309 | 3 => {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Unexpected codec ID: %lX\x00" as *const u8,
                    (safe_zip).codec,
                )
            };
            return -(25 as i32);
        }
        116457729 | 116458243 | 116459265 => {
            if !(safe_a).entry.is_null() {
                archive_entry_set_is_metadata_encrypted_safe((safe_a).entry, 1 as i32 as u8);
                archive_entry_set_is_data_encrypted_safe((safe_a).entry, 1 as i32 as u8);
                (safe_zip).has_encrypted_entries = 1 as i32
            }
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Crypto codec not supported yet (ID: 0x%lX)\x00" as *const u8,
                    (safe_zip).codec,
                )
            };
            return -(25 as i32);
        }
        _ => {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Unknown codec ID: %lX\x00" as *const u8,
                    (safe_zip).codec,
                )
            };
            return -(25 as i32);
        }
    }
    return 0 as i32;
}
unsafe fn decompress(
    mut a: *mut archive_read,
    mut zip: *mut _7zip,
    mut buff: *mut (),
    mut outbytes: *mut size_t,
    mut b: *const (),
    mut used: *mut size_t,
) -> i32 {
    let mut t_next_in: *const uint8_t = 0 as *const uint8_t;
    let mut t_next_out: *mut uint8_t = 0 as *mut uint8_t;
    let mut o_avail_in: size_t = 0;
    let mut o_avail_out: size_t = 0;
    let mut t_avail_in: size_t = 0;
    let mut t_avail_out: size_t = 0;
    let mut bcj2_next_out: *mut uint8_t = 0 as *mut uint8_t;
    let mut bcj2_avail_out: size_t = 0;
    let mut r: i32 = 0;
    let mut ret: i32 = 0 as i32;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    o_avail_in = unsafe { *used };
    t_avail_in = o_avail_in;
    o_avail_out = unsafe { *outbytes };
    t_avail_out = o_avail_out;
    t_next_in = b as *const uint8_t;
    t_next_out = buff as *mut uint8_t;
    if (safe_zip).codec != 0x21 as i32 as u64 && (safe_zip).codec2 == 0x3030103 as i32 as u64 {
        let mut i: i32 = 0;
        /* Do not copy out the BCJ remaining bytes when the output
         * buffer size is less than five bytes. */
        if o_avail_in != 0 as i32 as u64
            && t_avail_out < 5 as i32 as u64
            && (safe_zip).odd_bcj_size != 0
        {
            unsafe {
                *used = 0 as i32 as size_t;
                *outbytes = 0 as i32 as size_t;
            }
            return ret;
        }
        i = 0 as i32;
        while safe_zip.odd_bcj_size > 0 as i32 as u64 && t_avail_out != 0 {
            let fresh1 = t_next_out;
            t_next_out = unsafe { t_next_out.offset(1) };
            unsafe { *fresh1 = safe_zip.odd_bcj[i as usize] };
            t_avail_out = t_avail_out.wrapping_sub(1);
            (safe_zip).odd_bcj_size = (safe_zip).odd_bcj_size.wrapping_sub(1);
            i += 1
        }
        if o_avail_in == 0 as i32 as u64 || t_avail_out == 0 as i32 as u64 {
            unsafe {
                *used = o_avail_in.wrapping_sub(t_avail_in);
                *outbytes = o_avail_out.wrapping_sub(t_avail_out);
            }
            if o_avail_in == 0 as i32 as u64 {
                ret = 1 as i32
            }
            return ret;
        }
    }
    bcj2_next_out = t_next_out;
    bcj2_avail_out = t_avail_out;
    if (safe_zip).codec2 == 0x303011b as i32 as u64 {
        /*
         * Decord a remaining decompressed main stream for BCJ2.
         */
        if (safe_zip).tmp_stream_bytes_remaining != 0 {
            let mut bytes: ssize_t = 0;
            let mut remaining: size_t = (safe_zip).tmp_stream_bytes_remaining;
            bytes = Bcj2_Decode(zip, t_next_out, t_avail_out);
            if bytes < 0 as i32 as i64 {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as i32),
                        b"BCJ2 conversion Failed\x00" as *const u8,
                    )
                };
                return -(25 as i32);
            }
            (safe_zip).main_stream_bytes_remaining = ((safe_zip).main_stream_bytes_remaining as u64)
                .wrapping_sub(remaining.wrapping_sub((safe_zip).tmp_stream_bytes_remaining))
                as size_t as size_t;
            t_avail_out = (t_avail_out as u64).wrapping_sub(bytes as u64) as size_t as size_t;
            if o_avail_in == 0 as i32 as u64 || t_avail_out == 0 as i32 as u64 {
                unsafe {
                    *used = 0 as i32 as size_t;
                    *outbytes = o_avail_out.wrapping_sub(t_avail_out);
                }
                if o_avail_in == 0 as i32 as u64 && (safe_zip).tmp_stream_bytes_remaining != 0 {
                    ret = 1 as i32
                }
                return ret;
            }
            t_next_out = unsafe { t_next_out.offset(bytes as isize) };
            bcj2_next_out = t_next_out;
            bcj2_avail_out = t_avail_out
        }
        t_next_out = (safe_zip).tmp_stream_buff;
        t_avail_out = (safe_zip).tmp_stream_buff_size
    }
    match (safe_zip).codec {
        0 => {
            let mut bytes_0: size_t = if t_avail_in > t_avail_out {
                t_avail_out
            } else {
                t_avail_in
            };
            memcpy_safe(t_next_out as *mut (), t_next_in as *const (), bytes_0);
            t_avail_in = (t_avail_in as u64).wrapping_sub(bytes_0) as size_t as size_t;
            t_avail_out = (t_avail_out as u64).wrapping_sub(bytes_0) as size_t as size_t;
            if o_avail_in == 0 as i32 as u64 {
                ret = 1 as i32
            }
        }

        #[cfg(HAVE_LZMA_H)]
        196865 | 33 => {
            (safe_zip).lzstream.next_in = t_next_in;
            (safe_zip).lzstream.avail_in = t_avail_in;
            (safe_zip).lzstream.next_out = t_next_out;
            (safe_zip).lzstream.avail_out = t_avail_out;
            r = lzma_code_safe(&mut (safe_zip).lzstream, LZMA_RUN) as i32;
            match r {
                1 => {
                    /* Found end of stream. */
                    lzma_end_safe(&mut (safe_zip).lzstream);
                    (safe_zip).lzstream_valid = 0 as i32;
                    ret = 1 as i32
                }
                0 => {}
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as i32),
                            b"Decompression failed(%d)\x00" as *const u8,
                            r,
                        )
                    };
                    return -(25 as i32);
                }
            }
            t_avail_in = (safe_zip).lzstream.avail_in;
            t_avail_out = (safe_zip).lzstream.avail_out
        }

        #[cfg(all(HAVE_BZLIB_H, BZ_CONFIG_ERROR))]
        262658 => {
            (safe_zip).bzstream.next_in = t_next_in as uintptr_t as *mut u8;
            (safe_zip).bzstream.avail_in = t_avail_in as u32;
            (safe_zip).bzstream.next_out = t_next_out as uintptr_t as *mut u8;
            (safe_zip).bzstream.avail_out = t_avail_out as u32;
            r = BZ2_bzDecompress_safe(&mut (safe_zip).bzstream);
            match r {
                4 => {
                    /* Found end of stream. */
                    match BZ2_bzDecompressEnd_safe(&mut (safe_zip).bzstream) {
                        0 => {}
                        _ => {
                            unsafe {
                                archive_set_error(
                                    &mut (safe_a).archive as *mut archive,
                                    -(1 as i32),
                                    b"Failed to clean up decompressor\x00" as *const u8
                                        as *const u8,
                                )
                            };
                            return -(25 as i32);
                        }
                    }
                    (safe_zip).bzstream_valid = 0 as i32;
                    ret = 1 as i32
                }
                0 => {}
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as i32),
                            b"bzip decompression failed\x00" as *const u8,
                        )
                    };
                    return -(25 as i32);
                }
            }
            t_avail_in = (safe_zip).bzstream.avail_in as size_t;
            t_avail_out = (safe_zip).bzstream.avail_out as size_t
        }

        #[cfg(HAVE_ZLIB_H)]
        262408 => {
            safe_zip.stream.next_in = t_next_in as uintptr_t as *mut Bytef;
            safe_zip.stream.avail_in = t_avail_in as uInt;
            safe_zip.stream.next_out = t_next_out;
            safe_zip.stream.avail_out = t_avail_out as uInt;
            r = inflate_safe(&mut safe_zip.stream, 0 as i32);
            match r {
                1 => {
                    /* Found end of stream. */
                    ret = 1 as i32
                }
                0 => {}
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as i32),
                            b"File decompression failed (%d)\x00" as *const u8,
                            r,
                        )
                    };
                    return -(25 as i32);
                }
            }
            t_avail_in = (safe_zip).stream.avail_in as size_t;
            t_avail_out = (safe_zip).stream.avail_out as size_t
        }
        197633 => {
            let mut flush_bytes: uint64_t = 0;
            if (safe_zip).ppmd7_valid == 0
                || (safe_zip).ppmd7_stat < 0 as i32
                || t_avail_out <= 0 as i32 as u64
            {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as i32),
                        b"Decompression internal error\x00" as *const u8,
                    )
                };
                return -(25 as i32);
            }
            (safe_zip).ppstream.next_in = t_next_in;
            (safe_zip).ppstream.avail_in = t_avail_in as int64_t;
            (safe_zip).ppstream.next_out = t_next_out;
            (safe_zip).ppstream.avail_out = t_avail_out as int64_t;
            if (safe_zip).ppmd7_stat == 0 as i32 {
                (safe_zip).bytein.a = a;
                (safe_zip).bytein.Read = Some(ppmd_read as unsafe fn(_: *mut ()) -> Byte);
                (safe_zip).range_dec.Stream = &mut (safe_zip).bytein;
                r = unsafe {
                    __archive_ppmd7_functions
                        .Ppmd7z_RangeDec_Init
                        .expect("non-null function pointer")(
                        &mut (*zip).range_dec
                    )
                };
                if r == 0 as i32 {
                    (safe_zip).ppmd7_stat = -(1 as i32);
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as i32),
                            b"Failed to initialize PPMd range decoder\x00" as *const u8
                                as *const u8,
                        )
                    };
                    return -(25 as i32);
                }
                if (safe_zip).ppstream.overconsumed != 0 {
                    (safe_zip).ppmd7_stat = -(1 as i32);
                    return -(25 as i32);
                }
                (safe_zip).ppmd7_stat = 1 as i32
            }
            if t_avail_in == 0 as i32 as u64 {
                /* XXX Flush out remaining decoded data XXX */
                flush_bytes = (safe_zip).folder_outbytes_remaining
            } else {
                flush_bytes = 0 as i32 as uint64_t
            }
            loop {
                let mut sym: i32 = 0;
                sym = unsafe {
                    __archive_ppmd7_functions
                        .Ppmd7_DecodeSymbol
                        .expect("non-null function pointer")(
                        &mut (safe_zip).ppmd7_context,
                        &mut (safe_zip).range_dec.p,
                    )
                };
                if sym < 0 as i32 {
                    (safe_zip).ppmd7_stat = -(1 as i32);
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            84 as i32,
                            b"Failed to decode PPMd\x00" as *const u8,
                        )
                    };
                    return -(25 as i32);
                }
                if (safe_zip).ppstream.overconsumed != 0 {
                    (safe_zip).ppmd7_stat = -(1 as i32);
                    return -(25 as i32);
                }
                let fresh2 = (safe_zip).ppstream.next_out;
                (safe_zip).ppstream.next_out = unsafe { (safe_zip).ppstream.next_out.offset(1) };
                unsafe { *fresh2 = sym as u8 };
                (safe_zip).ppstream.avail_out -= 1;
                (safe_zip).ppstream.total_out += 1;
                if flush_bytes != 0 {
                    flush_bytes = flush_bytes.wrapping_sub(1)
                }
                if !((safe_zip).ppstream.avail_out != 0
                    && ((safe_zip).ppstream.avail_in != 0 || flush_bytes != 0))
                {
                    break;
                }
            }
            t_avail_in = (safe_zip).ppstream.avail_in as size_t;
            t_avail_out = (safe_zip).ppstream.avail_out as size_t
        }
        _ => {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Decompression internal error\x00" as *const u8,
                )
            };
            return -(25 as i32);
        }
    }
    if ret != 0 as i32 && ret != 1 as i32 {
        return ret;
    }
    unsafe {
        *used = o_avail_in.wrapping_sub(t_avail_in);
        *outbytes = o_avail_out.wrapping_sub(t_avail_out);
    }
    /*
     * Decord BCJ.
     */
    if (safe_zip).codec != 0x21 as i32 as u64 && (safe_zip).codec2 == 0x3030103 as i32 as u64 {
        let mut l: size_t = unsafe { x86_Convert(zip, buff as *mut uint8_t, *outbytes) };
        (safe_zip).odd_bcj_size = unsafe { (*outbytes).wrapping_sub(l) };
        if (safe_zip).odd_bcj_size > 0 as i32 as u64
            && (safe_zip).odd_bcj_size <= 4 as i32 as u64
            && o_avail_in != 0
            && ret != 1 as i32
        {
            unsafe {
                memcpy_safe(
                    safe_zip.odd_bcj.as_mut_ptr() as *mut (),
                    (buff as *mut u8).offset(l as isize) as *const (),
                    safe_zip.odd_bcj_size,
                );
                *outbytes = l
            }
        } else {
            safe_zip.odd_bcj_size = 0 as i32 as size_t
        }
    }
    /*
     * Decord BCJ2 with a decompressed main stream.
     */
    if safe_zip.codec2 == 0x303011b as i32 as u64 {
        let mut bytes_1: ssize_t = 0;
        safe_zip.tmp_stream_bytes_avail = safe_zip.tmp_stream_buff_size.wrapping_sub(t_avail_out);
        if safe_zip.tmp_stream_bytes_avail > safe_zip.main_stream_bytes_remaining {
            safe_zip.tmp_stream_bytes_avail = safe_zip.main_stream_bytes_remaining
        }
        safe_zip.tmp_stream_bytes_remaining = safe_zip.tmp_stream_bytes_avail;
        bytes_1 = Bcj2_Decode(zip, bcj2_next_out, bcj2_avail_out);
        if bytes_1 < 0 as i32 as i64 {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"BCJ2 conversion Failed\x00" as *const u8,
                )
            };
            return -(25 as i32);
        }
        (safe_zip).main_stream_bytes_remaining = ((safe_zip).main_stream_bytes_remaining as u64)
            .wrapping_sub(
                (safe_zip)
                    .tmp_stream_bytes_avail
                    .wrapping_sub((safe_zip).tmp_stream_bytes_remaining),
            ) as size_t as size_t;
        bcj2_avail_out = (bcj2_avail_out as u64).wrapping_sub(bytes_1 as u64) as size_t as size_t;
        unsafe { *outbytes = o_avail_out.wrapping_sub(bcj2_avail_out) }
    }
    return ret;
}
unsafe fn free_decompression(mut a: *mut archive_read, mut zip: *mut _7zip) -> i32 {
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    #[cfg_attr(not(HAVE_ZLIB_H), not(HAVE_BZLIB_H), BZ_CONFIG_ERROR)]
    let mut r: i32 = 0 as i32;

    #[cfg(HAVE_LZMA_H)]
    if (safe_zip).lzstream_valid != 0 {
        lzma_end_safe(&mut (safe_zip).lzstream);
    }

    #[cfg(all(HAVE_BZLIB_H, BZ_CONFIG_ERROR))]
    if (safe_zip).bzstream_valid != 0 {
        if BZ2_bzDecompressEnd_safe(&mut (safe_zip).bzstream) != 0 as i32 {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Failed to clean up bzip2 decompressor\x00" as *const u8,
                )
            };
            r = -(30 as i32)
        }
        (safe_zip).bzstream_valid = 0 as i32
    }

    #[cfg(HAVE_ZLIB_H)]
    if (safe_zip).stream_valid != 0 {
        if inflateEnd_safe(&mut (safe_zip).stream) != 0 as i32 {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Failed to clean up zlib decompressor\x00" as *const u8,
                )
            };
            r = -(30 as i32)
        }
        (safe_zip).stream_valid = 0 as i32
    }

    if (safe_zip).ppmd7_valid != 0 {
        unsafe {
            __archive_ppmd7_functions
                .Ppmd7_Free
                .expect("non-null function pointer")(&mut (*zip).ppmd7_context)
        };
        (safe_zip).ppmd7_valid = 0 as i32
    }
    return r;
}
unsafe fn parse_7zip_uint64(mut a: *mut archive_read, mut val: *mut uint64_t) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let mut avail: u8 = 0;
    let mut mask: u8 = 0;
    let mut i: i32 = 0;
    p = header_bytes(a, 1 as i32 as size_t);
    if p.is_null() {
        return -(1 as i32);
    }
    avail = unsafe { *p };
    mask = 0x80 as i32 as u8;
    unsafe { *val = 0 as i32 as uint64_t };
    i = 0 as i32;
    while i < 8 as i32 {
        if avail as i32 & mask as i32 != 0 {
            p = header_bytes(a, 1 as i32 as size_t);
            if p.is_null() {
                return -(1 as i32);
            }
            unsafe { *val |= (*p as uint64_t) << 8 as i32 * i };
            mask = (mask as i32 >> 1 as i32) as u8;
            i += 1
        } else {
            unsafe {
                *val = (*val as u64).wrapping_add(
                    ((avail as i32 & mask as i32 - 1 as i32) as uint64_t) << 8 as i32 * i,
                ) as uint64_t as uint64_t
            };
            break;
        }
    }
    return 0 as i32;
}
unsafe fn read_Bools(mut a: *mut archive_read, mut data: *mut u8, mut num: size_t) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let mut i: u32 = 0;
    let mut mask: u32 = 0 as i32 as u32;
    let mut avail: u32 = 0 as i32 as u32;
    i = 0 as i32 as u32;
    while (i as u64) < num {
        unsafe {
            if mask == 0 as i32 as u32 {
                p = header_bytes(a, 1 as i32 as size_t);
                if p.is_null() {
                    return -(1 as i32);
                }
                avail = *p as u32;
                mask = 0x80 as i32 as u32
            }
            *data.offset(i as isize) = if avail & mask != 0 {
                1 as i32
            } else {
                0 as i32
            } as u8;
            mask >>= 1 as i32;
            i = i.wrapping_add(1)
        }
    }
    return 0 as i32;
}
unsafe fn free_Digest(mut d: *mut _7z_digests) {
    let safe_d = unsafe { &mut *d };
    free_safe((safe_d).defineds as *mut ());
    free_safe((safe_d).digests as *mut ());
}
unsafe fn read_Digests(mut a: *mut archive_read, mut d: *mut _7z_digests, mut num: size_t) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let safe_d = unsafe { &mut *d };
    let mut i: u32 = 0;
    if num == 0 as i32 as u64 {
        return -(1 as i32);
    }
    memset_safe(d as *mut (), 0 as i32, size_of::<_7z_digests>() as u64);
    (safe_d).defineds = malloc_safe(num) as *mut u8;
    if (safe_d).defineds.is_null() {
        return -(1 as i32);
    }
    /*
     * Read Bools.
     */
    p = header_bytes(a, 1 as i32 as size_t);
    if p.is_null() {
        return -(1 as i32);
    }
    if unsafe { *p as i32 == 0 as i32 } {
        if read_Bools(a, (safe_d).defineds, num) < 0 as i32 {
            return -(1 as i32);
        }
    } else {
        /* All are defined */
        memset_safe((safe_d).defineds as *mut (), 1 as i32, num);
    }
    (safe_d).digests = calloc_safe(num, size_of::<uint32_t>() as u64) as *mut uint32_t;
    if (safe_d).digests.is_null() {
        return -(1 as i32);
    }
    i = 0 as i32 as u32;
    unsafe {
        while (i as u64) < num {
            if *(safe_d).defineds.offset(i as isize) != 0 {
                p = header_bytes(a, 4 as i32 as size_t);
                if p.is_null() {
                    return -(1 as i32);
                }
                *(safe_d).digests.offset(i as isize) = archive_le32dec(p as *const ())
            }
            i = i.wrapping_add(1)
        }
    }
    return 0 as i32;
}
unsafe fn free_PackInfo(mut pi: *mut _7z_pack_info) {
    let safe_pi = unsafe { &mut *pi };
    free_safe(safe_pi.sizes as *mut ());
    free_safe(safe_pi.positions as *mut ());
    free_Digest(&mut safe_pi.digest);
}
unsafe fn read_PackInfo(mut a: *mut archive_read, mut pi: *mut _7z_pack_info) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let mut i: u32 = 0;
    let safe_pi = unsafe { &mut *pi };
    memset_safe(pi as *mut (), 0 as i32, size_of::<_7z_pack_info>() as u64);
    /*
     * Read PackPos.
     */
    if parse_7zip_uint64(a, &mut safe_pi.pos) < 0 as i32 {
        return -(1 as i32);
    }
    /*
     * Read NumPackStreams.
     */
    if parse_7zip_uint64(a, &mut safe_pi.numPackStreams) < 0 as i32 {
        return -(1 as i32);
    }
    if safe_pi.numPackStreams == 0 as i32 as u64 {
        return -(1 as i32);
    }
    if (100000000 as u64) < safe_pi.numPackStreams as u64 {
        return -(1 as i32);
    }
    /*
     * Read PackSizes[num]
     */
    p = header_bytes(a, 1 as i32 as size_t);
    if p.is_null() {
        return -(1 as i32);
    }
    if unsafe { *p as i32 == 0 as i32 } {
        /* PackSizes[num] are not present. */
        return 0 as i32;
    }
    if unsafe { *p as i32 != 0x9 as i32 } {
        return -(1 as i32);
    }
    (safe_pi).sizes =
        calloc_safe((safe_pi).numPackStreams, size_of::<uint64_t>() as u64) as *mut uint64_t;
    (safe_pi).positions =
        calloc_safe((safe_pi).numPackStreams, size_of::<uint64_t>() as u64) as *mut uint64_t;
    if (safe_pi).sizes.is_null() || (safe_pi).positions.is_null() {
        return -(1 as i32);
    }
    i = 0 as i32 as u32;
    while (i as u64) < (safe_pi).numPackStreams {
        if parse_7zip_uint64(a, unsafe { &mut *(*pi).sizes.offset(i as isize) }) < 0 as i32 {
            return -(1 as i32);
        }
        i = i.wrapping_add(1)
    }
    /*
     * Read PackStreamDigests[num]
     */
    p = header_bytes(a, 1 as i32 as size_t);
    if p.is_null() {
        return -(1 as i32);
    }
    if unsafe { *p as i32 == 0 as i32 } {
        /* PackStreamDigests[num] are not present. */
        (safe_pi).digest.defineds =
            calloc_safe((safe_pi).numPackStreams, size_of::<u8>() as u64) as *mut u8;
        (safe_pi).digest.digests =
            calloc_safe((safe_pi).numPackStreams, size_of::<uint32_t>() as u64) as *mut uint32_t;
        if (safe_pi).digest.defineds.is_null() || (safe_pi).digest.digests.is_null() {
            return -(1 as i32);
        }
        return 0 as i32;
    }
    if unsafe { *p as i32 != 0xa as i32 } {
        return -(1 as i32);
    }
    if read_Digests(a, &mut (safe_pi).digest, (safe_pi).numPackStreams) < 0 as i32 {
        return -(1 as i32);
    }
    /*
     *  Must be marked by kEnd.
     */
    p = header_bytes(a, 1 as i32 as size_t);
    if p.is_null() {
        return -(1 as i32);
    }
    if unsafe { *p as i32 != 0 as i32 } {
        return -(1 as i32);
    }
    return 0 as i32;
}
unsafe fn free_Folder(mut f: *mut _7z_folder) {
    let mut i: u32 = 0;
    let safe_f = unsafe { &mut *f };
    if !(safe_f).coders.is_null() {
        i = 0 as i32 as u32;
        while (i as u64) < (safe_f).numCoders {
            free_safe(unsafe { (*(safe_f).coders.offset(i as isize)).properties as *mut () });
            i = i.wrapping_add(1)
        }
        free_safe((safe_f).coders as *mut ());
    }
    free_safe((safe_f).bindPairs as *mut ());
    free_safe((safe_f).packedStreams as *mut ());
    free_safe((safe_f).unPackSize as *mut ());
}

unsafe fn free_CodersInfo(mut ci: *mut _7z_coders_info) {
    let mut i: u32 = 0;
    let safe_ci = unsafe { &mut *ci };
    if !(safe_ci).folders.is_null() {
        i = 0 as i32 as u32;
        while (i as u64) < (safe_ci).numFolders {
            unsafe { free_Folder(&mut *(safe_ci).folders.offset(i as isize)) };
            i = i.wrapping_add(1)
        }
        free_safe((safe_ci).folders as *mut ());
    };
}
unsafe fn read_Folder(mut a: *mut archive_read, mut f: *mut _7z_folder) -> i32 {
    unsafe {
        let mut zip: *mut _7zip = (*(*a).format).data as *mut _7zip;
        let mut p: *const u8 = 0 as *const u8;
        let mut numInStreamsTotal: uint64_t = 0 as i32 as uint64_t;
        let mut numOutStreamsTotal: uint64_t = 0 as i32 as uint64_t;
        let mut i: u32 = 0;
        memset(f as *mut (), 0 as i32, size_of::<_7z_folder>() as u64);
        /*
         * Read NumCoders.
         */
        if parse_7zip_uint64(a, &mut (*f).numCoders) < 0 as i32 {
            return -(1 as i32);
        }
        if (*f).numCoders > 4 as i32 as u64 {
            /* Too many coders. */
            return -(1 as i32);
        }
        (*f).coders = calloc((*f).numCoders, size_of::<_7z_coder>() as u64) as *mut _7z_coder;
        if (*f).coders.is_null() {
            return -(1 as i32);
        }
        i = 0 as i32 as u32;
        while (i as u64) < (*f).numCoders {
            let mut codec_size: size_t = 0;
            let mut simple: i32 = 0;
            let mut attr: i32 = 0;
            p = header_bytes(a, 1 as i32 as size_t);
            if p.is_null() {
                return -(1 as i32);
            }
            /*
             * 0:3 CodecIdSize
             * 4:  0 - IsSimple
             *     1 - Is not Simple
             * 5:  0 - No Attributes
             *     1 - There are Attributes;
             * 7:  Must be zero.
             */
            codec_size = (*p as i32 & 0xf as i32) as size_t; /* Not supported. */
            simple = if *p as i32 & 0x10 as i32 != 0 {
                0 as i32
            } else {
                1 as i32
            };
            attr = *p as i32 & 0x20 as i32;
            if *p as i32 & 0x80 as i32 != 0 {
                return -(1 as i32);
            }
            /*
             * Read Decompression Method IDs.
             */
            p = header_bytes(a, codec_size);
            if p.is_null() {
                return -(1 as i32);
            }
            (*(*f).coders.offset(i as isize)).codec = decode_codec_id(p, codec_size);
            if simple != 0 {
                (*(*f).coders.offset(i as isize)).numInStreams = 1 as i32 as uint64_t;
                (*(*f).coders.offset(i as isize)).numOutStreams = 1 as i32 as uint64_t
            } else {
                if parse_7zip_uint64(a, &mut (*(*f).coders.offset(i as isize)).numInStreams)
                    < 0 as i32
                {
                    return -(1 as i32);
                }
                if (100000000 as u64) < (*(*f).coders.offset(i as isize)).numInStreams as u64 {
                    return -(1 as i32);
                }
                if parse_7zip_uint64(a, &mut (*(*f).coders.offset(i as isize)).numOutStreams)
                    < 0 as i32
                {
                    return -(1 as i32);
                }
                if (100000000 as u64) < (*(*f).coders.offset(i as isize)).numOutStreams as u64 {
                    return -(1 as i32);
                }
            }
            if attr != 0 {
                if parse_7zip_uint64(a, &mut (*(*f).coders.offset(i as isize)).propertiesSize)
                    < 0 as i32
                {
                    return -(1 as i32);
                }
                p = header_bytes(a, (*(*f).coders.offset(i as isize)).propertiesSize);
                if p.is_null() {
                    return -(1 as i32);
                }
                let ref mut fresh3 = (*(*f).coders.offset(i as isize)).properties;
                *fresh3 = malloc((*(*f).coders.offset(i as isize)).propertiesSize) as *mut u8;
                if (*(*f).coders.offset(i as isize)).properties.is_null() {
                    return -(1 as i32);
                }
                memcpy(
                    (*(*f).coders.offset(i as isize)).properties as *mut (),
                    p as *const (),
                    (*(*f).coders.offset(i as isize)).propertiesSize,
                );
            }
            numInStreamsTotal = (numInStreamsTotal as u64)
                .wrapping_add((*(*f).coders.offset(i as isize)).numInStreams)
                as uint64_t as uint64_t;
            numOutStreamsTotal = (numOutStreamsTotal as u64)
                .wrapping_add((*(*f).coders.offset(i as isize)).numOutStreams)
                as uint64_t as uint64_t;
            i = i.wrapping_add(1)
        }
        if numOutStreamsTotal == 0 as i32 as u64
            || numInStreamsTotal < numOutStreamsTotal.wrapping_sub(1 as i32 as u64)
        {
            return -(1 as i32);
        }
        (*f).numBindPairs = numOutStreamsTotal.wrapping_sub(1 as i32 as u64);
        if (*zip).header_bytes_remaining < (*f).numBindPairs {
            return -(1 as i32);
        }
        if (*f).numBindPairs > 0 as i32 as u64 {
            (*f).bindPairs = calloc((*f).numBindPairs, size_of::<obj1>() as u64) as *mut obj1;
            if (*f).bindPairs.is_null() {
                return -(1 as i32);
            }
        } else {
            (*f).bindPairs = 0 as *mut obj1
        }
        i = 0 as i32 as u32;
        while (i as u64) < (*f).numBindPairs {
            if parse_7zip_uint64(a, &mut (*(*f).bindPairs.offset(i as isize)).inIndex) < 0 as i32 {
                return -(1 as i32);
            }
            if (100000000 as u64) < (*(*f).bindPairs.offset(i as isize)).inIndex as u64 {
                return -(1 as i32);
            }
            if parse_7zip_uint64(a, &mut (*(*f).bindPairs.offset(i as isize)).outIndex) < 0 as i32 {
                return -(1 as i32);
            }
            if (100000000 as u64) < (*(*f).bindPairs.offset(i as isize)).outIndex as u64 {
                return -(1 as i32);
            }
            i = i.wrapping_add(1)
        }
        (*f).numPackedStreams = numInStreamsTotal.wrapping_sub((*f).numBindPairs);
        (*f).packedStreams =
            calloc((*f).numPackedStreams, size_of::<uint64_t>() as u64) as *mut uint64_t;
        if (*f).packedStreams.is_null() {
            return -(1 as i32);
        }
        if (*f).numPackedStreams == 1 as i32 as u64 {
            i = 0 as i32 as u32;
            while (i as u64) < numInStreamsTotal {
                let mut j: u32 = 0;
                j = 0 as i32 as u32;
                while (j as u64) < (*f).numBindPairs {
                    if (*(*f).bindPairs.offset(j as isize)).inIndex == i as u64 {
                        break;
                    }
                    j = j.wrapping_add(1)
                }
                if j as u64 == (*f).numBindPairs {
                    break;
                }
                i = i.wrapping_add(1)
            }
            if i as u64 == numInStreamsTotal {
                return -(1 as i32);
            }
            *(*f).packedStreams.offset(0 as i32 as isize) = i as uint64_t
        } else {
            i = 0 as i32 as u32;
            while (i as u64) < (*f).numPackedStreams {
                if parse_7zip_uint64(a, &mut *(*f).packedStreams.offset(i as isize)) < 0 as i32 {
                    return -(1 as i32);
                }
                if (100000000 as u64) < *(*f).packedStreams.offset(i as isize) as u64 {
                    return -(1 as i32);
                }
                i = i.wrapping_add(1)
            }
        }
        (*f).numInStreams = numInStreamsTotal;
        (*f).numOutStreams = numOutStreamsTotal;
        return 0 as i32;
    }
}

unsafe fn read_CodersInfo(mut a: *mut archive_read, mut ci: *mut _7z_coders_info) -> i32 {
    let mut current_block: u64;
    let mut p: *const u8 = 0 as *const u8;
    let mut digest: _7z_digests = _7z_digests {
        defineds: 0 as *mut u8,
        digests: 0 as *mut uint32_t,
    };
    let mut i: u32 = 0;
    memset_safe(ci as *mut (), 0 as i32, size_of::<_7z_coders_info>() as u64);
    memset_safe(
        &mut digest as *mut _7z_digests as *mut (),
        0 as i32,
        size_of::<_7z_digests>() as u64,
    );
    let safe_a = unsafe { &mut *a };
    let safe_ci = unsafe { &mut *ci };

    p = header_bytes(a, 1 as i32 as size_t);
    if !p.is_null() {
        if unsafe { !(*p as i32 != 0xb as i32) } {
            /*
             * Read NumFolders.
             */
            if !(parse_7zip_uint64(a, &mut (safe_ci).numFolders) < 0 as i32) {
                if (100000000 as u64) < (safe_ci).numFolders as u64 {
                    return -(1 as i32);
                }
                /*
                 * Read External.
                 */
                p = header_bytes(a, 1 as i32 as size_t);
                if !p.is_null() {
                    match unsafe { *p as i32 } {
                        0 => {
                            (safe_ci).folders =
                                calloc_safe((safe_ci).numFolders, size_of::<_7z_folder>() as u64)
                                    as *mut _7z_folder;
                            if (safe_ci).folders.is_null() {
                                return -(1 as i32);
                            }
                            i = 0 as i32 as u32;
                            loop {
                                if !((i as u64) < (safe_ci).numFolders) {
                                    current_block = 4068382217303356765;
                                    break;
                                }
                                if unsafe {
                                    read_Folder(a, &mut *(safe_ci).folders.offset(i as isize))
                                        < 0 as i32
                                } {
                                    current_block = 14585062455194940643;
                                    break;
                                }
                                i = i.wrapping_add(1)
                            }
                        }
                        1 => {
                            if parse_7zip_uint64(a, &mut (safe_ci).dataStreamIndex) < 0 as i32 {
                                return -(1 as i32);
                            }
                            if (100000000 as u64) < (safe_ci).dataStreamIndex as u64 {
                                return -(1 as i32);
                            }
                            if (safe_ci).numFolders > 0 as i32 as u64 {
                                unsafe {
                                    archive_set_error(
                                        &mut (safe_a).archive as *mut archive,
                                        -(1 as i32),
                                        b"Malformed 7-Zip archive\x00" as *const u8,
                                    )
                                };
                                current_block = 14585062455194940643;
                            } else {
                                current_block = 4068382217303356765;
                            }
                        }
                        _ => {
                            unsafe {
                                archive_set_error(
                                    &mut (*a).archive as *mut archive,
                                    -(1 as i32),
                                    b"Malformed 7-Zip archive\x00" as *const u8,
                                )
                            };
                            current_block = 14585062455194940643;
                        }
                    }
                    match current_block {
                        14585062455194940643 => {}
                        _ => {
                            p = header_bytes(a, 1 as i32 as size_t);
                            if !p.is_null() {
                                if unsafe { !(*p as i32 != 0xc as i32) } {
                                    i = 0 as i32 as u32;
                                    's_148: loop {
                                        if !((i as u64) < (safe_ci).numFolders) {
                                            current_block = 7746103178988627676;
                                            break;
                                        }
                                        let mut folder: *mut _7z_folder = unsafe {
                                            &mut *(safe_ci).folders.offset(i as isize)
                                                as *mut _7z_folder
                                        };
                                        let safe_folder = unsafe { &mut *folder };
                                        let mut j: u32 = 0;
                                        (safe_folder).unPackSize = calloc_safe(
                                            (safe_folder).numOutStreams,
                                            size_of::<uint64_t>() as u64,
                                        )
                                            as *mut uint64_t;
                                        if (safe_folder).unPackSize.is_null() {
                                            current_block = 14585062455194940643;
                                            break;
                                        }
                                        j = 0 as i32 as u32;
                                        while (j as u64) < (safe_folder).numOutStreams {
                                            if unsafe {
                                                parse_7zip_uint64(
                                                    a,
                                                    &mut *(safe_folder)
                                                        .unPackSize
                                                        .offset(j as isize),
                                                ) < 0 as i32
                                            } {
                                                current_block = 14585062455194940643;
                                                break 's_148;
                                            }
                                            j = j.wrapping_add(1)
                                        }
                                        i = i.wrapping_add(1)
                                    }
                                    match current_block {
                                        14585062455194940643 => {}
                                        _ =>
                                        /*
                                         * Read CRCs.
                                         */
                                        {
                                            p = header_bytes(a, 1 as i32 as size_t);
                                            if !p.is_null() {
                                                if unsafe { *p as i32 == 0 as i32 } {
                                                    return 0 as i32;
                                                }
                                                if unsafe { !(*p as i32 != 0xa as i32) } {
                                                    if !(read_Digests(
                                                        a,
                                                        &mut digest,
                                                        (safe_ci).numFolders,
                                                    ) < 0 as i32)
                                                    {
                                                        i = 0 as i32 as u32;
                                                        while (i as u64) < (safe_ci).numFolders {
                                                            unsafe {
                                                                (*(*ci)
                                                                    .folders
                                                                    .offset(i as isize))
                                                                .digest_defined = *digest
                                                                    .defineds
                                                                    .offset(i as isize);
                                                                (*(*ci)
                                                                    .folders
                                                                    .offset(i as isize))
                                                                .digest = *digest
                                                                    .digests
                                                                    .offset(i as isize);
                                                                i = i.wrapping_add(1)
                                                            }
                                                        }
                                                        /*
                                                         *  Must be kEnd.
                                                         */
                                                        p = header_bytes(a, 1 as i32 as size_t);
                                                        if !p.is_null() {
                                                            if unsafe { !(*p as i32 != 0 as i32) } {
                                                                free_Digest(&mut digest);
                                                                return 0 as i32;
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
            }
        }
    }
    free_Digest(&mut digest);
    return -(1 as i32);
}
unsafe fn folder_uncompressed_size(mut f: *mut _7z_folder) -> uint64_t {
    let safe_f = unsafe { &mut *f };
    let mut n: i32 = safe_f.numOutStreams as i32;
    let mut pairs: u32 = safe_f.numBindPairs as u32;
    loop {
        n -= 1;
        if !(n >= 0 as i32) {
            break;
        }
        let mut i: u32 = 0;
        i = 0 as i32 as u32;
        while i < pairs {
            if unsafe { (*safe_f.bindPairs.offset(i as isize)).outIndex == n as uint64_t } {
                break;
            }
            i = i.wrapping_add(1)
        }
        if i >= pairs {
            return unsafe { *(safe_f).unPackSize.offset(n as isize) };
        }
    }
    return 0 as i32 as uint64_t;
}
unsafe fn free_SubStreamsInfo(mut ss: *mut _7z_substream_info) {
    let safe_ss = unsafe { &mut *ss };
    free_safe(safe_ss.unpackSizes as *mut ());
    free_safe(safe_ss.digestsDefined as *mut ());
    free_safe(safe_ss.digests as *mut ());
}
unsafe fn read_SubStreamsInfo(
    mut a: *mut archive_read,
    mut ss: *mut _7z_substream_info,
    mut f: *mut _7z_folder,
    mut numFolders: size_t,
) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let mut usizes: *mut uint64_t = 0 as *mut uint64_t;
    let mut unpack_streams: size_t = 0;
    let mut type_0: i32 = 0;
    let mut i: u32 = 0;
    let mut numDigests: uint32_t = 0;
    memset_safe(
        ss as *mut (),
        0 as i32,
        size_of::<_7z_substream_info>() as u64,
    );
    let safe_f = unsafe { &mut *f };
    let safe_ss = unsafe { &mut *ss };
    i = 0 as i32 as u32;
    while (i as u64) < numFolders {
        unsafe { (*f.offset(i as isize)).numUnpackStreams = 1 as i32 as uint64_t };
        i = i.wrapping_add(1)
    }
    p = header_bytes(a, 1 as i32 as size_t);
    if p.is_null() {
        return -(1 as i32);
    }
    type_0 = unsafe { *p as i32 };
    if type_0 == 0xd as i32 {
        unpack_streams = 0 as i32 as size_t;
        i = 0 as i32 as u32;
        while (i as u64) < numFolders {
            if unsafe {
                parse_7zip_uint64(a, &mut (*f.offset(i as isize)).numUnpackStreams) < 0 as i32
            } {
                return -(1 as i32);
            }
            if unsafe { (100000000 as u64) < (*f.offset(i as isize)).numUnpackStreams as u64 } {
                return -(1 as i32);
            }
            if unpack_streams as u64
                > (18446744073709551615 as u64 as u64).wrapping_sub(100000000 as u64)
            {
                return -(1 as i32);
            }
            unpack_streams = unsafe {
                (unpack_streams as u64).wrapping_add((*f.offset(i as isize)).numUnpackStreams)
                    as size_t as size_t
            };
            i = i.wrapping_add(1)
        }
        p = header_bytes(a, 1 as i32 as size_t);
        if p.is_null() {
            return -(1 as i32);
        }
        type_0 = unsafe { *p as i32 }
    } else {
        unpack_streams = numFolders
    }
    (safe_ss).unpack_streams = unpack_streams;
    if unpack_streams != 0 {
        (safe_ss).unpackSizes =
            calloc_safe(unpack_streams, size_of::<uint64_t>() as u64) as *mut uint64_t;
        (safe_ss).digestsDefined = calloc_safe(unpack_streams, size_of::<u8>() as u64) as *mut u8;
        (safe_ss).digests =
            calloc_safe(unpack_streams, size_of::<uint32_t>() as u64) as *mut uint32_t;
        if (safe_ss).unpackSizes.is_null()
            || (safe_ss).digestsDefined.is_null()
            || (safe_ss).digests.is_null()
        {
            return -(1 as i32);
        }
    }
    usizes = (safe_ss).unpackSizes;
    i = 0 as i32 as u32;
    while (i as u64) < numFolders {
        let mut pack: u32 = 0;
        let mut sum: uint64_t = 0;
        if unsafe { !((*f.offset(i as isize)).numUnpackStreams == 0 as i32 as u64) } {
            sum = 0 as i32 as uint64_t;
            if type_0 == 0x9 as i32 {
                pack = 1 as i32 as u32;
                while unsafe { (pack as u64) < (*f.offset(i as isize)).numUnpackStreams } {
                    if parse_7zip_uint64(a, usizes) < 0 as i32 {
                        return -(1 as i32);
                    }
                    let fresh4 = usizes;
                    usizes = unsafe { usizes.offset(1) };
                    sum = unsafe { (sum as u64).wrapping_add(*fresh4) as uint64_t as uint64_t };
                    pack = pack.wrapping_add(1)
                }
            }
            let fresh5 = usizes;
            usizes = unsafe { usizes.offset(1) };
            unsafe {
                *fresh5 = folder_uncompressed_size(&mut *f.offset(i as isize)).wrapping_sub(sum)
            }
        }
        i = i.wrapping_add(1)
    }
    if type_0 == 0x9 as i32 {
        p = header_bytes(a, 1 as i32 as size_t);
        if p.is_null() {
            return -(1 as i32);
        }
        type_0 = unsafe { *p as i32 }
    }
    i = 0 as i32 as u32;
    while (i as u64) < unpack_streams {
        unsafe { *(safe_ss).digestsDefined.offset(i as isize) = 0 as i32 as u8 };
        unsafe { *(safe_ss).digests.offset(i as isize) = 0 as i32 as uint32_t };
        i = i.wrapping_add(1)
    }
    numDigests = 0 as i32 as uint32_t;
    i = 0 as i32 as u32;
    while (i as u64) < numFolders {
        if unsafe {
            (*f.offset(i as isize)).numUnpackStreams != 1 as i32 as u64
                || (*f.offset(i as isize)).digest_defined == 0
        } {
            numDigests = unsafe {
                (numDigests as u32)
                    .wrapping_add((*f.offset(i as isize)).numUnpackStreams as uint32_t)
                    as uint32_t as uint32_t
            }
        }
        i = i.wrapping_add(1)
    }
    if type_0 == 0xa as i32 {
        let mut tmpDigests: _7z_digests = _7z_digests {
            defineds: 0 as *mut u8,
            digests: 0 as *mut uint32_t,
        };
        let mut digestsDefined: *mut u8 = (safe_ss).digestsDefined;
        let mut digests: *mut uint32_t = (safe_ss).digests;
        let mut di: i32 = 0 as i32;
        memset_safe(
            &mut tmpDigests as *mut _7z_digests as *mut (),
            0 as i32,
            size_of::<_7z_digests>() as u64,
        );
        if read_Digests(a, &mut tmpDigests, numDigests as size_t) < 0 as i32 {
            free_Digest(&mut tmpDigests);
            return -(1 as i32);
        }
        i = 0 as i32 as u32;
        while (i as u64) < numFolders {
            if unsafe {
                (*f.offset(i as isize)).numUnpackStreams == 1 as i32 as u64
                    && (*f.offset(i as isize)).digest_defined as i32 != 0
            } {
                let fresh6 = digestsDefined;
                digestsDefined = unsafe { digestsDefined.offset(1) };
                unsafe { *fresh6 = 1 as i32 as u8 };
                let fresh7 = digests;
                digests = unsafe { digests.offset(1) };
                unsafe { *fresh7 = (*f.offset(i as isize)).digest }
            } else {
                let mut j: u32 = 0;
                j = 0 as i32 as u32;
                unsafe {
                    while (j as u64) < (*f.offset(i as isize)).numUnpackStreams {
                        let fresh8 = digestsDefined;
                        digestsDefined = digestsDefined.offset(1);
                        *fresh8 = *tmpDigests.defineds.offset(di as isize);
                        let fresh9 = digests;
                        digests = digests.offset(1);
                        *fresh9 = *tmpDigests.digests.offset(di as isize);
                        j = j.wrapping_add(1);
                        di += 1
                    }
                }
            }
            i = i.wrapping_add(1)
        }
        free_Digest(&mut tmpDigests);
        p = header_bytes(a, 1 as i32 as size_t);
        if p.is_null() {
            return -(1 as i32);
        }
        type_0 = unsafe { *p as i32 }
    }
    /*
     *  Must be kEnd.
     */
    if type_0 != 0 as i32 {
        return -(1 as i32);
    }
    return 0 as i32;
}
unsafe fn free_StreamsInfo(mut si: *mut _7z_stream_info) {
    let safe_si = unsafe { &mut *si };
    free_PackInfo(&mut safe_si.pi);
    free_CodersInfo(&mut safe_si.ci);
    free_SubStreamsInfo(&mut safe_si.ss);
}
unsafe fn read_StreamsInfo(mut a: *mut archive_read, mut si: *mut _7z_stream_info) -> i32 {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut p: *const u8 = 0 as *const u8;
    let mut i: u32 = 0;
    memset_safe(si as *mut (), 0 as i32, size_of::<_7z_stream_info>() as u64);
    let safe_si = unsafe { &mut *si };
    p = header_bytes(a, 1 as i32 as size_t);
    if p.is_null() {
        return -(1 as i32);
    }
    if unsafe { *p as i32 == 0x6 as i32 } {
        let mut packPos: uint64_t = 0;
        if read_PackInfo(a, &mut (safe_si).pi) < 0 as i32 {
            return -(1 as i32);
        }
        if (safe_si).pi.positions.is_null() || (safe_si).pi.sizes.is_null() {
            return -(1 as i32);
        }
        /*
         * Calculate packed stream positions.
         */
        packPos = (safe_si).pi.pos;
        i = 0 as i32 as u32;
        while (i as u64) < (safe_si).pi.numPackStreams {
            unsafe {
                *(safe_si).pi.positions.offset(i as isize) = packPos;
                packPos = (packPos as u64).wrapping_add(*(*si).pi.sizes.offset(i as isize))
                    as uint64_t as uint64_t;
                if packPos > (*zip).header_offset {
                    return -(1 as i32);
                }
                i = i.wrapping_add(1)
            }
        }
        p = header_bytes(a, 1 as i32 as size_t);
        if p.is_null() {
            return -(1 as i32);
        }
    }
    if unsafe { *p as i32 == 0x7 as i32 } {
        let mut packIndex: uint32_t = 0;
        let mut f: *mut _7z_folder = 0 as *mut _7z_folder;
        if read_CodersInfo(a, &mut (safe_si).ci) < 0 as i32 {
            return -(1 as i32);
        }
        /*
         * Calculate packed stream indexes.
         */
        packIndex = 0 as i32 as uint32_t;
        f = (safe_si).ci.folders;
        i = 0 as i32 as u32;
        while (i as u64) < (safe_si).ci.numFolders {
            unsafe {
                (*f.offset(i as isize)).packIndex = packIndex;
                packIndex = (packIndex as u32)
                    .wrapping_add((*f.offset(i as isize)).numPackedStreams as uint32_t)
                    as uint32_t as uint32_t;
                if packIndex as u64 > (*si).pi.numPackStreams {
                    return -(1 as i32);
                }
                i = i.wrapping_add(1)
            }
        }
        p = header_bytes(a, 1 as i32 as size_t);
        if p.is_null() {
            return -(1 as i32);
        }
    }
    if unsafe { *p as i32 == 0x8 as i32 } {
        if read_SubStreamsInfo(
            a,
            &mut (safe_si).ss,
            (safe_si).ci.folders,
            (safe_si).ci.numFolders,
        ) < 0 as i32
        {
            return -(1 as i32);
        }
        p = header_bytes(a, 1 as i32 as size_t);
        if p.is_null() {
            return -(1 as i32);
        }
    }
    /*
     *  Must be kEnd.
     */
    if unsafe { *p as i32 != 0 as i32 } {
        return -(1 as i32);
    }
    return 0 as i32;
}
unsafe fn free_Header(mut h: *mut _7z_header_info) {
    let safe_h = unsafe { &mut *h };
    free_safe((safe_h).emptyStreamBools as *mut ());
    free_safe((safe_h).emptyFileBools as *mut ());
    free_safe((safe_h).antiBools as *mut ());
    free_safe((safe_h).attrBools as *mut ());
}
unsafe fn read_Header(
    mut a: *mut archive_read,
    mut h: *mut _7z_header_info,
    mut check_header_id: i32,
) -> i32 {
    unsafe {
        let mut zip: *mut _7zip = (*(*a).format).data as *mut _7zip;
        let mut p: *const u8 = 0 as *const u8;
        let mut folders: *mut _7z_folder = 0 as *mut _7z_folder;
        let mut si: *mut _7z_stream_info = &mut (*zip).si;
        let mut entries: *mut _7zip_entry = 0 as *mut _7zip_entry;
        let mut folderIndex: uint32_t = 0;
        let mut indexInFolder: uint32_t = 0;
        let mut i: u32 = 0;
        let mut eindex: i32 = 0;
        let mut empty_streams: i32 = 0;
        let mut sindex: i32 = 0;

        if check_header_id != 0 {
            /*
             * Read Header.
             */
            p = header_bytes(a, 1 as i32 as size_t);
            if p.is_null() {
                return -(1 as i32);
            }
            if *p as i32 != 0x1 as i32 {
                return -(1 as i32);
            }
        }
        /*
         * Read ArchiveProperties.
         */
        p = header_bytes(a, 1 as i32 as size_t);
        if p.is_null() {
            return -(1 as i32);
        }
        if *p as i32 == 0x2 as i32 {
            loop {
                let mut size: uint64_t = 0;
                p = header_bytes(a, 1 as i32 as size_t);
                if p.is_null() {
                    return -(1 as i32);
                }
                if *p as i32 == 0 as i32 {
                    break;
                }
                if parse_7zip_uint64(a, &mut size) < 0 as i32 {
                    return -(1 as i32);
                }
            }
            p = header_bytes(a, 1 as i32 as size_t);
            if p.is_null() {
                return -(1 as i32);
            }
        }
        /*
         * Read MainStreamsInfo.
         */
        if *p as i32 == 0x4 as i32 {
            if read_StreamsInfo(a, &mut (*zip).si) < 0 as i32 {
                return -(1 as i32);
            }
            p = header_bytes(a, 1 as i32 as size_t);
            if p.is_null() {
                return -(1 as i32);
            }
        }
        if *p as i32 == 0 as i32 {
            return 0 as i32;
        }
        /*
         * Read FilesInfo.
         */
        if *p as i32 != 0x5 as i32 {
            return -(1 as i32);
        }
        if parse_7zip_uint64(a, &mut (*zip).numFiles) < 0 as i32 {
            return -(1 as i32);
        }
        if (100000000 as u64) < (*zip).numFiles as u64 {
            return -(1 as i32);
        }
        (*zip).entries =
            calloc((*zip).numFiles, size_of::<_7zip_entry>() as u64) as *mut _7zip_entry;
        if (*zip).entries.is_null() {
            return -(1 as i32);
        }
        entries = (*zip).entries;
        empty_streams = 0 as i32;
        loop {
            let mut type_0: i32 = 0;
            let mut size_0: uint64_t = 0;
            let mut ll: size_t = 0;
            p = header_bytes(a, 1 as i32 as size_t);
            if p.is_null() {
                return -(1 as i32);
            }
            type_0 = *p as i32;
            if type_0 == 0 as i32 {
                break;
            }
            if parse_7zip_uint64(a, &mut size_0) < 0 as i32 {
                return -(1 as i32);
            }
            if (*zip).header_bytes_remaining < size_0 {
                return -(1 as i32);
            }
            ll = size_0;
            let mut current_block_137: u64;
            match type_0 {
                14 => {
                    if !(*h).emptyStreamBools.is_null() {
                        return -(1 as i32);
                    }
                    (*h).emptyStreamBools =
                        calloc((*zip).numFiles, size_of::<u8>() as u64) as *mut u8;
                    if (*h).emptyStreamBools.is_null() {
                        return -(1 as i32);
                    }
                    if read_Bools(a, (*h).emptyStreamBools, (*zip).numFiles) < 0 as i32 {
                        return -(1 as i32);
                    }
                    empty_streams = 0 as i32;
                    i = 0 as i32 as u32;
                    while (i as u64) < (*zip).numFiles {
                        if *(*h).emptyStreamBools.offset(i as isize) != 0 {
                            empty_streams += 1
                        }
                        i = i.wrapping_add(1)
                    }
                    current_block_137 = 7999014830792590863;
                }
                15 => {
                    if empty_streams <= 0 as i32 {
                        /* Unexcepted sequence. Skip this. */
                        if header_bytes(a, ll).is_null() {
                            return -(1 as i32);
                        }
                    } else {
                        if !(*h).emptyFileBools.is_null() {
                            return -(1 as i32);
                        }
                        (*h).emptyFileBools =
                            calloc(empty_streams as u64, size_of::<u8>() as u64) as *mut u8;
                        if (*h).emptyFileBools.is_null() {
                            return -(1 as i32);
                        }
                        if read_Bools(a, (*h).emptyFileBools, empty_streams as size_t) < 0 as i32 {
                            return -(1 as i32);
                        }
                    }
                    current_block_137 = 7999014830792590863;
                }
                16 => {
                    if empty_streams <= 0 as i32 {
                        /* Unexcepted sequence. Skip this. */
                        if header_bytes(a, ll).is_null() {
                            return -(1 as i32);
                        }
                    } else {
                        if !(*h).antiBools.is_null() {
                            return -(1 as i32);
                        }
                        (*h).antiBools =
                            calloc(empty_streams as u64, size_of::<u8>() as u64) as *mut u8;
                        if (*h).antiBools.is_null() {
                            return -(1 as i32);
                        }
                        if read_Bools(a, (*h).antiBools, empty_streams as size_t) < 0 as i32 {
                            return -(1 as i32);
                        }
                    }
                    current_block_137 = 7999014830792590863;
                }
                18 | 19 | 20 => {
                    if read_Times(a, h, type_0) < 0 as i32 {
                        return -(1 as i32);
                    }
                    current_block_137 = 7999014830792590863;
                }
                17 => {
                    let mut np: *mut u8 = 0 as *mut u8;
                    let mut nl: size_t = 0;
                    let mut nb: size_t = 0;
                    /* Skip one byte. */
                    p = header_bytes(a, 1 as i32 as size_t);
                    if p.is_null() {
                        return -(1 as i32);
                    }
                    ll = ll.wrapping_sub(1);
                    if ll & 1 as i32 as u64 != 0
                        || ll < (*zip).numFiles.wrapping_mul(4 as i32 as u64)
                    {
                        return -(1 as i32);
                    }
                    if !(*zip).entry_names.is_null() {
                        return -(1 as i32);
                    }
                    (*zip).entry_names = malloc(ll) as *mut u8;
                    if (*zip).entry_names.is_null() {
                        return -(1 as i32);
                    }
                    np = (*zip).entry_names;
                    nb = ll;
                    /*
                     * Copy whole file names.
                     * NOTE: This loop prevents from expanding
                     * the uncompressed buffer in order not to
                     * use extra memory resource.
                     */
                    while nb != 0 {
                        let mut b: size_t = 0;
                        if nb > (64 as i32 * 1024 as i32) as u64 {
                            b = (64 as i32 * 1024 as i32) as size_t
                        } else {
                            b = nb
                        }
                        p = header_bytes(a, b);
                        if p.is_null() {
                            return -(1 as i32);
                        }
                        memcpy(np as *mut (), p as *const (), b);
                        np = np.offset(b as isize);
                        nb = (nb as u64).wrapping_sub(b) as size_t as size_t
                    }
                    np = (*zip).entry_names;
                    nl = ll;
                    i = 0 as i32 as u32;
                    while (i as u64) < (*zip).numFiles {
                        let ref mut fresh10 = (*entries.offset(i as isize)).utf16name;
                        *fresh10 = np;

                        match () {
                            #[cfg_attr(_WIN32, _DEBUG, cfg(not(__CYGWIN__)))]
                            _ => {
                                let ref mut fresh_cfg_1 = (*entries.offset(i as isize)).wname;
                                *fresh_cfg_1 = np as *mut wchar_t;
                            }
                            #[cfg(any(not(_WIN32), not(_DEBUG), __CYGWIN__))]
                            _ => {}
                        }

                        /* Find a terminator. */
                        while nl >= 2 as i32 as u64
                            && (*np.offset(0 as i32 as isize) as i32 != 0
                                || *np.offset(1 as i32 as isize) as i32 != 0)
                        {
                            np = np.offset(2 as i32 as isize); /* Terminator not found */
                            nl = (nl as u64).wrapping_sub(2 as i32 as u64) as size_t as size_t
                        }
                        if nl < 2 as i32 as u64 {
                            return -(1 as i32);
                        }
                        (*entries.offset(i as isize)).name_len =
                            np.offset_from((*entries.offset(i as isize)).utf16name) as i64
                                as size_t;
                        np = np.offset(2 as i32 as isize);
                        nl = (nl as u64).wrapping_sub(2 as i32 as u64) as size_t as size_t;
                        i = i.wrapping_add(1)
                    }
                    current_block_137 = 7999014830792590863;
                }
                21 => {
                    let mut allAreDefined: i32 = 0;
                    p = header_bytes(a, 2 as i32 as size_t);
                    if p.is_null() {
                        return -(1 as i32);
                    }
                    allAreDefined = *p as i32;
                    if !(*h).attrBools.is_null() {
                        return -(1 as i32);
                    }
                    (*h).attrBools = calloc((*zip).numFiles, size_of::<u8>() as u64) as *mut u8;
                    if (*h).attrBools.is_null() {
                        return -(1 as i32);
                    }
                    if allAreDefined != 0 {
                        memset((*h).attrBools as *mut (), 1 as i32, (*zip).numFiles);
                    } else if read_Bools(a, (*h).attrBools, (*zip).numFiles) < 0 as i32 {
                        return -(1 as i32);
                    }
                    i = 0 as i32 as u32;
                    while (i as u64) < (*zip).numFiles {
                        if *(*h).attrBools.offset(i as isize) != 0 {
                            p = header_bytes(a, 4 as i32 as size_t);
                            if p.is_null() {
                                return -(1 as i32);
                            }
                            (*entries.offset(i as isize)).attr = archive_le32dec(p as *const ())
                        }
                        i = i.wrapping_add(1)
                    }
                    current_block_137 = 7999014830792590863;
                }
                25 => {
                    if ll == 0 as i32 as u64 {
                        current_block_137 = 7999014830792590863;
                    } else {
                        current_block_137 = 3209824902443492620;
                    }
                }
                _ => {
                    current_block_137 = 3209824902443492620;
                }
            }
            match current_block_137 {
                3209824902443492620 => {
                    if header_bytes(a, ll).is_null() {
                        return -(1 as i32);
                    }
                }
                _ => {}
            }
        }
        /*
         * Set up entry's attributes.
         */
        folders = (*si).ci.folders;
        sindex = 0 as i32;
        eindex = sindex;
        indexInFolder = 0 as i32 as uint32_t;
        folderIndex = indexInFolder;
        i = 0 as i32 as u32;
        while (i as u64) < (*zip).numFiles {
            if (*h).emptyStreamBools.is_null()
                || *(*h).emptyStreamBools.offset(i as isize) as i32 == 0 as i32
            {
                (*entries.offset(i as isize)).flg |= ((1 as i32) << 4 as i32) as u32
            }
            /* The high 16 bits of attributes is a posix file mode. */
            (*entries.offset(i as isize)).mode = (*entries.offset(i as isize)).attr >> 16 as i32; /* Read only. */
            if (*entries.offset(i as isize)).flg & ((1 as i32) << 4 as i32) as u32 != 0 {
                if sindex as size_t >= (*si).ss.unpack_streams {
                    return -(1 as i32);
                }
                if (*entries.offset(i as isize)).mode == 0 as i32 as u32 {
                    (*entries.offset(i as isize)).mode =
                        0o100000 as i32 as mode_t | 0o666 as i32 as u32
                }
                if *(*si).ss.digestsDefined.offset(sindex as isize) != 0 {
                    (*entries.offset(i as isize)).flg |= ((1 as i32) << 3 as i32) as u32
                }
                (*entries.offset(i as isize)).ssIndex = sindex as uint32_t;
                sindex += 1
            } else {
                let mut dir: i32 = 0;
                if (*h).emptyFileBools.is_null() {
                    dir = 1 as i32
                } else {
                    if *(*h).emptyFileBools.offset(eindex as isize) != 0 {
                        dir = 0 as i32
                    } else {
                        dir = 1 as i32
                    }
                    eindex += 1
                }
                if (*entries.offset(i as isize)).mode == 0 as i32 as u32 {
                    if dir != 0 {
                        (*entries.offset(i as isize)).mode =
                            0o40000 as i32 as mode_t | 0o777 as i32 as u32
                    } else {
                        (*entries.offset(i as isize)).mode =
                            0o100000 as i32 as mode_t | 0o666 as i32 as u32
                    }
                } else if dir != 0
                    && (*entries.offset(i as isize)).mode & 0o170000 as i32 as mode_t
                        != 0o40000 as i32 as mode_t
                {
                    let ref mut fresh11 = (*entries.offset(i as isize)).mode;
                    *fresh11 &= !(0o170000 as i32 as mode_t);
                    let ref mut fresh12 = (*entries.offset(i as isize)).mode;
                    *fresh12 |= 0o40000 as i32 as mode_t
                }
                if (*entries.offset(i as isize)).mode & 0o170000 as i32 as mode_t
                    == 0o40000 as i32 as mode_t
                    && (*entries.offset(i as isize)).name_len >= 2 as i32 as u64
                    && (*(*entries.offset(i as isize)).utf16name.offset(
                        (*entries.offset(i as isize))
                            .name_len
                            .wrapping_sub(2 as i32 as u64) as isize,
                    ) as i32
                        != '/' as i32
                        || *(*entries.offset(i as isize)).utf16name.offset(
                            (*entries.offset(i as isize))
                                .name_len
                                .wrapping_sub(1 as i32 as u64) as isize,
                        ) as i32
                            != 0 as i32)
                {
                    *(*entries.offset(i as isize))
                        .utf16name
                        .offset((*entries.offset(i as isize)).name_len as isize) = '/' as i32 as u8;
                    *(*entries.offset(i as isize)).utf16name.offset(
                        (*entries.offset(i as isize))
                            .name_len
                            .wrapping_add(1 as i32 as u64) as isize,
                    ) = 0 as i32 as u8;
                    let ref mut fresh13 = (*entries.offset(i as isize)).name_len;
                    *fresh13 = (*fresh13 as u64).wrapping_add(2 as i32 as u64) as size_t as size_t
                }
                (*entries.offset(i as isize)).ssIndex = -(1 as i32) as uint32_t
            }
            if (*entries.offset(i as isize)).attr & 0x1 as i32 as u32 != 0 {
                let ref mut fresh14 = (*entries.offset(i as isize)).mode;
                *fresh14 &= !(0o222 as i32) as u32
            }
            if (*entries.offset(i as isize)).flg & ((1 as i32) << 4 as i32) as u32
                == 0 as i32 as u32
                && indexInFolder == 0 as i32 as u32
            {
                /*
                 * The entry is an empty file or a directory file,
                 * those both have no contents.
                 */
                (*entries.offset(i as isize)).folderIndex = -(1 as i32) as uint32_t
            } else {
                if indexInFolder == 0 as i32 as u32 {
                    loop {
                        if folderIndex as u64 >= (*si).ci.numFolders {
                            return -(1 as i32);
                        }
                        if (*folders.offset(folderIndex as isize)).numUnpackStreams != 0 {
                            break;
                        }
                        folderIndex = folderIndex.wrapping_add(1)
                    }
                }
                (*entries.offset(i as isize)).folderIndex = folderIndex;
                if !((*entries.offset(i as isize)).flg & ((1 as i32) << 4 as i32) as u32
                    == 0 as i32 as u32)
                {
                    indexInFolder = indexInFolder.wrapping_add(1);
                    if indexInFolder as u64
                        >= (*folders.offset(folderIndex as isize)).numUnpackStreams
                    {
                        folderIndex = folderIndex.wrapping_add(1);
                        indexInFolder = 0 as i32 as uint32_t
                    }
                }
            }
            i = i.wrapping_add(1)
        }
        return 0 as i32;
    }
}
unsafe fn fileTimeToUtc(mut fileTime: uint64_t, mut timep: *mut time_t, mut ns: *mut i64) {
    if fileTime as u64 >= 116444736000000000 as u64 {
        fileTime =
            (fileTime as u64).wrapping_sub(116444736000000000 as u64) as uint64_t as uint64_t;
        /* milli seconds base */
        unsafe {
            *timep = fileTime.wrapping_div(10000000 as i32 as u64) as time_t;
            /* nano seconds base */
            *ns = fileTime.wrapping_rem(10000000 as i32 as u64) as i64 * 100 as i32 as i64
        }
    } else {
        unsafe {
            *timep = 0 as i32 as time_t;
            *ns = 0 as i32 as i64
        }
    };
}
unsafe fn read_Times(
    mut a: *mut archive_read,
    mut h: *mut _7z_header_info,
    mut type_0: i32,
) -> i32 {
    let mut current_block: u64;
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut p: *const u8 = 0 as *const u8;
    let safe_zip = unsafe { &mut *zip };
    let mut entries: *mut _7zip_entry = (safe_zip).entries;
    let mut timeBools: *mut u8 = 0 as *mut u8;
    let mut allAreDefined: i32 = 0;
    let mut i: u32 = 0;
    timeBools = calloc_safe((safe_zip).numFiles, size_of::<u8>() as u64) as *mut u8;
    if timeBools.is_null() {
        return -(1 as i32);
    }
    /* Read allAreDefined. */
    p = header_bytes(a, 1 as i32 as size_t);
    if !p.is_null() {
        allAreDefined = unsafe { *p as i32 };
        if allAreDefined != 0 {
            memset_safe(timeBools as *mut (), 1 as i32, (safe_zip).numFiles);
            current_block = 7746791466490516765;
        } else if read_Bools(a, timeBools, (safe_zip).numFiles) < 0 as i32 {
            current_block = 4688298256779699391;
        } else {
            current_block = 7746791466490516765;
        }
        match current_block {
            4688298256779699391 => {}
            _ =>
            /* Read external. */
            {
                p = header_bytes(a, 1 as i32 as size_t);
                if !p.is_null() {
                    unsafe {
                        if *p != 0 {
                            if parse_7zip_uint64(a, &mut (*h).dataIndex) < 0 as i32
                                || (100000000 as u64) < (*h).dataIndex as u64
                            {
                                current_block = 4688298256779699391;
                            } else {
                                current_block = 15976848397966268834;
                            }
                        } else {
                            current_block = 15976848397966268834;
                        }
                    }
                    match current_block {
                        4688298256779699391 => {}
                        _ => {
                            i = 0 as i32 as u32;
                            loop {
                                if !((i as u64) < (safe_zip).numFiles) {
                                    current_block = 8693738493027456495;
                                    break;
                                }
                                if unsafe { !(*timeBools.offset(i as isize) == 0) } {
                                    p = header_bytes(a, 8 as i32 as size_t);
                                    if p.is_null() {
                                        current_block = 4688298256779699391;
                                        break;
                                    }
                                    unsafe {
                                        match type_0 {
                                            18 => {
                                                fileTimeToUtc(
                                                    archive_le64dec(p as *const ()),
                                                    &mut (*entries.offset(i as isize)).ctime,
                                                    &mut (*entries.offset(i as isize)).ctime_ns,
                                                );
                                                (*entries.offset(i as isize)).flg |=
                                                    ((1 as i32) << 2 as i32) as u32
                                            }
                                            19 => {
                                                fileTimeToUtc(
                                                    archive_le64dec(p as *const ()),
                                                    &mut (*entries.offset(i as isize)).atime,
                                                    &mut (*entries.offset(i as isize)).atime_ns,
                                                );
                                                (*entries.offset(i as isize)).flg |=
                                                    ((1 as i32) << 1 as i32) as u32
                                            }
                                            20 => {
                                                fileTimeToUtc(
                                                    archive_le64dec(p as *const ()),
                                                    &mut (*entries.offset(i as isize)).mtime,
                                                    &mut (*entries.offset(i as isize)).mtime_ns,
                                                );
                                                (*entries.offset(i as isize)).flg |=
                                                    ((1 as i32) << 0 as i32) as u32
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                i = i.wrapping_add(1)
                            }
                            match current_block {
                                4688298256779699391 => {}
                                _ => {
                                    free_safe(timeBools as *mut ());
                                    return 0 as i32;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    free_safe(timeBools as *mut ());
    return -(1 as i32);
}
unsafe fn decode_encoded_header_info(
    mut a: *mut archive_read,
    mut si: *mut _7z_stream_info,
) -> i32 {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    let safe_si = unsafe { &mut *si };
    unsafe { *__errno_location() = 0 as i32 };
    if read_StreamsInfo(a, si) < 0 as i32 {
        if unsafe { *__errno_location() == 12 as i32 } {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Couldn\'t allocate memory\x00" as *const u8,
                )
            };
        } else {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    -(1 as i32),
                    b"Malformed 7-Zip archive\x00" as *const u8,
                )
            };
        }
        return -(30 as i32);
    }
    if (safe_si).pi.numPackStreams == 0 as i32 as u64 || (safe_si).ci.numFolders == 0 as i32 as u64
    {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as i32),
                b"Malformed 7-Zip archive\x00" as *const u8,
            )
        };
        return -(30 as i32);
    }
    if unsafe {
        (safe_zip).header_offset
            < (safe_si)
                .pi
                .pos
                .wrapping_add(*(safe_si).pi.sizes.offset(0 as i32 as isize))
            || ((safe_si)
                .pi
                .pos
                .wrapping_add(*(safe_si).pi.sizes.offset(0 as i32 as isize))
                as int64_t)
                < 0 as i32 as i64
            || *(safe_si).pi.sizes.offset(0 as i32 as isize) == 0 as i32 as u64
            || ((safe_si).pi.pos as int64_t) < 0 as i32 as i64
    } {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as i32),
                b"Malformed Header offset\x00" as *const u8,
            )
        };
        return -(30 as i32);
    }
    return 0 as i32;
}
unsafe fn header_bytes(mut a: *mut archive_read, mut rbytes: size_t) -> *const u8 {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut p: *const u8 = 0 as *const u8;
    let safe_zip = unsafe { &mut *zip };
    if (safe_zip).header_bytes_remaining < rbytes {
        return 0 as *const u8;
    }
    if (safe_zip).pack_stream_bytes_unconsumed != 0 {
        read_consume(a);
    }
    if (safe_zip).header_is_encoded == 0 as i32 {
        p = __archive_read_ahead_safe(a, rbytes, 0 as *mut ssize_t) as *const u8;
        if p.is_null() {
            return 0 as *const u8;
        }
        (safe_zip).header_bytes_remaining =
            ((safe_zip).header_bytes_remaining as u64).wrapping_sub(rbytes) as uint64_t as uint64_t;
        (safe_zip).pack_stream_bytes_unconsumed = rbytes
    } else {
        let mut buff: *const () = 0 as *const ();
        let mut bytes: ssize_t = 0;
        bytes = read_stream(a, &mut buff, rbytes, rbytes);
        if bytes <= 0 as i32 as i64 {
            return 0 as *const u8;
        }
        (safe_zip).header_bytes_remaining = ((safe_zip).header_bytes_remaining as u64)
            .wrapping_sub(bytes as u64) as uint64_t
            as uint64_t;
        p = buff as *const u8
    }
    /* Update checksum */
    (safe_zip).header_crc32 = crc32_safe((safe_zip).header_crc32, p, rbytes as u32);
    return p;
}
unsafe fn slurp_central_directory(
    mut a: *mut archive_read,
    mut zip: *mut _7zip,
    mut header: *mut _7z_header_info,
) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let mut next_header_offset: uint64_t = 0;
    let mut next_header_size: uint64_t = 0;
    let mut next_header_crc: uint32_t = 0;
    let mut bytes_avail: ssize_t = 0;
    let mut check_header_crc: i32 = 0;
    let mut r: i32 = 0;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    p = __archive_read_ahead_safe(a, 32 as i32 as size_t, &mut bytes_avail) as *const u8;
    if p.is_null() {
        return -(30 as i32);
    }
    if unsafe {
        *p.offset(0 as i32 as isize) as i32 == 'M' as i32
            && *p.offset(1 as i32 as isize) as i32 == 'Z' as i32
            || memcmp(
                p as *const (),
                b"\x7fELF\x00" as *const u8 as *const (),
                4 as i32 as u64,
            ) == 0 as i32
    } {
        /* This is an executable ? Must be self-extracting... */
        r = skip_sfx(a, bytes_avail);
        if r < -(20 as i32) {
            return r;
        }
        p = __archive_read_ahead_safe(a, 32 as i32 as size_t, &mut bytes_avail) as *const u8;
        if p.is_null() {
            return -(30 as i32);
        }
    }
    (safe_zip).seek_base =
        ((safe_zip).seek_base as u64).wrapping_add(32 as i32 as u64) as uint64_t as uint64_t;
    if memcmp_safe(
        p as *const (),
        b"7z\xbc\xaf\'\x1c\x00" as *const u8 as *const (),
        6 as i32 as u64,
    ) != 0 as i32
    {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as i32),
                b"Not 7-Zip archive file\x00" as *const u8,
            )
        };
        return -(30 as i32);
    }
    /* CRC check. */
    if crc32_safe(
        0 as i32 as uLong,
        unsafe { p.offset(12 as i32 as isize) },
        20 as i32 as uInt,
    ) != archive_le32dec(unsafe { p.offset(8 as i32 as isize) as *const () }) as u64
    {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as i32),
                b"Header CRC error\x00" as *const u8,
            )
        };
        return -(30 as i32);
    }
    next_header_offset = archive_le64dec(unsafe { p.offset(12 as i32 as isize) as *const () });
    next_header_size = archive_le64dec(unsafe { p.offset(20 as i32 as isize) as *const () });
    next_header_crc = archive_le32dec(unsafe { p.offset(28 as i32 as isize) as *const () });
    if next_header_size == 0 as i32 as u64 {
        /* There is no entry in an archive file. */
        return 1 as i32;
    }
    if (next_header_offset as int64_t) < 0 as i32 as i64 {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as i32),
                b"Malformed 7-Zip archive\x00" as *const u8,
            )
        };
        return -(30 as i32);
    }
    __archive_read_consume_safe(a, 32 as i32 as int64_t);
    if next_header_offset != 0 as i32 as u64 {
        if bytes_avail >= next_header_offset as ssize_t {
            __archive_read_consume_safe(a, next_header_offset as int64_t);
        } else if __archive_read_seek_safe(
            a,
            next_header_offset.wrapping_add((safe_zip).seek_base) as int64_t,
            0 as i32,
        ) < 0 as i32 as i64
        {
            return -(30 as i32);
        }
    }
    (safe_zip).stream_offset = next_header_offset as int64_t;
    (safe_zip).header_offset = next_header_offset;
    (safe_zip).header_bytes_remaining = next_header_size;
    (safe_zip).header_crc32 = 0 as i32 as u64;
    (safe_zip).header_is_encoded = 0 as i32;
    (safe_zip).header_is_being_read = 1 as i32;
    (safe_zip).has_encrypted_entries = 0 as i32;
    check_header_crc = 1 as i32;
    p = header_bytes(a, 1 as i32 as size_t);
    if p.is_null() {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84 as i32,
                b"Truncated 7-Zip file body\x00" as *const u8,
            )
        };
        return -(30 as i32);
    }
    /* Parse ArchiveProperties. */
    match unsafe { *p.offset(0 as i32 as isize) as i32 } {
        23 => {
            /*
             * The archive has an encoded header and we have to decode it
             * in order to parse the header correctly.
             */
            r = decode_encoded_header_info(a, &mut (safe_zip).si);
            /* Check the EncodedHeader CRC.*/
            if r == 0 as i32 && (safe_zip).header_crc32 != next_header_crc as u64 {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as i32),
                        b"Damaged 7-Zip archive\x00" as *const u8,
                    )
                };
                r = -(1 as i32)
            }
            if r == 0 as i32 {
                if unsafe {
                    (*(safe_zip).si.ci.folders.offset(0 as i32 as isize)).digest_defined != 0
                } {
                    next_header_crc =
                        unsafe { (*(safe_zip).si.ci.folders.offset(0 as i32 as isize)).digest }
                } else {
                    check_header_crc = 0 as i32
                }
                if (safe_zip).pack_stream_bytes_unconsumed != 0 {
                    read_consume(a);
                }
                r = setup_decode_folder(a, (safe_zip).si.ci.folders, 1 as i32);
                if r == 0 as i32 {
                    (safe_zip).header_bytes_remaining = (safe_zip).folder_outbytes_remaining;
                    r = seek_pack(a)
                }
            }
            /* Clean up StreamsInfo. */
            free_StreamsInfo(&mut (safe_zip).si);
            memset_safe(
                &mut (safe_zip).si as *mut _7z_stream_info as *mut (),
                0 as i32,
                size_of::<_7z_stream_info>() as u64,
            );
            if r < 0 as i32 {
                return -(30 as i32);
            }
            (safe_zip).header_is_encoded = 1 as i32;
            (safe_zip).header_crc32 = 0 as i32 as u64
        }
        1 => {}
        _ => {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Unexpected Property ID = %X\x00" as *const u8,
                    *p.offset(0 as i32 as isize) as i32,
                )
            };
            return -(30 as i32);
        }
    }
    /* FALL THROUGH */
    /*
     * Parse the header.
     */
    unsafe { *__errno_location() = 0 as i32 };
    r = read_Header(a, header, (safe_zip).header_is_encoded);
    if r < 0 as i32 {
        if unsafe { *__errno_location() == 12 as i32 } {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Couldn\'t allocate memory\x00" as *const u8,
                )
            };
        } else {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Damaged 7-Zip archive\x00" as *const u8,
                )
            };
        }
        return -(30 as i32);
    }
    p = header_bytes(a, 1 as i32 as size_t);
    if unsafe { p.is_null() || *p as i32 != 0 as i32 } {
        unsafe {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                -(1 as i32),
                b"Malformed 7-Zip archive\x00" as *const u8,
            )
        };
        return -(30 as i32);
    }
    if check_header_crc != 0 && (safe_zip).header_crc32 != next_header_crc as u64 {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as i32),
                b"Malformed 7-Zip archive\x00" as *const u8,
            )
        };
        return -(30 as i32);
    }
    /*
     *  Must be kEnd.
     */
    /* Check the Header CRC.*/
    /* Clean up variables be used for decoding the archive header */
    (safe_zip).pack_stream_remaining = 0 as i32 as u32;
    (safe_zip).pack_stream_index = 0 as i32 as u32;
    (safe_zip).folder_outbytes_remaining = 0 as i32 as uint64_t;
    (safe_zip).uncompressed_buffer_bytes_remaining = 0 as i32 as size_t;
    (safe_zip).pack_stream_bytes_unconsumed = 0 as i32 as size_t;
    (safe_zip).header_is_being_read = 0 as i32;
    return 0 as i32;
}
unsafe fn get_uncompressed_data(
    mut a: *mut archive_read,
    mut buff: *mut *const (),
    mut size: size_t,
    mut minimum: size_t,
) -> ssize_t {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut bytes_avail: ssize_t = 0;
    let safe_zip = unsafe { &mut *zip };
    let safe_a = unsafe { &mut *a };
    if (safe_zip).codec == 0 as i32 as u64 && (safe_zip).codec2 == -(1 as i32) as u64 {
        /* Copy mode. */
        unsafe { *buff = __archive_read_ahead(a, minimum, &mut bytes_avail) };
        if bytes_avail <= 0 as i32 as i64 {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    84 as i32,
                    b"Truncated 7-Zip file data\x00" as *const u8,
                )
            };
            return -(30 as i32) as ssize_t;
        }
        if bytes_avail as size_t > (safe_zip).uncompressed_buffer_bytes_remaining {
            bytes_avail = (safe_zip).uncompressed_buffer_bytes_remaining as ssize_t
        }
        if bytes_avail as size_t > size {
            bytes_avail = size as ssize_t
        }
        (safe_zip).pack_stream_bytes_unconsumed = bytes_avail as size_t
    } else if (safe_zip).uncompressed_buffer_pointer.is_null() {
        /* Decompression has failed. */
        unsafe {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                -(1 as i32),
                b"Damaged 7-Zip archive\x00" as *const u8,
            )
        };
        return -(30 as i32) as ssize_t;
    } else {
        /* Packed mode. */
        if minimum > (safe_zip).uncompressed_buffer_bytes_remaining {
            /*
             * If remaining uncompressed data size is less than
             * the minimum size, fill the buffer up to the
             * minimum size.
             */
            if extract_pack_stream(a, minimum) < 0 as i32 as i64 {
                return -(30 as i32) as ssize_t;
            }
        }
        if size > (safe_zip).uncompressed_buffer_bytes_remaining {
            bytes_avail = (safe_zip).uncompressed_buffer_bytes_remaining as ssize_t
        } else {
            bytes_avail = size as ssize_t
        }
        unsafe { *buff = (safe_zip).uncompressed_buffer_pointer as *const () };
        (safe_zip).uncompressed_buffer_pointer = unsafe {
            (safe_zip)
                .uncompressed_buffer_pointer
                .offset(bytes_avail as isize)
        }
    }
    (safe_zip).uncompressed_buffer_bytes_remaining =
        ((safe_zip).uncompressed_buffer_bytes_remaining as u64).wrapping_sub(bytes_avail as u64)
            as size_t as size_t;
    return bytes_avail;
}
unsafe fn extract_pack_stream(mut a: *mut archive_read, mut minimum: size_t) -> ssize_t {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut bytes_avail: ssize_t = 0;
    let mut r: i32 = 0;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    if (safe_zip).codec == 0 as i32 as u64 && (safe_zip).codec2 == -(1 as i32) as u64 {
        if minimum == 0 as i32 as u64 {
            minimum = 1 as i32 as size_t
        }
        if __archive_read_ahead_safe(a, minimum, &mut bytes_avail) == 0 as *mut ()
            || bytes_avail <= 0 as i32 as i64
        {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    84 as i32,
                    b"Truncated 7-Zip file body\x00" as *const u8,
                )
            };
            return -(30 as i32) as ssize_t;
        }
        if bytes_avail as uint64_t > (safe_zip).pack_stream_inbytes_remaining {
            bytes_avail = (safe_zip).pack_stream_inbytes_remaining as ssize_t
        }
        (safe_zip).pack_stream_inbytes_remaining = ((safe_zip).pack_stream_inbytes_remaining as u64)
            .wrapping_sub(bytes_avail as u64)
            as uint64_t as uint64_t;
        if bytes_avail as uint64_t > (safe_zip).folder_outbytes_remaining {
            bytes_avail = (safe_zip).folder_outbytes_remaining as ssize_t
        }
        (safe_zip).folder_outbytes_remaining = ((safe_zip).folder_outbytes_remaining as u64)
            .wrapping_sub(bytes_avail as u64)
            as uint64_t as uint64_t;
        (safe_zip).uncompressed_buffer_bytes_remaining = bytes_avail as size_t;
        return 0 as i32 as ssize_t;
    }
    /* If the buffer hasn't been allocated, allocate it now. */
    if (safe_zip).uncompressed_buffer.is_null() {
        (safe_zip).uncompressed_buffer_size = (64 as i32 * 1024 as i32) as size_t;
        if (safe_zip).uncompressed_buffer_size < minimum {
            (safe_zip).uncompressed_buffer_size = minimum.wrapping_add(1023 as i32 as u64);
            (safe_zip).uncompressed_buffer_size &= !(0x3ff as i32) as u64
        }
        (safe_zip).uncompressed_buffer =
            malloc_safe((safe_zip).uncompressed_buffer_size) as *mut u8;
        if (safe_zip).uncompressed_buffer.is_null() {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    12 as i32,
                    b"No memory for 7-Zip decompression\x00" as *const u8,
                )
            };
            return -(30 as i32) as ssize_t;
        }
        (safe_zip).uncompressed_buffer_bytes_remaining = 0 as i32 as size_t
    } else if (safe_zip).uncompressed_buffer_size < minimum
        || (safe_zip).uncompressed_buffer_bytes_remaining < minimum
    {
        /*
         * Make sure the uncompressed buffer can have bytes
         * at least `minimum' bytes.
         * NOTE: This case happen when reading the header.
         */
        let mut used: size_t = 0;
        if !(safe_zip).uncompressed_buffer_pointer.is_null() {
            used = unsafe {
                (safe_zip)
                    .uncompressed_buffer_pointer
                    .offset_from((safe_zip).uncompressed_buffer) as i64 as size_t
            }
        } else {
            used = 0 as i32 as size_t
        }
        if (safe_zip).uncompressed_buffer_size < minimum {
            /*
             * Expand the uncompressed buffer up to
             * the minimum size.
             */
            let mut p: *mut () = 0 as *mut ();
            let mut new_size: size_t = 0;
            new_size = minimum.wrapping_add(1023 as i32 as u64);
            new_size &= !(0x3ff as i32) as u64;
            p = realloc_safe((safe_zip).uncompressed_buffer as *mut (), new_size);
            if p.is_null() {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        12 as i32,
                        b"No memory for 7-Zip decompression\x00" as *const u8,
                    )
                };
                return -(30 as i32) as ssize_t;
            }
            (safe_zip).uncompressed_buffer = p as *mut u8;
            (safe_zip).uncompressed_buffer_size = new_size
        }
        /*
         * Move unconsumed bytes to the head.
         */
        if used != 0 {
            memmove_safe(
                (safe_zip).uncompressed_buffer as *mut (),
                unsafe { (safe_zip).uncompressed_buffer.offset(used as isize) as *const () },
                (safe_zip).uncompressed_buffer_bytes_remaining,
            );
        }
    } else {
        (safe_zip).uncompressed_buffer_bytes_remaining = 0 as i32 as size_t
    }
    (safe_zip).uncompressed_buffer_pointer = 0 as *mut u8;
    loop {
        let mut bytes_in: size_t = 0;
        let mut bytes_out: size_t = 0;
        let mut buff_in: *const () = 0 as *const ();
        let mut buff_out: *mut u8 = 0 as *mut u8;
        let mut end_of_data: i32 = 0;
        /*
         * Note: '1' here is a performance optimization.
         * Recall that the decompression layer returns a count of
         * available bytes; asking for more than that forces the
         * decompressor to combine reads by copying data.
         */
        buff_in = __archive_read_ahead_safe(a, 1 as i32 as size_t, &mut bytes_avail);
        if bytes_avail <= 0 as i32 as i64 {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    84 as i32,
                    b"Truncated 7-Zip file body\x00" as *const u8,
                )
            };
            return -(30 as i32) as ssize_t;
        }
        buff_out = unsafe {
            (safe_zip)
                .uncompressed_buffer
                .offset((safe_zip).uncompressed_buffer_bytes_remaining as isize)
        };
        bytes_out = (safe_zip)
            .uncompressed_buffer_size
            .wrapping_sub((safe_zip).uncompressed_buffer_bytes_remaining);
        bytes_in = bytes_avail as size_t;
        if bytes_in > (safe_zip).pack_stream_inbytes_remaining {
            bytes_in = (safe_zip).pack_stream_inbytes_remaining
        }
        /* Drive decompression. */
        r = decompress(
            a,
            zip,
            buff_out as *mut (),
            &mut bytes_out,
            buff_in,
            &mut bytes_in,
        );
        match r {
            0 => end_of_data = 0 as i32,
            1 => end_of_data = 1 as i32,
            _ => return -(30 as i32) as ssize_t,
        }
        (safe_zip).pack_stream_inbytes_remaining = ((safe_zip).pack_stream_inbytes_remaining as u64)
            .wrapping_sub(bytes_in) as uint64_t
            as uint64_t;
        if bytes_out > (safe_zip).folder_outbytes_remaining {
            bytes_out = (safe_zip).folder_outbytes_remaining
        }
        (safe_zip).folder_outbytes_remaining = ((safe_zip).folder_outbytes_remaining as u64)
            .wrapping_sub(bytes_out) as uint64_t
            as uint64_t;
        (safe_zip).uncompressed_buffer_bytes_remaining =
            ((safe_zip).uncompressed_buffer_bytes_remaining as u64).wrapping_add(bytes_out)
                as size_t as size_t;
        (safe_zip).pack_stream_bytes_unconsumed = bytes_in;
        /*
         * Continue decompression until uncompressed_buffer is full.
         */
        if (safe_zip).uncompressed_buffer_bytes_remaining == (safe_zip).uncompressed_buffer_size {
            break;
        }
        if (safe_zip).codec2 == 0x3030103 as i32 as u64
            && (safe_zip).odd_bcj_size != 0
            && (safe_zip)
                .uncompressed_buffer_bytes_remaining
                .wrapping_add(5 as i32 as u64)
                > (safe_zip).uncompressed_buffer_size
        {
            break;
        }
        if (safe_zip).pack_stream_inbytes_remaining == 0 as i32 as u64
            && (safe_zip).folder_outbytes_remaining == 0 as i32 as u64
        {
            break;
        }
        if end_of_data != 0 || bytes_in == 0 as i32 as u64 && bytes_out == 0 as i32 as u64 {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Damaged 7-Zip archive\x00" as *const u8,
                )
            };
            return -(30 as i32) as ssize_t;
        }
        read_consume(a);
    }
    if (safe_zip).uncompressed_buffer_bytes_remaining < minimum {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as i32),
                b"Damaged 7-Zip archive\x00" as *const u8,
            )
        };
        return -(30 as i32) as ssize_t;
    }
    (safe_zip).uncompressed_buffer_pointer = (safe_zip).uncompressed_buffer;
    return 0 as i32 as ssize_t;
}
unsafe fn seek_pack(mut a: *mut archive_read) -> i32 {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut pack_offset: int64_t = 0;
    let safe_zip = unsafe { &mut *zip };
    if (safe_zip).pack_stream_remaining <= 0 as i32 as u32 {
        unsafe {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                -(1 as i32),
                b"Damaged 7-Zip archive\x00" as *const u8,
            )
        };
        return -(30 as i32);
    }
    (safe_zip).pack_stream_inbytes_remaining = unsafe {
        *(safe_zip)
            .si
            .pi
            .sizes
            .offset((safe_zip).pack_stream_index as isize)
    };
    pack_offset = unsafe {
        *(safe_zip)
            .si
            .pi
            .positions
            .offset((safe_zip).pack_stream_index as isize) as int64_t
    };
    if (safe_zip).stream_offset != pack_offset {
        if 0 as i32 as i64
            > __archive_read_seek_safe(
                a,
                (pack_offset as u64).wrapping_add((safe_zip).seek_base) as int64_t,
                0 as i32,
            )
        {
            return -(30 as i32);
        }
        (safe_zip).stream_offset = pack_offset
    }
    (safe_zip).pack_stream_index = (safe_zip).pack_stream_index.wrapping_add(1);
    (safe_zip).pack_stream_remaining = (safe_zip).pack_stream_remaining.wrapping_sub(1);
    return 0 as i32;
}
unsafe fn read_stream(
    mut a: *mut archive_read,
    mut buff: *mut *const (),
    mut size: size_t,
    mut minimum: size_t,
) -> ssize_t {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut skip_bytes: uint64_t = 0 as i32 as uint64_t;
    let mut r: ssize_t = 0;
    let safe_zip = unsafe { &mut *zip };
    let safe_a = unsafe { &mut *a };
    if (safe_zip).uncompressed_buffer_bytes_remaining == 0 as i32 as u64 {
        if (safe_zip).pack_stream_inbytes_remaining > 0 as i32 as u64 {
            r = extract_pack_stream(a, 0 as i32 as size_t);
            if r < 0 as i32 as i64 {
                return r;
            }
            return get_uncompressed_data(a, buff, size, minimum);
        } else {
            if (safe_zip).folder_outbytes_remaining > 0 as i32 as u64 {
                /* Extract a remaining pack stream. */
                r = extract_pack_stream(a, 0 as i32 as size_t);
                if r < 0 as i32 as i64 {
                    return r;
                }
                return get_uncompressed_data(a, buff, size, minimum);
            }
        }
    } else {
        return get_uncompressed_data(a, buff, size, minimum);
    }
    /*
     * Current pack stream has been consumed.
     */
    if (safe_zip).pack_stream_remaining == 0 as i32 as u32 {
        if (safe_zip).header_is_being_read != 0 {
            /* Invalid sequence. This might happen when
             * reading a malformed archive. */
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    -(1 as i32),
                    b"Malformed 7-Zip archive\x00" as *const u8,
                )
            };
            return -(30 as i32) as ssize_t;
        }
        /*
         * All current folder's pack streams have been
         * consumed. Switch to next folder.
         */
        if unsafe {
            (safe_zip).folder_index == 0 as i32 as u32
                && ((*(safe_zip)
                    .si
                    .ci
                    .folders
                    .offset((*(safe_zip).entry).folderIndex as isize))
                .skipped_bytes
                    != 0
                    || (safe_zip).folder_index != (*(safe_zip).entry).folderIndex)
        } {
            (safe_zip).folder_index = unsafe { (*(safe_zip).entry).folderIndex };
            skip_bytes = unsafe {
                (*(safe_zip)
                    .si
                    .ci
                    .folders
                    .offset((safe_zip).folder_index as isize))
                .skipped_bytes
            }
        }
        if (safe_zip).folder_index as u64 >= (safe_zip).si.ci.numFolders {
            /*
             * We have consumed all folders and its pack streams.
             */
            unsafe { *buff = 0 as *const () };
            return 0 as i32 as ssize_t;
        }
        r = setup_decode_folder(
            a,
            unsafe {
                &mut *(safe_zip)
                    .si
                    .ci
                    .folders
                    .offset((safe_zip).folder_index as isize)
            },
            0 as i32,
        ) as ssize_t;
        if r != 0 as i32 as i64 {
            return -(30 as i32) as ssize_t;
        }
        (safe_zip).folder_index = (safe_zip).folder_index.wrapping_add(1)
    }
    /*
     * Switch to next pack stream.
     */
    r = seek_pack(a) as ssize_t;
    if r < 0 as i32 as i64 {
        return r;
    }
    /* Extract a new pack stream. */
    r = extract_pack_stream(a, 0 as i32 as size_t);
    if r < 0 as i32 as i64 {
        return r;
    }
    /*
     * Skip the bytes we already has skipped in skip_stream().
     */
    while skip_bytes != 0 {
        let mut skipped: ssize_t = 0;
        if (safe_zip).uncompressed_buffer_bytes_remaining == 0 as i32 as u64 {
            if (safe_zip).pack_stream_inbytes_remaining > 0 as i32 as u64
                || (safe_zip).folder_outbytes_remaining > 0 as i32 as u64
            {
                /* Extract a remaining pack stream. */
                r = extract_pack_stream(a, 0 as i32 as size_t);
                if r < 0 as i32 as i64 {
                    return r;
                }
            } else {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        84 as i32,
                        b"Truncated 7-Zip file body\x00" as *const u8,
                    )
                };
                return -(30 as i32) as ssize_t;
            }
        }
        skipped = get_uncompressed_data(a, buff, skip_bytes, 0 as i32 as size_t);
        if skipped < 0 as i32 as i64 {
            return skipped;
        }
        skip_bytes = (skip_bytes as u64).wrapping_sub(skipped as u64) as uint64_t as uint64_t;
        if (safe_zip).pack_stream_bytes_unconsumed != 0 {
            read_consume(a);
        }
    }
    return get_uncompressed_data(a, buff, size, minimum);
}
unsafe fn setup_decode_folder(
    mut a: *mut archive_read,
    mut folder: *mut _7z_folder,
    mut header: i32,
) -> i32 {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut coder1: *const _7z_coder = 0 as *const _7z_coder;
    let mut coder2: *const _7z_coder = 0 as *const _7z_coder;
    let mut cname: *const u8 = if header != 0 {
        b"archive header\x00" as *const u8
    } else {
        b"file content\x00" as *const u8
    };
    let mut i: u32 = 0;
    let mut r: i32 = 0;
    let mut found_bcj2: i32 = 0 as i32;
    /*
     * Release the memory which the previous folder used for BCJ2.
     */
    i = 0 as i32 as u32;
    let safe_a = unsafe { &mut *a };
    let mut safe_zip = unsafe { &mut *zip };
    let safe_folder = unsafe { &mut *folder };
    while i < 3 as i32 as u32 {
        free_safe((safe_zip).sub_stream_buff[i as usize] as *mut ());
        (safe_zip).sub_stream_buff[i as usize] = 0 as *mut u8;
        i = i.wrapping_add(1)
    }
    /*
     * Initialize a stream reader.
     */
    (safe_zip).pack_stream_remaining = (safe_folder).numPackedStreams as u32;
    (safe_zip).pack_stream_index = (safe_folder).packIndex;
    (safe_zip).folder_outbytes_remaining = folder_uncompressed_size(folder);
    (safe_zip).uncompressed_buffer_bytes_remaining = 0 as i32 as size_t;
    /*
     * Check coder types.
     */
    i = 0 as i32 as u32;
    while (i as u64) < (safe_folder).numCoders {
        match unsafe { (*(safe_folder).coders.offset(i as isize)).codec } {
            116457729 | 116458243 | 116459265 => {
                /* For entry that is associated with this folder, mark
                it as encrypted (data+metadata). */
                (safe_zip).has_encrypted_entries = 1 as i32;
                if !(safe_a).entry.is_null() {
                    archive_entry_set_is_data_encrypted_safe((safe_a).entry, 1 as i32 as u8);
                    archive_entry_set_is_metadata_encrypted_safe((safe_a).entry, 1 as i32 as u8);
                }
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as i32),
                        b"The %s is encrypted, but currently not supported\x00" as *const u8
                            as *const u8,
                        cname,
                    )
                };
                return -(30 as i32);
            }
            50528539 => found_bcj2 += 1,
            _ => {}
        }
        i = i.wrapping_add(1)
    }
    /* Now that we've checked for encryption, if there were still no
     * encrypted entries found we can say for sure that there are none.
     */
    if (safe_zip).has_encrypted_entries == -(1 as i32) {
        (safe_zip).has_encrypted_entries = 0 as i32
    }
    if (safe_folder).numCoders > 2 as i32 as u64 && found_bcj2 == 0 || found_bcj2 > 1 as i32 {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as i32),
                b"The %s is encoded with many filters, but currently not supported\x00" as *const u8
                    as *const u8,
                cname,
            )
        };
        return -(30 as i32);
    }
    coder1 = unsafe { &mut *(safe_folder).coders.offset(0 as i32 as isize) as *mut _7z_coder };
    if (safe_folder).numCoders == 2 as i32 as u64 {
        coder2 = unsafe { &mut *(safe_folder).coders.offset(1 as i32 as isize) as *mut _7z_coder }
    } else {
        coder2 = 0 as *const _7z_coder
    }
    if found_bcj2 != 0 {
        /*
         * Preparation to decode BCJ2.
         * Decoding BCJ2 requires four sources. Those are at least,
         * as far as I know, two types of the storage form.
         */
        let mut fc: *const _7z_coder = (safe_folder).coders;
        static mut coder_copy: _7z_coder = {
            let mut init = _7z_coder {
                codec: 0 as i32 as u64,
                numInStreams: 1 as i32 as uint64_t,
                numOutStreams: 1 as i32 as uint64_t,
                propertiesSize: 0 as i32 as uint64_t,
                properties: 0 as *const u8 as *mut u8,
            };
            init
        };
        let mut scoder: [*const _7z_coder; 3] = unsafe { [&coder_copy, &coder_copy, &coder_copy] };
        let mut buff: *const () = 0 as *const ();
        let mut bytes: ssize_t = 0;
        let mut b: [*mut u8; 3] = [0 as *mut u8, 0 as *mut u8, 0 as *mut u8];
        let mut sunpack: [uint64_t; 3] = [
            -(1 as i32) as uint64_t,
            -(1 as i32) as uint64_t,
            -(1 as i32) as uint64_t,
        ];
        let mut s: [size_t; 3] = [0 as i32 as size_t, 0 as i32 as size_t, 0 as i32 as size_t];
        let mut idx: [i32; 3] = [0 as i32, 1 as i32, 2 as i32];
        if unsafe {
            (safe_folder).numCoders == 4 as i32 as u64
                && (*fc.offset(3 as i32 as isize)).codec == 0x303011b as i32 as u64
                && (safe_folder).numInStreams == 7 as i32 as u64
                && (safe_folder).numOutStreams == 4 as i32 as u64
                && (safe_zip).pack_stream_remaining == 4 as i32 as u32
        } {
            /* Source type 1 made by 7zr or 7z with -m options. */
            if unsafe {
                (*(safe_folder).bindPairs.offset(0 as i32 as isize)).inIndex == 5 as i32 as u64
            } {
                /* The form made by 7zr */
                idx[0 as i32 as usize] = 1 as i32;
                idx[1 as i32 as usize] = 2 as i32;
                idx[2 as i32 as usize] = 0 as i32;
                unsafe {
                    scoder[1 as i32 as usize] = &*fc.offset(1 as i32 as isize) as *const _7z_coder;
                    scoder[2 as i32 as usize] = &*fc.offset(0 as i32 as isize) as *const _7z_coder;
                    sunpack[1 as i32 as usize] = *(*folder).unPackSize.offset(1 as i32 as isize);
                    sunpack[2 as i32 as usize] = *(*folder).unPackSize.offset(0 as i32 as isize);
                    coder1 = &*fc.offset(2 as i32 as isize) as *const _7z_coder
                }
            } else if unsafe {
                (*fc.offset(0 as i32 as isize)).codec == 0 as i32 as u64
                    && (*fc.offset(1 as i32 as isize)).codec == 0 as i32 as u64
            } {
                coder1 =
                    unsafe { &mut *(*folder).coders.offset(2 as i32 as isize) as *mut _7z_coder }
            } else if unsafe {
                (*fc.offset(0 as i32 as isize)).codec == 0 as i32 as u64
                    && (*fc.offset(2 as i32 as isize)).codec == 0 as i32 as u64
            } {
                coder1 =
                    unsafe { &mut *(*folder).coders.offset(1 as i32 as isize) as *mut _7z_coder }
            } else if unsafe {
                (*fc.offset(1 as i32 as isize)).codec == 0 as i32 as u64
                    && (*fc.offset(2 as i32 as isize)).codec == 0 as i32 as u64
            } {
                coder1 =
                    unsafe { &mut *(*folder).coders.offset(0 as i32 as isize) as *mut _7z_coder }
            } else {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as i32),
                        b"Unsupported form of BCJ2 streams\x00" as *const u8,
                    )
                };
                return -(30 as i32);
            }
            coder2 = unsafe { &*fc.offset(3 as i32 as isize) as *const _7z_coder };
            (safe_zip).main_stream_bytes_remaining =
                unsafe { *(safe_folder).unPackSize.offset(2 as i32 as isize) }
        } else if unsafe {
            !coder2.is_null()
                && (*coder2).codec == 0x303011b as i32 as u64
                && (safe_zip).pack_stream_remaining == 4 as i32 as u32
                && (safe_folder).numInStreams == 5 as i32 as u64
                && (safe_folder).numOutStreams == 2 as i32 as u64
        } {
            /*
             * NOTE: Some patterns do not work.
             * work:
             *  7z a -m0=BCJ2 -m1=COPY -m2=COPY
             *       -m3=(any)
             *  7z a -m0=BCJ2 -m1=COPY -m2=(any)
             *       -m3=COPY
             *  7z a -m0=BCJ2 -m1=(any) -m2=COPY
             *       -m3=COPY
             * not work:
             *  other patterns.
             *
             * We have to handle this like `pipe' or
             * our libarchive7s filter frame work,
             * decoding the BCJ2 main stream sequentially,
             * m3 -> m2 -> m1 -> BCJ2.
             *
             */
            /* Source type 0 made by 7z */
            (safe_zip).main_stream_bytes_remaining =
                unsafe { *(safe_folder).unPackSize.offset(0 as i32 as isize) }
        } else {
            /* We got an unexpected form. */
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as i32),
                    b"Unsupported form of BCJ2 streams\x00" as *const u8,
                )
            };
            return -(30 as i32);
        }
        /* Skip the main stream at this time. */
        r = seek_pack(a);
        if r < 0 as i32 {
            return r;
        }
        (safe_zip).pack_stream_bytes_unconsumed = (safe_zip).pack_stream_inbytes_remaining;
        read_consume(a);
        /* Read following three sub streams. */
        i = 0 as i32 as u32;
        while i < 3 as i32 as u32 {
            let mut coder: *const _7z_coder = scoder[i as usize];
            r = seek_pack(a);
            if r < 0 as i32 {
                free_safe(b[0 as i32 as usize] as *mut ());
                free_safe(b[1 as i32 as usize] as *mut ());
                free_safe(b[2 as i32 as usize] as *mut ());
                return r;
            }
            if sunpack[i as usize] == -(1 as i32) as uint64_t {
                (safe_zip).folder_outbytes_remaining = (safe_zip).pack_stream_inbytes_remaining
            } else {
                (safe_zip).folder_outbytes_remaining = sunpack[i as usize]
            }
            r = init_decompression(a, zip, coder, 0 as *const _7z_coder);
            if r != 0 as i32 {
                free_safe(b[0 as i32 as usize] as *mut ());
                free_safe(b[1 as i32 as usize] as *mut ());
                free_safe(b[2 as i32 as usize] as *mut ());
                return -(30 as i32);
            }
            /* Allocate memory for the decoded data of a sub
             * stream. */
            b[i as usize] = malloc_safe((safe_zip).folder_outbytes_remaining) as *mut u8;
            if b[i as usize].is_null() {
                free_safe(b[0 as i32 as usize] as *mut ());
                free_safe(b[1 as i32 as usize] as *mut ());
                free_safe(b[2 as i32 as usize] as *mut ());
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        12 as i32,
                        b"No memory for 7-Zip decompression\x00" as *const u8,
                    )
                };
                return -(30 as i32);
            }
            /* Extract a sub stream. */
            while (safe_zip).pack_stream_inbytes_remaining > 0 as i32 as u64 {
                r = extract_pack_stream(a, 0 as i32 as size_t) as i32;
                if r < 0 as i32 {
                    free_safe(b[0 as i32 as usize] as *mut ());
                    free_safe(b[1 as i32 as usize] as *mut ());
                    free_safe(b[2 as i32 as usize] as *mut ());
                    return r;
                }
                bytes = get_uncompressed_data(
                    a,
                    &mut buff,
                    (safe_zip).uncompressed_buffer_bytes_remaining,
                    0 as i32 as size_t,
                );
                if bytes < 0 as i32 as i64 {
                    free_safe(b[0 as i32 as usize] as *mut ());
                    free_safe(b[1 as i32 as usize] as *mut ());
                    free_safe(b[2 as i32 as usize] as *mut ());
                    return bytes as i32;
                }
                memcpy_safe(
                    unsafe { b[i as usize].offset(s[i as usize] as isize) as *mut () },
                    buff,
                    bytes as u64,
                );
                s[i as usize] =
                    (s[i as usize] as u64).wrapping_add(bytes as u64) as size_t as size_t;
                if (safe_zip).pack_stream_bytes_unconsumed != 0 {
                    read_consume(a);
                }
                safe_zip = unsafe { &mut *((*(*a).format).data as *mut _7zip) };
            }
            i = i.wrapping_add(1)
        }
        /* Set the sub streams to the right place. */
        i = 0 as i32 as u32;
        while i < 3 as i32 as u32 {
            (safe_zip).sub_stream_buff[i as usize] = b[idx[i as usize] as usize];
            (safe_zip).sub_stream_size[i as usize] = s[idx[i as usize] as usize];
            (safe_zip).sub_stream_bytes_remaining[i as usize] = s[idx[i as usize] as usize];
            i = i.wrapping_add(1)
        }
        /* Allocate memory used for decoded main stream bytes. */
        if (safe_zip).tmp_stream_buff.is_null() {
            (safe_zip).tmp_stream_buff_size = (32 as i32 * 1024 as i32) as size_t;
            (safe_zip).tmp_stream_buff = malloc_safe((safe_zip).tmp_stream_buff_size) as *mut u8;
            if (safe_zip).tmp_stream_buff.is_null() {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        12 as i32,
                        b"No memory for 7-Zip decompression\x00" as *const u8,
                    )
                };
                return -(30 as i32);
            }
        }
        (safe_zip).tmp_stream_bytes_avail = 0 as i32 as size_t;
        (safe_zip).tmp_stream_bytes_remaining = 0 as i32 as size_t;
        (safe_zip).odd_bcj_size = 0 as i32 as size_t;
        (safe_zip).bcj2_outPos = 0 as i32 as uint64_t;
        /*
         * Reset a stream reader in order to read the main stream
         * of BCJ2.
         */
        (safe_zip).pack_stream_remaining = 1 as i32 as u32;
        (safe_zip).pack_stream_index = (safe_folder).packIndex;
        (safe_zip).folder_outbytes_remaining = folder_uncompressed_size(folder);
        (safe_zip).uncompressed_buffer_bytes_remaining = 0 as i32 as size_t
    }
    /*
     * Initialize the decompressor for the new folder's pack streams.
     */
    r = init_decompression(a, zip, coder1, coder2);
    if r != 0 as i32 {
        return -(30 as i32);
    }
    return 0 as i32;
}

unsafe fn skip_stream(mut a: *mut archive_read, mut skip_bytes: size_t) -> int64_t {
    unsafe {
        let mut zip: *mut _7zip = (*(*a).format).data as *mut _7zip;
        let mut p: *const () = 0 as *const ();
        let mut skipped_bytes: int64_t = 0;
        let mut bytes: size_t = skip_bytes;
        if (*zip).folder_index == 0 as i32 as u32 {
            /*
             * Optimization for a list mode.
             * Avoid unnecessary decoding operations.
             */
            let ref mut fresh15 = (*(*zip)
                .si
                .ci
                .folders
                .offset((*(*zip).entry).folderIndex as isize))
            .skipped_bytes;
            *fresh15 = (*fresh15 as u64).wrapping_add(skip_bytes) as uint64_t as uint64_t;
            return skip_bytes as int64_t;
        }
        while bytes != 0 {
            skipped_bytes = read_stream(a, &mut p, bytes, 0 as i32 as size_t);
            if skipped_bytes < 0 as i32 as i64 {
                return skipped_bytes;
            }
            if skipped_bytes == 0 as i32 as i64 {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    84 as i32,
                    b"Truncated 7-Zip file body\x00" as *const u8,
                );
                return -(30 as i32) as int64_t;
            }
            bytes = (bytes as u64).wrapping_sub(skipped_bytes as size_t) as size_t as size_t;
            if (*zip).pack_stream_bytes_unconsumed != 0 {
                read_consume(a);
            }
        }
        return skip_bytes as int64_t;
    }
}

unsafe fn x86_Init(mut zip: *mut _7zip) {
    let safe_zip = unsafe { &mut *zip };
    safe_zip.bcj_state = 0 as i32 as uint32_t;
    safe_zip.bcj_prevPosT = unsafe { (0 as i32 as size_t).wrapping_sub(1 as i32 as u64) };
    safe_zip.bcj_prevMask = 0 as i32 as uint32_t;
    safe_zip.bcj_ip = 5 as i32 as uint32_t;
}

unsafe fn x86_Convert(mut zip: *mut _7zip, mut data: *mut uint8_t, mut size: size_t) -> size_t {
    static mut kMaskToAllowedStatus: [uint8_t; 8] = [
        1 as i32 as uint8_t,
        1 as i32 as uint8_t,
        1 as i32 as uint8_t,
        0 as i32 as uint8_t,
        1 as i32 as uint8_t,
        0 as i32 as uint8_t,
        0 as i32 as uint8_t,
        0 as i32 as uint8_t,
    ];
    static mut kMaskToBitNumber: [uint8_t; 8] = [
        0 as i32 as uint8_t,
        1 as i32 as uint8_t,
        2 as i32 as uint8_t,
        2 as i32 as uint8_t,
        3 as i32 as uint8_t,
        3 as i32 as uint8_t,
        3 as i32 as uint8_t,
        3 as i32 as uint8_t,
    ];
    let mut bufferPos: size_t = 0;
    let mut prevPosT: size_t = 0;
    let mut ip: uint32_t = 0;
    let mut prevMask: uint32_t = 0;
    let safe_zip = unsafe { &mut *zip };
    if size < 5 as i32 as u64 {
        return 0 as i32 as size_t;
    }
    bufferPos = 0 as i32 as size_t;
    prevPosT = (safe_zip).bcj_prevPosT;
    prevMask = (safe_zip).bcj_prevMask;
    ip = (safe_zip).bcj_ip;
    loop {
        let mut p: *mut uint8_t = unsafe { data.offset(bufferPos as isize) };
        let mut limit: *mut uint8_t =
            unsafe { data.offset(size as isize).offset(-(4 as i32 as isize)) };
        unsafe {
            while p < limit {
                if *p as i32 & 0xfe as i32 == 0xe8 as i32 {
                    break;
                }
                p = p.offset(1)
            }
        }
        bufferPos = unsafe { p.offset_from(data) as i64 as size_t };
        if p >= limit {
            break;
        }
        prevPosT = bufferPos.wrapping_sub(prevPosT);
        if prevPosT > 3 as i32 as u64 {
            prevMask = 0 as i32 as uint32_t
        } else {
            prevMask = prevMask << prevPosT as i32 - 1 as i32 & 0x7 as i32 as u32;
            if prevMask != 0 as i32 as u32 {
                let mut b: u8 = unsafe {
                    *p.offset((4 as i32 - kMaskToBitNumber[prevMask as usize] as i32) as isize)
                };
                if unsafe {
                    kMaskToAllowedStatus[prevMask as usize] == 0
                        || (b as i32 == 0 as i32 || b as i32 == 0xff as i32)
                } {
                    prevPosT = bufferPos;
                    prevMask = prevMask << 1 as i32 & 0x7 as i32 as u32 | 1 as i32 as u32;
                    bufferPos = bufferPos.wrapping_add(1);
                    continue;
                }
            }
        }
        prevPosT = bufferPos;
        if unsafe {
            *p.offset(4 as i32 as isize) as i32 == 0 as i32
                || *p.offset(4 as i32 as isize) as i32 == 0xff as i32
        } {
            let mut src: uint32_t = unsafe {
                (*p.offset(4 as i32 as isize) as uint32_t) << 24 as i32
                    | (*p.offset(3 as i32 as isize) as uint32_t) << 16 as i32
                    | (*p.offset(2 as i32 as isize) as uint32_t) << 8 as i32
                    | *p.offset(1 as i32 as isize) as uint32_t
            };
            let mut dest: uint32_t = 0;
            loop {
                let mut b_0: uint8_t = 0;
                let mut b_index: i32 = 0;
                dest = src.wrapping_sub(ip.wrapping_add(bufferPos as uint32_t));
                if prevMask == 0 as i32 as u32 {
                    break;
                }
                b_index = unsafe { kMaskToBitNumber[prevMask as usize] as i32 * 8 as i32 };
                b_0 = (dest >> 24 as i32 - b_index) as uint8_t;
                if !(b_0 as i32 == 0 as i32 || b_0 as i32 == 0xff as i32) {
                    break;
                }
                src = dest ^ (((1 as i32) << 32 as i32 - b_index) - 1 as i32) as u32
            }
            unsafe {
                *p.offset(4 as i32 as isize) =
                    !(dest >> 24 as i32 & 1 as i32 as u32).wrapping_sub(1 as i32 as u32) as uint8_t;
                *p.offset(3 as i32 as isize) = (dest >> 16 as i32) as uint8_t;
                *p.offset(2 as i32 as isize) = (dest >> 8 as i32) as uint8_t;
                *p.offset(1 as i32 as isize) = dest as uint8_t;
            }
            bufferPos = (bufferPos as u64).wrapping_add(5 as i32 as u64) as size_t as size_t
        } else {
            prevMask = prevMask << 1 as i32 & 0x7 as i32 as u32 | 1 as i32 as u32;
            bufferPos = bufferPos.wrapping_add(1)
        }
    }
    (safe_zip).bcj_prevPosT = prevPosT;
    (safe_zip).bcj_prevMask = prevMask;
    (safe_zip).bcj_ip =
        ((safe_zip).bcj_ip as u32).wrapping_add(bufferPos as uint32_t) as uint32_t as uint32_t;
    return bufferPos;
}
unsafe fn Bcj2_Decode(
    mut zip: *mut _7zip,
    mut outBuf: *mut uint8_t,
    mut outSize: size_t,
) -> ssize_t {
    unsafe {
        let mut inPos: size_t = 0 as i32 as size_t;
        let mut outPos: size_t = 0 as i32 as size_t;
        let mut buf0: *const uint8_t = 0 as *const uint8_t;
        let mut buf1: *const uint8_t = 0 as *const uint8_t;
        let mut buf2: *const uint8_t = 0 as *const uint8_t;
        let mut buf3: *const uint8_t = 0 as *const uint8_t;
        let mut size0: size_t = 0;
        let mut size1: size_t = 0;
        let mut size2: size_t = 0;
        let mut size3: size_t = 0;
        let mut buffer: *const uint8_t = 0 as *const uint8_t;
        let mut bufferLim: *const uint8_t = 0 as *const uint8_t;
        let mut i: u32 = 0;
        let mut j: u32 = 0;
        let safe_zip = unsafe { &mut *zip };
        size0 = safe_zip.tmp_stream_bytes_remaining;
        buf0 = unsafe {
            safe_zip
                .tmp_stream_buff
                .offset(safe_zip.tmp_stream_bytes_avail as isize)
                .offset(-(size0 as isize))
        };
        size1 = safe_zip.sub_stream_bytes_remaining[0 as i32 as usize];
        buf1 = unsafe {
            safe_zip.sub_stream_buff[0 as i32 as usize]
                .offset(safe_zip.sub_stream_size[0 as i32 as usize] as isize)
                .offset(-(size1 as isize))
        };
        size2 = safe_zip.sub_stream_bytes_remaining[1 as i32 as usize];
        buf2 = unsafe {
            safe_zip.sub_stream_buff[1 as i32 as usize]
                .offset(safe_zip.sub_stream_size[1 as i32 as usize] as isize)
                .offset(-(size2 as isize))
        };
        size3 = safe_zip.sub_stream_bytes_remaining[2 as i32 as usize];
        buf3 = unsafe {
            safe_zip.sub_stream_buff[2 as i32 as usize]
                .offset(safe_zip.sub_stream_size[2 as i32 as usize] as isize)
                .offset(-(size3 as isize))
        };
        buffer = buf3;
        bufferLim = unsafe { buffer.offset(size3 as isize) };
        if safe_zip.bcj_state == 0 as i32 as u32 {
            /*
             * Initialize.
             */
            safe_zip.bcj2_prevByte = 0 as i32 as uint8_t;
            i = 0 as i32 as u32;
            while (i as u64)
                < (size_of::<[uint16_t; 258]>() as u64).wrapping_div(size_of::<uint16_t>() as u64)
            {
                safe_zip.bcj2_p[i as usize] = ((1 as i32) << 11 as i32 >> 1 as i32) as uint16_t;
                i = i.wrapping_add(1)
            }
            safe_zip.bcj2_code = 0 as i32 as uint32_t;
            safe_zip.bcj2_range = 0xffffffff as u32;
            let mut ii: i32 = 0;
            ii = 0 as i32;
            while ii < 5 as i32 {
                if buffer == bufferLim {
                    return -(25 as i32) as ssize_t;
                }
                let fresh16 = buffer;
                buffer = unsafe { buffer.offset(1) };
                safe_zip.bcj2_code = safe_zip.bcj2_code << 8 as i32 | *fresh16 as u32;
                ii += 1
            }
            safe_zip.bcj_state = 1 as i32 as uint32_t
        }
        /*
         * Gather the odd bytes of a previous call.
         */
        i = 0 as i32 as u32;
        while safe_zip.odd_bcj_size > 0 as i32 as u64 && outPos < outSize {
            let fresh17 = outPos;
            outPos = outPos.wrapping_add(1);
            unsafe { *outBuf.offset(fresh17 as isize) = safe_zip.odd_bcj[i as usize] };
            safe_zip.odd_bcj_size = safe_zip.odd_bcj_size.wrapping_sub(1);
            i = i.wrapping_add(1)
        }
        if outSize == 0 as i32 as u64 {
            safe_zip.bcj2_outPos =
                (safe_zip.bcj2_outPos as u64).wrapping_add(outPos) as uint64_t as uint64_t;
            return outPos as ssize_t;
        }
        loop {
            let mut b: uint8_t = 0;
            let mut prob: *mut uint16_t = 0 as *mut uint16_t;
            let mut bound: uint32_t = 0;
            let mut ttt: uint32_t = 0;
            let mut limit: size_t = size0.wrapping_sub(inPos);
            if outSize.wrapping_sub(outPos) < limit {
                limit = outSize.wrapping_sub(outPos)
            }
            if safe_zip.bcj_state == 1 as i32 as u32 {
                while limit != 0 as i32 as u64 {
                    let mut bb: uint8_t = *buf0.offset(inPos as isize);
                    let fresh18 = outPos;
                    outPos = outPos.wrapping_add(1);
                    unsafe { *outBuf.offset(fresh18 as isize) = bb };
                    if bb as i32 & 0xfe as i32 == 0xe8 as i32
                        || safe_zip.bcj2_prevByte as i32 == 0xf as i32
                            && bb as i32 & 0xf0 as i32 == 0x80 as i32
                    {
                        safe_zip.bcj_state = 2 as i32 as uint32_t;
                        break;
                    } else {
                        inPos = inPos.wrapping_add(1);
                        safe_zip.bcj2_prevByte = bb;
                        limit = limit.wrapping_sub(1)
                    }
                }
            }
            if limit == 0 as i32 as u64 || outPos == outSize {
                break;
            }
            safe_zip.bcj_state = 1 as i32 as uint32_t;
            let fresh19 = inPos;
            inPos = inPos.wrapping_add(1);
            b = unsafe { *buf0.offset(fresh19 as isize) };
            if b as i32 == 0xe8 as i32 {
                prob = unsafe {
                    safe_zip
                        .bcj2_p
                        .as_mut_ptr()
                        .offset(safe_zip.bcj2_prevByte as i32 as isize)
                }
            } else if b as i32 == 0xe9 as i32 {
                prob = unsafe { safe_zip.bcj2_p.as_mut_ptr().offset(256 as i32 as isize) }
            } else {
                prob = unsafe { safe_zip.bcj2_p.as_mut_ptr().offset(257 as i32 as isize) }
            }
            ttt = unsafe { *prob as uint32_t };
            bound = (safe_zip.bcj2_range >> 11 as i32).wrapping_mul(ttt);
            if safe_zip.bcj2_code < bound {
                safe_zip.bcj2_range = bound;
                unsafe {
                    *prob = ttt.wrapping_add(
                        (((1 as i32) << 11 as i32) as u32).wrapping_sub(ttt) >> 5 as i32,
                    ) as uint16_t
                };
                if safe_zip.bcj2_range < (1 as i32 as uint32_t) << 24 as i32 {
                    if buffer == bufferLim {
                        return -(25 as i32) as ssize_t;
                    }
                    safe_zip.bcj2_range <<= 8 as i32;
                    let fresh20 = buffer;
                    buffer = unsafe { buffer.offset(1) };
                    safe_zip.bcj2_code = unsafe { safe_zip.bcj2_code << 8 as i32 | *fresh20 as u32 }
                }
                safe_zip.bcj2_prevByte = b
            } else {
                let mut dest: uint32_t = 0;
                let mut v: *const uint8_t = 0 as *const uint8_t;
                let mut out: [uint8_t; 4] = [0; 4];
                safe_zip.bcj2_range =
                    (safe_zip.bcj2_range as u32).wrapping_sub(bound) as uint32_t as uint32_t;
                safe_zip.bcj2_code =
                    (safe_zip.bcj2_code as u32).wrapping_sub(bound) as uint32_t as uint32_t;
                unsafe { *prob = ttt.wrapping_sub(ttt >> 5 as i32) as uint16_t };
                if safe_zip.bcj2_range < (1 as i32 as uint32_t) << 24 as i32 {
                    if buffer == bufferLim {
                        return -(25 as i32) as ssize_t;
                    }
                    safe_zip.bcj2_range <<= 8 as i32;
                    let fresh21 = buffer;
                    buffer = buffer.offset(1);
                    safe_zip.bcj2_code = safe_zip.bcj2_code << 8 as i32 | *fresh21 as u32
                }
                if b as i32 == 0xe8 as i32 {
                    v = buf1;
                    if size1 < 4 as i32 as u64 {
                        return -(25 as i32) as ssize_t;
                    }
                    buf1 = buf1.offset(4 as i32 as isize);
                    size1 = (size1 as u64).wrapping_sub(4 as i32 as u64) as size_t as size_t
                } else {
                    v = buf2;
                    if size2 < 4 as i32 as u64 {
                        return -(25 as i32) as ssize_t;
                    }
                    buf2 = unsafe { buf2.offset(4 as i32 as isize) };
                    size2 = (size2 as u64).wrapping_sub(4 as i32 as u64) as size_t as size_t
                }
                dest = unsafe {
                    ((*v.offset(0 as i32 as isize) as uint32_t) << 24 as i32
                        | (*v.offset(1 as i32 as isize) as uint32_t) << 16 as i32
                        | (*v.offset(2 as i32 as isize) as uint32_t) << 8 as i32
                        | *v.offset(3 as i32 as isize) as uint32_t)
                        .wrapping_sub(
                            ((*zip).bcj2_outPos as uint32_t)
                                .wrapping_add(outPos as uint32_t)
                                .wrapping_add(4 as i32 as u32),
                        )
                };
                out[0 as i32 as usize] = dest as uint8_t;
                out[1 as i32 as usize] = (dest >> 8 as i32) as uint8_t;
                out[2 as i32 as usize] = (dest >> 16 as i32) as uint8_t;
                safe_zip.bcj2_prevByte = (dest >> 24 as i32) as uint8_t;
                out[3 as i32 as usize] = safe_zip.bcj2_prevByte;
                i = 0 as i32 as u32;
                while i < 4 as i32 as u32 && outPos < outSize {
                    let fresh22 = outPos;
                    outPos = outPos.wrapping_add(1);
                    unsafe { *outBuf.offset(fresh22 as isize) = out[i as usize] };
                    i = i.wrapping_add(1)
                }
                if !(i < 4 as i32 as u32) {
                    continue;
                }
                /*
                 * Save odd bytes which we could not add into
                 * the output buffer because of out of space.
                 */
                safe_zip.odd_bcj_size = (4 as i32 as u32).wrapping_sub(i) as size_t;
                while i < 4 as i32 as u32 {
                    j = i
                        .wrapping_sub(4 as i32 as u32)
                        .wrapping_add(safe_zip.odd_bcj_size as u32);
                    safe_zip.odd_bcj[j as usize] = out[i as usize];
                    i = i.wrapping_add(1)
                }
                break;
            }
        }
        safe_zip.tmp_stream_bytes_remaining =
            (safe_zip.tmp_stream_bytes_remaining as u64).wrapping_sub(inPos) as size_t as size_t;
        safe_zip.sub_stream_bytes_remaining[0 as i32 as usize] = size1;
        safe_zip.sub_stream_bytes_remaining[1 as i32 as usize] = size2;
        safe_zip.sub_stream_bytes_remaining[2 as i32 as usize] =
            bufferLim.offset_from(buffer) as i64 as size_t;
        safe_zip.bcj2_outPos =
            (safe_zip.bcj2_outPos as u64).wrapping_add(outPos) as uint64_t as uint64_t;
        return outPos as ssize_t;
    }
}

#[no_mangle]
pub unsafe fn archive_test_check_7zip_header_in_sfx(mut p: *const u8) {
    check_7zip_header_in_sfx(p);
}

#[no_mangle]
pub unsafe fn archive_test_skip_sfx(mut _a: *mut archive, mut bytes_avail: ssize_t) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    skip_sfx(a, bytes_avail);
}

#[no_mangle]
pub unsafe fn archive_test_init_decompression(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut _7zip: *mut _7zip = 0 as *mut _7zip;
    _7zip = calloc_safe(1 as i32 as u64, size_of::<_7zip>() as u64) as *mut _7zip;
    let mut coder1: *mut _7z_coder = 0 as *mut _7z_coder;
    coder1 = calloc_safe(1 as i32 as u64, size_of::<_7z_coder>() as u64) as *mut _7z_coder;
    let mut coder2: *mut _7z_coder = 0 as *mut _7z_coder;
    coder2 = calloc_safe(1 as i32 as u64, size_of::<_7z_coder>() as u64) as *mut _7z_coder;
    (*(coder1)).codec = 0x030401 as u64;
    (*(coder1)).propertiesSize = 4 as uint64_t;
    (*(_7zip)).ppmd7_valid = 1 as i32;
    (*(coder2)).codec = 0x03030103 as u64;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x030401 as u64;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder1)).codec = 0x21 as u64;
    (*(coder2)).codec = 0x03030205 as u64;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x03030401 as u64;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x03030501 as u64;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x03030701 as u64;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x03030104 as u64;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x03030805 as u64;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder1)).codec = 0x03 as u64;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder1)).codec = 0x06F10702 as u64;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder1)).codec = 0x06F10701 as u64;
    init_decompression(a, _7zip, coder1, coder2);
}

#[no_mangle]
pub unsafe fn archive_test_archive_read_support_format_7zip() {
    let mut archive_read: *mut archive_read = 0 as *mut archive_read;
    archive_read = unsafe { calloc_safe(1 as i32 as u64, size_of::<archive_read>() as u64) }
        as *mut archive_read;
    (*archive_read).archive.magic = ARCHIVE_AR_DEFINED_PARAM.archive_read_magic;
    (*archive_read).archive.state = ARCHIVE_AR_DEFINED_PARAM.archive_state_new;
    archive_read_support_format_7zip(&mut (*archive_read).archive as *mut archive);
}

#[no_mangle]
pub unsafe fn archive_test_ppmd_read(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    zip = calloc_safe(1 as i32 as u64, size_of::<_7zip>() as u64) as *mut _7zip;
    (*zip).ppstream.avail_in = 0;
    let mut ibytein: *mut IByteIn = 0 as *mut IByteIn;
    ibytein = calloc_safe(1 as i32 as u64, size_of::<IByteIn>() as u64) as *mut IByteIn;
    (*ibytein).a = a as *mut archive_read;
    let mut p: *mut () = ibytein as *mut ();
    ppmd_read(p);
}

#[no_mangle]
pub unsafe fn archive_test_decompress(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    zip = calloc_safe(1 as i32 as u64, size_of::<_7zip>() as u64) as *mut _7zip;
    (*zip).codec = 0x20;
    (*zip).codec2 = 0x03030103;
    (*zip).odd_bcj_size = 1;
    let mut buff2: *mut () = 0 as *const () as *mut ();
    let mut b2: *const () = 0 as *const ();
    let mut outbytes: size_t = 0;
    let mut outbytes2: *mut size_t = &outbytes as *const size_t as *mut size_t;
    let mut used: size_t = 0;
    let mut used2: *mut size_t = &used as *const size_t as *mut size_t;
    decompress(a, zip, buff2, outbytes2, b2, used2);
    (*zip).codec2 = 0x0303011B;
    (*zip).tmp_stream_bytes_remaining = 1;
    let mut used4: size_t = 0;
    let mut used3: *mut size_t = &used4 as *const size_t as *mut size_t;
    decompress(a, zip, buff2, outbytes2, b2, used3);
    (*zip).codec2 = 0x03030111;
    (*zip).codec = 0x030401;
    (*zip).ppmd7_valid = 0;
    decompress(a, zip, buff2, outbytes2, b2, used3);
    (*zip).ppmd7_valid = 1;
    (*zip).ppmd7_stat = 0;
    (*zip).ppmd7_valid = 1;
    (*zip).ppmd7_stat = 0;
    (*zip).ppstream.overconsumed = 1;
    let mut outbytes4: size_t = 0;
    let mut outbytes3: *mut size_t = &outbytes4 as *const size_t as *mut size_t;
    decompress(a, zip, buff2, outbytes3, b2, used3);
    (*zip).codec = 0x030401;
    decompress(a, zip, buff2, outbytes3, b2, used3);
    (*zip).codec = 0;
    (*zip).codec2 = 0x0303011B;
    (*zip).tmp_stream_buff_size = 20;
    (*zip).main_stream_bytes_remaining = 1;
    decompress(a, zip, buff2, outbytes3, b2, used3);
}

#[no_mangle]
pub unsafe fn archive_test_Bcj2_Decode() {
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    zip = calloc_safe(1 as i32 as u64, size_of::<_7zip>() as u64) as *mut _7zip;
    (*zip).bcj_state = 1;
    (*zip).odd_bcj[0] = 'a' as u8;
    (*zip).odd_bcj[1] = 'b' as u8;
    (*zip).odd_bcj_size = 1;
    let mut p: [uint8_t; 3] = [1 as uint8_t, 2 as uint8_t, 3 as uint8_t];
    let mut outBuf: *mut uint8_t = &p as *const [uint8_t; 3] as *mut [uint8_t; 3] as *mut uint8_t;
    Bcj2_Decode(zip, outBuf, 1);
}

#[no_mangle]
pub unsafe fn archive_test_x86_Convert() {
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    zip = calloc_safe(1 as i32 as u64, size_of::<_7zip>() as u64) as *mut _7zip;
    (*zip).bcj_prevMask = 0x7;
    (*zip).bcj_prevPosT = 2;
    (*zip).bcj_ip = 0;
    let mut data4: [uint8_t; 6] = [
        0xE8 as uint8_t,
        0xE8 as uint8_t,
        0xE8 as uint8_t,
        0xE8 as uint8_t,
        0xE8 as uint8_t,
        0xE8 as uint8_t,
    ];
    let mut data3: *mut uint8_t =
        &data4 as *const [uint8_t; 6] as *mut [uint8_t; 6] as *mut uint8_t;
    x86_Convert(zip, data3, 6);
    let mut data2: [uint8_t; 6] = [
        0xE8 as uint8_t,
        0xE8 as uint8_t,
        0xE8 as uint8_t,
        0xE8 as uint8_t,
        0xE8 as uint8_t,
        0xE8 as uint8_t,
    ];
    let mut data: *mut uint8_t = &data2 as *const [uint8_t; 6] as *mut [uint8_t; 6] as *mut uint8_t;
    (*zip).bcj_prevMask = 15;
    (*zip).bcj_prevPosT = 3;
    (*zip).bcj_ip = 0;
    x86_Convert(zip, data, 6);
}

#[no_mangle]
pub unsafe fn archive_test_seek_pack(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    zip = calloc_safe(1 as i32 as u64, size_of::<_7zip>() as u64) as *mut _7zip;
    (*(*a).format).data = zip as *mut ();
    (*zip).pack_stream_remaining = 0;
    seek_pack(a);
}

#[no_mangle]
pub unsafe fn archive_test_extract_pack_stream(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    zip = calloc_safe(1 as i32 as u64, size_of::<_7zip>() as u64) as *mut _7zip;
    (*(*a).format).data = zip as *mut ();
    extract_pack_stream(a, (64 * 1024) + 1);
    let mut p1: [u8; 2] = ['1' as u8, '2' as u8];
    let mut p2: *mut u8 = &p1 as *const [u8; 2] as *mut [u8; 2] as *mut u8;
    let mut p3: [u8; 2] = ['1' as u8, '2' as u8];
    let mut p4: *mut u8 = &p3 as *const [u8; 2] as *mut [u8; 2] as *mut u8;
    (*zip).uncompressed_buffer = p2;
    (*zip).uncompressed_buffer_pointer = p4;
    (*zip).uncompressed_buffer_size = 1;
    extract_pack_stream(a, 0);
}

#[no_mangle]
pub unsafe fn archive_test_get_uncompressed_data(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut buff: *mut () = 0 as *const () as *mut ();
    let mut buff2: *mut *const () =
        unsafe { &buff as *const *mut () as *mut *mut () as *mut *const () };
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    zip = calloc_safe(1 as i32 as u64, size_of::<_7zip>() as u64) as *mut _7zip;
    (*(*a).format).data = zip as *mut ();
    get_uncompressed_data(a, buff2, 1, 1);
    (*zip).codec = 0;
    (*zip).codec2 = 1;
    let mut archive_read_filter: *mut archive_read_filter = 0 as *mut archive_read_filter;
    archive_read_filter = calloc_safe(1 as i32 as u64, size_of::<archive_read_filter>() as u64)
        as *mut archive_read_filter;
    (*archive_read_filter).fatal = 'a' as u8;
    (*a).filter = archive_read_filter;
    get_uncompressed_data(a, buff2, 1, 1);
}

#[no_mangle]
pub unsafe fn archive_test_decode_encoded_header_info(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut _7z_stream_info: *mut _7z_stream_info = 0 as *mut _7z_stream_info;
    _7z_stream_info =
        calloc_safe(1 as i32 as u64, size_of::<_7z_stream_info>() as u64) as *mut _7z_stream_info;
    (*_7z_stream_info).pi.numPackStreams = 0;
    decode_encoded_header_info(a, _7z_stream_info);
}

#[no_mangle]
pub unsafe fn archive_test_fileTimeToUtc() {
    let mut timepp: [time_t; 2] = [1 as time_t, 2 as time_t];
    let mut timep: *mut time_t = &timepp as *const [time_t; 2] as *mut [time_t; 2] as *mut time_t;
}

#[no_mangle]
pub unsafe fn archive_test_archive_read_format_7zip_bid(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut filter: *mut archive_read_filter = 0 as *mut archive_read_filter;
    filter = calloc_safe(1 as i32 as u64, size_of::<archive_read_filter>() as u64)
        as *mut archive_read_filter;
    (*filter).avail = 4096;
    (*filter).client_total = 0x27000 + 4096;
    (*filter).client_avail = 0x27000;
    archive_read_format_7zip_bid(a, 31);
}

#[no_mangle]
pub unsafe fn archive_test_read_stream(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut buff: *mut () = 0 as *const () as *mut ();
    let mut buff2: *mut *const () =
        unsafe { &buff as *const *mut () as *mut *mut () as *mut *const () };
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    zip = calloc_safe(1 as i32 as u64, size_of::<_7zip>() as u64) as *mut _7zip;
    let mut _7zip_entry: *mut _7zip_entry = 0 as *mut _7zip_entry;
    _7zip_entry = calloc_safe(1 as i32 as u64, size_of::<_7zip_entry>() as u64) as *mut _7zip_entry;
    let mut _7z_folder: *mut _7z_folder = 0 as *mut _7z_folder;
    _7z_folder = calloc_safe(2 as i32 as u64, size_of::<_7z_folder>() as u64) as *mut _7z_folder;
    (*(*a).format).data = zip as *mut ();
    (*zip).uncompressed_buffer_bytes_remaining = 0;
    (*zip).pack_stream_remaining = 0;
    (*zip).header_is_being_read = 1;
    read_stream(a, buff2, 0, 0);
    (*zip).entry = _7zip_entry;
    (*_7zip_entry).folderIndex = 1;
    (*zip).si.ci.folders = _7z_folder;
    (*zip).si.ci.numFolders = 0;
    read_stream(a, buff2, 0, 0);
    (*zip).si.ci.numFolders = 2;
    (*zip).pack_stream_inbytes_remaining = 1;
    read_stream(a, buff2, 0, 0);
    (*zip).pack_stream_inbytes_remaining = 0;
    (*zip).folder_outbytes_remaining = 1;
    read_stream(a, buff2, 0, 0);
}
