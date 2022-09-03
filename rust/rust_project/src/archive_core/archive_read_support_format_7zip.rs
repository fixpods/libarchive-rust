use archive_core::archive_endian::*;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7zip {
    pub si: _7z_stream_info,
    pub header_is_being_read: libc::c_int,
    pub header_is_encoded: libc::c_int,
    pub header_bytes_remaining: uint64_t,
    pub header_crc32: libc::c_ulong,
    pub header_offset: uint64_t,
    pub seek_base: uint64_t,
    pub entries_remaining: size_t,
    pub numFiles: uint64_t,
    pub entries: *mut _7zip_entry,
    pub entry: *mut _7zip_entry,
    pub entry_names: *mut libc::c_uchar,
    pub entry_offset: int64_t,
    pub entry_bytes_remaining: uint64_t,
    pub entry_crc32: libc::c_ulong,
    pub end_of_entry: libc::c_char,
    pub uncompressed_buffer: *mut libc::c_uchar,
    pub uncompressed_buffer_pointer: *mut libc::c_uchar,
    pub uncompressed_buffer_size: size_t,
    pub uncompressed_buffer_bytes_remaining: size_t,
    pub stream_offset: int64_t,
    pub folder_index: libc::c_uint,
    pub folder_outbytes_remaining: uint64_t,
    pub pack_stream_index: libc::c_uint,
    pub pack_stream_remaining: libc::c_uint,
    pub pack_stream_inbytes_remaining: uint64_t,
    pub pack_stream_bytes_unconsumed: size_t,
    pub codec: libc::c_ulong,
    pub codec2: libc::c_ulong,
    #[cfg(HAVE_LZMA_H)]
    pub lzstream: lzma_stream,
    #[cfg(HAVE_LZMA_H)]
    pub lzstream_valid: libc::c_int,
    #[cfg(all(HAVE_ZLIB_H, BZ_CONFIG_ERROR))]
    pub bzstream: bz_stream,
    #[cfg(all(HAVE_ZLIB_H, BZ_CONFIG_ERROR))]
    pub bzstream_valid: libc::c_int,
    #[cfg(HAVE_ZLIB_H)]
    pub stream: z_stream,
    #[cfg(HAVE_ZLIB_H)]
    pub stream_valid: libc::c_int,
    pub ppmd7_stat: libc::c_int,
    pub ppmd7_context: CPpmd7,
    pub range_dec: CPpmd7z_RangeDec,
    pub bytein: IByteIn,
    pub ppstream: obj,
    pub ppmd7_valid: libc::c_int,
    pub bcj_state: uint32_t,
    pub odd_bcj_size: size_t,
    pub odd_bcj: [libc::c_uchar; 4],
    pub bcj_prevPosT: size_t,
    pub bcj_prevMask: uint32_t,
    pub bcj_ip: uint32_t,
    pub main_stream_bytes_remaining: size_t,
    pub sub_stream_buff: [*mut libc::c_uchar; 3],
    pub sub_stream_size: [size_t; 3],
    pub sub_stream_bytes_remaining: [size_t; 3],
    pub tmp_stream_buff: *mut libc::c_uchar,
    pub tmp_stream_buff_size: size_t,
    pub tmp_stream_bytes_avail: size_t,
    pub tmp_stream_bytes_remaining: size_t,
    pub bcj2_p: [uint16_t; 258],
    pub bcj2_prevByte: uint8_t,
    pub bcj2_range: uint32_t,
    pub bcj2_code: uint32_t,
    pub bcj2_outPos: uint64_t,
    pub sconv: *mut archive_string_conv,
    pub format_name: [libc::c_char; 64],
    pub has_encrypted_entries: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct obj {
    pub next_in: *const libc::c_uchar,
    pub avail_in: int64_t,
    pub total_in: int64_t,
    pub next_out: *mut libc::c_uchar,
    pub avail_out: int64_t,
    pub total_out: int64_t,
    pub overconsumed: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct obj0 {
    pub first: *mut archive_read_passphrase,
    pub last: *mut *mut archive_read_passphrase,
    pub candidate: libc::c_int,
    pub callback: Option<archive_passphrase_callback>,
    pub client_data: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7zip_entry {
    pub name_len: size_t,
    pub utf16name: *mut libc::c_uchar,

    #[cfg_attr(_WIN32, _DEBUG, cfg(not(HAVE_TIMEGM)))]
    pub wname: *const wchar_t,

    pub folderIndex: uint32_t,
    pub ssIndex: uint32_t,
    pub flg: libc::c_uint,
    pub mtime: time_t,
    pub atime: time_t,
    pub ctime: time_t,
    pub mtime_ns: libc::c_long,
    pub atime_ns: libc::c_long,
    pub ctime_ns: libc::c_long,
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
    pub digestsDefined: *mut libc::c_uchar,
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
    pub digest_defined: libc::c_uchar,
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
    pub codec: libc::c_ulong,
    pub numInStreams: uint64_t,
    pub numOutStreams: uint64_t,
    pub propertiesSize: uint64_t,
    pub properties: *mut libc::c_uchar,
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
    pub defineds: *mut libc::c_uchar,
    pub digests: *mut uint32_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _7z_header_info {
    pub dataIndex: uint64_t,
    pub emptyStreamBools: *mut libc::c_uchar,
    pub emptyFileBools: *mut libc::c_uchar,
    pub antiBools: *mut libc::c_uchar,
    pub attrBools: *mut libc::c_uchar,
}

#[no_mangle]
pub unsafe extern "C" fn archive_read_support_format_7zip(mut _a: *mut archive) -> libc::c_int {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    let mut r: libc::c_int = 0;
    let mut magic_test: libc::c_int = __archive_check_magic_safe(
        _a,
        0xdeb0c5 as libc::c_uint,
        1 as libc::c_uint,
        b"archive_read_support_format_7zip\x00" as *const u8 as *const libc::c_char,
    );
    if magic_test == -(30 as libc::c_int) {
        return -(30 as libc::c_int);
    }
    zip = calloc_safe(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<_7zip>() as libc::c_ulong,
    ) as *mut _7zip;
    let safe_zip = unsafe { &mut *zip };
    let safe_a = unsafe { &mut *a };

    if zip.is_null() {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                12 as libc::c_int,
                b"Can\'t allocate 7zip data\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int);
    }
    /*
     * Until enough data has been read, we cannot tell about
     * any encrypted entries yet.
     */
    (safe_zip).has_encrypted_entries = -(1 as libc::c_int);
    r = __archive_read_register_format_safe(
        a,
        zip as *mut libc::c_void,
        b"7zip\x00" as *const u8 as *const libc::c_char,
        Some(
            archive_read_format_7zip_bid
                as unsafe extern "C" fn(_: *mut archive_read, _: libc::c_int) -> libc::c_int,
        ),
        None,
        Some(
            archive_read_format_7zip_read_header
                as unsafe extern "C" fn(_: *mut archive_read, _: *mut archive_entry) -> libc::c_int,
        ),
        Some(
            archive_read_format_7zip_read_data
                as unsafe extern "C" fn(
                    _: *mut archive_read,
                    _: *mut *const libc::c_void,
                    _: *mut size_t,
                    _: *mut int64_t,
                ) -> libc::c_int,
        ),
        Some(
            archive_read_format_7zip_read_data_skip
                as unsafe extern "C" fn(_: *mut archive_read) -> libc::c_int,
        ),
        None,
        Some(
            archive_read_format_7zip_cleanup
                as unsafe extern "C" fn(_: *mut archive_read) -> libc::c_int,
        ),
        Some(
            archive_read_support_format_7zip_capabilities
                as unsafe extern "C" fn(_: *mut archive_read) -> libc::c_int,
        ),
        Some(
            archive_read_format_7zip_has_encrypted_entries
                as unsafe extern "C" fn(_: *mut archive_read) -> libc::c_int,
        ),
    );
    if r != 0 as libc::c_int {
        free_safe(zip as *mut libc::c_void);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn archive_read_support_format_7zip_capabilities(
    mut a: *mut archive_read,
) -> libc::c_int {
    /* UNUSED */
    return (1 as libc::c_int) << 0 as libc::c_int | (1 as libc::c_int) << 1 as libc::c_int;
}
/* Maximum entry size. This limitation prevents reading intentional
* corrupted 7-zip files on assuming there are not so many entries in
* the files. */
unsafe extern "C" fn archive_read_format_7zip_has_encrypted_entries(
    mut _a: *mut archive_read,
) -> libc::c_int {
    let safe__a = unsafe { &mut *_a };
    if !_a.is_null() && !safe__a.format.is_null() {
        let mut zip: *mut _7zip = unsafe { (*safe__a.format).data as *mut _7zip };
        let safe_zip = unsafe { &mut *zip };
        if !zip.is_null() {
            return safe_zip.has_encrypted_entries;
        }
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn archive_read_format_7zip_bid(
    mut a: *mut archive_read,
    mut best_bid: libc::c_int,
) -> libc::c_int {
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    /* If someone has already bid more than 32, then avoid
    trashing the look-ahead buffers with a seek. */
    if best_bid > 32 as libc::c_int {
        return -(1 as libc::c_int);
    }
    p = __archive_read_ahead_safe(a, 6 as libc::c_int as size_t, 0 as *mut ssize_t)
        as *const libc::c_char;
    if p.is_null() {
        return 0 as libc::c_int;
    }
    /* If first six bytes are the 7-Zip signature,
     * return the bid right now. */
    if memcmp_safe(
        p as *const libc::c_void,
        b"7z\xbc\xaf\'\x1c\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        6 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        return 48 as libc::c_int;
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
        *p.offset(0 as libc::c_int as isize) as libc::c_int == 'M' as i32
            && *p.offset(1 as libc::c_int as isize) as libc::c_int == 'Z' as i32
            || memcmp_safe(
                p as *const libc::c_void,
                b"\x7fELF\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
                4 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
    } {
        let mut offset: ssize_t = 0x27000 as libc::c_int as ssize_t;
        let mut window: ssize_t = 4096 as libc::c_int as ssize_t;
        let mut bytes_avail: ssize_t = 0;
        while offset + window <= 0x60000 as libc::c_int as libc::c_long {
            let mut buff: *const libc::c_char =
                __archive_read_ahead_safe(a, (offset + window) as size_t, &mut bytes_avail)
                    as *const libc::c_char;
            if buff.is_null() {
                /* Remaining bytes are less than window. */
                window >>= 1 as libc::c_int;
                if window < 0x40 as libc::c_int as libc::c_long {
                    return 0 as libc::c_int;
                }
            } else {
                unsafe {
                    p = buff.offset(offset as isize);
                    while p.offset(32 as libc::c_int as isize) < buff.offset(bytes_avail as isize) {
                        let mut step: libc::c_int = check_7zip_header_in_sfx(p);
                        if step == 0 as libc::c_int {
                            return 48 as libc::c_int;
                        }
                        p = p.offset(step as isize)
                    }
                    offset = p.offset_from(buff) as libc::c_long
                }
            }
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn check_7zip_header_in_sfx(mut p: *const libc::c_char) -> libc::c_int {
    match unsafe { *p.offset(5 as libc::c_int as isize) as libc::c_uchar as libc::c_int } {
        28 => {
            if memcmp_safe(
                p as *const libc::c_void,
                b"7z\xbc\xaf\'\x1c\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
                6 as libc::c_int as libc::c_ulong,
            ) != 0 as libc::c_int
            {
                return 6 as libc::c_int;
            }
            /*
             * Test the CRC because its extraction code has 7-Zip
             * Magic Code, so we should do this in order not to
             * make a mis-detection.
             */
            if unsafe {
                crc32_safe(
                    0 as libc::c_int as uLong,
                    (p as *const libc::c_uchar).offset(12 as libc::c_int as isize),
                    20 as libc::c_int as uInt,
                ) != archive_le32dec(p.offset(8 as libc::c_int as isize) as *const libc::c_void)
                    as libc::c_ulong
            } {
                return 6 as libc::c_int;
            }
            /* Hit the header! */
            return 0 as libc::c_int;
        }
        55 => return 5 as libc::c_int,
        122 => return 4 as libc::c_int,
        188 => return 3 as libc::c_int,
        175 => return 2 as libc::c_int,
        39 => return 1 as libc::c_int,
        _ => return 6 as libc::c_int,
    };
}
unsafe extern "C" fn skip_sfx(mut a: *mut archive_read, mut bytes_avail: ssize_t) -> libc::c_int {
    let mut h: *const libc::c_void = 0 as *const libc::c_void;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut q: *const libc::c_char = 0 as *const libc::c_char;
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
    if bytes_avail > 0x27000 as libc::c_int as libc::c_long {
        __archive_read_consume_safe(a, 0x27000 as libc::c_int as int64_t);
    } else if __archive_read_seek_safe(a, 0x27000 as libc::c_int as int64_t, 0 as libc::c_int)
        < 0 as libc::c_int as libc::c_long
    {
        return -(30 as libc::c_int);
    }
    offset = 0 as libc::c_int as size_t;
    window = 1 as libc::c_int as ssize_t;
    while offset.wrapping_add(window as libc::c_ulong)
        <= (0x60000 as libc::c_int - 0x27000 as libc::c_int) as libc::c_ulong
    {
        h = __archive_read_ahead_safe(a, window as size_t, &mut bytes);
        if h == 0 as *mut libc::c_void {
            /* Remaining bytes are less than window. */
            window >>= 1 as libc::c_int;
            if window < 0x40 as libc::c_int as libc::c_long {
                break;
            }
        } else if bytes < 6 as libc::c_int as libc::c_long {
            /* This case might happen when window == 1. */
            window = 4096 as libc::c_int as ssize_t
        } else {
            p = h as *const libc::c_char;
            q = unsafe { p.offset(bytes as isize) };
            /*
             * Scan ahead until we find something that looks
             * like the 7-Zip header.
             */
            unsafe {
                while p.offset(32 as libc::c_int as isize) < q {
                    let mut step: libc::c_int = check_7zip_header_in_sfx(p);
                    if step == 0 as libc::c_int {
                        let mut zip: *mut _7zip = (*(*a).format).data as *mut _7zip;
                        skip = p.offset_from(h as *const libc::c_char) as libc::c_long as size_t;
                        __archive_read_consume(a, skip as int64_t);
                        (*zip).seek_base = (0x27000 as libc::c_int as libc::c_ulong)
                            .wrapping_add(offset)
                            .wrapping_add(skip);
                        return 0 as libc::c_int;
                    }
                    p = p.offset(step as isize)
                }
            }
            skip = unsafe { p.offset_from(h as *const libc::c_char) as libc::c_long as size_t };
            __archive_read_consume_safe(a, skip as int64_t);
            offset = (offset as libc::c_ulong).wrapping_add(skip) as size_t as size_t;
            if window == 1 as libc::c_int as libc::c_long {
                window = 4096 as libc::c_int as ssize_t
            }
        }
    }
    unsafe {
        archive_set_error(
            &mut (safe_a).archive as *mut archive,
            84 as libc::c_int,
            b"Couldn\'t find out 7-Zip header\x00" as *const u8 as *const libc::c_char,
        )
    };
    return -(30 as libc::c_int);
}
unsafe extern "C" fn archive_read_format_7zip_read_header(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
) -> libc::c_int {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut zip_entry: *mut _7zip_entry = 0 as *mut _7zip_entry;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut folder: *mut _7z_folder = 0 as *mut _7z_folder;
    let mut fidx: uint64_t = 0 as libc::c_int as uint64_t;
    let safe_a = unsafe { &mut *a };
    let mut safe_zip = unsafe { &mut *zip };

    if safe_zip.has_encrypted_entries == -(1 as libc::c_int) {
        safe_zip.has_encrypted_entries = 0 as libc::c_int
    }
    safe_a.archive.archive_format = 0xe0000 as libc::c_int;
    if safe_a.archive.archive_format_name.is_null() {
        safe_a.archive.archive_format_name = b"7-Zip\x00" as *const u8 as *const libc::c_char
    }
    if safe_zip.entries.is_null() {
        let mut header: _7z_header_info = _7z_header_info {
            dataIndex: 0,
            emptyStreamBools: 0 as *mut libc::c_uchar,
            emptyFileBools: 0 as *mut libc::c_uchar,
            antiBools: 0 as *mut libc::c_uchar,
            attrBools: 0 as *mut libc::c_uchar,
        };
        memset_safe(
            &mut header as *mut _7z_header_info as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<_7z_header_info>() as libc::c_ulong,
        );
        r = slurp_central_directory(a, zip, &mut header);
        free_Header(&mut header);
        if r != 0 as libc::c_int {
            return r;
        }
        (safe_zip).entries_remaining = (safe_zip).numFiles;
        (safe_zip).entry = (safe_zip).entries
    } else {
        (safe_zip).entry = unsafe { (safe_zip).entry.offset(1) }
    }
    zip_entry = (safe_zip).entry;
    let safe_zip_entry = unsafe { &mut *zip_entry };
    if (safe_zip).entries_remaining <= 0 as libc::c_int as libc::c_ulong || zip_entry.is_null() {
        return 1 as libc::c_int;
    }
    (safe_zip).entries_remaining = (safe_zip).entries_remaining.wrapping_sub(1);
    (safe_zip).entry_offset = 0 as libc::c_int as int64_t;
    (safe_zip).end_of_entry = 0 as libc::c_int as libc::c_char;
    (safe_zip).entry_crc32 = crc32_safe(
        0 as libc::c_int as uLong,
        0 as *const Bytef,
        0 as libc::c_int as uInt,
    );
    /* Setup a string conversion for a filename. */
    if (safe_zip).sconv.is_null() {
        (safe_zip).sconv = archive_string_conversion_from_charset_safe(
            &mut (safe_a).archive,
            b"UTF-16LE\x00" as *const u8 as *const libc::c_char,
            1 as libc::c_int,
        );
        if (safe_zip).sconv.is_null() {
            return -(30 as libc::c_int);
        }
    }

    if !zip_entry.is_null()
        && ((safe_zip_entry).folderIndex as libc::c_ulong) < (safe_zip).si.ci.numFolders
    {
        folder = unsafe {
            &mut *(safe_zip)
                .si
                .ci
                .folders
                .offset((safe_zip_entry).folderIndex as isize) as *mut _7z_folder
        };
        fidx = 0 as libc::c_int as uint64_t;
        unsafe {
            while !folder.is_null() && fidx < (*folder).numCoders {
                match (*(*folder).coders.offset(fidx as isize)).codec {
                    116457729 | 116458243 | 116459265 => {
                        archive_entry_set_is_data_encrypted(
                            entry,
                            1 as libc::c_int as libc::c_char,
                        );
                        (safe_zip).has_encrypted_entries = 1 as libc::c_int
                    }
                    _ => {}
                }
                fidx = fidx.wrapping_add(1)
            }
        }
    }

    if (safe_zip).has_encrypted_entries == -(1 as libc::c_int) {
        (safe_zip).has_encrypted_entries = 0 as libc::c_int
    }
    if _archive_entry_copy_pathname_l_safe(
        entry,
        (safe_zip_entry).utf16name as *const libc::c_char,
        (safe_zip_entry).name_len,
        (safe_zip).sconv,
    ) != 0 as libc::c_int
    {
        if unsafe { *__errno_location() == 12 as libc::c_int } {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    12 as libc::c_int,
                    b"Can\'t allocate memory for Pathname\x00" as *const u8 as *const libc::c_char,
                )
            };
            return -(30 as libc::c_int);
        }
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84 as libc::c_int,
                b"Pathname cannot be converted from %s to current locale.\x00" as *const u8
                    as *const libc::c_char,
                archive_string_conversion_charset_name((safe_zip).sconv),
            )
        };
        ret = -(20 as libc::c_int)
    }
    /* Populate some additional entry fields: */
    archive_entry_set_mode_safe(entry, (safe_zip_entry).mode);
    if (safe_zip_entry).flg & ((1 as libc::c_int) << 0 as libc::c_int) as libc::c_uint != 0 {
        archive_entry_set_mtime_safe(entry, (safe_zip_entry).mtime, (safe_zip_entry).mtime_ns);
    }
    if (safe_zip_entry).flg & ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_uint != 0 {
        archive_entry_set_ctime_safe(entry, (safe_zip_entry).ctime, (safe_zip_entry).ctime_ns);
    }
    if (safe_zip_entry).flg & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint != 0 {
        archive_entry_set_atime_safe(entry, (safe_zip_entry).atime, (safe_zip_entry).atime_ns);
    }
    if (safe_zip_entry).ssIndex != -(1 as libc::c_int) as uint32_t {
        (safe_zip).entry_bytes_remaining = unsafe {
            *(safe_zip)
                .si
                .ss
                .unpackSizes
                .offset((safe_zip_entry).ssIndex as isize)
        };
        archive_entry_set_size_safe(entry, (safe_zip).entry_bytes_remaining as la_int64_t);
    } else {
        (safe_zip).entry_bytes_remaining = 0 as libc::c_int as uint64_t;
        archive_entry_set_size_safe(entry, 0 as libc::c_int as la_int64_t);
    }
    /* If there's no body, force read_data() to return EOF immediately. */
    if (safe_zip).entry_bytes_remaining < 1 as libc::c_int as libc::c_ulong {
        (safe_zip).end_of_entry = 1 as libc::c_int as libc::c_char
    }
    if (safe_zip_entry).mode & 0o170000 as libc::c_int as mode_t
        == 0o120000 as libc::c_int as mode_t
    {
        let mut symname: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
        let mut symsize: size_t = 0 as libc::c_int as size_t;

        while (safe_zip).entry_bytes_remaining > 0 as libc::c_int as libc::c_ulong {
            let mut buff: *const libc::c_void = 0 as *const libc::c_void;
            let mut mem: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
            let mut size: size_t = 0;
            let mut offset: int64_t = 0;
            r = archive_read_format_7zip_read_data(a, &mut buff, &mut size, &mut offset);
            if r < -(20 as libc::c_int) {
                free_safe(symname as *mut libc::c_void);
                return r;
            }
            mem = realloc_safe(
                symname as *mut libc::c_void,
                symsize
                    .wrapping_add(size)
                    .wrapping_add(1 as libc::c_int as libc::c_ulong),
            ) as *mut libc::c_uchar;
            if mem.is_null() {
                free_safe(symname as *mut libc::c_void);
                unsafe {
                    archive_set_error(
                        &mut (*a).archive as *mut archive,
                        12 as libc::c_int,
                        b"Can\'t allocate memory for Symname\x00" as *const u8
                            as *const libc::c_char,
                    )
                };
                return -(30 as libc::c_int);
            }
            symname = mem;
            memcpy_safe(
                unsafe { symname.offset(symsize as isize) as *mut libc::c_void },
                buff,
                size,
            );
            symsize = (symsize as libc::c_ulong).wrapping_add(size) as size_t as size_t;
            safe_zip = unsafe { &mut *((*(*a).format).data as *mut _7zip) };
        }
        if symsize == 0 as libc::c_int as libc::c_ulong {
            /* If there is no symname, handle it as a regular
             * file. */
            (safe_zip_entry).mode &= !(0o170000 as libc::c_int as mode_t);
            (safe_zip_entry).mode |= 0o100000 as libc::c_int as mode_t;
            archive_entry_set_mode_safe(entry, (safe_zip_entry).mode);
        } else {
            unsafe { *symname.offset(symsize as isize) = '\u{0}' as i32 as libc::c_uchar };
            archive_entry_copy_symlink_safe(entry, symname as *const libc::c_char);
        }
        free_safe(symname as *mut libc::c_void);
        archive_entry_set_size_safe(entry, 0 as libc::c_int as la_int64_t);
    }
    /* Set up a more descriptive format name. */
    unsafe {
        sprintf(
            (safe_zip).format_name.as_mut_ptr(),
            b"7-Zip\x00" as *const u8 as *const libc::c_char,
        )
    };
    (safe_a).archive.archive_format_name = (safe_zip).format_name.as_mut_ptr();
    return ret;
}
unsafe extern "C" fn archive_read_format_7zip_read_data(
    mut a: *mut archive_read,
    mut buff: *mut *const libc::c_void,
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) -> libc::c_int {
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    let mut bytes: ssize_t = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let safe_a = unsafe { &mut *a };
    zip = unsafe { (*(safe_a).format).data as *mut _7zip };
    let safe_zip = unsafe { &mut *zip };
    if safe_zip.has_encrypted_entries == -(1 as libc::c_int) {
        safe_zip.has_encrypted_entries = 0 as libc::c_int
    }
    if safe_zip.pack_stream_bytes_unconsumed != 0 {
        read_consume(a);
    }
    unsafe {
        *offset = (safe_zip).entry_offset;
        *size = 0 as libc::c_int as size_t;
        *buff = 0 as *const libc::c_void;
    }

    if safe_zip.end_of_entry != 0 {
        return 1 as libc::c_int;
    } // Don't try to read more than 16 MB at a time
    let max_read_size: uint64_t =
        (16 as libc::c_int * 1024 as libc::c_int * 1024 as libc::c_int) as uint64_t;
    let mut bytes_to_read: size_t = max_read_size;
    if bytes_to_read > safe_zip.entry_bytes_remaining {
        bytes_to_read = safe_zip.entry_bytes_remaining
    }
    bytes = read_stream(a, buff, bytes_to_read, 0 as libc::c_int as size_t);
    if bytes < 0 as libc::c_int as libc::c_long {
        return bytes as libc::c_int;
    }
    if bytes == 0 as libc::c_int as libc::c_long {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84 as libc::c_int,
                b"Truncated 7-Zip file body\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int);
    }
    (safe_zip).entry_bytes_remaining = (safe_zip.entry_bytes_remaining as libc::c_ulong)
        .wrapping_sub(bytes as libc::c_ulong) as uint64_t
        as uint64_t;
    if safe_zip.entry_bytes_remaining == 0 as libc::c_int as libc::c_ulong {
        safe_zip.end_of_entry = 1 as libc::c_int as libc::c_char
    }
    /* Update checksum */
    if unsafe {
        (*safe_zip.entry).flg & ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint != 0
            && bytes != 0
    } {
        safe_zip.entry_crc32 = crc32_safe(
            safe_zip.entry_crc32,
            unsafe { *buff as *const Bytef },
            bytes as libc::c_uint,
        )
    }
    /* If we hit the end, swallow any end-of-data marker. */
    if (safe_zip).end_of_entry != 0 {
        /* Check computed CRC against file contents. */
        if unsafe {
            (*safe_zip.entry).flg & ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint != 0
                && *safe_zip
                    .si
                    .ss
                    .digests
                    .offset((*safe_zip.entry).ssIndex as isize) as libc::c_ulong
                    != safe_zip.entry_crc32
        } {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"7-Zip bad CRC: 0x%lx should be 0x%lx\x00" as *const u8 as *const libc::c_char,
                    safe_zip.entry_crc32,
                    *safe_zip
                        .si
                        .ss
                        .digests
                        .offset((*safe_zip.entry).ssIndex as isize)
                        as libc::c_ulong,
                )
            };
            ret = -(20 as libc::c_int)
        }
    }
    unsafe {
        *size = bytes as size_t;
        *offset = (*zip).entry_offset;
    }
    (safe_zip).entry_offset += bytes;
    return ret;
}
unsafe extern "C" fn archive_read_format_7zip_read_data_skip(
    mut a: *mut archive_read,
) -> libc::c_int {
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
        return 0 as libc::c_int;
    }
    /*
     * If the length is at the beginning, we can skip the
     * compressed data much more quickly.
     */
    bytes_skipped = skip_stream(a, safe_zip.entry_bytes_remaining);
    if bytes_skipped < 0 as libc::c_int as libc::c_long {
        return -(30 as libc::c_int);
    }
    safe_zip.entry_bytes_remaining = 0 as libc::c_int as uint64_t;
    /* This entry is finished and done. */
    safe_zip.end_of_entry = 1 as libc::c_int as libc::c_char;
    return 0 as libc::c_int;
}
unsafe extern "C" fn archive_read_format_7zip_cleanup(mut a: *mut archive_read) -> libc::c_int {
    let mut zip: *mut _7zip = 0 as *mut _7zip;
    zip = unsafe { (*(*a).format).data as *mut _7zip };
    let safe_zip = unsafe { &mut *zip };
    free_StreamsInfo(&mut safe_zip.si);
    free_safe(safe_zip.entries as *mut libc::c_void);
    free_safe(safe_zip.entry_names as *mut libc::c_void);
    free_decompression(a, zip);
    free_safe(safe_zip.uncompressed_buffer as *mut libc::c_void);
    free_safe(safe_zip.sub_stream_buff[0 as libc::c_int as usize] as *mut libc::c_void);
    free_safe(safe_zip.sub_stream_buff[1 as libc::c_int as usize] as *mut libc::c_void);
    free_safe(safe_zip.sub_stream_buff[2 as libc::c_int as usize] as *mut libc::c_void);
    free_safe(safe_zip.tmp_stream_buff as *mut libc::c_void);
    free_safe(zip as *mut libc::c_void);
    unsafe { (*(*a).format).data = 0 as *mut libc::c_void };
    return 0 as libc::c_int;
}
unsafe extern "C" fn read_consume(mut a: *mut archive_read) {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let safe_zip = unsafe { &mut *zip };
    if safe_zip.pack_stream_bytes_unconsumed != 0 {
        __archive_read_consume_safe(a, safe_zip.pack_stream_bytes_unconsumed as int64_t);
        safe_zip.stream_offset = (safe_zip.stream_offset as libc::c_ulong)
            .wrapping_add(safe_zip.pack_stream_bytes_unconsumed)
            as int64_t as int64_t;
        safe_zip.pack_stream_bytes_unconsumed = 0 as libc::c_int as size_t
    };
}
/*
* Set an error code and choose an error message for liblzma.
*/
#[cfg(HAVE_LZMA_H)]
unsafe extern "C" fn set_error(mut a: *mut archive_read, mut ret: libc::c_int) {
    let safe_a = unsafe { &mut *a };
    unsafe {
        match ret {
            1 => {}
            0 => {}
            5 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    12 as libc::c_int,
                    b"Lzma library error: Cannot allocate memory\x00" as *const u8
                        as *const libc::c_char,
                );
            }
            6 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    12 as libc::c_int,
                    b"Lzma library error: Out of memory\x00" as *const u8 as *const libc::c_char,
                );
            }
            7 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Lzma library error: format not recognized\x00" as *const u8
                        as *const libc::c_char,
                );
            }
            8 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Lzma library error: Invalid options\x00" as *const u8 as *const libc::c_char,
                );
            }
            9 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Lzma library error: Corrupted input data\x00" as *const u8
                        as *const libc::c_char,
                );
            }
            10 => {
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Lzma library error:  No progress is possible\x00" as *const u8
                        as *const libc::c_char,
                );
            }
            _ => {
                /* Return an error. */
                archive_set_error(
                    &mut safe_a.archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Lzma decompression failed:  Unknown error\x00" as *const u8
                        as *const libc::c_char,
                );
            }
        };
    }
}
unsafe extern "C" fn decode_codec_id(
    mut codecId: *const libc::c_uchar,
    mut id_size: size_t,
) -> libc::c_ulong {
    let mut i: libc::c_uint = 0;
    let mut id: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) < id_size {
        id <<= 8 as libc::c_int;
        id = unsafe { id.wrapping_add(*codecId.offset(i as isize) as libc::c_ulong) };
        i = i.wrapping_add(1)
    }
    return id;
}
unsafe extern "C" fn ppmd_read(mut p: *mut libc::c_void) -> Byte {
    let mut a: *mut archive_read = unsafe { (*(p as *mut IByteIn)).a };
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut b: Byte = 0;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    if safe_zip.ppstream.avail_in == 0 as libc::c_int as libc::c_long {
        unsafe {
            archive_set_error(
                &mut safe_a.archive as *mut archive,
                84 as libc::c_int,
                b"Truncated RAR file data\x00" as *const u8 as *const libc::c_char,
            )
        };
        safe_zip.ppstream.overconsumed = 1 as libc::c_int;
        return 0 as libc::c_int as Byte;
    }
    let fresh0 = safe_zip.ppstream.next_in;
    safe_zip.ppstream.next_in = unsafe { safe_zip.ppstream.next_in.offset(1) };
    b = unsafe { *fresh0 };
    safe_zip.ppstream.avail_in -= 1;
    safe_zip.ppstream.total_in += 1;
    return b;
}
unsafe extern "C" fn init_decompression(
    mut a: *mut archive_read,
    mut zip: *mut _7zip,
    mut coder1: *const _7z_coder,
    mut coder2: *const _7z_coder,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    let safe_coder1 = unsafe { &*coder1 };
    safe_zip.codec = (safe_coder1).codec;
    safe_zip.codec2 = -(1 as libc::c_int) as libc::c_ulong;
    let safe_coder2 = unsafe { &*coder2 };
    match safe_zip.codec {
        0 | 262658 | 262408 | 197633 => {
            if !coder2.is_null() {
                if safe_coder2.codec != 0x3030103 as libc::c_int as libc::c_ulong
                    && safe_coder2.codec != 0x303011b as libc::c_int as libc::c_ulong
                {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as libc::c_int),
                            b"Unsupported filter %lx for %lx\x00" as *const u8
                                as *const libc::c_char,
                            safe_coder2.codec,
                            safe_coder1.codec,
                        )
                    };
                    return -(25 as libc::c_int);
                }
                safe_zip.codec2 = safe_coder2.codec;
                safe_zip.bcj_state = 0 as libc::c_int as uint32_t;
                if safe_coder2.codec == 0x3030103 as libc::c_int as libc::c_ulong {
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
                            reserved_ptr1: 0 as *mut libc::c_void,
                            reserved_ptr2: 0 as *mut libc::c_void,
                        };
                        let mut filters: [lzma_filter; 4] = [lzma_filter {
                            id: 0,
                            options: 0 as *mut libc::c_void,
                        }; 4];
                        let mut ff: *mut lzma_filter = 0 as *mut lzma_filter;
                        let mut fi: libc::c_int = 0 as libc::c_int;
                        if (safe_zip).lzstream_valid != 0 {
                            lzma_end_safe(&mut (safe_zip).lzstream);
                            (safe_zip).lzstream_valid = 0 as libc::c_int
                        }

                        if !coder2.is_null() {
                            (safe_zip).codec2 = (safe_coder2).codec;
                            filters[fi as usize].options = 0 as *mut libc::c_void;
                            match (safe_zip).codec2 {
                                50528515 => {
                                    if (safe_zip).codec == 0x21 as libc::c_int as libc::c_ulong {
                                        filters[fi as usize].id = 0x4 as libc::c_ulong;
                                        fi += 1
                                    } else {
                                        /* Use our filter. */
                                        x86_Init(zip);
                                    }
                                }
                                50528539 => {
                                    /* Use our filter. */
                                    (safe_zip).bcj_state = 0 as libc::c_int as uint32_t
                                }
                                3 => {
                                    if (safe_coder2).propertiesSize
                                        != 1 as libc::c_int as libc::c_ulong
                                    {
                                        unsafe {
                                            archive_set_error(
                                                &mut (safe_a).archive as *mut archive,
                                                -(1 as libc::c_int),
                                                b"Invalid Delta parameter\x00" as *const u8
                                                    as *const libc::c_char,
                                            )
                                        };
                                        return -(25 as libc::c_int);
                                    }
                                    filters[fi as usize].id = 0x3 as libc::c_ulong;
                                    memset_safe(
                                        &mut delta_opt as *mut lzma_options_delta
                                            as *mut libc::c_void,
                                        0 as libc::c_int,
                                        ::std::mem::size_of::<lzma_options_delta>()
                                            as libc::c_ulong,
                                    );
                                    delta_opt.type_0 = LZMA_DELTA_TYPE_BYTE;
                                    delta_opt.dist = unsafe {
                                        (*(safe_coder2).properties.offset(0 as libc::c_int as isize)
                                            as uint32_t)
                                            .wrapping_add(1 as libc::c_int as libc::c_uint)
                                    };
                                    filters[fi as usize].options = &mut delta_opt
                                        as *mut lzma_options_delta
                                        as *mut libc::c_void;
                                    fi += 1
                                }
                                50528773 => {
                                    /* Following filters have not been tested yet. */
                                    filters[fi as usize].id = 0x5 as libc::c_ulong;
                                    fi += 1
                                }
                                50529281 => {
                                    filters[fi as usize].id = 0x6 as libc::c_ulong;
                                    fi += 1
                                }
                                50529537 => {
                                    filters[fi as usize].id = 0x7 as libc::c_ulong;
                                    fi += 1
                                }
                                50530049 => {
                                    filters[fi as usize].id = 0x8 as libc::c_ulong;
                                    fi += 1
                                }
                                50530309 => {
                                    filters[fi as usize].id = 0x9 as libc::c_ulong;
                                    fi += 1
                                }
                                _ => {
                                    unsafe {
                                        archive_set_error(
                                            &mut (safe_a).archive as *mut archive,
                                            -(1 as libc::c_int),
                                            b"Unexpected codec ID: %lX\x00" as *const u8
                                                as *const libc::c_char,
                                            (safe_zip).codec2,
                                        )
                                    };
                                    return -(25 as libc::c_int);
                                }
                            }
                        }
                        if (safe_zip).codec == 0x21 as libc::c_int as libc::c_ulong {
                            filters[fi as usize].id = 0x21 as libc::c_ulong
                        } else {
                            filters[fi as usize].id = 0x4000000000000001 as libc::c_ulong
                        }
                        filters[fi as usize].options = 0 as *mut libc::c_void;
                        ff = unsafe {
                            &mut *filters.as_mut_ptr().offset(fi as isize) as *mut lzma_filter
                        };
                        r = lzma_properties_decode_safe(
                            unsafe { &mut *filters.as_mut_ptr().offset(fi as isize) },
                            0 as *const lzma_allocator,
                            (safe_coder1).properties,
                            (safe_coder1).propertiesSize,
                        ) as libc::c_int;
                        if r != LZMA_OK as libc::c_int {
                            set_error(a, r);
                            return -(25 as libc::c_int);
                        }
                        fi += 1;
                        filters[fi as usize].id = 18446744073709551615 as libc::c_ulong;
                        filters[fi as usize].options = 0 as *mut libc::c_void;
                        r = lzma_raw_decoder_safe(&mut (safe_zip).lzstream, filters.as_mut_ptr())
                            as libc::c_int;
                        unsafe { free((*ff).options) };
                        if r != LZMA_OK as libc::c_int {
                            set_error(a, r);
                            return -(25 as libc::c_int);
                        }
                        (safe_zip).lzstream_valid = 1 as libc::c_int;
                        (safe_zip).lzstream.total_in = 0 as libc::c_int as uint64_t;
                        (safe_zip).lzstream.total_out = 0 as libc::c_int as uint64_t
                    }
                }

                #[cfg(not(HAVE_LZMA_H))]
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as libc::c_int),
                            b"LZMA codec is unsupported.\x00" as *const u8 as *const libc::c_char,
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
                    (safe_zip).bzstream_valid = 0 as libc::c_int
                }
                r = BZ2_bzDecompressInit_safe(
                    &mut (safe_zip).bzstream,
                    0 as libc::c_int,
                    0 as libc::c_int,
                );
                if r == -(3 as libc::c_int) {
                    r = BZ2_bzDecompressInit_safe(
                        &mut (safe_zip).bzstream,
                        0 as libc::c_int,
                        1 as libc::c_int,
                    )
                }
                if r != 0 as libc::c_int {
                    let mut err: libc::c_int = -(1 as libc::c_int);
                    let mut detail: *const libc::c_char = 0 as *const libc::c_char;
                    match r {
                        -2 => {
                            detail =
                                b"invalid setup parameter\x00" as *const u8 as *const libc::c_char
                        }
                        -3 => {
                            err = 12 as libc::c_int;
                            detail = b"out of memory\x00" as *const u8 as *const libc::c_char
                        }
                        -9 => {
                            detail = b"mis-compiled library\x00" as *const u8 as *const libc::c_char
                        }
                        _ => {}
                    }
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            err,
                            b"Internal error initializing decompressor: %s\x00" as *const u8
                                as *const libc::c_char,
                            if !detail.is_null() {
                                detail
                            } else {
                                b"??\x00" as *const u8 as *const libc::c_char
                            },
                        )
                    };
                    (safe_zip).bzstream_valid = 0 as libc::c_int;
                    return -(25 as libc::c_int);
                }
                safe_zip.bzstream_valid = 1 as libc::c_int;
                safe_zip.bzstream.total_in_lo32 = 0 as libc::c_int as libc::c_uint;
                safe_zip.bzstream.total_in_hi32 = 0 as libc::c_int as libc::c_uint;
                safe_zip.bzstream.total_out_lo32 = 0 as libc::c_int as libc::c_uint;
                safe_zip.bzstream.total_out_hi32 = 0 as libc::c_int as libc::c_uint
            }

            #[cfg(not(all(HAVE_BZLIB_H, BZ_CONFIG_ERROR)))]
            _ => {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as libc::c_int),
                        b"BZ2 codec is unsupported\x00" as *const u8 as *const libc::c_char,
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
                                -(15 as libc::c_int),
                                b"1.2.11\x00" as *const u8 as *const libc::c_char,
                                ::std::mem::size_of::<z_stream>() as libc::c_ulong as libc::c_int,
                            )
                        }
                        /* Don't check for zlib header */
                        if r != 0 as libc::c_int {
                            unsafe {
                                archive_set_error(
                                    &mut (safe_a).archive as *mut archive,
                                    -(1 as libc::c_int),
                                    b"Couldn\'t initialize zlib stream.\x00" as *const u8
                                        as *const libc::c_char,
                                )
                            };
                            return -(25 as libc::c_int);
                        }
                        (safe_zip).stream_valid = 1 as libc::c_int;
                        (safe_zip).stream.total_in = 0 as libc::c_int as uLong;
                        (safe_zip).stream.total_out = 0 as libc::c_int as uLong
                    }
                }

                #[cfg(not(HAVE_ZLIB_H))]
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as libc::c_int),
                            b"DEFLATE codec is unsupported\x00" as *const u8 as *const libc::c_char,
                        )
                    };
                    return -25;
                }
            }
        }

        197633 => {
            let mut order: libc::c_uint = 0;
            let mut msize: uint32_t = 0;
            if (safe_zip).ppmd7_valid != 0 {
                unsafe {
                    __archive_ppmd7_functions
                        .Ppmd7_Free
                        .expect("non-null function pointer")(
                        &mut (*zip).ppmd7_context
                    )
                };
                (safe_zip).ppmd7_valid = 0 as libc::c_int
            }
            if (safe_coder1).propertiesSize < 5 as libc::c_int as libc::c_ulong {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as libc::c_int),
                        b"Malformed PPMd parameter\x00" as *const u8 as *const libc::c_char,
                    )
                };
                return -(25 as libc::c_int);
            }
            order = unsafe {
                *(safe_coder1).properties.offset(0 as libc::c_int as isize) as libc::c_uint
            };
            msize = archive_le32dec(unsafe {
                &mut *(safe_coder1).properties.offset(1 as libc::c_int as isize)
                    as *mut libc::c_uchar as *const libc::c_void
            });
            if order < 2 as libc::c_int as libc::c_uint
                || order > 64 as libc::c_int as libc::c_uint
                || msize < ((1 as libc::c_int) << 11 as libc::c_int) as libc::c_uint
                || msize
                    > (0xffffffff as libc::c_uint)
                        .wrapping_sub((12 as libc::c_int * 3 as libc::c_int) as libc::c_uint)
            {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as libc::c_int),
                        b"Malformed PPMd parameter\x00" as *const u8 as *const libc::c_char,
                    )
                };
                return -(25 as libc::c_int);
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
            if r == 0 as libc::c_int {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        12 as libc::c_int,
                        b"Coludn\'t allocate memory for PPMd\x00" as *const u8
                            as *const libc::c_char,
                    )
                };
                return -(30 as libc::c_int);
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
            (safe_zip).ppmd7_valid = 1 as libc::c_int;
            (safe_zip).ppmd7_stat = 0 as libc::c_int;
            (safe_zip).ppstream.overconsumed = 0 as libc::c_int;
            (safe_zip).ppstream.total_in = 0 as libc::c_int as int64_t;
            (safe_zip).ppstream.total_out = 0 as libc::c_int as int64_t
        }
        50528515 | 50528539 | 50528773 | 50529281 | 50529537 | 50530049 | 50530309 | 3 => {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Unexpected codec ID: %lX\x00" as *const u8 as *const libc::c_char,
                    (safe_zip).codec,
                )
            };
            return -(25 as libc::c_int);
        }
        116457729 | 116458243 | 116459265 => {
            if !(safe_a).entry.is_null() {
                archive_entry_set_is_metadata_encrypted_safe(
                    (safe_a).entry,
                    1 as libc::c_int as libc::c_char,
                );
                archive_entry_set_is_data_encrypted_safe(
                    (safe_a).entry,
                    1 as libc::c_int as libc::c_char,
                );
                (safe_zip).has_encrypted_entries = 1 as libc::c_int
            }
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Crypto codec not supported yet (ID: 0x%lX)\x00" as *const u8
                        as *const libc::c_char,
                    (safe_zip).codec,
                )
            };
            return -(25 as libc::c_int);
        }
        _ => {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Unknown codec ID: %lX\x00" as *const u8 as *const libc::c_char,
                    (safe_zip).codec,
                )
            };
            return -(25 as libc::c_int);
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn decompress(
    mut a: *mut archive_read,
    mut zip: *mut _7zip,
    mut buff: *mut libc::c_void,
    mut outbytes: *mut size_t,
    mut b: *const libc::c_void,
    mut used: *mut size_t,
) -> libc::c_int {
    let mut t_next_in: *const uint8_t = 0 as *const uint8_t;
    let mut t_next_out: *mut uint8_t = 0 as *mut uint8_t;
    let mut o_avail_in: size_t = 0;
    let mut o_avail_out: size_t = 0;
    let mut t_avail_in: size_t = 0;
    let mut t_avail_out: size_t = 0;
    let mut bcj2_next_out: *mut uint8_t = 0 as *mut uint8_t;
    let mut bcj2_avail_out: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    o_avail_in = unsafe { *used };
    t_avail_in = o_avail_in;
    o_avail_out = unsafe { *outbytes };
    t_avail_out = o_avail_out;
    t_next_in = b as *const uint8_t;
    t_next_out = buff as *mut uint8_t;
    if (safe_zip).codec != 0x21 as libc::c_int as libc::c_ulong
        && (safe_zip).codec2 == 0x3030103 as libc::c_int as libc::c_ulong
    {
        let mut i: libc::c_int = 0;
        /* Do not copy out the BCJ remaining bytes when the output
         * buffer size is less than five bytes. */
        if o_avail_in != 0 as libc::c_int as libc::c_ulong
            && t_avail_out < 5 as libc::c_int as libc::c_ulong
            && (safe_zip).odd_bcj_size != 0
        {
            unsafe {
                *used = 0 as libc::c_int as size_t;
                *outbytes = 0 as libc::c_int as size_t;
            }
            return ret;
        }
        i = 0 as libc::c_int;
        while safe_zip.odd_bcj_size > 0 as libc::c_int as libc::c_ulong && t_avail_out != 0 {
            let fresh1 = t_next_out;
            t_next_out = unsafe { t_next_out.offset(1) };
            unsafe { *fresh1 = safe_zip.odd_bcj[i as usize] };
            t_avail_out = t_avail_out.wrapping_sub(1);
            (safe_zip).odd_bcj_size = (safe_zip).odd_bcj_size.wrapping_sub(1);
            i += 1
        }
        if o_avail_in == 0 as libc::c_int as libc::c_ulong
            || t_avail_out == 0 as libc::c_int as libc::c_ulong
        {
            unsafe {
                *used = o_avail_in.wrapping_sub(t_avail_in);
                *outbytes = o_avail_out.wrapping_sub(t_avail_out);
            }
            if o_avail_in == 0 as libc::c_int as libc::c_ulong {
                ret = 1 as libc::c_int
            }
            return ret;
        }
    }
    bcj2_next_out = t_next_out;
    bcj2_avail_out = t_avail_out;
    if (safe_zip).codec2 == 0x303011b as libc::c_int as libc::c_ulong {
        /*
         * Decord a remaining decompressed main stream for BCJ2.
         */
        if (safe_zip).tmp_stream_bytes_remaining != 0 {
            let mut bytes: ssize_t = 0;
            let mut remaining: size_t = (safe_zip).tmp_stream_bytes_remaining;
            bytes = Bcj2_Decode(zip, t_next_out, t_avail_out);
            if bytes < 0 as libc::c_int as libc::c_long {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as libc::c_int),
                        b"BCJ2 conversion Failed\x00" as *const u8 as *const libc::c_char,
                    )
                };
                return -(25 as libc::c_int);
            }
            (safe_zip).main_stream_bytes_remaining = ((safe_zip).main_stream_bytes_remaining
                as libc::c_ulong)
                .wrapping_sub(remaining.wrapping_sub((safe_zip).tmp_stream_bytes_remaining))
                as size_t as size_t;
            t_avail_out = (t_avail_out as libc::c_ulong).wrapping_sub(bytes as libc::c_ulong)
                as size_t as size_t;
            if o_avail_in == 0 as libc::c_int as libc::c_ulong
                || t_avail_out == 0 as libc::c_int as libc::c_ulong
            {
                unsafe {
                    *used = 0 as libc::c_int as size_t;
                    *outbytes = o_avail_out.wrapping_sub(t_avail_out);
                }
                if o_avail_in == 0 as libc::c_int as libc::c_ulong
                    && (safe_zip).tmp_stream_bytes_remaining != 0
                {
                    ret = 1 as libc::c_int
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
            memcpy_safe(
                t_next_out as *mut libc::c_void,
                t_next_in as *const libc::c_void,
                bytes_0,
            );
            t_avail_in = (t_avail_in as libc::c_ulong).wrapping_sub(bytes_0) as size_t as size_t;
            t_avail_out = (t_avail_out as libc::c_ulong).wrapping_sub(bytes_0) as size_t as size_t;
            if o_avail_in == 0 as libc::c_int as libc::c_ulong {
                ret = 1 as libc::c_int
            }
        }

        #[cfg(HAVE_LZMA_H)]
        196865 | 33 => {
            (safe_zip).lzstream.next_in = t_next_in;
            (safe_zip).lzstream.avail_in = t_avail_in;
            (safe_zip).lzstream.next_out = t_next_out;
            (safe_zip).lzstream.avail_out = t_avail_out;
            r = lzma_code_safe(&mut (safe_zip).lzstream, LZMA_RUN) as libc::c_int;
            match r {
                1 => {
                    /* Found end of stream. */
                    lzma_end_safe(&mut (safe_zip).lzstream);
                    (safe_zip).lzstream_valid = 0 as libc::c_int;
                    ret = 1 as libc::c_int
                }
                0 => {}
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as libc::c_int),
                            b"Decompression failed(%d)\x00" as *const u8 as *const libc::c_char,
                            r,
                        )
                    };
                    return -(25 as libc::c_int);
                }
            }
            t_avail_in = (safe_zip).lzstream.avail_in;
            t_avail_out = (safe_zip).lzstream.avail_out
        }

        #[cfg(all(HAVE_BZLIB_H, BZ_CONFIG_ERROR))]
        262658 => {
            (safe_zip).bzstream.next_in = t_next_in as uintptr_t as *mut libc::c_char;
            (safe_zip).bzstream.avail_in = t_avail_in as libc::c_uint;
            (safe_zip).bzstream.next_out = t_next_out as uintptr_t as *mut libc::c_char;
            (safe_zip).bzstream.avail_out = t_avail_out as libc::c_uint;
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
                                    -(1 as libc::c_int),
                                    b"Failed to clean up decompressor\x00" as *const u8
                                        as *const libc::c_char,
                                )
                            };
                            return -(25 as libc::c_int);
                        }
                    }
                    (safe_zip).bzstream_valid = 0 as libc::c_int;
                    ret = 1 as libc::c_int
                }
                0 => {}
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as libc::c_int),
                            b"bzip decompression failed\x00" as *const u8 as *const libc::c_char,
                        )
                    };
                    return -(25 as libc::c_int);
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
            r = inflate_safe(&mut safe_zip.stream, 0 as libc::c_int);
            match r {
                1 => {
                    /* Found end of stream. */
                    ret = 1 as libc::c_int
                }
                0 => {}
                _ => {
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as libc::c_int),
                            b"File decompression failed (%d)\x00" as *const u8
                                as *const libc::c_char,
                            r,
                        )
                    };
                    return -(25 as libc::c_int);
                }
            }
            t_avail_in = (safe_zip).stream.avail_in as size_t;
            t_avail_out = (safe_zip).stream.avail_out as size_t
        }
        197633 => {
            let mut flush_bytes: uint64_t = 0;
            if (safe_zip).ppmd7_valid == 0
                || (safe_zip).ppmd7_stat < 0 as libc::c_int
                || t_avail_out <= 0 as libc::c_int as libc::c_ulong
            {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as libc::c_int),
                        b"Decompression internal error\x00" as *const u8 as *const libc::c_char,
                    )
                };
                return -(25 as libc::c_int);
            }
            (safe_zip).ppstream.next_in = t_next_in;
            (safe_zip).ppstream.avail_in = t_avail_in as int64_t;
            (safe_zip).ppstream.next_out = t_next_out;
            (safe_zip).ppstream.avail_out = t_avail_out as int64_t;
            if (safe_zip).ppmd7_stat == 0 as libc::c_int {
                (safe_zip).bytein.a = a;
                (safe_zip).bytein.Read =
                    Some(ppmd_read as unsafe extern "C" fn(_: *mut libc::c_void) -> Byte);
                (safe_zip).range_dec.Stream = &mut (safe_zip).bytein;
                r = unsafe {
                    __archive_ppmd7_functions
                        .Ppmd7z_RangeDec_Init
                        .expect("non-null function pointer")(
                        &mut (*zip).range_dec
                    )
                };
                if r == 0 as libc::c_int {
                    (safe_zip).ppmd7_stat = -(1 as libc::c_int);
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            -(1 as libc::c_int),
                            b"Failed to initialize PPMd range decoder\x00" as *const u8
                                as *const libc::c_char,
                        )
                    };
                    return -(25 as libc::c_int);
                }
                if (safe_zip).ppstream.overconsumed != 0 {
                    (safe_zip).ppmd7_stat = -(1 as libc::c_int);
                    return -(25 as libc::c_int);
                }
                (safe_zip).ppmd7_stat = 1 as libc::c_int
            }
            if t_avail_in == 0 as libc::c_int as libc::c_ulong {
                /* XXX Flush out remaining decoded data XXX */
                flush_bytes = (safe_zip).folder_outbytes_remaining
            } else {
                flush_bytes = 0 as libc::c_int as uint64_t
            }
            loop {
                let mut sym: libc::c_int = 0;
                sym = unsafe {
                    __archive_ppmd7_functions
                        .Ppmd7_DecodeSymbol
                        .expect("non-null function pointer")(
                        &mut (safe_zip).ppmd7_context,
                        &mut (safe_zip).range_dec.p,
                    )
                };
                if sym < 0 as libc::c_int {
                    (safe_zip).ppmd7_stat = -(1 as libc::c_int);
                    unsafe {
                        archive_set_error(
                            &mut (safe_a).archive as *mut archive,
                            84 as libc::c_int,
                            b"Failed to decode PPMd\x00" as *const u8 as *const libc::c_char,
                        )
                    };
                    return -(25 as libc::c_int);
                }
                if (safe_zip).ppstream.overconsumed != 0 {
                    (safe_zip).ppmd7_stat = -(1 as libc::c_int);
                    return -(25 as libc::c_int);
                }
                let fresh2 = (safe_zip).ppstream.next_out;
                (safe_zip).ppstream.next_out = unsafe { (safe_zip).ppstream.next_out.offset(1) };
                unsafe { *fresh2 = sym as libc::c_uchar };
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
                    -(1 as libc::c_int),
                    b"Decompression internal error\x00" as *const u8 as *const libc::c_char,
                )
            };
            return -(25 as libc::c_int);
        }
    }
    if ret != 0 as libc::c_int && ret != 1 as libc::c_int {
        return ret;
    }
    unsafe {
        *used = o_avail_in.wrapping_sub(t_avail_in);
        *outbytes = o_avail_out.wrapping_sub(t_avail_out);
    }
    /*
     * Decord BCJ.
     */
    if (safe_zip).codec != 0x21 as libc::c_int as libc::c_ulong
        && (safe_zip).codec2 == 0x3030103 as libc::c_int as libc::c_ulong
    {
        let mut l: size_t = unsafe { x86_Convert(zip, buff as *mut uint8_t, *outbytes) };
        (safe_zip).odd_bcj_size = unsafe { (*outbytes).wrapping_sub(l) };
        if (safe_zip).odd_bcj_size > 0 as libc::c_int as libc::c_ulong
            && (safe_zip).odd_bcj_size <= 4 as libc::c_int as libc::c_ulong
            && o_avail_in != 0
            && ret != 1 as libc::c_int
        {
            unsafe {
                memcpy_safe(
                    safe_zip.odd_bcj.as_mut_ptr() as *mut libc::c_void,
                    (buff as *mut libc::c_uchar).offset(l as isize) as *const libc::c_void,
                    safe_zip.odd_bcj_size,
                );
                *outbytes = l
            }
        } else {
            safe_zip.odd_bcj_size = 0 as libc::c_int as size_t
        }
    }
    /*
     * Decord BCJ2 with a decompressed main stream.
     */
    if safe_zip.codec2 == 0x303011b as libc::c_int as libc::c_ulong {
        let mut bytes_1: ssize_t = 0;
        safe_zip.tmp_stream_bytes_avail = safe_zip.tmp_stream_buff_size.wrapping_sub(t_avail_out);
        if safe_zip.tmp_stream_bytes_avail > safe_zip.main_stream_bytes_remaining {
            safe_zip.tmp_stream_bytes_avail = safe_zip.main_stream_bytes_remaining
        }
        safe_zip.tmp_stream_bytes_remaining = safe_zip.tmp_stream_bytes_avail;
        bytes_1 = Bcj2_Decode(zip, bcj2_next_out, bcj2_avail_out);
        if bytes_1 < 0 as libc::c_int as libc::c_long {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"BCJ2 conversion Failed\x00" as *const u8 as *const libc::c_char,
                )
            };
            return -(25 as libc::c_int);
        }
        (safe_zip).main_stream_bytes_remaining =
            ((safe_zip).main_stream_bytes_remaining as libc::c_ulong).wrapping_sub(
                (safe_zip)
                    .tmp_stream_bytes_avail
                    .wrapping_sub((safe_zip).tmp_stream_bytes_remaining),
            ) as size_t as size_t;
        bcj2_avail_out = (bcj2_avail_out as libc::c_ulong).wrapping_sub(bytes_1 as libc::c_ulong)
            as size_t as size_t;
        unsafe { *outbytes = o_avail_out.wrapping_sub(bcj2_avail_out) }
    }
    return ret;
}
unsafe extern "C" fn free_decompression(
    mut a: *mut archive_read,
    mut zip: *mut _7zip,
) -> libc::c_int {
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    #[cfg_attr(not(HAVE_ZLIB_H), not(HAVE_BZLIB_H), BZ_CONFIG_ERROR)]
    let mut r: libc::c_int = 0 as libc::c_int;

    #[cfg(HAVE_LZMA_H)]
    if (safe_zip).lzstream_valid != 0 {
        lzma_end_safe(&mut (safe_zip).lzstream);
    }

    #[cfg(all(HAVE_BZLIB_H, BZ_CONFIG_ERROR))]
    if (safe_zip).bzstream_valid != 0 {
        if BZ2_bzDecompressEnd_safe(&mut (safe_zip).bzstream) != 0 as libc::c_int {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Failed to clean up bzip2 decompressor\x00" as *const u8
                        as *const libc::c_char,
                )
            };
            r = -(30 as libc::c_int)
        }
        (safe_zip).bzstream_valid = 0 as libc::c_int
    }

    #[cfg(HAVE_ZLIB_H)]
    if (safe_zip).stream_valid != 0 {
        if inflateEnd_safe(&mut (safe_zip).stream) != 0 as libc::c_int {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Failed to clean up zlib decompressor\x00" as *const u8 as *const libc::c_char,
                )
            };
            r = -(30 as libc::c_int)
        }
        (safe_zip).stream_valid = 0 as libc::c_int
    }

    if (safe_zip).ppmd7_valid != 0 {
        unsafe {
            __archive_ppmd7_functions
                .Ppmd7_Free
                .expect("non-null function pointer")(&mut (*zip).ppmd7_context)
        };
        (safe_zip).ppmd7_valid = 0 as libc::c_int
    }
    return r;
}
unsafe extern "C" fn parse_7zip_uint64(
    mut a: *mut archive_read,
    mut val: *mut uint64_t,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut avail: libc::c_uchar = 0;
    let mut mask: libc::c_uchar = 0;
    let mut i: libc::c_int = 0;
    p = header_bytes(a, 1 as libc::c_int as size_t);
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    avail = unsafe { *p };
    mask = 0x80 as libc::c_int as libc::c_uchar;
    unsafe { *val = 0 as libc::c_int as uint64_t };
    i = 0 as libc::c_int;
    while i < 8 as libc::c_int {
        if avail as libc::c_int & mask as libc::c_int != 0 {
            p = header_bytes(a, 1 as libc::c_int as size_t);
            if p.is_null() {
                return -(1 as libc::c_int);
            }
            unsafe { *val |= (*p as uint64_t) << 8 as libc::c_int * i };
            mask = (mask as libc::c_int >> 1 as libc::c_int) as libc::c_uchar;
            i += 1
        } else {
            unsafe {
                *val = (*val as libc::c_ulong).wrapping_add(
                    ((avail as libc::c_int & mask as libc::c_int - 1 as libc::c_int) as uint64_t)
                        << 8 as libc::c_int * i,
                ) as uint64_t as uint64_t
            };
            break;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn read_Bools(
    mut a: *mut archive_read,
    mut data: *mut libc::c_uchar,
    mut num: size_t,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut i: libc::c_uint = 0;
    let mut mask: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut avail: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) < num {
        unsafe {
            if mask == 0 as libc::c_int as libc::c_uint {
                p = header_bytes(a, 1 as libc::c_int as size_t);
                if p.is_null() {
                    return -(1 as libc::c_int);
                }
                avail = *p as libc::c_uint;
                mask = 0x80 as libc::c_int as libc::c_uint
            }
            *data.offset(i as isize) = if avail & mask != 0 {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            } as libc::c_uchar;
            mask >>= 1 as libc::c_int;
            i = i.wrapping_add(1)
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn free_Digest(mut d: *mut _7z_digests) {
    let safe_d = unsafe { &mut *d };
    free_safe((safe_d).defineds as *mut libc::c_void);
    free_safe((safe_d).digests as *mut libc::c_void);
}
unsafe extern "C" fn read_Digests(
    mut a: *mut archive_read,
    mut d: *mut _7z_digests,
    mut num: size_t,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let safe_d = unsafe { &mut *d };
    let mut i: libc::c_uint = 0;
    if num == 0 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    memset_safe(
        d as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<_7z_digests>() as libc::c_ulong,
    );
    (safe_d).defineds = malloc_safe(num) as *mut libc::c_uchar;
    if (safe_d).defineds.is_null() {
        return -(1 as libc::c_int);
    }
    /*
     * Read Bools.
     */
    p = header_bytes(a, 1 as libc::c_int as size_t);
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    if unsafe { *p as libc::c_int == 0 as libc::c_int } {
        if read_Bools(a, (safe_d).defineds, num) < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
    } else {
        /* All are defined */
        memset_safe(
            (safe_d).defineds as *mut libc::c_void,
            1 as libc::c_int,
            num,
        );
    }
    (safe_d).digests =
        calloc_safe(num, ::std::mem::size_of::<uint32_t>() as libc::c_ulong) as *mut uint32_t;
    if (safe_d).digests.is_null() {
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int as libc::c_uint;
    unsafe {
        while (i as libc::c_ulong) < num {
            if *(safe_d).defineds.offset(i as isize) != 0 {
                p = header_bytes(a, 4 as libc::c_int as size_t);
                if p.is_null() {
                    return -(1 as libc::c_int);
                }
                *(safe_d).digests.offset(i as isize) = archive_le32dec(p as *const libc::c_void)
            }
            i = i.wrapping_add(1)
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn free_PackInfo(mut pi: *mut _7z_pack_info) {
    let safe_pi = unsafe { &mut *pi };
    free_safe(safe_pi.sizes as *mut libc::c_void);
    free_safe(safe_pi.positions as *mut libc::c_void);
    free_Digest(&mut safe_pi.digest);
}
unsafe extern "C" fn read_PackInfo(
    mut a: *mut archive_read,
    mut pi: *mut _7z_pack_info,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut i: libc::c_uint = 0;
    let safe_pi = unsafe { &mut *pi };
    memset_safe(
        pi as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<_7z_pack_info>() as libc::c_ulong,
    );
    /*
     * Read PackPos.
     */
    if parse_7zip_uint64(a, &mut safe_pi.pos) < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    /*
     * Read NumPackStreams.
     */
    if parse_7zip_uint64(a, &mut safe_pi.numPackStreams) < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if safe_pi.numPackStreams == 0 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    if (100000000 as libc::c_ulonglong) < safe_pi.numPackStreams as libc::c_ulonglong {
        return -(1 as libc::c_int);
    }
    /*
     * Read PackSizes[num]
     */
    p = header_bytes(a, 1 as libc::c_int as size_t);
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    if unsafe { *p as libc::c_int == 0 as libc::c_int } {
        /* PackSizes[num] are not present. */
        return 0 as libc::c_int;
    }
    if unsafe { *p as libc::c_int != 0x9 as libc::c_int } {
        return -(1 as libc::c_int);
    }
    (safe_pi).sizes = calloc_safe(
        (safe_pi).numPackStreams,
        ::std::mem::size_of::<uint64_t>() as libc::c_ulong,
    ) as *mut uint64_t;
    (safe_pi).positions = calloc_safe(
        (safe_pi).numPackStreams,
        ::std::mem::size_of::<uint64_t>() as libc::c_ulong,
    ) as *mut uint64_t;
    if (safe_pi).sizes.is_null() || (safe_pi).positions.is_null() {
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) < (safe_pi).numPackStreams {
        if parse_7zip_uint64(a, unsafe { &mut *(*pi).sizes.offset(i as isize) }) < 0 as libc::c_int
        {
            return -(1 as libc::c_int);
        }
        i = i.wrapping_add(1)
    }
    /*
     * Read PackStreamDigests[num]
     */
    p = header_bytes(a, 1 as libc::c_int as size_t);
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    if unsafe { *p as libc::c_int == 0 as libc::c_int } {
        /* PackStreamDigests[num] are not present. */
        (safe_pi).digest.defineds = calloc_safe(
            (safe_pi).numPackStreams,
            ::std::mem::size_of::<libc::c_uchar>() as libc::c_ulong,
        ) as *mut libc::c_uchar;
        (safe_pi).digest.digests = calloc_safe(
            (safe_pi).numPackStreams,
            ::std::mem::size_of::<uint32_t>() as libc::c_ulong,
        ) as *mut uint32_t;
        if (safe_pi).digest.defineds.is_null() || (safe_pi).digest.digests.is_null() {
            return -(1 as libc::c_int);
        }
        return 0 as libc::c_int;
    }
    if unsafe { *p as libc::c_int != 0xa as libc::c_int } {
        return -(1 as libc::c_int);
    }
    if read_Digests(a, &mut (safe_pi).digest, (safe_pi).numPackStreams) < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    /*
     *  Must be marked by kEnd.
     */
    p = header_bytes(a, 1 as libc::c_int as size_t);
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    if unsafe { *p as libc::c_int != 0 as libc::c_int } {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn free_Folder(mut f: *mut _7z_folder) {
    let mut i: libc::c_uint = 0;
    let safe_f = unsafe { &mut *f };
    if !(safe_f).coders.is_null() {
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong) < (safe_f).numCoders {
            free_safe(unsafe {
                (*(safe_f).coders.offset(i as isize)).properties as *mut libc::c_void
            });
            i = i.wrapping_add(1)
        }
        free_safe((safe_f).coders as *mut libc::c_void);
    }
    free_safe((safe_f).bindPairs as *mut libc::c_void);
    free_safe((safe_f).packedStreams as *mut libc::c_void);
    free_safe((safe_f).unPackSize as *mut libc::c_void);
}

unsafe extern "C" fn free_CodersInfo(mut ci: *mut _7z_coders_info) {
    let mut i: libc::c_uint = 0;
    let safe_ci = unsafe { &mut *ci };
    if !(safe_ci).folders.is_null() {
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong) < (safe_ci).numFolders {
            unsafe { free_Folder(&mut *(safe_ci).folders.offset(i as isize)) };
            i = i.wrapping_add(1)
        }
        free_safe((safe_ci).folders as *mut libc::c_void);
    };
}
unsafe extern "C" fn read_Folder(mut a: *mut archive_read, mut f: *mut _7z_folder) -> libc::c_int {
    unsafe {
        let mut zip: *mut _7zip = (*(*a).format).data as *mut _7zip;
        let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
        let mut numInStreamsTotal: uint64_t = 0 as libc::c_int as uint64_t;
        let mut numOutStreamsTotal: uint64_t = 0 as libc::c_int as uint64_t;
        let mut i: libc::c_uint = 0;
        memset(
            f as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<_7z_folder>() as libc::c_ulong,
        );
        /*
         * Read NumCoders.
         */
        if parse_7zip_uint64(a, &mut (*f).numCoders) < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if (*f).numCoders > 4 as libc::c_int as libc::c_ulong {
            /* Too many coders. */
            return -(1 as libc::c_int);
        }
        (*f).coders = calloc(
            (*f).numCoders,
            ::std::mem::size_of::<_7z_coder>() as libc::c_ulong,
        ) as *mut _7z_coder;
        if (*f).coders.is_null() {
            return -(1 as libc::c_int);
        }
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong) < (*f).numCoders {
            let mut codec_size: size_t = 0;
            let mut simple: libc::c_int = 0;
            let mut attr: libc::c_int = 0;
            p = header_bytes(a, 1 as libc::c_int as size_t);
            if p.is_null() {
                return -(1 as libc::c_int);
            }
            /*
             * 0:3 CodecIdSize
             * 4:  0 - IsSimple
             *     1 - Is not Simple
             * 5:  0 - No Attributes
             *     1 - There are Attributes;
             * 7:  Must be zero.
             */
            codec_size = (*p as libc::c_int & 0xf as libc::c_int) as size_t; /* Not supported. */
            simple = if *p as libc::c_int & 0x10 as libc::c_int != 0 {
                0 as libc::c_int
            } else {
                1 as libc::c_int
            };
            attr = *p as libc::c_int & 0x20 as libc::c_int;
            if *p as libc::c_int & 0x80 as libc::c_int != 0 {
                return -(1 as libc::c_int);
            }
            /*
             * Read Decompression Method IDs.
             */
            p = header_bytes(a, codec_size);
            if p.is_null() {
                return -(1 as libc::c_int);
            }
            (*(*f).coders.offset(i as isize)).codec = decode_codec_id(p, codec_size);
            if simple != 0 {
                (*(*f).coders.offset(i as isize)).numInStreams = 1 as libc::c_int as uint64_t;
                (*(*f).coders.offset(i as isize)).numOutStreams = 1 as libc::c_int as uint64_t
            } else {
                if parse_7zip_uint64(a, &mut (*(*f).coders.offset(i as isize)).numInStreams)
                    < 0 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
                if (100000000 as libc::c_ulonglong)
                    < (*(*f).coders.offset(i as isize)).numInStreams as libc::c_ulonglong
                {
                    return -(1 as libc::c_int);
                }
                if parse_7zip_uint64(a, &mut (*(*f).coders.offset(i as isize)).numOutStreams)
                    < 0 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
                if (100000000 as libc::c_ulonglong)
                    < (*(*f).coders.offset(i as isize)).numOutStreams as libc::c_ulonglong
                {
                    return -(1 as libc::c_int);
                }
            }
            if attr != 0 {
                if parse_7zip_uint64(a, &mut (*(*f).coders.offset(i as isize)).propertiesSize)
                    < 0 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
                p = header_bytes(a, (*(*f).coders.offset(i as isize)).propertiesSize);
                if p.is_null() {
                    return -(1 as libc::c_int);
                }
                let ref mut fresh3 = (*(*f).coders.offset(i as isize)).properties;
                *fresh3 =
                    malloc((*(*f).coders.offset(i as isize)).propertiesSize) as *mut libc::c_uchar;
                if (*(*f).coders.offset(i as isize)).properties.is_null() {
                    return -(1 as libc::c_int);
                }
                memcpy(
                    (*(*f).coders.offset(i as isize)).properties as *mut libc::c_void,
                    p as *const libc::c_void,
                    (*(*f).coders.offset(i as isize)).propertiesSize,
                );
            }
            numInStreamsTotal = (numInStreamsTotal as libc::c_ulong)
                .wrapping_add((*(*f).coders.offset(i as isize)).numInStreams)
                as uint64_t as uint64_t;
            numOutStreamsTotal = (numOutStreamsTotal as libc::c_ulong)
                .wrapping_add((*(*f).coders.offset(i as isize)).numOutStreams)
                as uint64_t as uint64_t;
            i = i.wrapping_add(1)
        }
        if numOutStreamsTotal == 0 as libc::c_int as libc::c_ulong
            || numInStreamsTotal
                < numOutStreamsTotal.wrapping_sub(1 as libc::c_int as libc::c_ulong)
        {
            return -(1 as libc::c_int);
        }
        (*f).numBindPairs = numOutStreamsTotal.wrapping_sub(1 as libc::c_int as libc::c_ulong);
        if (*zip).header_bytes_remaining < (*f).numBindPairs {
            return -(1 as libc::c_int);
        }
        if (*f).numBindPairs > 0 as libc::c_int as libc::c_ulong {
            (*f).bindPairs = calloc(
                (*f).numBindPairs,
                ::std::mem::size_of::<obj1>() as libc::c_ulong,
            ) as *mut obj1;
            if (*f).bindPairs.is_null() {
                return -(1 as libc::c_int);
            }
        } else {
            (*f).bindPairs = 0 as *mut obj1
        }
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong) < (*f).numBindPairs {
            if parse_7zip_uint64(a, &mut (*(*f).bindPairs.offset(i as isize)).inIndex)
                < 0 as libc::c_int
            {
                return -(1 as libc::c_int);
            }
            if (100000000 as libc::c_ulonglong)
                < (*(*f).bindPairs.offset(i as isize)).inIndex as libc::c_ulonglong
            {
                return -(1 as libc::c_int);
            }
            if parse_7zip_uint64(a, &mut (*(*f).bindPairs.offset(i as isize)).outIndex)
                < 0 as libc::c_int
            {
                return -(1 as libc::c_int);
            }
            if (100000000 as libc::c_ulonglong)
                < (*(*f).bindPairs.offset(i as isize)).outIndex as libc::c_ulonglong
            {
                return -(1 as libc::c_int);
            }
            i = i.wrapping_add(1)
        }
        (*f).numPackedStreams = numInStreamsTotal.wrapping_sub((*f).numBindPairs);
        (*f).packedStreams = calloc(
            (*f).numPackedStreams,
            ::std::mem::size_of::<uint64_t>() as libc::c_ulong,
        ) as *mut uint64_t;
        if (*f).packedStreams.is_null() {
            return -(1 as libc::c_int);
        }
        if (*f).numPackedStreams == 1 as libc::c_int as libc::c_ulong {
            i = 0 as libc::c_int as libc::c_uint;
            while (i as libc::c_ulong) < numInStreamsTotal {
                let mut j: libc::c_uint = 0;
                j = 0 as libc::c_int as libc::c_uint;
                while (j as libc::c_ulong) < (*f).numBindPairs {
                    if (*(*f).bindPairs.offset(j as isize)).inIndex == i as libc::c_ulong {
                        break;
                    }
                    j = j.wrapping_add(1)
                }
                if j as libc::c_ulong == (*f).numBindPairs {
                    break;
                }
                i = i.wrapping_add(1)
            }
            if i as libc::c_ulong == numInStreamsTotal {
                return -(1 as libc::c_int);
            }
            *(*f).packedStreams.offset(0 as libc::c_int as isize) = i as uint64_t
        } else {
            i = 0 as libc::c_int as libc::c_uint;
            while (i as libc::c_ulong) < (*f).numPackedStreams {
                if parse_7zip_uint64(a, &mut *(*f).packedStreams.offset(i as isize))
                    < 0 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
                if (100000000 as libc::c_ulonglong)
                    < *(*f).packedStreams.offset(i as isize) as libc::c_ulonglong
                {
                    return -(1 as libc::c_int);
                }
                i = i.wrapping_add(1)
            }
        }
        (*f).numInStreams = numInStreamsTotal;
        (*f).numOutStreams = numOutStreamsTotal;
        return 0 as libc::c_int;
    }
}

unsafe extern "C" fn read_CodersInfo(
    mut a: *mut archive_read,
    mut ci: *mut _7z_coders_info,
) -> libc::c_int {
    let mut current_block: u64;
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut digest: _7z_digests = _7z_digests {
        defineds: 0 as *mut libc::c_uchar,
        digests: 0 as *mut uint32_t,
    };
    let mut i: libc::c_uint = 0;
    memset_safe(
        ci as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<_7z_coders_info>() as libc::c_ulong,
    );
    memset_safe(
        &mut digest as *mut _7z_digests as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<_7z_digests>() as libc::c_ulong,
    );
    let safe_a = unsafe { &mut *a };
    let safe_ci = unsafe { &mut *ci };

    p = header_bytes(a, 1 as libc::c_int as size_t);
    if !p.is_null() {
        if unsafe { !(*p as libc::c_int != 0xb as libc::c_int) } {
            /*
             * Read NumFolders.
             */
            if !(parse_7zip_uint64(a, &mut (safe_ci).numFolders) < 0 as libc::c_int) {
                if (100000000 as libc::c_ulonglong) < (safe_ci).numFolders as libc::c_ulonglong {
                    return -(1 as libc::c_int);
                }
                /*
                 * Read External.
                 */
                p = header_bytes(a, 1 as libc::c_int as size_t);
                if !p.is_null() {
                    match unsafe { *p as libc::c_int } {
                        0 => {
                            (safe_ci).folders = calloc_safe(
                                (safe_ci).numFolders,
                                ::std::mem::size_of::<_7z_folder>() as libc::c_ulong,
                            ) as *mut _7z_folder;
                            if (safe_ci).folders.is_null() {
                                return -(1 as libc::c_int);
                            }
                            i = 0 as libc::c_int as libc::c_uint;
                            loop {
                                if !((i as libc::c_ulong) < (safe_ci).numFolders) {
                                    current_block = 4068382217303356765;
                                    break;
                                }
                                if unsafe {
                                    read_Folder(a, &mut *(safe_ci).folders.offset(i as isize))
                                        < 0 as libc::c_int
                                } {
                                    current_block = 14585062455194940643;
                                    break;
                                }
                                i = i.wrapping_add(1)
                            }
                        }
                        1 => {
                            if parse_7zip_uint64(a, &mut (safe_ci).dataStreamIndex)
                                < 0 as libc::c_int
                            {
                                return -(1 as libc::c_int);
                            }
                            if (100000000 as libc::c_ulonglong)
                                < (safe_ci).dataStreamIndex as libc::c_ulonglong
                            {
                                return -(1 as libc::c_int);
                            }
                            if (safe_ci).numFolders > 0 as libc::c_int as libc::c_ulong {
                                unsafe {
                                    archive_set_error(
                                        &mut (safe_a).archive as *mut archive,
                                        -(1 as libc::c_int),
                                        b"Malformed 7-Zip archive\x00" as *const u8
                                            as *const libc::c_char,
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
                                    -(1 as libc::c_int),
                                    b"Malformed 7-Zip archive\x00" as *const u8
                                        as *const libc::c_char,
                                )
                            };
                            current_block = 14585062455194940643;
                        }
                    }
                    match current_block {
                        14585062455194940643 => {}
                        _ => {
                            p = header_bytes(a, 1 as libc::c_int as size_t);
                            if !p.is_null() {
                                if unsafe { !(*p as libc::c_int != 0xc as libc::c_int) } {
                                    i = 0 as libc::c_int as libc::c_uint;
                                    's_148: loop {
                                        if !((i as libc::c_ulong) < (safe_ci).numFolders) {
                                            current_block = 7746103178988627676;
                                            break;
                                        }
                                        let mut folder: *mut _7z_folder = unsafe {
                                            &mut *(safe_ci).folders.offset(i as isize)
                                                as *mut _7z_folder
                                        };
                                        let safe_folder = unsafe { &mut *folder };
                                        let mut j: libc::c_uint = 0;
                                        (safe_folder).unPackSize = calloc_safe(
                                            (safe_folder).numOutStreams,
                                            ::std::mem::size_of::<uint64_t>() as libc::c_ulong,
                                        )
                                            as *mut uint64_t;
                                        if (safe_folder).unPackSize.is_null() {
                                            current_block = 14585062455194940643;
                                            break;
                                        }
                                        j = 0 as libc::c_int as libc::c_uint;
                                        while (j as libc::c_ulong) < (safe_folder).numOutStreams {
                                            if unsafe {
                                                parse_7zip_uint64(
                                                    a,
                                                    &mut *(safe_folder)
                                                        .unPackSize
                                                        .offset(j as isize),
                                                ) < 0 as libc::c_int
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
                                            p = header_bytes(a, 1 as libc::c_int as size_t);
                                            if !p.is_null() {
                                                if unsafe { *p as libc::c_int == 0 as libc::c_int }
                                                {
                                                    return 0 as libc::c_int;
                                                }
                                                if unsafe {
                                                    !(*p as libc::c_int != 0xa as libc::c_int)
                                                } {
                                                    if !(read_Digests(
                                                        a,
                                                        &mut digest,
                                                        (safe_ci).numFolders,
                                                    ) < 0 as libc::c_int)
                                                    {
                                                        i = 0 as libc::c_int as libc::c_uint;
                                                        while (i as libc::c_ulong)
                                                            < (safe_ci).numFolders
                                                        {
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
                                                        p = header_bytes(
                                                            a,
                                                            1 as libc::c_int as size_t,
                                                        );
                                                        if !p.is_null() {
                                                            if unsafe {
                                                                !(*p as libc::c_int
                                                                    != 0 as libc::c_int)
                                                            } {
                                                                free_Digest(&mut digest);
                                                                return 0 as libc::c_int;
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
    return -(1 as libc::c_int);
}
unsafe extern "C" fn folder_uncompressed_size(mut f: *mut _7z_folder) -> uint64_t {
    let safe_f = unsafe { &mut *f };
    let mut n: libc::c_int = safe_f.numOutStreams as libc::c_int;
    let mut pairs: libc::c_uint = safe_f.numBindPairs as libc::c_uint;
    loop {
        n -= 1;
        if !(n >= 0 as libc::c_int) {
            break;
        }
        let mut i: libc::c_uint = 0;
        i = 0 as libc::c_int as libc::c_uint;
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
    return 0 as libc::c_int as uint64_t;
}
unsafe extern "C" fn free_SubStreamsInfo(mut ss: *mut _7z_substream_info) {
    let safe_ss = unsafe { &mut *ss };
    free_safe(safe_ss.unpackSizes as *mut libc::c_void);
    free_safe(safe_ss.digestsDefined as *mut libc::c_void);
    free_safe(safe_ss.digests as *mut libc::c_void);
}
unsafe extern "C" fn read_SubStreamsInfo(
    mut a: *mut archive_read,
    mut ss: *mut _7z_substream_info,
    mut f: *mut _7z_folder,
    mut numFolders: size_t,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut usizes: *mut uint64_t = 0 as *mut uint64_t;
    let mut unpack_streams: size_t = 0;
    let mut type_0: libc::c_int = 0;
    let mut i: libc::c_uint = 0;
    let mut numDigests: uint32_t = 0;
    memset_safe(
        ss as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<_7z_substream_info>() as libc::c_ulong,
    );
    let safe_f = unsafe { &mut *f };
    let safe_ss = unsafe { &mut *ss };
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) < numFolders {
        unsafe { (*f.offset(i as isize)).numUnpackStreams = 1 as libc::c_int as uint64_t };
        i = i.wrapping_add(1)
    }
    p = header_bytes(a, 1 as libc::c_int as size_t);
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    type_0 = unsafe { *p as libc::c_int };
    if type_0 == 0xd as libc::c_int {
        unpack_streams = 0 as libc::c_int as size_t;
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong) < numFolders {
            if unsafe {
                parse_7zip_uint64(a, &mut (*f.offset(i as isize)).numUnpackStreams)
                    < 0 as libc::c_int
            } {
                return -(1 as libc::c_int);
            }
            if unsafe {
                (100000000 as libc::c_ulonglong)
                    < (*f.offset(i as isize)).numUnpackStreams as libc::c_ulonglong
            } {
                return -(1 as libc::c_int);
            }
            if unpack_streams as libc::c_ulonglong
                > (18446744073709551615 as libc::c_ulong as libc::c_ulonglong)
                    .wrapping_sub(100000000 as libc::c_ulonglong)
            {
                return -(1 as libc::c_int);
            }
            unpack_streams = unsafe {
                (unpack_streams as libc::c_ulong)
                    .wrapping_add((*f.offset(i as isize)).numUnpackStreams)
                    as size_t as size_t
            };
            i = i.wrapping_add(1)
        }
        p = header_bytes(a, 1 as libc::c_int as size_t);
        if p.is_null() {
            return -(1 as libc::c_int);
        }
        type_0 = unsafe { *p as libc::c_int }
    } else {
        unpack_streams = numFolders
    }
    (safe_ss).unpack_streams = unpack_streams;
    if unpack_streams != 0 {
        (safe_ss).unpackSizes = calloc_safe(
            unpack_streams,
            ::std::mem::size_of::<uint64_t>() as libc::c_ulong,
        ) as *mut uint64_t;
        (safe_ss).digestsDefined = calloc_safe(
            unpack_streams,
            ::std::mem::size_of::<libc::c_uchar>() as libc::c_ulong,
        ) as *mut libc::c_uchar;
        (safe_ss).digests = calloc_safe(
            unpack_streams,
            ::std::mem::size_of::<uint32_t>() as libc::c_ulong,
        ) as *mut uint32_t;
        if (safe_ss).unpackSizes.is_null()
            || (safe_ss).digestsDefined.is_null()
            || (safe_ss).digests.is_null()
        {
            return -(1 as libc::c_int);
        }
    }
    usizes = (safe_ss).unpackSizes;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) < numFolders {
        let mut pack: libc::c_uint = 0;
        let mut sum: uint64_t = 0;
        if unsafe {
            !((*f.offset(i as isize)).numUnpackStreams == 0 as libc::c_int as libc::c_ulong)
        } {
            sum = 0 as libc::c_int as uint64_t;
            if type_0 == 0x9 as libc::c_int {
                pack = 1 as libc::c_int as libc::c_uint;
                while unsafe { (pack as libc::c_ulong) < (*f.offset(i as isize)).numUnpackStreams }
                {
                    if parse_7zip_uint64(a, usizes) < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    let fresh4 = usizes;
                    usizes = unsafe { usizes.offset(1) };
                    sum = unsafe {
                        (sum as libc::c_ulong).wrapping_add(*fresh4) as uint64_t as uint64_t
                    };
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
    if type_0 == 0x9 as libc::c_int {
        p = header_bytes(a, 1 as libc::c_int as size_t);
        if p.is_null() {
            return -(1 as libc::c_int);
        }
        type_0 = unsafe { *p as libc::c_int }
    }
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) < unpack_streams {
        unsafe { *(safe_ss).digestsDefined.offset(i as isize) = 0 as libc::c_int as libc::c_uchar };
        unsafe { *(safe_ss).digests.offset(i as isize) = 0 as libc::c_int as uint32_t };
        i = i.wrapping_add(1)
    }
    numDigests = 0 as libc::c_int as uint32_t;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) < numFolders {
        if unsafe {
            (*f.offset(i as isize)).numUnpackStreams != 1 as libc::c_int as libc::c_ulong
                || (*f.offset(i as isize)).digest_defined == 0
        } {
            numDigests = unsafe {
                (numDigests as libc::c_uint)
                    .wrapping_add((*f.offset(i as isize)).numUnpackStreams as uint32_t)
                    as uint32_t as uint32_t
            }
        }
        i = i.wrapping_add(1)
    }
    if type_0 == 0xa as libc::c_int {
        let mut tmpDigests: _7z_digests = _7z_digests {
            defineds: 0 as *mut libc::c_uchar,
            digests: 0 as *mut uint32_t,
        };
        let mut digestsDefined: *mut libc::c_uchar = (safe_ss).digestsDefined;
        let mut digests: *mut uint32_t = (safe_ss).digests;
        let mut di: libc::c_int = 0 as libc::c_int;
        memset_safe(
            &mut tmpDigests as *mut _7z_digests as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<_7z_digests>() as libc::c_ulong,
        );
        if read_Digests(a, &mut tmpDigests, numDigests as size_t) < 0 as libc::c_int {
            free_Digest(&mut tmpDigests);
            return -(1 as libc::c_int);
        }
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong) < numFolders {
            if unsafe {
                (*f.offset(i as isize)).numUnpackStreams == 1 as libc::c_int as libc::c_ulong
                    && (*f.offset(i as isize)).digest_defined as libc::c_int != 0
            } {
                let fresh6 = digestsDefined;
                digestsDefined = unsafe { digestsDefined.offset(1) };
                unsafe { *fresh6 = 1 as libc::c_int as libc::c_uchar };
                let fresh7 = digests;
                digests = unsafe { digests.offset(1) };
                unsafe { *fresh7 = (*f.offset(i as isize)).digest }
            } else {
                let mut j: libc::c_uint = 0;
                j = 0 as libc::c_int as libc::c_uint;
                unsafe {
                    while (j as libc::c_ulong) < (*f.offset(i as isize)).numUnpackStreams {
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
        p = header_bytes(a, 1 as libc::c_int as size_t);
        if p.is_null() {
            return -(1 as libc::c_int);
        }
        type_0 = unsafe { *p as libc::c_int }
    }
    /*
     *  Must be kEnd.
     */
    if type_0 != 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn free_StreamsInfo(mut si: *mut _7z_stream_info) {
    let safe_si = unsafe { &mut *si };
    free_PackInfo(&mut safe_si.pi);
    free_CodersInfo(&mut safe_si.ci);
    free_SubStreamsInfo(&mut safe_si.ss);
}
unsafe extern "C" fn read_StreamsInfo(
    mut a: *mut archive_read,
    mut si: *mut _7z_stream_info,
) -> libc::c_int {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut i: libc::c_uint = 0;
    memset_safe(
        si as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<_7z_stream_info>() as libc::c_ulong,
    );
    let safe_si = unsafe { &mut *si };
    p = header_bytes(a, 1 as libc::c_int as size_t);
    if p.is_null() {
        return -(1 as libc::c_int);
    }
    if unsafe { *p as libc::c_int == 0x6 as libc::c_int } {
        let mut packPos: uint64_t = 0;
        if read_PackInfo(a, &mut (safe_si).pi) < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if (safe_si).pi.positions.is_null() || (safe_si).pi.sizes.is_null() {
            return -(1 as libc::c_int);
        }
        /*
         * Calculate packed stream positions.
         */
        packPos = (safe_si).pi.pos;
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong) < (safe_si).pi.numPackStreams {
            unsafe {
                *(safe_si).pi.positions.offset(i as isize) = packPos;
                packPos = (packPos as libc::c_ulong)
                    .wrapping_add(*(*si).pi.sizes.offset(i as isize))
                    as uint64_t as uint64_t;
                if packPos > (*zip).header_offset {
                    return -(1 as libc::c_int);
                }
                i = i.wrapping_add(1)
            }
        }
        p = header_bytes(a, 1 as libc::c_int as size_t);
        if p.is_null() {
            return -(1 as libc::c_int);
        }
    }
    if unsafe { *p as libc::c_int == 0x7 as libc::c_int } {
        let mut packIndex: uint32_t = 0;
        let mut f: *mut _7z_folder = 0 as *mut _7z_folder;
        if read_CodersInfo(a, &mut (safe_si).ci) < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        /*
         * Calculate packed stream indexes.
         */
        packIndex = 0 as libc::c_int as uint32_t;
        f = (safe_si).ci.folders;
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong) < (safe_si).ci.numFolders {
            unsafe {
                (*f.offset(i as isize)).packIndex = packIndex;
                packIndex = (packIndex as libc::c_uint)
                    .wrapping_add((*f.offset(i as isize)).numPackedStreams as uint32_t)
                    as uint32_t as uint32_t;
                if packIndex as libc::c_ulong > (*si).pi.numPackStreams {
                    return -(1 as libc::c_int);
                }
                i = i.wrapping_add(1)
            }
        }
        p = header_bytes(a, 1 as libc::c_int as size_t);
        if p.is_null() {
            return -(1 as libc::c_int);
        }
    }
    if unsafe { *p as libc::c_int == 0x8 as libc::c_int } {
        if read_SubStreamsInfo(
            a,
            &mut (safe_si).ss,
            (safe_si).ci.folders,
            (safe_si).ci.numFolders,
        ) < 0 as libc::c_int
        {
            return -(1 as libc::c_int);
        }
        p = header_bytes(a, 1 as libc::c_int as size_t);
        if p.is_null() {
            return -(1 as libc::c_int);
        }
    }
    /*
     *  Must be kEnd.
     */
    if unsafe { *p as libc::c_int != 0 as libc::c_int } {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn free_Header(mut h: *mut _7z_header_info) {
    let safe_h = unsafe { &mut *h };
    free_safe((safe_h).emptyStreamBools as *mut libc::c_void);
    free_safe((safe_h).emptyFileBools as *mut libc::c_void);
    free_safe((safe_h).antiBools as *mut libc::c_void);
    free_safe((safe_h).attrBools as *mut libc::c_void);
}
unsafe extern "C" fn read_Header(
    mut a: *mut archive_read,
    mut h: *mut _7z_header_info,
    mut check_header_id: libc::c_int,
) -> libc::c_int {
    unsafe {
        let mut zip: *mut _7zip = (*(*a).format).data as *mut _7zip;
        let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
        let mut folders: *mut _7z_folder = 0 as *mut _7z_folder;
        let mut si: *mut _7z_stream_info = &mut (*zip).si;
        let mut entries: *mut _7zip_entry = 0 as *mut _7zip_entry;
        let mut folderIndex: uint32_t = 0;
        let mut indexInFolder: uint32_t = 0;
        let mut i: libc::c_uint = 0;
        let mut eindex: libc::c_int = 0;
        let mut empty_streams: libc::c_int = 0;
        let mut sindex: libc::c_int = 0;

        if check_header_id != 0 {
            /*
             * Read Header.
             */
            p = header_bytes(a, 1 as libc::c_int as size_t);
            if p.is_null() {
                return -(1 as libc::c_int);
            }
            if *p as libc::c_int != 0x1 as libc::c_int {
                return -(1 as libc::c_int);
            }
        }
        /*
         * Read ArchiveProperties.
         */
        p = header_bytes(a, 1 as libc::c_int as size_t);
        if p.is_null() {
            return -(1 as libc::c_int);
        }
        if *p as libc::c_int == 0x2 as libc::c_int {
            loop {
                let mut size: uint64_t = 0;
                p = header_bytes(a, 1 as libc::c_int as size_t);
                if p.is_null() {
                    return -(1 as libc::c_int);
                }
                if *p as libc::c_int == 0 as libc::c_int {
                    break;
                }
                if parse_7zip_uint64(a, &mut size) < 0 as libc::c_int {
                    return -(1 as libc::c_int);
                }
            }
            p = header_bytes(a, 1 as libc::c_int as size_t);
            if p.is_null() {
                return -(1 as libc::c_int);
            }
        }
        /*
         * Read MainStreamsInfo.
         */
        if *p as libc::c_int == 0x4 as libc::c_int {
            if read_StreamsInfo(a, &mut (*zip).si) < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            p = header_bytes(a, 1 as libc::c_int as size_t);
            if p.is_null() {
                return -(1 as libc::c_int);
            }
        }
        if *p as libc::c_int == 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        /*
         * Read FilesInfo.
         */
        if *p as libc::c_int != 0x5 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if parse_7zip_uint64(a, &mut (*zip).numFiles) < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        if (100000000 as libc::c_ulonglong) < (*zip).numFiles as libc::c_ulonglong {
            return -(1 as libc::c_int);
        }
        (*zip).entries = calloc(
            (*zip).numFiles,
            ::std::mem::size_of::<_7zip_entry>() as libc::c_ulong,
        ) as *mut _7zip_entry;
        if (*zip).entries.is_null() {
            return -(1 as libc::c_int);
        }
        entries = (*zip).entries;
        empty_streams = 0 as libc::c_int;
        loop {
            let mut type_0: libc::c_int = 0;
            let mut size_0: uint64_t = 0;
            let mut ll: size_t = 0;
            p = header_bytes(a, 1 as libc::c_int as size_t);
            if p.is_null() {
                return -(1 as libc::c_int);
            }
            type_0 = *p as libc::c_int;
            if type_0 == 0 as libc::c_int {
                break;
            }
            if parse_7zip_uint64(a, &mut size_0) < 0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            if (*zip).header_bytes_remaining < size_0 {
                return -(1 as libc::c_int);
            }
            ll = size_0;
            let mut current_block_137: u64;
            match type_0 {
                14 => {
                    if !(*h).emptyStreamBools.is_null() {
                        return -(1 as libc::c_int);
                    }
                    (*h).emptyStreamBools = calloc(
                        (*zip).numFiles,
                        ::std::mem::size_of::<libc::c_uchar>() as libc::c_ulong,
                    ) as *mut libc::c_uchar;
                    if (*h).emptyStreamBools.is_null() {
                        return -(1 as libc::c_int);
                    }
                    if read_Bools(a, (*h).emptyStreamBools, (*zip).numFiles) < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    empty_streams = 0 as libc::c_int;
                    i = 0 as libc::c_int as libc::c_uint;
                    while (i as libc::c_ulong) < (*zip).numFiles {
                        if *(*h).emptyStreamBools.offset(i as isize) != 0 {
                            empty_streams += 1
                        }
                        i = i.wrapping_add(1)
                    }
                    current_block_137 = 7999014830792590863;
                }
                15 => {
                    if empty_streams <= 0 as libc::c_int {
                        /* Unexcepted sequence. Skip this. */
                        if header_bytes(a, ll).is_null() {
                            return -(1 as libc::c_int);
                        }
                    } else {
                        if !(*h).emptyFileBools.is_null() {
                            return -(1 as libc::c_int);
                        }
                        (*h).emptyFileBools = calloc(
                            empty_streams as libc::c_ulong,
                            ::std::mem::size_of::<libc::c_uchar>() as libc::c_ulong,
                        ) as *mut libc::c_uchar;
                        if (*h).emptyFileBools.is_null() {
                            return -(1 as libc::c_int);
                        }
                        if read_Bools(a, (*h).emptyFileBools, empty_streams as size_t)
                            < 0 as libc::c_int
                        {
                            return -(1 as libc::c_int);
                        }
                    }
                    current_block_137 = 7999014830792590863;
                }
                16 => {
                    if empty_streams <= 0 as libc::c_int {
                        /* Unexcepted sequence. Skip this. */
                        if header_bytes(a, ll).is_null() {
                            return -(1 as libc::c_int);
                        }
                    } else {
                        if !(*h).antiBools.is_null() {
                            return -(1 as libc::c_int);
                        }
                        (*h).antiBools = calloc(
                            empty_streams as libc::c_ulong,
                            ::std::mem::size_of::<libc::c_uchar>() as libc::c_ulong,
                        ) as *mut libc::c_uchar;
                        if (*h).antiBools.is_null() {
                            return -(1 as libc::c_int);
                        }
                        if read_Bools(a, (*h).antiBools, empty_streams as size_t) < 0 as libc::c_int
                        {
                            return -(1 as libc::c_int);
                        }
                    }
                    current_block_137 = 7999014830792590863;
                }
                18 | 19 | 20 => {
                    if read_Times(a, h, type_0) < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    current_block_137 = 7999014830792590863;
                }
                17 => {
                    let mut np: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
                    let mut nl: size_t = 0;
                    let mut nb: size_t = 0;
                    /* Skip one byte. */
                    p = header_bytes(a, 1 as libc::c_int as size_t);
                    if p.is_null() {
                        return -(1 as libc::c_int);
                    }
                    ll = ll.wrapping_sub(1);
                    if ll & 1 as libc::c_int as libc::c_ulong != 0
                        || ll
                            < (*zip)
                                .numFiles
                                .wrapping_mul(4 as libc::c_int as libc::c_ulong)
                    {
                        return -(1 as libc::c_int);
                    }
                    if !(*zip).entry_names.is_null() {
                        return -(1 as libc::c_int);
                    }
                    (*zip).entry_names = malloc(ll) as *mut libc::c_uchar;
                    if (*zip).entry_names.is_null() {
                        return -(1 as libc::c_int);
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
                        if nb > (64 as libc::c_int * 1024 as libc::c_int) as libc::c_ulong {
                            b = (64 as libc::c_int * 1024 as libc::c_int) as size_t
                        } else {
                            b = nb
                        }
                        p = header_bytes(a, b);
                        if p.is_null() {
                            return -(1 as libc::c_int);
                        }
                        memcpy(np as *mut libc::c_void, p as *const libc::c_void, b);
                        np = np.offset(b as isize);
                        nb = (nb as libc::c_ulong).wrapping_sub(b) as size_t as size_t
                    }
                    np = (*zip).entry_names;
                    nl = ll;
                    i = 0 as libc::c_int as libc::c_uint;
                    while (i as libc::c_ulong) < (*zip).numFiles {
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
                        while nl >= 2 as libc::c_int as libc::c_ulong
                            && (*np.offset(0 as libc::c_int as isize) as libc::c_int != 0
                                || *np.offset(1 as libc::c_int as isize) as libc::c_int != 0)
                        {
                            np = np.offset(2 as libc::c_int as isize); /* Terminator not found */
                            nl = (nl as libc::c_ulong)
                                .wrapping_sub(2 as libc::c_int as libc::c_ulong)
                                as size_t as size_t
                        }
                        if nl < 2 as libc::c_int as libc::c_ulong {
                            return -(1 as libc::c_int);
                        }
                        (*entries.offset(i as isize)).name_len =
                            np.offset_from((*entries.offset(i as isize)).utf16name) as libc::c_long
                                as size_t;
                        np = np.offset(2 as libc::c_int as isize);
                        nl = (nl as libc::c_ulong).wrapping_sub(2 as libc::c_int as libc::c_ulong)
                            as size_t as size_t;
                        i = i.wrapping_add(1)
                    }
                    current_block_137 = 7999014830792590863;
                }
                21 => {
                    let mut allAreDefined: libc::c_int = 0;
                    p = header_bytes(a, 2 as libc::c_int as size_t);
                    if p.is_null() {
                        return -(1 as libc::c_int);
                    }
                    allAreDefined = *p as libc::c_int;
                    if !(*h).attrBools.is_null() {
                        return -(1 as libc::c_int);
                    }
                    (*h).attrBools = calloc(
                        (*zip).numFiles,
                        ::std::mem::size_of::<libc::c_uchar>() as libc::c_ulong,
                    ) as *mut libc::c_uchar;
                    if (*h).attrBools.is_null() {
                        return -(1 as libc::c_int);
                    }
                    if allAreDefined != 0 {
                        memset(
                            (*h).attrBools as *mut libc::c_void,
                            1 as libc::c_int,
                            (*zip).numFiles,
                        );
                    } else if read_Bools(a, (*h).attrBools, (*zip).numFiles) < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    i = 0 as libc::c_int as libc::c_uint;
                    while (i as libc::c_ulong) < (*zip).numFiles {
                        if *(*h).attrBools.offset(i as isize) != 0 {
                            p = header_bytes(a, 4 as libc::c_int as size_t);
                            if p.is_null() {
                                return -(1 as libc::c_int);
                            }
                            (*entries.offset(i as isize)).attr =
                                archive_le32dec(p as *const libc::c_void)
                        }
                        i = i.wrapping_add(1)
                    }
                    current_block_137 = 7999014830792590863;
                }
                25 => {
                    if ll == 0 as libc::c_int as libc::c_ulong {
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
                        return -(1 as libc::c_int);
                    }
                }
                _ => {}
            }
        }
        /*
         * Set up entry's attributes.
         */
        folders = (*si).ci.folders;
        sindex = 0 as libc::c_int;
        eindex = sindex;
        indexInFolder = 0 as libc::c_int as uint32_t;
        folderIndex = indexInFolder;
        i = 0 as libc::c_int as libc::c_uint;
        while (i as libc::c_ulong) < (*zip).numFiles {
            if (*h).emptyStreamBools.is_null()
                || *(*h).emptyStreamBools.offset(i as isize) as libc::c_int == 0 as libc::c_int
            {
                (*entries.offset(i as isize)).flg |=
                    ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint
            }
            /* The high 16 bits of attributes is a posix file mode. */
            (*entries.offset(i as isize)).mode =
                (*entries.offset(i as isize)).attr >> 16 as libc::c_int; /* Read only. */
            if (*entries.offset(i as isize)).flg
                & ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint
                != 0
            {
                if sindex as size_t >= (*si).ss.unpack_streams {
                    return -(1 as libc::c_int);
                }
                if (*entries.offset(i as isize)).mode == 0 as libc::c_int as libc::c_uint {
                    (*entries.offset(i as isize)).mode =
                        0o100000 as libc::c_int as mode_t | 0o666 as libc::c_int as libc::c_uint
                }
                if *(*si).ss.digestsDefined.offset(sindex as isize) != 0 {
                    (*entries.offset(i as isize)).flg |=
                        ((1 as libc::c_int) << 3 as libc::c_int) as libc::c_uint
                }
                (*entries.offset(i as isize)).ssIndex = sindex as uint32_t;
                sindex += 1
            } else {
                let mut dir: libc::c_int = 0;
                if (*h).emptyFileBools.is_null() {
                    dir = 1 as libc::c_int
                } else {
                    if *(*h).emptyFileBools.offset(eindex as isize) != 0 {
                        dir = 0 as libc::c_int
                    } else {
                        dir = 1 as libc::c_int
                    }
                    eindex += 1
                }
                if (*entries.offset(i as isize)).mode == 0 as libc::c_int as libc::c_uint {
                    if dir != 0 {
                        (*entries.offset(i as isize)).mode =
                            0o40000 as libc::c_int as mode_t | 0o777 as libc::c_int as libc::c_uint
                    } else {
                        (*entries.offset(i as isize)).mode =
                            0o100000 as libc::c_int as mode_t | 0o666 as libc::c_int as libc::c_uint
                    }
                } else if dir != 0
                    && (*entries.offset(i as isize)).mode & 0o170000 as libc::c_int as mode_t
                        != 0o40000 as libc::c_int as mode_t
                {
                    let ref mut fresh11 = (*entries.offset(i as isize)).mode;
                    *fresh11 &= !(0o170000 as libc::c_int as mode_t);
                    let ref mut fresh12 = (*entries.offset(i as isize)).mode;
                    *fresh12 |= 0o40000 as libc::c_int as mode_t
                }
                if (*entries.offset(i as isize)).mode & 0o170000 as libc::c_int as mode_t
                    == 0o40000 as libc::c_int as mode_t
                    && (*entries.offset(i as isize)).name_len >= 2 as libc::c_int as libc::c_ulong
                    && (*(*entries.offset(i as isize)).utf16name.offset(
                        (*entries.offset(i as isize))
                            .name_len
                            .wrapping_sub(2 as libc::c_int as libc::c_ulong)
                            as isize,
                    ) as libc::c_int
                        != '/' as i32
                        || *(*entries.offset(i as isize)).utf16name.offset(
                            (*entries.offset(i as isize))
                                .name_len
                                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                as isize,
                        ) as libc::c_int
                            != 0 as libc::c_int)
                {
                    *(*entries.offset(i as isize))
                        .utf16name
                        .offset((*entries.offset(i as isize)).name_len as isize) =
                        '/' as i32 as libc::c_uchar;
                    *(*entries.offset(i as isize)).utf16name.offset(
                        (*entries.offset(i as isize))
                            .name_len
                            .wrapping_add(1 as libc::c_int as libc::c_ulong)
                            as isize,
                    ) = 0 as libc::c_int as libc::c_uchar;
                    let ref mut fresh13 = (*entries.offset(i as isize)).name_len;
                    *fresh13 = (*fresh13 as libc::c_ulong)
                        .wrapping_add(2 as libc::c_int as libc::c_ulong)
                        as size_t as size_t
                }
                (*entries.offset(i as isize)).ssIndex = -(1 as libc::c_int) as uint32_t
            }
            if (*entries.offset(i as isize)).attr & 0x1 as libc::c_int as libc::c_uint != 0 {
                let ref mut fresh14 = (*entries.offset(i as isize)).mode;
                *fresh14 &= !(0o222 as libc::c_int) as libc::c_uint
            }
            if (*entries.offset(i as isize)).flg
                & ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint
                == 0 as libc::c_int as libc::c_uint
                && indexInFolder == 0 as libc::c_int as libc::c_uint
            {
                /*
                 * The entry is an empty file or a directory file,
                 * those both have no contents.
                 */
                (*entries.offset(i as isize)).folderIndex = -(1 as libc::c_int) as uint32_t
            } else {
                if indexInFolder == 0 as libc::c_int as libc::c_uint {
                    loop {
                        if folderIndex as libc::c_ulong >= (*si).ci.numFolders {
                            return -(1 as libc::c_int);
                        }
                        if (*folders.offset(folderIndex as isize)).numUnpackStreams != 0 {
                            break;
                        }
                        folderIndex = folderIndex.wrapping_add(1)
                    }
                }
                (*entries.offset(i as isize)).folderIndex = folderIndex;
                if !((*entries.offset(i as isize)).flg
                    & ((1 as libc::c_int) << 4 as libc::c_int) as libc::c_uint
                    == 0 as libc::c_int as libc::c_uint)
                {
                    indexInFolder = indexInFolder.wrapping_add(1);
                    if indexInFolder as libc::c_ulong
                        >= (*folders.offset(folderIndex as isize)).numUnpackStreams
                    {
                        folderIndex = folderIndex.wrapping_add(1);
                        indexInFolder = 0 as libc::c_int as uint32_t
                    }
                }
            }
            i = i.wrapping_add(1)
        }
        return 0 as libc::c_int;
    }
}
unsafe extern "C" fn fileTimeToUtc(
    mut fileTime: uint64_t,
    mut timep: *mut time_t,
    mut ns: *mut libc::c_long,
) {
    if fileTime as libc::c_ulonglong >= 116444736000000000 as libc::c_ulonglong {
        fileTime = (fileTime as libc::c_ulonglong)
            .wrapping_sub(116444736000000000 as libc::c_ulonglong) as uint64_t
            as uint64_t;
        /* milli seconds base */
        unsafe {
            *timep = fileTime.wrapping_div(10000000 as libc::c_int as libc::c_ulong) as time_t;
            /* nano seconds base */
            *ns = fileTime.wrapping_rem(10000000 as libc::c_int as libc::c_ulong) as libc::c_long
                * 100 as libc::c_int as libc::c_long
        }
    } else {
        unsafe {
            *timep = 0 as libc::c_int as time_t;
            *ns = 0 as libc::c_int as libc::c_long
        }
    };
}
unsafe extern "C" fn read_Times(
    mut a: *mut archive_read,
    mut h: *mut _7z_header_info,
    mut type_0: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let safe_zip = unsafe { &mut *zip };
    let mut entries: *mut _7zip_entry = (safe_zip).entries;
    let mut timeBools: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut allAreDefined: libc::c_int = 0;
    let mut i: libc::c_uint = 0;
    timeBools = calloc_safe(
        (safe_zip).numFiles,
        ::std::mem::size_of::<libc::c_uchar>() as libc::c_ulong,
    ) as *mut libc::c_uchar;
    if timeBools.is_null() {
        return -(1 as libc::c_int);
    }
    /* Read allAreDefined. */
    p = header_bytes(a, 1 as libc::c_int as size_t);
    if !p.is_null() {
        allAreDefined = unsafe { *p as libc::c_int };
        if allAreDefined != 0 {
            memset_safe(
                timeBools as *mut libc::c_void,
                1 as libc::c_int,
                (safe_zip).numFiles,
            );
            current_block = 7746791466490516765;
        } else if read_Bools(a, timeBools, (safe_zip).numFiles) < 0 as libc::c_int {
            current_block = 4688298256779699391;
        } else {
            current_block = 7746791466490516765;
        }
        match current_block {
            4688298256779699391 => {}
            _ =>
            /* Read external. */
            {
                p = header_bytes(a, 1 as libc::c_int as size_t);
                if !p.is_null() {
                    unsafe {
                        if *p != 0 {
                            if parse_7zip_uint64(a, &mut (*h).dataIndex) < 0 as libc::c_int
                                || (100000000 as libc::c_ulonglong)
                                    < (*h).dataIndex as libc::c_ulonglong
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
                            i = 0 as libc::c_int as libc::c_uint;
                            loop {
                                if !((i as libc::c_ulong) < (safe_zip).numFiles) {
                                    current_block = 8693738493027456495;
                                    break;
                                }
                                if unsafe { !(*timeBools.offset(i as isize) == 0) } {
                                    p = header_bytes(a, 8 as libc::c_int as size_t);
                                    if p.is_null() {
                                        current_block = 4688298256779699391;
                                        break;
                                    }
                                    unsafe {
                                        match type_0 {
                                            18 => {
                                                fileTimeToUtc(
                                                    archive_le64dec(p as *const libc::c_void),
                                                    &mut (*entries.offset(i as isize)).ctime,
                                                    &mut (*entries.offset(i as isize)).ctime_ns,
                                                );
                                                (*entries.offset(i as isize)).flg |=
                                                    ((1 as libc::c_int) << 2 as libc::c_int)
                                                        as libc::c_uint
                                            }
                                            19 => {
                                                fileTimeToUtc(
                                                    archive_le64dec(p as *const libc::c_void),
                                                    &mut (*entries.offset(i as isize)).atime,
                                                    &mut (*entries.offset(i as isize)).atime_ns,
                                                );
                                                (*entries.offset(i as isize)).flg |=
                                                    ((1 as libc::c_int) << 1 as libc::c_int)
                                                        as libc::c_uint
                                            }
                                            20 => {
                                                fileTimeToUtc(
                                                    archive_le64dec(p as *const libc::c_void),
                                                    &mut (*entries.offset(i as isize)).mtime,
                                                    &mut (*entries.offset(i as isize)).mtime_ns,
                                                );
                                                (*entries.offset(i as isize)).flg |=
                                                    ((1 as libc::c_int) << 0 as libc::c_int)
                                                        as libc::c_uint
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
                                    free_safe(timeBools as *mut libc::c_void);
                                    return 0 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    free_safe(timeBools as *mut libc::c_void);
    return -(1 as libc::c_int);
}
unsafe extern "C" fn decode_encoded_header_info(
    mut a: *mut archive_read,
    mut si: *mut _7z_stream_info,
) -> libc::c_int {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    let safe_si = unsafe { &mut *si };
    unsafe { *__errno_location() = 0 as libc::c_int };
    if read_StreamsInfo(a, si) < 0 as libc::c_int {
        if unsafe { *__errno_location() == 12 as libc::c_int } {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Couldn\'t allocate memory\x00" as *const u8 as *const libc::c_char,
                )
            };
        } else {
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Malformed 7-Zip archive\x00" as *const u8 as *const libc::c_char,
                )
            };
        }
        return -(30 as libc::c_int);
    }
    if (safe_si).pi.numPackStreams == 0 as libc::c_int as libc::c_ulong
        || (safe_si).ci.numFolders == 0 as libc::c_int as libc::c_ulong
    {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as libc::c_int),
                b"Malformed 7-Zip archive\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int);
    }
    if unsafe {
        (safe_zip).header_offset
            < (safe_si)
                .pi
                .pos
                .wrapping_add(*(safe_si).pi.sizes.offset(0 as libc::c_int as isize))
            || ((safe_si)
                .pi
                .pos
                .wrapping_add(*(safe_si).pi.sizes.offset(0 as libc::c_int as isize))
                as int64_t)
                < 0 as libc::c_int as libc::c_long
            || *(safe_si).pi.sizes.offset(0 as libc::c_int as isize)
                == 0 as libc::c_int as libc::c_ulong
            || ((safe_si).pi.pos as int64_t) < 0 as libc::c_int as libc::c_long
    } {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as libc::c_int),
                b"Malformed Header offset\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn header_bytes(
    mut a: *mut archive_read,
    mut rbytes: size_t,
) -> *const libc::c_uchar {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let safe_zip = unsafe { &mut *zip };
    if (safe_zip).header_bytes_remaining < rbytes {
        return 0 as *const libc::c_uchar;
    }
    if (safe_zip).pack_stream_bytes_unconsumed != 0 {
        read_consume(a);
    }
    if (safe_zip).header_is_encoded == 0 as libc::c_int {
        p = __archive_read_ahead_safe(a, rbytes, 0 as *mut ssize_t) as *const libc::c_uchar;
        if p.is_null() {
            return 0 as *const libc::c_uchar;
        }
        (safe_zip).header_bytes_remaining = ((safe_zip).header_bytes_remaining as libc::c_ulong)
            .wrapping_sub(rbytes) as uint64_t
            as uint64_t;
        (safe_zip).pack_stream_bytes_unconsumed = rbytes
    } else {
        let mut buff: *const libc::c_void = 0 as *const libc::c_void;
        let mut bytes: ssize_t = 0;
        bytes = read_stream(a, &mut buff, rbytes, rbytes);
        if bytes <= 0 as libc::c_int as libc::c_long {
            return 0 as *const libc::c_uchar;
        }
        (safe_zip).header_bytes_remaining = ((safe_zip).header_bytes_remaining as libc::c_ulong)
            .wrapping_sub(bytes as libc::c_ulong)
            as uint64_t as uint64_t;
        p = buff as *const libc::c_uchar
    }
    /* Update checksum */
    (safe_zip).header_crc32 = crc32_safe((safe_zip).header_crc32, p, rbytes as libc::c_uint);
    return p;
}
unsafe extern "C" fn slurp_central_directory(
    mut a: *mut archive_read,
    mut zip: *mut _7zip,
    mut header: *mut _7z_header_info,
) -> libc::c_int {
    let mut p: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut next_header_offset: uint64_t = 0;
    let mut next_header_size: uint64_t = 0;
    let mut next_header_crc: uint32_t = 0;
    let mut bytes_avail: ssize_t = 0;
    let mut check_header_crc: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    p = __archive_read_ahead_safe(a, 32 as libc::c_int as size_t, &mut bytes_avail)
        as *const libc::c_uchar;
    if p.is_null() {
        return -(30 as libc::c_int);
    }
    if unsafe {
        *p.offset(0 as libc::c_int as isize) as libc::c_int == 'M' as i32
            && *p.offset(1 as libc::c_int as isize) as libc::c_int == 'Z' as i32
            || memcmp(
                p as *const libc::c_void,
                b"\x7fELF\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
                4 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
    } {
        /* This is an executable ? Must be self-extracting... */
        r = skip_sfx(a, bytes_avail);
        if r < -(20 as libc::c_int) {
            return r;
        }
        p = __archive_read_ahead_safe(a, 32 as libc::c_int as size_t, &mut bytes_avail)
            as *const libc::c_uchar;
        if p.is_null() {
            return -(30 as libc::c_int);
        }
    }
    (safe_zip).seek_base = ((safe_zip).seek_base as libc::c_ulong)
        .wrapping_add(32 as libc::c_int as libc::c_ulong) as uint64_t
        as uint64_t;
    if memcmp_safe(
        p as *const libc::c_void,
        b"7z\xbc\xaf\'\x1c\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        6 as libc::c_int as libc::c_ulong,
    ) != 0 as libc::c_int
    {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as libc::c_int),
                b"Not 7-Zip archive file\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int);
    }
    /* CRC check. */
    if crc32_safe(
        0 as libc::c_int as uLong,
        unsafe { p.offset(12 as libc::c_int as isize) },
        20 as libc::c_int as uInt,
    ) != archive_le32dec(unsafe { p.offset(8 as libc::c_int as isize) as *const libc::c_void })
        as libc::c_ulong
    {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as libc::c_int),
                b"Header CRC error\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int);
    }
    next_header_offset =
        archive_le64dec(unsafe { p.offset(12 as libc::c_int as isize) as *const libc::c_void });
    next_header_size =
        archive_le64dec(unsafe { p.offset(20 as libc::c_int as isize) as *const libc::c_void });
    next_header_crc =
        archive_le32dec(unsafe { p.offset(28 as libc::c_int as isize) as *const libc::c_void });
    if next_header_size == 0 as libc::c_int as libc::c_ulong {
        /* There is no entry in an archive file. */
        return 1 as libc::c_int;
    }
    if (next_header_offset as int64_t) < 0 as libc::c_int as libc::c_long {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as libc::c_int),
                b"Malformed 7-Zip archive\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int);
    }
    __archive_read_consume_safe(a, 32 as libc::c_int as int64_t);
    if next_header_offset != 0 as libc::c_int as libc::c_ulong {
        if bytes_avail >= next_header_offset as ssize_t {
            __archive_read_consume_safe(a, next_header_offset as int64_t);
        } else if __archive_read_seek_safe(
            a,
            next_header_offset.wrapping_add((safe_zip).seek_base) as int64_t,
            0 as libc::c_int,
        ) < 0 as libc::c_int as libc::c_long
        {
            return -(30 as libc::c_int);
        }
    }
    (safe_zip).stream_offset = next_header_offset as int64_t;
    (safe_zip).header_offset = next_header_offset;
    (safe_zip).header_bytes_remaining = next_header_size;
    (safe_zip).header_crc32 = 0 as libc::c_int as libc::c_ulong;
    (safe_zip).header_is_encoded = 0 as libc::c_int;
    (safe_zip).header_is_being_read = 1 as libc::c_int;
    (safe_zip).has_encrypted_entries = 0 as libc::c_int;
    check_header_crc = 1 as libc::c_int;
    p = header_bytes(a, 1 as libc::c_int as size_t);
    if p.is_null() {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                84 as libc::c_int,
                b"Truncated 7-Zip file body\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int);
    }
    /* Parse ArchiveProperties. */
    match unsafe { *p.offset(0 as libc::c_int as isize) as libc::c_int } {
        23 => {
            /*
             * The archive has an encoded header and we have to decode it
             * in order to parse the header correctly.
             */
            r = decode_encoded_header_info(a, &mut (safe_zip).si);
            /* Check the EncodedHeader CRC.*/
            if r == 0 as libc::c_int && (safe_zip).header_crc32 != next_header_crc as libc::c_ulong
            {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as libc::c_int),
                        b"Damaged 7-Zip archive\x00" as *const u8 as *const libc::c_char,
                    )
                };
                r = -(1 as libc::c_int)
            }
            if r == 0 as libc::c_int {
                if unsafe {
                    (*(safe_zip).si.ci.folders.offset(0 as libc::c_int as isize)).digest_defined
                        != 0
                } {
                    next_header_crc = unsafe {
                        (*(safe_zip).si.ci.folders.offset(0 as libc::c_int as isize)).digest
                    }
                } else {
                    check_header_crc = 0 as libc::c_int
                }
                if (safe_zip).pack_stream_bytes_unconsumed != 0 {
                    read_consume(a);
                }
                r = setup_decode_folder(a, (safe_zip).si.ci.folders, 1 as libc::c_int);
                if r == 0 as libc::c_int {
                    (safe_zip).header_bytes_remaining = (safe_zip).folder_outbytes_remaining;
                    r = seek_pack(a)
                }
            }
            /* Clean up StreamsInfo. */
            free_StreamsInfo(&mut (safe_zip).si);
            memset_safe(
                &mut (safe_zip).si as *mut _7z_stream_info as *mut libc::c_void,
                0 as libc::c_int,
                ::std::mem::size_of::<_7z_stream_info>() as libc::c_ulong,
            );
            if r < 0 as libc::c_int {
                return -(30 as libc::c_int);
            }
            (safe_zip).header_is_encoded = 1 as libc::c_int;
            (safe_zip).header_crc32 = 0 as libc::c_int as libc::c_ulong
        }
        1 => {}
        _ => {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Unexpected Property ID = %X\x00" as *const u8 as *const libc::c_char,
                    *p.offset(0 as libc::c_int as isize) as libc::c_int,
                )
            };
            return -(30 as libc::c_int);
        }
    }
    /* FALL THROUGH */
    /*
     * Parse the header.
     */
    unsafe { *__errno_location() = 0 as libc::c_int };
    r = read_Header(a, header, (safe_zip).header_is_encoded);
    if r < 0 as libc::c_int {
        if unsafe { *__errno_location() == 12 as libc::c_int } {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Couldn\'t allocate memory\x00" as *const u8 as *const libc::c_char,
                )
            };
        } else {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Damaged 7-Zip archive\x00" as *const u8 as *const libc::c_char,
                )
            };
        }
        return -(30 as libc::c_int);
    }
    p = header_bytes(a, 1 as libc::c_int as size_t);
    if unsafe { p.is_null() || *p as libc::c_int != 0 as libc::c_int } {
        unsafe {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                -(1 as libc::c_int),
                b"Malformed 7-Zip archive\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int);
    }
    if check_header_crc != 0 && (safe_zip).header_crc32 != next_header_crc as libc::c_ulong {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as libc::c_int),
                b"Malformed 7-Zip archive\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int);
    }
    /*
     *  Must be kEnd.
     */
    /* Check the Header CRC.*/
    /* Clean up variables be used for decoding the archive header */
    (safe_zip).pack_stream_remaining = 0 as libc::c_int as libc::c_uint;
    (safe_zip).pack_stream_index = 0 as libc::c_int as libc::c_uint;
    (safe_zip).folder_outbytes_remaining = 0 as libc::c_int as uint64_t;
    (safe_zip).uncompressed_buffer_bytes_remaining = 0 as libc::c_int as size_t;
    (safe_zip).pack_stream_bytes_unconsumed = 0 as libc::c_int as size_t;
    (safe_zip).header_is_being_read = 0 as libc::c_int;
    return 0 as libc::c_int;
}
unsafe extern "C" fn get_uncompressed_data(
    mut a: *mut archive_read,
    mut buff: *mut *const libc::c_void,
    mut size: size_t,
    mut minimum: size_t,
) -> ssize_t {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut bytes_avail: ssize_t = 0;
    let safe_zip = unsafe { &mut *zip };
    let safe_a = unsafe { &mut *a };
    if (safe_zip).codec == 0 as libc::c_int as libc::c_ulong
        && (safe_zip).codec2 == -(1 as libc::c_int) as libc::c_ulong
    {
        /* Copy mode. */
        unsafe { *buff = __archive_read_ahead(a, minimum, &mut bytes_avail) };
        if bytes_avail <= 0 as libc::c_int as libc::c_long {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    84 as libc::c_int,
                    b"Truncated 7-Zip file data\x00" as *const u8 as *const libc::c_char,
                )
            };
            return -(30 as libc::c_int) as ssize_t;
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
                -(1 as libc::c_int),
                b"Damaged 7-Zip archive\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int) as ssize_t;
    } else {
        /* Packed mode. */
        if minimum > (safe_zip).uncompressed_buffer_bytes_remaining {
            /*
             * If remaining uncompressed data size is less than
             * the minimum size, fill the buffer up to the
             * minimum size.
             */
            if extract_pack_stream(a, minimum) < 0 as libc::c_int as libc::c_long {
                return -(30 as libc::c_int) as ssize_t;
            }
        }
        if size > (safe_zip).uncompressed_buffer_bytes_remaining {
            bytes_avail = (safe_zip).uncompressed_buffer_bytes_remaining as ssize_t
        } else {
            bytes_avail = size as ssize_t
        }
        unsafe { *buff = (safe_zip).uncompressed_buffer_pointer as *const libc::c_void };
        (safe_zip).uncompressed_buffer_pointer = unsafe {
            (safe_zip)
                .uncompressed_buffer_pointer
                .offset(bytes_avail as isize)
        }
    }
    (safe_zip).uncompressed_buffer_bytes_remaining =
        ((safe_zip).uncompressed_buffer_bytes_remaining as libc::c_ulong)
            .wrapping_sub(bytes_avail as libc::c_ulong) as size_t as size_t;
    return bytes_avail;
}
unsafe extern "C" fn extract_pack_stream(mut a: *mut archive_read, mut minimum: size_t) -> ssize_t {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut bytes_avail: ssize_t = 0;
    let mut r: libc::c_int = 0;
    let safe_a = unsafe { &mut *a };
    let safe_zip = unsafe { &mut *zip };
    if (safe_zip).codec == 0 as libc::c_int as libc::c_ulong
        && (safe_zip).codec2 == -(1 as libc::c_int) as libc::c_ulong
    {
        if minimum == 0 as libc::c_int as libc::c_ulong {
            minimum = 1 as libc::c_int as size_t
        }
        if __archive_read_ahead_safe(a, minimum, &mut bytes_avail) == 0 as *mut libc::c_void
            || bytes_avail <= 0 as libc::c_int as libc::c_long
        {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    84 as libc::c_int,
                    b"Truncated 7-Zip file body\x00" as *const u8 as *const libc::c_char,
                )
            };
            return -(30 as libc::c_int) as ssize_t;
        }
        if bytes_avail as uint64_t > (safe_zip).pack_stream_inbytes_remaining {
            bytes_avail = (safe_zip).pack_stream_inbytes_remaining as ssize_t
        }
        (safe_zip).pack_stream_inbytes_remaining =
            ((safe_zip).pack_stream_inbytes_remaining as libc::c_ulong)
                .wrapping_sub(bytes_avail as libc::c_ulong) as uint64_t as uint64_t;
        if bytes_avail as uint64_t > (safe_zip).folder_outbytes_remaining {
            bytes_avail = (safe_zip).folder_outbytes_remaining as ssize_t
        }
        (safe_zip).folder_outbytes_remaining =
            ((safe_zip).folder_outbytes_remaining as libc::c_ulong)
                .wrapping_sub(bytes_avail as libc::c_ulong) as uint64_t as uint64_t;
        (safe_zip).uncompressed_buffer_bytes_remaining = bytes_avail as size_t;
        return 0 as libc::c_int as ssize_t;
    }
    /* If the buffer hasn't been allocated, allocate it now. */
    if (safe_zip).uncompressed_buffer.is_null() {
        (safe_zip).uncompressed_buffer_size = (64 as libc::c_int * 1024 as libc::c_int) as size_t;
        if (safe_zip).uncompressed_buffer_size < minimum {
            (safe_zip).uncompressed_buffer_size =
                minimum.wrapping_add(1023 as libc::c_int as libc::c_ulong);
            (safe_zip).uncompressed_buffer_size &= !(0x3ff as libc::c_int) as libc::c_ulong
        }
        (safe_zip).uncompressed_buffer =
            malloc_safe((safe_zip).uncompressed_buffer_size) as *mut libc::c_uchar;
        if (safe_zip).uncompressed_buffer.is_null() {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    12 as libc::c_int,
                    b"No memory for 7-Zip decompression\x00" as *const u8 as *const libc::c_char,
                )
            };
            return -(30 as libc::c_int) as ssize_t;
        }
        (safe_zip).uncompressed_buffer_bytes_remaining = 0 as libc::c_int as size_t
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
                    .offset_from((safe_zip).uncompressed_buffer) as libc::c_long
                    as size_t
            }
        } else {
            used = 0 as libc::c_int as size_t
        }
        if (safe_zip).uncompressed_buffer_size < minimum {
            /*
             * Expand the uncompressed buffer up to
             * the minimum size.
             */
            let mut p: *mut libc::c_void = 0 as *mut libc::c_void;
            let mut new_size: size_t = 0;
            new_size = minimum.wrapping_add(1023 as libc::c_int as libc::c_ulong);
            new_size &= !(0x3ff as libc::c_int) as libc::c_ulong;
            p = realloc_safe(
                (safe_zip).uncompressed_buffer as *mut libc::c_void,
                new_size,
            );
            if p.is_null() {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        12 as libc::c_int,
                        b"No memory for 7-Zip decompression\x00" as *const u8
                            as *const libc::c_char,
                    )
                };
                return -(30 as libc::c_int) as ssize_t;
            }
            (safe_zip).uncompressed_buffer = p as *mut libc::c_uchar;
            (safe_zip).uncompressed_buffer_size = new_size
        }
        /*
         * Move unconsumed bytes to the head.
         */
        if used != 0 {
            memmove_safe(
                (safe_zip).uncompressed_buffer as *mut libc::c_void,
                unsafe {
                    (safe_zip).uncompressed_buffer.offset(used as isize) as *const libc::c_void
                },
                (safe_zip).uncompressed_buffer_bytes_remaining,
            );
        }
    } else {
        (safe_zip).uncompressed_buffer_bytes_remaining = 0 as libc::c_int as size_t
    }
    (safe_zip).uncompressed_buffer_pointer = 0 as *mut libc::c_uchar;
    loop {
        let mut bytes_in: size_t = 0;
        let mut bytes_out: size_t = 0;
        let mut buff_in: *const libc::c_void = 0 as *const libc::c_void;
        let mut buff_out: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
        let mut end_of_data: libc::c_int = 0;
        /*
         * Note: '1' here is a performance optimization.
         * Recall that the decompression layer returns a count of
         * available bytes; asking for more than that forces the
         * decompressor to combine reads by copying data.
         */
        buff_in = __archive_read_ahead_safe(a, 1 as libc::c_int as size_t, &mut bytes_avail);
        if bytes_avail <= 0 as libc::c_int as libc::c_long {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    84 as libc::c_int,
                    b"Truncated 7-Zip file body\x00" as *const u8 as *const libc::c_char,
                )
            };
            return -(30 as libc::c_int) as ssize_t;
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
            buff_out as *mut libc::c_void,
            &mut bytes_out,
            buff_in,
            &mut bytes_in,
        );
        match r {
            0 => end_of_data = 0 as libc::c_int,
            1 => end_of_data = 1 as libc::c_int,
            _ => return -(30 as libc::c_int) as ssize_t,
        }
        (safe_zip).pack_stream_inbytes_remaining =
            ((safe_zip).pack_stream_inbytes_remaining as libc::c_ulong).wrapping_sub(bytes_in)
                as uint64_t as uint64_t;
        if bytes_out > (safe_zip).folder_outbytes_remaining {
            bytes_out = (safe_zip).folder_outbytes_remaining
        }
        (safe_zip).folder_outbytes_remaining =
            ((safe_zip).folder_outbytes_remaining as libc::c_ulong).wrapping_sub(bytes_out)
                as uint64_t as uint64_t;
        (safe_zip).uncompressed_buffer_bytes_remaining =
            ((safe_zip).uncompressed_buffer_bytes_remaining as libc::c_ulong)
                .wrapping_add(bytes_out) as size_t as size_t;
        (safe_zip).pack_stream_bytes_unconsumed = bytes_in;
        /*
         * Continue decompression until uncompressed_buffer is full.
         */
        if (safe_zip).uncompressed_buffer_bytes_remaining == (safe_zip).uncompressed_buffer_size {
            break;
        }
        if (safe_zip).codec2 == 0x3030103 as libc::c_int as libc::c_ulong
            && (safe_zip).odd_bcj_size != 0
            && (safe_zip)
                .uncompressed_buffer_bytes_remaining
                .wrapping_add(5 as libc::c_int as libc::c_ulong)
                > (safe_zip).uncompressed_buffer_size
        {
            break;
        }
        if (safe_zip).pack_stream_inbytes_remaining == 0 as libc::c_int as libc::c_ulong
            && (safe_zip).folder_outbytes_remaining == 0 as libc::c_int as libc::c_ulong
        {
            break;
        }
        if end_of_data != 0
            || bytes_in == 0 as libc::c_int as libc::c_ulong
                && bytes_out == 0 as libc::c_int as libc::c_ulong
        {
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Damaged 7-Zip archive\x00" as *const u8 as *const libc::c_char,
                )
            };
            return -(30 as libc::c_int) as ssize_t;
        }
        read_consume(a);
    }
    if (safe_zip).uncompressed_buffer_bytes_remaining < minimum {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as libc::c_int),
                b"Damaged 7-Zip archive\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int) as ssize_t;
    }
    (safe_zip).uncompressed_buffer_pointer = (safe_zip).uncompressed_buffer;
    return 0 as libc::c_int as ssize_t;
}
unsafe extern "C" fn seek_pack(mut a: *mut archive_read) -> libc::c_int {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut pack_offset: int64_t = 0;
    let safe_zip = unsafe { &mut *zip };
    if (safe_zip).pack_stream_remaining <= 0 as libc::c_int as libc::c_uint {
        unsafe {
            archive_set_error(
                &mut (*a).archive as *mut archive,
                -(1 as libc::c_int),
                b"Damaged 7-Zip archive\x00" as *const u8 as *const libc::c_char,
            )
        };
        return -(30 as libc::c_int);
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
        if 0 as libc::c_int as libc::c_long
            > __archive_read_seek_safe(
                a,
                (pack_offset as libc::c_ulong).wrapping_add((safe_zip).seek_base) as int64_t,
                0 as libc::c_int,
            )
        {
            return -(30 as libc::c_int);
        }
        (safe_zip).stream_offset = pack_offset
    }
    (safe_zip).pack_stream_index = (safe_zip).pack_stream_index.wrapping_add(1);
    (safe_zip).pack_stream_remaining = (safe_zip).pack_stream_remaining.wrapping_sub(1);
    return 0 as libc::c_int;
}
unsafe extern "C" fn read_stream(
    mut a: *mut archive_read,
    mut buff: *mut *const libc::c_void,
    mut size: size_t,
    mut minimum: size_t,
) -> ssize_t {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut skip_bytes: uint64_t = 0 as libc::c_int as uint64_t;
    let mut r: ssize_t = 0;
    let safe_zip = unsafe { &mut *zip };
    let safe_a = unsafe { &mut *a };
    if (safe_zip).uncompressed_buffer_bytes_remaining == 0 as libc::c_int as libc::c_ulong {
        if (safe_zip).pack_stream_inbytes_remaining > 0 as libc::c_int as libc::c_ulong {
            r = extract_pack_stream(a, 0 as libc::c_int as size_t);
            if r < 0 as libc::c_int as libc::c_long {
                return r;
            }
            return get_uncompressed_data(a, buff, size, minimum);
        } else {
            if (safe_zip).folder_outbytes_remaining > 0 as libc::c_int as libc::c_ulong {
                /* Extract a remaining pack stream. */
                r = extract_pack_stream(a, 0 as libc::c_int as size_t);
                if r < 0 as libc::c_int as libc::c_long {
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
    if (safe_zip).pack_stream_remaining == 0 as libc::c_int as libc::c_uint {
        if (safe_zip).header_is_being_read != 0 {
            /* Invalid sequence. This might happen when
             * reading a malformed archive. */
            unsafe {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Malformed 7-Zip archive\x00" as *const u8 as *const libc::c_char,
                )
            };
            return -(30 as libc::c_int) as ssize_t;
        }
        /*
         * All current folder's pack streams have been
         * consumed. Switch to next folder.
         */
        if unsafe {
            (safe_zip).folder_index == 0 as libc::c_int as libc::c_uint
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
        if (safe_zip).folder_index as libc::c_ulong >= (safe_zip).si.ci.numFolders {
            /*
             * We have consumed all folders and its pack streams.
             */
            unsafe { *buff = 0 as *const libc::c_void };
            return 0 as libc::c_int as ssize_t;
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
            0 as libc::c_int,
        ) as ssize_t;
        if r != 0 as libc::c_int as libc::c_long {
            return -(30 as libc::c_int) as ssize_t;
        }
        (safe_zip).folder_index = (safe_zip).folder_index.wrapping_add(1)
    }
    /*
     * Switch to next pack stream.
     */
    r = seek_pack(a) as ssize_t;
    if r < 0 as libc::c_int as libc::c_long {
        return r;
    }
    /* Extract a new pack stream. */
    r = extract_pack_stream(a, 0 as libc::c_int as size_t);
    if r < 0 as libc::c_int as libc::c_long {
        return r;
    }
    /*
     * Skip the bytes we already has skipped in skip_stream().
     */
    while skip_bytes != 0 {
        let mut skipped: ssize_t = 0;
        if (safe_zip).uncompressed_buffer_bytes_remaining == 0 as libc::c_int as libc::c_ulong {
            if (safe_zip).pack_stream_inbytes_remaining > 0 as libc::c_int as libc::c_ulong
                || (safe_zip).folder_outbytes_remaining > 0 as libc::c_int as libc::c_ulong
            {
                /* Extract a remaining pack stream. */
                r = extract_pack_stream(a, 0 as libc::c_int as size_t);
                if r < 0 as libc::c_int as libc::c_long {
                    return r;
                }
            } else {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        84 as libc::c_int,
                        b"Truncated 7-Zip file body\x00" as *const u8 as *const libc::c_char,
                    )
                };
                return -(30 as libc::c_int) as ssize_t;
            }
        }
        skipped = get_uncompressed_data(a, buff, skip_bytes, 0 as libc::c_int as size_t);
        if skipped < 0 as libc::c_int as libc::c_long {
            return skipped;
        }
        skip_bytes = (skip_bytes as libc::c_ulong).wrapping_sub(skipped as libc::c_ulong)
            as uint64_t as uint64_t;
        if (safe_zip).pack_stream_bytes_unconsumed != 0 {
            read_consume(a);
        }
    }
    return get_uncompressed_data(a, buff, size, minimum);
}
unsafe extern "C" fn setup_decode_folder(
    mut a: *mut archive_read,
    mut folder: *mut _7z_folder,
    mut header: libc::c_int,
) -> libc::c_int {
    let mut zip: *mut _7zip = unsafe { (*(*a).format).data as *mut _7zip };
    let mut coder1: *const _7z_coder = 0 as *const _7z_coder;
    let mut coder2: *const _7z_coder = 0 as *const _7z_coder;
    let mut cname: *const libc::c_char = if header != 0 {
        b"archive header\x00" as *const u8 as *const libc::c_char
    } else {
        b"file content\x00" as *const u8 as *const libc::c_char
    };
    let mut i: libc::c_uint = 0;
    let mut r: libc::c_int = 0;
    let mut found_bcj2: libc::c_int = 0 as libc::c_int;
    /*
     * Release the memory which the previous folder used for BCJ2.
     */
    i = 0 as libc::c_int as libc::c_uint;
    let safe_a = unsafe { &mut *a };
    let mut safe_zip = unsafe { &mut *zip };
    let safe_folder = unsafe { &mut *folder };
    while i < 3 as libc::c_int as libc::c_uint {
        free_safe((safe_zip).sub_stream_buff[i as usize] as *mut libc::c_void);
        (safe_zip).sub_stream_buff[i as usize] = 0 as *mut libc::c_uchar;
        i = i.wrapping_add(1)
    }
    /*
     * Initialize a stream reader.
     */
    (safe_zip).pack_stream_remaining = (safe_folder).numPackedStreams as libc::c_uint;
    (safe_zip).pack_stream_index = (safe_folder).packIndex;
    (safe_zip).folder_outbytes_remaining = folder_uncompressed_size(folder);
    (safe_zip).uncompressed_buffer_bytes_remaining = 0 as libc::c_int as size_t;
    /*
     * Check coder types.
     */
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong) < (safe_folder).numCoders {
        match unsafe { (*(safe_folder).coders.offset(i as isize)).codec } {
            116457729 | 116458243 | 116459265 => {
                /* For entry that is associated with this folder, mark
                it as encrypted (data+metadata). */
                (safe_zip).has_encrypted_entries = 1 as libc::c_int;
                if !(safe_a).entry.is_null() {
                    archive_entry_set_is_data_encrypted_safe(
                        (safe_a).entry,
                        1 as libc::c_int as libc::c_char,
                    );
                    archive_entry_set_is_metadata_encrypted_safe(
                        (safe_a).entry,
                        1 as libc::c_int as libc::c_char,
                    );
                }
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as libc::c_int),
                        b"The %s is encrypted, but currently not supported\x00" as *const u8
                            as *const libc::c_char,
                        cname,
                    )
                };
                return -(30 as libc::c_int);
            }
            50528539 => found_bcj2 += 1,
            _ => {}
        }
        i = i.wrapping_add(1)
    }
    /* Now that we've checked for encryption, if there were still no
     * encrypted entries found we can say for sure that there are none.
     */
    if (safe_zip).has_encrypted_entries == -(1 as libc::c_int) {
        (safe_zip).has_encrypted_entries = 0 as libc::c_int
    }
    if (safe_folder).numCoders > 2 as libc::c_int as libc::c_ulong && found_bcj2 == 0
        || found_bcj2 > 1 as libc::c_int
    {
        unsafe {
            archive_set_error(
                &mut (safe_a).archive as *mut archive,
                -(1 as libc::c_int),
                b"The %s is encoded with many filters, but currently not supported\x00" as *const u8
                    as *const libc::c_char,
                cname,
            )
        };
        return -(30 as libc::c_int);
    }
    coder1 =
        unsafe { &mut *(safe_folder).coders.offset(0 as libc::c_int as isize) as *mut _7z_coder };
    if (safe_folder).numCoders == 2 as libc::c_int as libc::c_ulong {
        coder2 = unsafe {
            &mut *(safe_folder).coders.offset(1 as libc::c_int as isize) as *mut _7z_coder
        }
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
                codec: 0 as libc::c_int as libc::c_ulong,
                numInStreams: 1 as libc::c_int as uint64_t,
                numOutStreams: 1 as libc::c_int as uint64_t,
                propertiesSize: 0 as libc::c_int as uint64_t,
                properties: 0 as *const libc::c_uchar as *mut libc::c_uchar,
            };
            init
        };
        let mut scoder: [*const _7z_coder; 3] = unsafe { [&coder_copy, &coder_copy, &coder_copy] };
        let mut buff: *const libc::c_void = 0 as *const libc::c_void;
        let mut bytes: ssize_t = 0;
        let mut b: [*mut libc::c_uchar; 3] = [
            0 as *mut libc::c_uchar,
            0 as *mut libc::c_uchar,
            0 as *mut libc::c_uchar,
        ];
        let mut sunpack: [uint64_t; 3] = [
            -(1 as libc::c_int) as uint64_t,
            -(1 as libc::c_int) as uint64_t,
            -(1 as libc::c_int) as uint64_t,
        ];
        let mut s: [size_t; 3] = [
            0 as libc::c_int as size_t,
            0 as libc::c_int as size_t,
            0 as libc::c_int as size_t,
        ];
        let mut idx: [libc::c_int; 3] = [0 as libc::c_int, 1 as libc::c_int, 2 as libc::c_int];
        if unsafe {
            (safe_folder).numCoders == 4 as libc::c_int as libc::c_ulong
                && (*fc.offset(3 as libc::c_int as isize)).codec
                    == 0x303011b as libc::c_int as libc::c_ulong
                && (safe_folder).numInStreams == 7 as libc::c_int as libc::c_ulong
                && (safe_folder).numOutStreams == 4 as libc::c_int as libc::c_ulong
                && (safe_zip).pack_stream_remaining == 4 as libc::c_int as libc::c_uint
        } {
            /* Source type 1 made by 7zr or 7z with -m options. */
            if unsafe {
                (*(safe_folder).bindPairs.offset(0 as libc::c_int as isize)).inIndex
                    == 5 as libc::c_int as libc::c_ulong
            } {
                /* The form made by 7zr */
                idx[0 as libc::c_int as usize] = 1 as libc::c_int;
                idx[1 as libc::c_int as usize] = 2 as libc::c_int;
                idx[2 as libc::c_int as usize] = 0 as libc::c_int;
                unsafe {
                    scoder[1 as libc::c_int as usize] =
                        &*fc.offset(1 as libc::c_int as isize) as *const _7z_coder;
                    scoder[2 as libc::c_int as usize] =
                        &*fc.offset(0 as libc::c_int as isize) as *const _7z_coder;
                    sunpack[1 as libc::c_int as usize] =
                        *(*folder).unPackSize.offset(1 as libc::c_int as isize);
                    sunpack[2 as libc::c_int as usize] =
                        *(*folder).unPackSize.offset(0 as libc::c_int as isize);
                    coder1 = &*fc.offset(2 as libc::c_int as isize) as *const _7z_coder
                }
            } else if unsafe {
                (*fc.offset(0 as libc::c_int as isize)).codec == 0 as libc::c_int as libc::c_ulong
                    && (*fc.offset(1 as libc::c_int as isize)).codec
                        == 0 as libc::c_int as libc::c_ulong
            } {
                coder1 = unsafe {
                    &mut *(*folder).coders.offset(2 as libc::c_int as isize) as *mut _7z_coder
                }
            } else if unsafe {
                (*fc.offset(0 as libc::c_int as isize)).codec == 0 as libc::c_int as libc::c_ulong
                    && (*fc.offset(2 as libc::c_int as isize)).codec
                        == 0 as libc::c_int as libc::c_ulong
            } {
                coder1 = unsafe {
                    &mut *(*folder).coders.offset(1 as libc::c_int as isize) as *mut _7z_coder
                }
            } else if unsafe {
                (*fc.offset(1 as libc::c_int as isize)).codec == 0 as libc::c_int as libc::c_ulong
                    && (*fc.offset(2 as libc::c_int as isize)).codec
                        == 0 as libc::c_int as libc::c_ulong
            } {
                coder1 = unsafe {
                    &mut *(*folder).coders.offset(0 as libc::c_int as isize) as *mut _7z_coder
                }
            } else {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        -(1 as libc::c_int),
                        b"Unsupported form of BCJ2 streams\x00" as *const u8 as *const libc::c_char,
                    )
                };
                return -(30 as libc::c_int);
            }
            coder2 = unsafe { &*fc.offset(3 as libc::c_int as isize) as *const _7z_coder };
            (safe_zip).main_stream_bytes_remaining =
                unsafe { *(safe_folder).unPackSize.offset(2 as libc::c_int as isize) }
        } else if unsafe {
            !coder2.is_null()
                && (*coder2).codec == 0x303011b as libc::c_int as libc::c_ulong
                && (safe_zip).pack_stream_remaining == 4 as libc::c_int as libc::c_uint
                && (safe_folder).numInStreams == 5 as libc::c_int as libc::c_ulong
                && (safe_folder).numOutStreams == 2 as libc::c_int as libc::c_ulong
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
                unsafe { *(safe_folder).unPackSize.offset(0 as libc::c_int as isize) }
        } else {
            /* We got an unexpected form. */
            unsafe {
                archive_set_error(
                    &mut (safe_a).archive as *mut archive,
                    -(1 as libc::c_int),
                    b"Unsupported form of BCJ2 streams\x00" as *const u8 as *const libc::c_char,
                )
            };
            return -(30 as libc::c_int);
        }
        /* Skip the main stream at this time. */
        r = seek_pack(a);
        if r < 0 as libc::c_int {
            return r;
        }
        (safe_zip).pack_stream_bytes_unconsumed = (safe_zip).pack_stream_inbytes_remaining;
        read_consume(a);
        /* Read following three sub streams. */
        i = 0 as libc::c_int as libc::c_uint;
        while i < 3 as libc::c_int as libc::c_uint {
            let mut coder: *const _7z_coder = scoder[i as usize];
            r = seek_pack(a);
            if r < 0 as libc::c_int {
                free_safe(b[0 as libc::c_int as usize] as *mut libc::c_void);
                free_safe(b[1 as libc::c_int as usize] as *mut libc::c_void);
                free_safe(b[2 as libc::c_int as usize] as *mut libc::c_void);
                return r;
            }
            if sunpack[i as usize] == -(1 as libc::c_int) as uint64_t {
                (safe_zip).folder_outbytes_remaining = (safe_zip).pack_stream_inbytes_remaining
            } else {
                (safe_zip).folder_outbytes_remaining = sunpack[i as usize]
            }
            r = init_decompression(a, zip, coder, 0 as *const _7z_coder);
            if r != 0 as libc::c_int {
                free_safe(b[0 as libc::c_int as usize] as *mut libc::c_void);
                free_safe(b[1 as libc::c_int as usize] as *mut libc::c_void);
                free_safe(b[2 as libc::c_int as usize] as *mut libc::c_void);
                return -(30 as libc::c_int);
            }
            /* Allocate memory for the decoded data of a sub
             * stream. */
            b[i as usize] = malloc_safe((safe_zip).folder_outbytes_remaining) as *mut libc::c_uchar;
            if b[i as usize].is_null() {
                free_safe(b[0 as libc::c_int as usize] as *mut libc::c_void);
                free_safe(b[1 as libc::c_int as usize] as *mut libc::c_void);
                free_safe(b[2 as libc::c_int as usize] as *mut libc::c_void);
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        12 as libc::c_int,
                        b"No memory for 7-Zip decompression\x00" as *const u8
                            as *const libc::c_char,
                    )
                };
                return -(30 as libc::c_int);
            }
            /* Extract a sub stream. */
            while (safe_zip).pack_stream_inbytes_remaining > 0 as libc::c_int as libc::c_ulong {
                r = extract_pack_stream(a, 0 as libc::c_int as size_t) as libc::c_int;
                if r < 0 as libc::c_int {
                    free_safe(b[0 as libc::c_int as usize] as *mut libc::c_void);
                    free_safe(b[1 as libc::c_int as usize] as *mut libc::c_void);
                    free_safe(b[2 as libc::c_int as usize] as *mut libc::c_void);
                    return r;
                }
                bytes = get_uncompressed_data(
                    a,
                    &mut buff,
                    (safe_zip).uncompressed_buffer_bytes_remaining,
                    0 as libc::c_int as size_t,
                );
                if bytes < 0 as libc::c_int as libc::c_long {
                    free_safe(b[0 as libc::c_int as usize] as *mut libc::c_void);
                    free_safe(b[1 as libc::c_int as usize] as *mut libc::c_void);
                    free_safe(b[2 as libc::c_int as usize] as *mut libc::c_void);
                    return bytes as libc::c_int;
                }
                memcpy_safe(
                    unsafe { b[i as usize].offset(s[i as usize] as isize) as *mut libc::c_void },
                    buff,
                    bytes as libc::c_ulong,
                );
                s[i as usize] = (s[i as usize] as libc::c_ulong)
                    .wrapping_add(bytes as libc::c_ulong) as size_t
                    as size_t;
                if (safe_zip).pack_stream_bytes_unconsumed != 0 {
                    read_consume(a);
                }
                safe_zip = unsafe { &mut *((*(*a).format).data as *mut _7zip) };
            }
            i = i.wrapping_add(1)
        }
        /* Set the sub streams to the right place. */
        i = 0 as libc::c_int as libc::c_uint;
        while i < 3 as libc::c_int as libc::c_uint {
            (safe_zip).sub_stream_buff[i as usize] = b[idx[i as usize] as usize];
            (safe_zip).sub_stream_size[i as usize] = s[idx[i as usize] as usize];
            (safe_zip).sub_stream_bytes_remaining[i as usize] = s[idx[i as usize] as usize];
            i = i.wrapping_add(1)
        }
        /* Allocate memory used for decoded main stream bytes. */
        if (safe_zip).tmp_stream_buff.is_null() {
            (safe_zip).tmp_stream_buff_size = (32 as libc::c_int * 1024 as libc::c_int) as size_t;
            (safe_zip).tmp_stream_buff =
                malloc_safe((safe_zip).tmp_stream_buff_size) as *mut libc::c_uchar;
            if (safe_zip).tmp_stream_buff.is_null() {
                unsafe {
                    archive_set_error(
                        &mut (safe_a).archive as *mut archive,
                        12 as libc::c_int,
                        b"No memory for 7-Zip decompression\x00" as *const u8
                            as *const libc::c_char,
                    )
                };
                return -(30 as libc::c_int);
            }
        }
        (safe_zip).tmp_stream_bytes_avail = 0 as libc::c_int as size_t;
        (safe_zip).tmp_stream_bytes_remaining = 0 as libc::c_int as size_t;
        (safe_zip).odd_bcj_size = 0 as libc::c_int as size_t;
        (safe_zip).bcj2_outPos = 0 as libc::c_int as uint64_t;
        /*
         * Reset a stream reader in order to read the main stream
         * of BCJ2.
         */
        (safe_zip).pack_stream_remaining = 1 as libc::c_int as libc::c_uint;
        (safe_zip).pack_stream_index = (safe_folder).packIndex;
        (safe_zip).folder_outbytes_remaining = folder_uncompressed_size(folder);
        (safe_zip).uncompressed_buffer_bytes_remaining = 0 as libc::c_int as size_t
    }
    /*
     * Initialize the decompressor for the new folder's pack streams.
     */
    r = init_decompression(a, zip, coder1, coder2);
    if r != 0 as libc::c_int {
        return -(30 as libc::c_int);
    }
    return 0 as libc::c_int;
}

unsafe extern "C" fn skip_stream(mut a: *mut archive_read, mut skip_bytes: size_t) -> int64_t {
    unsafe {
        let mut zip: *mut _7zip = (*(*a).format).data as *mut _7zip;
        let mut p: *const libc::c_void = 0 as *const libc::c_void;
        let mut skipped_bytes: int64_t = 0;
        let mut bytes: size_t = skip_bytes;
        if (*zip).folder_index == 0 as libc::c_int as libc::c_uint {
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
            *fresh15 = (*fresh15 as libc::c_ulong).wrapping_add(skip_bytes) as uint64_t as uint64_t;
            return skip_bytes as int64_t;
        }
        while bytes != 0 {
            skipped_bytes = read_stream(a, &mut p, bytes, 0 as libc::c_int as size_t);
            if skipped_bytes < 0 as libc::c_int as libc::c_long {
                return skipped_bytes;
            }
            if skipped_bytes == 0 as libc::c_int as libc::c_long {
                archive_set_error(
                    &mut (*a).archive as *mut archive,
                    84 as libc::c_int,
                    b"Truncated 7-Zip file body\x00" as *const u8 as *const libc::c_char,
                );
                return -(30 as libc::c_int) as int64_t;
            }
            bytes =
                (bytes as libc::c_ulong).wrapping_sub(skipped_bytes as size_t) as size_t as size_t;
            if (*zip).pack_stream_bytes_unconsumed != 0 {
                read_consume(a);
            }
        }
        return skip_bytes as int64_t;
    }
}

unsafe extern "C" fn x86_Init(mut zip: *mut _7zip) {
    let safe_zip = unsafe { &mut *zip };
    safe_zip.bcj_state = 0 as libc::c_int as uint32_t;
    safe_zip.bcj_prevPosT =
        unsafe { (0 as libc::c_int as size_t).wrapping_sub(1 as libc::c_int as libc::c_ulong) };
    safe_zip.bcj_prevMask = 0 as libc::c_int as uint32_t;
    safe_zip.bcj_ip = 5 as libc::c_int as uint32_t;
}

unsafe extern "C" fn x86_Convert(
    mut zip: *mut _7zip,
    mut data: *mut uint8_t,
    mut size: size_t,
) -> size_t {
    static mut kMaskToAllowedStatus: [uint8_t; 8] = [
        1 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ];
    static mut kMaskToBitNumber: [uint8_t; 8] = [
        0 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
    ];
    let mut bufferPos: size_t = 0;
    let mut prevPosT: size_t = 0;
    let mut ip: uint32_t = 0;
    let mut prevMask: uint32_t = 0;
    let safe_zip = unsafe { &mut *zip };
    if size < 5 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int as size_t;
    }
    bufferPos = 0 as libc::c_int as size_t;
    prevPosT = (safe_zip).bcj_prevPosT;
    prevMask = (safe_zip).bcj_prevMask;
    ip = (safe_zip).bcj_ip;
    loop {
        let mut p: *mut uint8_t = unsafe { data.offset(bufferPos as isize) };
        let mut limit: *mut uint8_t = unsafe {
            data.offset(size as isize)
                .offset(-(4 as libc::c_int as isize))
        };
        unsafe {
            while p < limit {
                if *p as libc::c_int & 0xfe as libc::c_int == 0xe8 as libc::c_int {
                    break;
                }
                p = p.offset(1)
            }
        }
        bufferPos = unsafe { p.offset_from(data) as libc::c_long as size_t };
        if p >= limit {
            break;
        }
        prevPosT = bufferPos.wrapping_sub(prevPosT);
        if prevPosT > 3 as libc::c_int as libc::c_ulong {
            prevMask = 0 as libc::c_int as uint32_t
        } else {
            prevMask = prevMask << prevPosT as libc::c_int - 1 as libc::c_int
                & 0x7 as libc::c_int as libc::c_uint;
            if prevMask != 0 as libc::c_int as libc::c_uint {
                let mut b: libc::c_uchar = unsafe {
                    *p.offset(
                        (4 as libc::c_int - kMaskToBitNumber[prevMask as usize] as libc::c_int)
                            as isize,
                    )
                };
                if unsafe {
                    kMaskToAllowedStatus[prevMask as usize] == 0
                        || (b as libc::c_int == 0 as libc::c_int
                            || b as libc::c_int == 0xff as libc::c_int)
                } {
                    prevPosT = bufferPos;
                    prevMask = prevMask << 1 as libc::c_int & 0x7 as libc::c_int as libc::c_uint
                        | 1 as libc::c_int as libc::c_uint;
                    bufferPos = bufferPos.wrapping_add(1);
                    continue;
                }
            }
        }
        prevPosT = bufferPos;
        if unsafe {
            *p.offset(4 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
                || *p.offset(4 as libc::c_int as isize) as libc::c_int == 0xff as libc::c_int
        } {
            let mut src: uint32_t = unsafe {
                (*p.offset(4 as libc::c_int as isize) as uint32_t) << 24 as libc::c_int
                    | (*p.offset(3 as libc::c_int as isize) as uint32_t) << 16 as libc::c_int
                    | (*p.offset(2 as libc::c_int as isize) as uint32_t) << 8 as libc::c_int
                    | *p.offset(1 as libc::c_int as isize) as uint32_t
            };
            let mut dest: uint32_t = 0;
            loop {
                let mut b_0: uint8_t = 0;
                let mut b_index: libc::c_int = 0;
                dest = src.wrapping_sub(ip.wrapping_add(bufferPos as uint32_t));
                if prevMask == 0 as libc::c_int as libc::c_uint {
                    break;
                }
                b_index = unsafe {
                    kMaskToBitNumber[prevMask as usize] as libc::c_int * 8 as libc::c_int
                };
                b_0 = (dest >> 24 as libc::c_int - b_index) as uint8_t;
                if !(b_0 as libc::c_int == 0 as libc::c_int
                    || b_0 as libc::c_int == 0xff as libc::c_int)
                {
                    break;
                }
                src = dest
                    ^ (((1 as libc::c_int) << 32 as libc::c_int - b_index) - 1 as libc::c_int)
                        as libc::c_uint
            }
            unsafe {
                *p.offset(4 as libc::c_int as isize) = !(dest >> 24 as libc::c_int
                    & 1 as libc::c_int as libc::c_uint)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint)
                    as uint8_t;
                *p.offset(3 as libc::c_int as isize) = (dest >> 16 as libc::c_int) as uint8_t;
                *p.offset(2 as libc::c_int as isize) = (dest >> 8 as libc::c_int) as uint8_t;
                *p.offset(1 as libc::c_int as isize) = dest as uint8_t;
            }
            bufferPos = (bufferPos as libc::c_ulong).wrapping_add(5 as libc::c_int as libc::c_ulong)
                as size_t as size_t
        } else {
            prevMask = prevMask << 1 as libc::c_int & 0x7 as libc::c_int as libc::c_uint
                | 1 as libc::c_int as libc::c_uint;
            bufferPos = bufferPos.wrapping_add(1)
        }
    }
    (safe_zip).bcj_prevPosT = prevPosT;
    (safe_zip).bcj_prevMask = prevMask;
    (safe_zip).bcj_ip = ((safe_zip).bcj_ip as libc::c_uint).wrapping_add(bufferPos as uint32_t)
        as uint32_t as uint32_t;
    return bufferPos;
}
unsafe extern "C" fn Bcj2_Decode(
    mut zip: *mut _7zip,
    mut outBuf: *mut uint8_t,
    mut outSize: size_t,
) -> ssize_t {
    unsafe {
        let mut inPos: size_t = 0 as libc::c_int as size_t;
        let mut outPos: size_t = 0 as libc::c_int as size_t;
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
        let mut i: libc::c_uint = 0;
        let mut j: libc::c_uint = 0;
        let safe_zip = unsafe { &mut *zip };
        size0 = safe_zip.tmp_stream_bytes_remaining;
        buf0 = unsafe {
            safe_zip
                .tmp_stream_buff
                .offset(safe_zip.tmp_stream_bytes_avail as isize)
                .offset(-(size0 as isize))
        };
        size1 = safe_zip.sub_stream_bytes_remaining[0 as libc::c_int as usize];
        buf1 = unsafe {
            safe_zip.sub_stream_buff[0 as libc::c_int as usize]
                .offset(safe_zip.sub_stream_size[0 as libc::c_int as usize] as isize)
                .offset(-(size1 as isize))
        };
        size2 = safe_zip.sub_stream_bytes_remaining[1 as libc::c_int as usize];
        buf2 = unsafe {
            safe_zip.sub_stream_buff[1 as libc::c_int as usize]
                .offset(safe_zip.sub_stream_size[1 as libc::c_int as usize] as isize)
                .offset(-(size2 as isize))
        };
        size3 = safe_zip.sub_stream_bytes_remaining[2 as libc::c_int as usize];
        buf3 = unsafe {
            safe_zip.sub_stream_buff[2 as libc::c_int as usize]
                .offset(safe_zip.sub_stream_size[2 as libc::c_int as usize] as isize)
                .offset(-(size3 as isize))
        };
        buffer = buf3;
        bufferLim = unsafe { buffer.offset(size3 as isize) };
        if safe_zip.bcj_state == 0 as libc::c_int as libc::c_uint {
            /*
             * Initialize.
             */
            safe_zip.bcj2_prevByte = 0 as libc::c_int as uint8_t;
            i = 0 as libc::c_int as libc::c_uint;
            while (i as libc::c_ulong)
                < (::std::mem::size_of::<[uint16_t; 258]>() as libc::c_ulong)
                    .wrapping_div(::std::mem::size_of::<uint16_t>() as libc::c_ulong)
            {
                safe_zip.bcj2_p[i as usize] =
                    ((1 as libc::c_int) << 11 as libc::c_int >> 1 as libc::c_int) as uint16_t;
                i = i.wrapping_add(1)
            }
            safe_zip.bcj2_code = 0 as libc::c_int as uint32_t;
            safe_zip.bcj2_range = 0xffffffff as libc::c_uint;
            let mut ii: libc::c_int = 0;
            ii = 0 as libc::c_int;
            while ii < 5 as libc::c_int {
                if buffer == bufferLim {
                    return -(25 as libc::c_int) as ssize_t;
                }
                let fresh16 = buffer;
                buffer = unsafe { buffer.offset(1) };
                safe_zip.bcj2_code =
                    safe_zip.bcj2_code << 8 as libc::c_int | *fresh16 as libc::c_uint;
                ii += 1
            }
            safe_zip.bcj_state = 1 as libc::c_int as uint32_t
        }
        /*
         * Gather the odd bytes of a previous call.
         */
        i = 0 as libc::c_int as libc::c_uint;
        while safe_zip.odd_bcj_size > 0 as libc::c_int as libc::c_ulong && outPos < outSize {
            let fresh17 = outPos;
            outPos = outPos.wrapping_add(1);
            unsafe { *outBuf.offset(fresh17 as isize) = safe_zip.odd_bcj[i as usize] };
            safe_zip.odd_bcj_size = safe_zip.odd_bcj_size.wrapping_sub(1);
            i = i.wrapping_add(1)
        }
        if outSize == 0 as libc::c_int as libc::c_ulong {
            safe_zip.bcj2_outPos = (safe_zip.bcj2_outPos as libc::c_ulong).wrapping_add(outPos)
                as uint64_t as uint64_t;
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
            if safe_zip.bcj_state == 1 as libc::c_int as libc::c_uint {
                while limit != 0 as libc::c_int as libc::c_ulong {
                    let mut bb: uint8_t = *buf0.offset(inPos as isize);
                    let fresh18 = outPos;
                    outPos = outPos.wrapping_add(1);
                    unsafe { *outBuf.offset(fresh18 as isize) = bb };
                    if bb as libc::c_int & 0xfe as libc::c_int == 0xe8 as libc::c_int
                        || safe_zip.bcj2_prevByte as libc::c_int == 0xf as libc::c_int
                            && bb as libc::c_int & 0xf0 as libc::c_int == 0x80 as libc::c_int
                    {
                        safe_zip.bcj_state = 2 as libc::c_int as uint32_t;
                        break;
                    } else {
                        inPos = inPos.wrapping_add(1);
                        safe_zip.bcj2_prevByte = bb;
                        limit = limit.wrapping_sub(1)
                    }
                }
            }
            if limit == 0 as libc::c_int as libc::c_ulong || outPos == outSize {
                break;
            }
            safe_zip.bcj_state = 1 as libc::c_int as uint32_t;
            let fresh19 = inPos;
            inPos = inPos.wrapping_add(1);
            b = unsafe { *buf0.offset(fresh19 as isize) };
            if b as libc::c_int == 0xe8 as libc::c_int {
                prob = unsafe {
                    safe_zip
                        .bcj2_p
                        .as_mut_ptr()
                        .offset(safe_zip.bcj2_prevByte as libc::c_int as isize)
                }
            } else if b as libc::c_int == 0xe9 as libc::c_int {
                prob = unsafe {
                    safe_zip
                        .bcj2_p
                        .as_mut_ptr()
                        .offset(256 as libc::c_int as isize)
                }
            } else {
                prob = unsafe {
                    safe_zip
                        .bcj2_p
                        .as_mut_ptr()
                        .offset(257 as libc::c_int as isize)
                }
            }
            ttt = unsafe { *prob as uint32_t };
            bound = (safe_zip.bcj2_range >> 11 as libc::c_int).wrapping_mul(ttt);
            if safe_zip.bcj2_code < bound {
                safe_zip.bcj2_range = bound;
                unsafe {
                    *prob = ttt.wrapping_add(
                        (((1 as libc::c_int) << 11 as libc::c_int) as libc::c_uint)
                            .wrapping_sub(ttt)
                            >> 5 as libc::c_int,
                    ) as uint16_t
                };
                if safe_zip.bcj2_range < (1 as libc::c_int as uint32_t) << 24 as libc::c_int {
                    if buffer == bufferLim {
                        return -(25 as libc::c_int) as ssize_t;
                    }
                    safe_zip.bcj2_range <<= 8 as libc::c_int;
                    let fresh20 = buffer;
                    buffer = unsafe { buffer.offset(1) };
                    safe_zip.bcj2_code =
                        unsafe { safe_zip.bcj2_code << 8 as libc::c_int | *fresh20 as libc::c_uint }
                }
                safe_zip.bcj2_prevByte = b
            } else {
                let mut dest: uint32_t = 0;
                let mut v: *const uint8_t = 0 as *const uint8_t;
                let mut out: [uint8_t; 4] = [0; 4];
                safe_zip.bcj2_range = (safe_zip.bcj2_range as libc::c_uint).wrapping_sub(bound)
                    as uint32_t as uint32_t;
                safe_zip.bcj2_code = (safe_zip.bcj2_code as libc::c_uint).wrapping_sub(bound)
                    as uint32_t as uint32_t;
                unsafe { *prob = ttt.wrapping_sub(ttt >> 5 as libc::c_int) as uint16_t };
                if safe_zip.bcj2_range < (1 as libc::c_int as uint32_t) << 24 as libc::c_int {
                    if buffer == bufferLim {
                        return -(25 as libc::c_int) as ssize_t;
                    }
                    safe_zip.bcj2_range <<= 8 as libc::c_int;
                    let fresh21 = buffer;
                    buffer = buffer.offset(1);
                    safe_zip.bcj2_code =
                        safe_zip.bcj2_code << 8 as libc::c_int | *fresh21 as libc::c_uint
                }
                if b as libc::c_int == 0xe8 as libc::c_int {
                    v = buf1;
                    if size1 < 4 as libc::c_int as libc::c_ulong {
                        return -(25 as libc::c_int) as ssize_t;
                    }
                    buf1 = buf1.offset(4 as libc::c_int as isize);
                    size1 = (size1 as libc::c_ulong).wrapping_sub(4 as libc::c_int as libc::c_ulong)
                        as size_t as size_t
                } else {
                    v = buf2;
                    if size2 < 4 as libc::c_int as libc::c_ulong {
                        return -(25 as libc::c_int) as ssize_t;
                    }
                    buf2 = unsafe { buf2.offset(4 as libc::c_int as isize) };
                    size2 = (size2 as libc::c_ulong).wrapping_sub(4 as libc::c_int as libc::c_ulong)
                        as size_t as size_t
                }
                dest = unsafe {
                    ((*v.offset(0 as libc::c_int as isize) as uint32_t) << 24 as libc::c_int
                        | (*v.offset(1 as libc::c_int as isize) as uint32_t) << 16 as libc::c_int
                        | (*v.offset(2 as libc::c_int as isize) as uint32_t) << 8 as libc::c_int
                        | *v.offset(3 as libc::c_int as isize) as uint32_t)
                        .wrapping_sub(
                            ((*zip).bcj2_outPos as uint32_t)
                                .wrapping_add(outPos as uint32_t)
                                .wrapping_add(4 as libc::c_int as libc::c_uint),
                        )
                };
                out[0 as libc::c_int as usize] = dest as uint8_t;
                out[1 as libc::c_int as usize] = (dest >> 8 as libc::c_int) as uint8_t;
                out[2 as libc::c_int as usize] = (dest >> 16 as libc::c_int) as uint8_t;
                safe_zip.bcj2_prevByte = (dest >> 24 as libc::c_int) as uint8_t;
                out[3 as libc::c_int as usize] = safe_zip.bcj2_prevByte;
                i = 0 as libc::c_int as libc::c_uint;
                while i < 4 as libc::c_int as libc::c_uint && outPos < outSize {
                    let fresh22 = outPos;
                    outPos = outPos.wrapping_add(1);
                    unsafe { *outBuf.offset(fresh22 as isize) = out[i as usize] };
                    i = i.wrapping_add(1)
                }
                if !(i < 4 as libc::c_int as libc::c_uint) {
                    continue;
                }
                /*
                 * Save odd bytes which we could not add into
                 * the output buffer because of out of space.
                 */
                safe_zip.odd_bcj_size =
                    (4 as libc::c_int as libc::c_uint).wrapping_sub(i) as size_t;
                while i < 4 as libc::c_int as libc::c_uint {
                    j = i
                        .wrapping_sub(4 as libc::c_int as libc::c_uint)
                        .wrapping_add(safe_zip.odd_bcj_size as libc::c_uint);
                    safe_zip.odd_bcj[j as usize] = out[i as usize];
                    i = i.wrapping_add(1)
                }
                break;
            }
        }
        safe_zip.tmp_stream_bytes_remaining = (safe_zip.tmp_stream_bytes_remaining as libc::c_ulong)
            .wrapping_sub(inPos) as size_t as size_t;
        safe_zip.sub_stream_bytes_remaining[0 as libc::c_int as usize] = size1;
        safe_zip.sub_stream_bytes_remaining[1 as libc::c_int as usize] = size2;
        safe_zip.sub_stream_bytes_remaining[2 as libc::c_int as usize] =
            bufferLim.offset_from(buffer) as libc::c_long as size_t;
        safe_zip.bcj2_outPos =
            (safe_zip.bcj2_outPos as libc::c_ulong).wrapping_add(outPos) as uint64_t as uint64_t;
        return outPos as ssize_t;
    }
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_check_7zip_header_in_sfx(mut p: *const libc::c_char) {
    check_7zip_header_in_sfx(p);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_skip_sfx(mut _a: *mut archive, mut bytes_avail: ssize_t) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    skip_sfx(a, bytes_avail);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_init_decompression(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut _7zip: *mut _7zip = 0 as *mut _7zip;
    _7zip = calloc_safe(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<_7zip>() as libc::c_ulong,
    ) as *mut _7zip;
    let mut coder1: *mut _7z_coder = 0 as *mut _7z_coder;
    coder1 = calloc_safe(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<_7z_coder>() as libc::c_ulong,
    ) as *mut _7z_coder;
    let mut coder2: *mut _7z_coder = 0 as *mut _7z_coder;
    coder2 = calloc_safe(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<_7z_coder>() as libc::c_ulong,
    ) as *mut _7z_coder;
    (*(coder1)).codec = 0x030401 as libc::c_ulong;
    (*(coder1)).propertiesSize = 4 as uint64_t;
    (*(_7zip)).ppmd7_valid = 1 as libc::c_int;
    (*(coder2)).codec = 0x03030103 as libc::c_ulong;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x030401 as libc::c_ulong;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder1)).codec = 0x21 as libc::c_ulong;
    (*(coder2)).codec = 0x03030205 as libc::c_ulong;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x03030401 as libc::c_ulong;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x03030501 as libc::c_ulong;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x03030701 as libc::c_ulong;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x03030104 as libc::c_ulong;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder2)).codec = 0x03030805 as libc::c_ulong;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder1)).codec = 0x03 as libc::c_ulong;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder1)).codec = 0x06F10702 as libc::c_ulong;
    init_decompression(a, _7zip, coder1, coder2);
    (*(coder1)).codec = 0x06F10701 as libc::c_ulong;
    init_decompression(a, _7zip, coder1, coder2);
}
