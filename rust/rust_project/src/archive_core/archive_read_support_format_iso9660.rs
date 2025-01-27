use archive_core::archive_endian::*;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;
use rust_ffi::{archive_set_error_safe, archive_string_sprintf_safe, sprintf_safe};
use std::mem::size_of;

extern "C" {
    #[cfg(HAVE_TIMEGM)]
    fn timegm(timeptr: *mut tm) -> time_t;

    #[cfg_attr(HAVE__MKGMTIME64, cfg(not(HAVE_TIMEGM)))]
    fn _mkgmtime(timeptr: *mut tm) -> time_t;
}

#[cfg(HAVE_TIMEGM)]
pub fn timegm_safe(timeptr: *mut tm) -> time_t {
    return unsafe { timegm(timeptr) };
}

#[cfg_attr(HAVE__MKGMTIME64, cfg(not(HAVE_TIMEGM)))]
pub fn _mkgmtime_safe(timeptr: *mut tm) -> time_t {
    return unsafe { _mkgmtime(timeptr) };
}

#[cfg(HAVE_ZLIB_H)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct zisofs {
    pub pz: i32,
    pub pz_log2_bs: i32,
    pub pz_uncompressed_size: uint64_t,
    pub initialized: i32,
    pub uncompressed_buffer: *mut u8,
    pub uncompressed_buffer_size: size_t,
    pub pz_offset: uint32_t,
    pub header: [u8; 16],
    pub header_avail: size_t,
    pub header_passed: i32,
    pub block_pointers: *mut u8,
    pub block_pointers_alloc: size_t,
    pub block_pointers_size: size_t,
    pub block_pointers_avail: size_t,
    pub block_off: size_t,
    pub block_avail: uint32_t,
    pub stream: z_stream,
    pub stream_valid: i32,
}

#[cfg(not(HAVE_ZLIB_H))]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct zisofs {
    pub pz: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct content {
    pub offset: uint64_t,
    pub size: uint64_t,
    pub next: *mut content,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct file_info {
    pub use_next: *mut file_info,
    pub parent: *mut file_info,
    pub next: *mut file_info,
    pub re_next: *mut file_info,
    pub subdirs: i32,
    pub key: uint64_t,
    pub offset: uint64_t,
    pub size: uint64_t,
    pub ce_offset: uint32_t,
    pub ce_size: uint32_t,
    pub rr_moved: i8,
    pub rr_moved_has_re_only: i8,
    pub re: i8,
    pub re_descendant: i8,
    pub cl_offset: uint64_t,
    pub birthtime_is_set: i32,
    pub birthtime: time_t,
    pub mtime: time_t,
    pub atime: time_t,
    pub ctime: time_t,
    pub rdev: uint64_t,
    pub mode: mode_t,
    pub uid: uid_t,
    pub gid: gid_t,
    pub number: int64_t,
    pub nlinks: i32,
    pub name: archive_string,
    pub utf16be_name: *mut u8,
    pub utf16be_bytes: size_t,
    pub name_continues: i8,
    pub symlink: archive_string,
    pub symlink_continues: i8,
    pub pz: i32,
    pub pz_log2_bs: i32,
    pub pz_uncompressed_size: uint64_t,
    pub multi_extent: i32,
    pub contents: archive_contents,
    pub rede_files: archive_rede_files,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_contents {
    pub first: *mut content,
    pub last: *mut *mut content,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_rede_files {
    pub first: *mut file_info,
    pub last: *mut *mut file_info,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct heap_queue {
    pub files: *mut *mut file_info,
    pub allocated: i32,
    pub used: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct iso9660 {
    pub magic: i32,
    pub opt_support_joliet: i32,
    pub opt_support_rockridge: i32,
    pub pathname: archive_string,
    pub seenRockridge: i8,
    pub seenSUSP: i8,
    pub seenJoliet: i8,
    pub suspOffset: u8,
    pub rr_moved: *mut file_info,
    pub read_ce_req: read_ce_queue,
    pub previous_number: int64_t,
    pub previous_pathname: archive_string,
    pub use_files: *mut file_info,
    pub pending_files: heap_queue,
    pub cache_files: archive_cache_files,
    pub re_files: archive_re_files,
    pub current_position: uint64_t,
    pub logical_block_size: ssize_t,
    pub volume_size: uint64_t,
    pub volume_block: int32_t,
    pub primary: vd,
    pub joliet: vd,
    pub entry_sparse_offset: int64_t,
    pub entry_bytes_remaining: int64_t,
    pub entry_bytes_unconsumed: size_t,
    pub entry_zisofs: zisofs,
    pub entry_content: *mut content,
    pub sconv_utf16be: *mut archive_string_conv,
    pub utf16be_path: *mut u8,
    pub utf16be_path_len: size_t,
    pub utf16be_previous_path: *mut u8,
    pub utf16be_previous_path_len: size_t,
    pub null: [u8; 2048],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct read_ce_queue {
    pub reqs: *mut read_ce_req,
    pub cnt: i32,
    pub allocated: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct read_ce_req {
    pub offset: uint64_t,
    pub file: *mut file_info,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_cache_files {
    pub first: *mut file_info,
    pub last: *mut *mut file_info,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_re_files {
    pub first: *mut file_info,
    pub last: *mut *mut file_info,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct vd {
    pub location: i32,
    pub size: uint32_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archvie_temporary_empty_files {
    pub first: *mut file_info,
    pub last: *mut *mut file_info,
}

#[cfg(HAVE_ZLIB_H)]
static mut zisofs_magic: [u8; 8] = [
    0x37 as u8, 0xe4 as u8, 0x53 as u8, 0x96 as u8, 0xc9 as u8, 0xdb as u8, 0xd6 as u8, 0x7 as u8,
];

#[no_mangle]
pub fn archive_read_support_format_iso9660(mut _a: *mut archive) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let r: i32;
    let mut magic_test: i32 = unsafe {
        __archive_check_magic_safe(
            _a,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_read_magic,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_state_new,
            b"archive_read_support_format_iso9660\x00" as *const u8,
        )
    };
    if magic_test == ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
    }
    let iso9660 = unsafe { &mut *(calloc_safe(1, size_of::<iso9660>() as u64) as *mut iso9660) };
    if (iso9660 as *mut iso9660).is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
            b"Can\'t allocate iso9660 data\x00" as *const u8
        );
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
    }
    iso9660.magic = ARCHIVE_ISO9660_DEFINED_PARAM.iso9660_magic;
    iso9660.cache_files.first = 0 as *mut file_info;
    iso9660.cache_files.last = &mut iso9660.cache_files.first;
    iso9660.re_files.first = 0 as *mut file_info;
    iso9660.re_files.last = &mut iso9660.re_files.first;
    /* Enable to support Joliet extensions by default.	*/
    iso9660.opt_support_joliet = 1;
    /* Enable to support Rock Ridge extensions by default.	*/
    iso9660.opt_support_rockridge = 1;
    r = unsafe {
        __archive_read_register_format_safe(
            a,
            iso9660 as *mut iso9660 as *mut (),
            b"iso9660\x00" as *const u8,
            Some(archive_read_format_iso9660_bid),
            Some(archive_read_format_iso9660_options),
            Some(archive_read_format_iso9660_read_header),
            Some(archive_read_format_iso9660_read_data),
            Some(archive_read_format_iso9660_read_data_skip),
            None,
            Some(archive_read_format_iso9660_cleanup),
            None,
            None,
        )
    };
    if r != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok {
        unsafe { free_safe(iso9660 as *mut iso9660 as *mut ()) };
        return r;
    }
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
}

fn archive_read_format_iso9660_bid(a: *mut archive_read, best_bid: i32) -> i32 {
    let mut bytes_read: ssize_t = 0;
    let mut p: *const u8 = 0 as *const u8;
    let mut seenTerminator: i32;
    /* If there's already a better bid than we can ever
    make, don't bother testing. */
    if best_bid > 48 {
        return -1;
    }
    let iso9660 = unsafe { &mut *((*(*a).format).data as *mut iso9660) };
    /*
     * Skip the first 32k (reserved area) and get the first
     * 8 sectors of the volume descriptor table.  Of course,
     * if the I/O layer gives us more, we'll take it.
     */
    p = unsafe {
        __archive_read_ahead_safe(
            a,
            (ARCHIVE_ISO9660_DEFINED_PARAM.reserved_area
                + 8 * ARCHIVE_ISO9660_DEFINED_PARAM.logical_block_size) as size_t,
            &mut bytes_read,
        ) as *const u8
    };
    if p.is_null() {
        return -1;
    }
    /* Skip the reserved area. */
    bytes_read -= ARCHIVE_ISO9660_DEFINED_PARAM.reserved_area as i64;
    unsafe {
        p = p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.reserved_area as isize);
    }
    /* Check each volume descriptor. */
    seenTerminator = 0;
    while bytes_read > ARCHIVE_ISO9660_DEFINED_PARAM.logical_block_size as i64 {
        /* Do not handle undefined Volume Descriptor Type. */
        if unsafe { *p.offset(0 as isize) } as i32 >= 4
            && unsafe { *p.offset(0 as isize) } as i32 <= 254
        {
            return 0;
        }
        /* Standard Identifier must be "CD001" */
        if unsafe {
            memcmp_safe(
                p.offset(1 as isize) as *const (),
                b"CD001\x00" as *const u8 as *const (),
                5,
            )
        } != 0
        {
            return 0;
        }
        if isPVD(iso9660, p) == 0 {
            if iso9660.joliet.location == 0 {
                if isJolietSVD(iso9660, p) == 0 {
                    if isBootRecord(iso9660, p) == 0 {
                        if isEVD(iso9660, p) == 0 {
                            if isSVD(iso9660, p) == 0 {
                                if isVolumePartition(iso9660, p) == 0 {
                                    if isVDSetTerminator(iso9660, p) != 0 {
                                        seenTerminator = 1;
                                        break;
                                    } else {
                                        return 0;
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                if isBootRecord(iso9660, p) == 0 {
                    if isEVD(iso9660, p) == 0 {
                        if isSVD(iso9660, p) == 0 {
                            if isVolumePartition(iso9660, p) == 0 {
                                if isVDSetTerminator(iso9660, p) != 0 {
                                    seenTerminator = 1;
                                    break;
                                } else {
                                    return 0;
                                }
                            }
                        }
                    }
                }
            }
        }
        bytes_read -= ARCHIVE_ISO9660_DEFINED_PARAM.logical_block_size as i64;
        unsafe { p = p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.logical_block_size as isize) }
    }
    /*
     * ISO 9660 format must have Primary Volume Descriptor and
     * Volume Descriptor Set Terminator.
     */
    if seenTerminator != 0 && iso9660.primary.location > 16 {
        return 48;
    }
    /* We didn't find a valid PVD; return a bid of zero. */
    return 0;
}

fn archive_read_format_iso9660_options(
    a: *mut archive_read,
    key: *const u8,
    val: *const u8,
) -> i32 {
    let iso9660 = unsafe { &mut *((*(*a).format).data as *mut iso9660) };
    if unsafe { strcmp_safe(key, b"joliet\x00" as *const u8) } == 0 {
        if val.is_null()
            || unsafe { strcmp_safe(val, b"off\x00" as *const u8) } == 0
            || unsafe { strcmp_safe(val, b"ignore\x00" as *const u8) } == 0
            || unsafe { strcmp_safe(val, b"disable\x00" as *const u8) } == 0
            || unsafe { strcmp_safe(val, b"0\x00" as *const u8) } == 0
        {
            iso9660.opt_support_joliet = 0
        } else {
            iso9660.opt_support_joliet = 1
        }
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
    }
    if unsafe { strcmp_safe(key, b"rockridge\x00" as *const u8) } == 0
        || unsafe { strcmp_safe(key, b"Rockridge\x00" as *const u8) } == 0
    {
        iso9660.opt_support_rockridge = (val != 0 as *mut () as *const u8) as i32;
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
    }
    /* Note: The "warn" return is just to inform the options
     * supervisor that we didn't handle it.  It will generate
     * a suitable error if no one used this option. */
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_warn;
}

fn isNull(iso9660: *mut iso9660, h: *const u8, mut offset: u32, mut bytes: u32) -> i32 {
    let iso9660 = unsafe { &mut *iso9660 };
    while bytes as u64 >= size_of::<[u8; 2048]>() as u64 {
        if unsafe {
            memcmp_safe(
                iso9660.null.as_mut_ptr() as *const (),
                h.offset(offset as isize) as *const (),
                size_of::<[u8; 2048]>() as u64,
            )
        } == 0
        {
            return 0;
        }
        offset = offset + size_of::<[u8; 2048]>() as u32;
        bytes = bytes - size_of::<[u8; 2048]>() as u32;
    }
    if bytes != 0 {
        return (unsafe {
            memcmp_safe(
                iso9660.null.as_mut_ptr() as *const (),
                h.offset(offset as isize) as *const (),
                bytes as u64,
            )
        } == 0) as i32;
    } else {
        return 1;
    };
}

fn isBootRecord(iso9660: *mut iso9660, h: *const u8) -> i32 {
    /* UNUSED */
    /* Type of the Volume Descriptor Boot Record must be 0. */
    if unsafe { *h.offset(0 as isize) } as i32 != 0 {
        return 0;
    }
    /* Volume Descriptor Version must be 1. */
    if unsafe { *h.offset(6 as isize) } as i32 != 1 {
        return 0;
    }
    return 1;
}

fn isVolumePartition(mut iso9660: *mut iso9660, mut h: *const u8) -> i32 {
    let iso9660 = unsafe { &mut *iso9660 };
    let location: int32_t;
    /* Type of the Volume Partition Descriptor must be 3. */
    if unsafe { *h.offset(0 as isize) } as i32 != 3 {
        return 0;
    }
    /* Volume Descriptor Version must be 1. */
    if unsafe { *h.offset(6 as isize) } as i32 != 1 {
        return 0;
    }
    /* Unused Field */
    if unsafe { *h.offset(7 as isize) } as i32 != 0 {
        return 0;
    }
    location = archive_le32dec(unsafe { h.offset(72 as isize) } as *const ()) as int32_t;
    if location <= ARCHIVE_ISO9660_DEFINED_PARAM.system_area_block
        || location >= iso9660.volume_block
    {
        return 0;
    }
    if location as uint32_t != archive_be32dec(unsafe { h.offset(76 as isize) } as *const ()) {
        return 0;
    }
    return 1;
}

fn isVDSetTerminator(iso9660: *mut iso9660, h: *const u8) -> i32 {
    /* UNUSED */
    /* Type of the Volume Descriptor Set Terminator must be 255. */
    if unsafe { *h.offset(0 as isize) } as i32 != 255 {
        return 0;
    }
    /* Volume Descriptor Version must be 1. */
    if unsafe { *h.offset(6 as isize) } as i32 != 1 {
        return 0;
    }
    /* Reserved field must be 0. */
    if isNull(iso9660, h, 7 as u32, (2048 - 7) as u32) == 0 {
        return 0;
    }
    return 1;
}

fn isJolietSVD(iso9660: *mut iso9660, h: *const u8) -> i32 {
    let iso9660 = unsafe { &mut *iso9660 };
    let mut p: *const u8 = 0 as *const u8;
    let logical_block_size: ssize_t;
    let volume_block: int32_t;
    /* Check if current sector is a kind of Supplementary Volume
     * Descriptor. */
    if isSVD(iso9660, h) == 0 {
        return 0;
    }
    /* FIXME: do more validations according to joliet spec. */
    /* check if this SVD contains joliet extension! */
    unsafe {
        p = h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.svd_escape_sequences_offset as isize);
    }
    /* N.B. Joliet spec says p[1] == '\\', but.... */
    if unsafe { *p.offset(0 as isize) } == '%' as u8
        && unsafe { *p.offset(1 as isize) } == '/' as u8
    {
        let level: i8; /* not joliet */
        if unsafe { *p.offset(2 as isize) } == '@' as u8 {
            level = 1
        } else if unsafe { *p.offset(2 as isize) } == 'C' as u8 {
            level = 2
        } else if unsafe { *p.offset(2 as isize) } == 'E' as u8 {
            level = 3
        } else {
            /* not joliet */
            return 0;
        }
        iso9660.seenJoliet = level;
    } else {
        return 0;
    }
    logical_block_size = archive_le16dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.svd_logical_block_size_offset as isize)
    } as *const ()) as ssize_t;
    volume_block = archive_le32dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.svd_volume_space_size_offset as isize)
    } as *const ()) as int32_t;
    iso9660.logical_block_size = logical_block_size;
    iso9660.volume_block = volume_block;
    iso9660.volume_size = (logical_block_size as u64) * (volume_block as uint64_t);
    /* Read Root Directory Record in Volume Descriptor. */
    unsafe {
        p = h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.svd_root_directory_record_offset as isize);
    }
    iso9660.joliet.location =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_extent_offset as isize) }
                as *const (),
        ) as i32;
    iso9660.joliet.size =
        archive_le32dec(
            unsafe { p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_size_offset as isize) } as *const (),
        );
    return 48;
}

fn isSVD(iso9660: *mut iso9660, h: *const u8) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let logical_block_size: ssize_t;
    let volume_block: int32_t;
    let mut location: int32_t;
    /* UNUSED */
    /* Type 2 means it's a SVD. */
    if unsafe { *h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.svd_type_offset as isize) } as i32 != 2 {
        return 0;
    }
    /* Reserved field must be 0. */
    if isNull(
        iso9660,
        h,
        ARCHIVE_ISO9660_DEFINED_PARAM.svd_reserved1_offset as u32,
        ARCHIVE_ISO9660_DEFINED_PARAM.svd_reserved1_size as u32,
    ) == 0
    {
        return 0;
    }
    if isNull(
        iso9660,
        h,
        ARCHIVE_ISO9660_DEFINED_PARAM.svd_reserved2_offset as u32,
        ARCHIVE_ISO9660_DEFINED_PARAM.svd_reserved2_size as u32,
    ) == 0
    {
        return 0;
    }
    if isNull(
        iso9660,
        h,
        ARCHIVE_ISO9660_DEFINED_PARAM.svd_reserved3_offset as u32,
        ARCHIVE_ISO9660_DEFINED_PARAM.svd_reserved3_size as u32,
    ) == 0
    {
        return 0;
    }
    /* File structure version must be 1 for ISO9660/ECMA119. */
    if unsafe {
        *h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.svd_file_structure_version_offset as isize)
    } as i32
        != 1
    {
        return 0;
    }
    logical_block_size = archive_le16dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.svd_logical_block_size_offset as isize)
    } as *const ()) as ssize_t;
    if logical_block_size <= 0 as i64 {
        return 0;
    }
    volume_block = archive_le32dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.svd_volume_space_size_offset as isize)
    } as *const ()) as int32_t;
    if volume_block <= ARCHIVE_ISO9660_DEFINED_PARAM.system_area_block + 4 {
        return 0;
    }
    /* Location of Occurrence of Type L Path Table must be
     * available location,
     * >= SYSTEM_AREA_BLOCK(16) + 2 and < Volume Space Size. */
    location = archive_le32dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.svd_type_l_path_table_offset as isize)
    } as *const ()) as int32_t;
    if location < ARCHIVE_ISO9660_DEFINED_PARAM.system_area_block + 2 || location >= volume_block {
        return 0;
    }
    /* The Type M Path Table must be at a valid location (WinISO
     * and probably other programs omit this, so we allow zero)
     *
     * >= SYSTEM_AREA_BLOCK(16) + 2 and < Volume Space Size. */
    location = archive_be32dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.svd_type_m_path_table_offset as isize)
    } as *const ()) as int32_t;
    if location > 0 && location < ARCHIVE_ISO9660_DEFINED_PARAM.system_area_block + 2
        || location >= volume_block
    {
        return 0;
    }
    /* Read Root Directory Record in Volume Descriptor. */
    unsafe {
        p = h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.svd_root_directory_record_offset as isize);
    }
    if unsafe { *p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_length_offset as isize) } as i32 != 34 {
        return 0;
    }
    return 48;
}

fn isEVD(iso9660: *mut iso9660, h: *const u8) -> i32 {
    let mut p: *const u8 = 0 as *const u8;
    let logical_block_size: ssize_t;
    let volume_block: int32_t;
    let mut location: int32_t;
    /* UNUSED */
    /* Type of the Enhanced Volume Descriptor must be 2. */
    if unsafe { *h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_type_offset as isize) } as i32 != 2 {
        return 0;
    }
    /* EVD version must be 2. */
    if unsafe { *h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_version_offset as isize) } as i32 != 2 {
        return 0;
    }
    /* Reserved field must be 0. */
    if unsafe { *h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved1_offset as isize) } as i32 != 0
    {
        return 0;
    }
    /* Reserved field must be 0. */
    if isNull(
        iso9660,
        h,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved2_offset as u32,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved2_size as u32,
    ) == 0
    {
        return 0;
    }
    /* Reserved field must be 0. */
    if isNull(
        iso9660,
        h,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved3_offset as u32,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved3_size as u32,
    ) == 0
    {
        return 0;
    }
    /* Logical block size must be > 0. */
    /* I've looked at Ecma 119 and can't find any stronger
     * restriction on this field. */
    logical_block_size = archive_le16dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_logical_block_size_offset as isize)
    } as *const ()) as ssize_t;
    if logical_block_size <= 0 {
        return 0;
    }
    volume_block = archive_le32dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_volume_space_size_offset as isize)
    } as *const ()) as int32_t;
    if volume_block <= ARCHIVE_ISO9660_DEFINED_PARAM.system_area_block + 4 {
        return 0;
    }
    /* File structure version must be 2 for ISO9660:1999. */
    if unsafe {
        *h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_file_structure_version_offset as isize)
    } as i32
        != 2
    {
        return 0;
    }
    /* Location of Occurrence of Type L Path Table must be
     * available location,
     * >= SYSTEM_AREA_BLOCK(16) + 2 and < Volume Space Size. */
    location = archive_le32dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_type_1_path_table_offset as isize)
    } as *const ()) as int32_t;
    if location < ARCHIVE_ISO9660_DEFINED_PARAM.system_area_block + 2 || location >= volume_block {
        return 0;
    }
    /* Location of Occurrence of Type M Path Table must be
     * available location,
     * >= SYSTEM_AREA_BLOCK(16) + 2 and < Volume Space Size. */
    location = archive_be32dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_type_m_path_table_offset as isize)
    } as *const ()) as int32_t;
    if location > 0 && location < ARCHIVE_ISO9660_DEFINED_PARAM.system_area_block + 2
        || location >= volume_block
    {
        return 0;
    }
    /* Reserved field must be 0. */
    if isNull(
        iso9660,
        h,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved4_offset as u32,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved4_size as u32,
    ) == 0
    {
        return 0;
    }
    /* Reserved field must be 0. */
    if isNull(
        iso9660,
        h,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved5_offset as u32,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved5_size as u32,
    ) == 0
    {
        return 0;
    }
    /* Read Root Directory Record in Volume Descriptor. */
    unsafe {
        p = h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_root_directory_record_offset as isize);
    }
    if unsafe { *p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_length_offset as isize) } as i32 != 34 {
        return 0;
    }
    return 48;
}

fn isPVD(iso9660: *mut iso9660, h: *const u8) -> i32 {
    let iso9660 = unsafe { &mut *iso9660 };
    let mut p: *const u8 = 0 as *const u8;
    let logical_block_size: ssize_t;
    let volume_block: int32_t;
    let mut location: int32_t;
    let mut i: i32;
    /* Type of the Primary Volume Descriptor must be 1. */
    if unsafe { *h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_type_offset as isize) } != 1 {
        return 0;
    }
    /* PVD version must be 1. */
    if unsafe { *h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_version_offset as isize) } != 1 {
        return 0;
    }
    /* Reserved field must be 0. */
    if unsafe { *h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved1_offset as isize) } as i32 != 0
    {
        return 0;
    }
    /* Reserved field must be 0. */
    if isNull(
        iso9660,
        h,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved2_offset as u32,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved2_size as u32,
    ) == 0
    {
        return 0;
    }
    /* Reserved field must be 0. */
    if isNull(
        iso9660,
        h,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved3_offset as u32,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved3_size as u32,
    ) == 0
    {
        return 0;
    }
    /* Logical block size must be > 0. */
    /* I've looked at Ecma 119 and can't find any stronger
     * restriction on this field. */
    logical_block_size = archive_le16dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_logical_block_size_offset as isize)
    } as *const ()) as ssize_t;
    if logical_block_size <= 0 {
        return 0;
    }
    volume_block = archive_le32dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_volume_space_size_offset as isize)
    } as *const ()) as int32_t;
    if volume_block <= ARCHIVE_ISO9660_DEFINED_PARAM.system_area_block + 4 {
        return 0;
    }
    /* File structure version must be 1 for ISO9660/ECMA119. */
    if unsafe {
        *h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_file_structure_version_offset as isize)
    } as i32
        != 1
    {
        return 0;
    }
    /* Location of Occurrence of Type L Path Table must be
     * available location,
     * > SYSTEM_AREA_BLOCK(16) + 2 and < Volume Space Size. */
    location = archive_le32dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_type_1_path_table_offset as isize)
    } as *const ()) as int32_t;
    if location < ARCHIVE_ISO9660_DEFINED_PARAM.system_area_block + 2 || location >= volume_block {
        return 0;
    }
    /* The Type M Path Table must also be at a valid location
     * (although ECMA 119 requires a Type M Path Table, WinISO and
     * probably other programs omit it, so we permit a zero here)
     *
     * >= SYSTEM_AREA_BLOCK(16) + 2 and < Volume Space Size. */
    location = archive_be32dec(unsafe {
        h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_type_m_path_table_offset as isize)
    } as *const ()) as int32_t;
    if location > 0 && location < ARCHIVE_ISO9660_DEFINED_PARAM.system_area_block + 2
        || location >= volume_block
    {
        return 0;
    }
    /* Reserved field must be 0. */
    /* But accept NetBSD/FreeBSD "makefs" images with 0x20 here. */
    i = 0;
    while i < ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved4_size {
        if unsafe { *h.offset((ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved4_offset + i) as isize) }
            != 0
            && unsafe {
                *h.offset((ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved4_offset + i) as isize)
            } != 0x20
        {
            return 0;
        }
        i += 1
    }
    /* Reserved field must be 0. */
    if isNull(
        iso9660,
        h,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved5_offset as u32,
        ARCHIVE_ISO9660_DEFINED_PARAM.pvd_reserved5_size as u32,
    ) == 0
    {
        return 0;
    }
    /* XXX TODO: Check other values for sanity; reject more
     * malformed PVDs. XXX */
    /* Read Root Directory Record in Volume Descriptor. */
    unsafe {
        p = h.offset(ARCHIVE_ISO9660_DEFINED_PARAM.pvd_root_directory_record_offset as isize);
    }
    if unsafe { *p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_length_offset as isize) } != 34 {
        return 0;
    }
    if iso9660.primary.location == 0 {
        iso9660.logical_block_size = logical_block_size;
        iso9660.volume_block = volume_block;
        iso9660.volume_size = (logical_block_size as u64) * (volume_block as uint64_t);
        iso9660.primary.location = archive_le32dec(unsafe {
            p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_extent_offset as isize)
        } as *const ()) as i32;
        iso9660.primary.size = archive_le32dec(unsafe {
            p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_size_offset as isize)
        } as *const ())
    }
    return 48;
}

fn read_children(a: *mut archive_read, parent: *mut file_info) -> i32 {
    let mut b: *const u8 = 0 as *const u8;
    let mut p: *const u8 = 0 as *const u8;
    let mut step: size_t;
    let skip_size: size_t;
    let iso9660 = unsafe { &mut *((*(*a).format).data as *mut iso9660) };
    let parent = unsafe { &mut *parent };
    /* flush any remaining bytes from the last round to ensure
     * we're positioned */
    if iso9660.entry_bytes_unconsumed != 0 {
        unsafe { __archive_read_consume_safe(a, iso9660.entry_bytes_unconsumed as int64_t) };
        iso9660.entry_bytes_unconsumed = 0 as size_t
    }
    if iso9660.current_position > parent.offset {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
            b"Ignoring out-of-order directory (%s) %jd > %jd\x00" as *const u8,
            parent.name.s,
            iso9660.current_position as intmax_t,
            parent.offset as intmax_t
        );
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_warn;
    }
    if parent.offset + parent.size > iso9660.volume_size {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
            b"Directory is beyond end-of-media: %s\x00" as *const u8,
            parent.name.s
        );
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_warn;
    }
    if iso9660.current_position < parent.offset {
        let mut skipsize: int64_t = 0;
        skipsize = (parent.offset - iso9660.current_position) as int64_t;
        skipsize = unsafe { __archive_read_consume_safe(a, skipsize) };
        if skipsize < 0 {
            return skipsize as i32;
        }
        iso9660.current_position = parent.offset
    }
    step = (parent.size + iso9660.logical_block_size as u64 - 1)
        / (iso9660.logical_block_size as u64)
        * (iso9660.logical_block_size as u64);
    b = unsafe { __archive_read_ahead_safe(a, step, 0 as *mut ssize_t) as *const u8 };
    if b.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
            b"Failed to read full block when scanning ISO9660 directory list\x00" as *const u8
                as *const u8
        );
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
    }
    iso9660.current_position = iso9660.current_position + step;
    let mut multi = 0 as *mut file_info;
    skip_size = step;
    while step != 0 {
        p = b;
        unsafe {
            b = b.offset(iso9660.logical_block_size as isize);
        }
        step = step - (iso9660.logical_block_size as u64);
        while unsafe { *p } != 0 && p < b && unsafe { p.offset(*p as isize) } <= b {
            let mut child: *mut file_info = 0 as *mut file_info;
            /* N.B.: these special directory identifiers
             * are 8 bit "values" even on a
             * Joliet CD with UCS-2 (16bit) encoding.
             */
            /* Skip '.' entry. */
            if !(unsafe { *p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_name_len_offset as isize) }
                == 1
                && unsafe { *p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_name_offset as isize) }
                    == '\u{0}' as u8)
            {
                /* Skip '..' entry. */
                if !(unsafe {
                    *p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_name_len_offset as isize)
                } == 1
                    && unsafe { *p.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_name_offset as isize) }
                        == '\u{1}' as u8)
                {
                    child = parse_file_info(a, parent, p, unsafe { b.offset_from(p) } as size_t);
                    let safe_child = unsafe { &*child };
                    if child.is_null() {
                        unsafe { __archive_read_consume_safe(a, skip_size as int64_t) };
                        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                    }
                    if safe_child.cl_offset == 0 as u64
                        && (safe_child.multi_extent != 0 || !multi.is_null())
                    {
                        let mut con: *mut content = 0 as *mut content;
                        if multi.is_null() {
                            multi = child;
                            let safe_multi = unsafe { &mut *multi };
                            safe_multi.contents.first = 0 as *mut content;
                            safe_multi.contents.last = &mut safe_multi.contents.first
                        }
                        con = unsafe { malloc_safe(size_of::<content>() as u64) } as *mut content;
                        if con.is_null() {
                            archive_set_error_safe!(
                                &mut (*a).archive as *mut archive,
                                ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                                b"No memory for multi extent\x00" as *const u8
                            );
                            unsafe { __archive_read_consume_safe(a, skip_size as int64_t) };
                            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                        }
                        let safe_multi = unsafe { &mut *multi };
                        let safe_con = unsafe { &mut *con };
                        safe_con.offset = safe_child.offset;
                        safe_con.size = safe_child.size;
                        safe_con.next = 0 as *mut content;
                        unsafe {
                            *safe_multi.contents.last = con;
                        }
                        safe_multi.contents.last = &mut safe_con.next;
                        if multi == child {
                            if heap_add_entry(
                                a,
                                &mut iso9660.pending_files,
                                child,
                                safe_child.offset,
                            ) != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok
                            {
                                return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                            }
                        } else {
                            safe_multi.size = safe_multi.size + safe_child.size as uint64_t;
                            if safe_child.multi_extent == 0 {
                                multi = 0 as *mut file_info
                            }
                        }
                    } else if heap_add_entry(
                        a,
                        &mut iso9660.pending_files,
                        child,
                        safe_child.offset,
                    ) != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok
                    {
                        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                    }
                }
            }
            unsafe { p = p.offset(*p as isize) }
        }
    }
    unsafe { __archive_read_consume_safe(a, skip_size as int64_t) };
    /* Read data which recorded by RRIP "CE" extension. */
    if read_CE(a, iso9660) != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok {
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
    }
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
}

fn choose_volume(mut a: *mut archive_read, mut iso9660: *mut iso9660) -> i32 {
    let safe_a = unsafe { &mut *a };
    let iso9660 = unsafe { &mut *iso9660 };
    let mut file: *mut file_info = 0 as *mut file_info;
    let mut skipsize: int64_t;
    let mut block: *const () = 0 as *const ();
    let seenJoliet: i8;
    let iso9660_primary_ptr = &mut iso9660.primary as *mut vd;
    let mut vd = unsafe { &mut *iso9660_primary_ptr };
    if iso9660.opt_support_joliet == 0 {
        iso9660.seenJoliet = 0
    }
    if iso9660.seenJoliet as i32 != 0 && vd.location > iso9660.joliet.location {
        /* This condition is unlikely; by way of caution. */
        vd = &mut iso9660.joliet
    }
    skipsize = ARCHIVE_ISO9660_DEFINED_PARAM.logical_block_size as i64 * vd.location as int64_t;
    skipsize = unsafe { __archive_read_consume_safe(a, skipsize) };
    if skipsize < 0 {
        return skipsize as i32;
    }
    iso9660.current_position = skipsize as uint64_t;
    block = unsafe { __archive_read_ahead_safe(a, vd.size as size_t, 0 as *mut ssize_t) };
    if block == 0 as *mut () {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
            b"Failed to read full block when scanning ISO9660 directory list\x00" as *const u8
                as *const u8
        );
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
    }
    /*
     * While reading Root Directory, flag seenJoliet must be zero to
     * avoid converting special name 0x00(Current Directory) and
     * next byte to UCS2.
     */
    seenJoliet = iso9660.seenJoliet; /* Save flag. */
    iso9660.seenJoliet = 0;
    file = parse_file_info(
        a,
        0 as *mut file_info,
        block as *const u8,
        vd.size as size_t,
    );
    if file.is_null() {
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
    }
    iso9660.seenJoliet = seenJoliet;
    /*
     * If the iso image has both RockRidge and Joliet, we preferentially
     * use RockRidge Extensions rather than Joliet ones.
     */
    if vd as *mut vd == iso9660_primary_ptr && iso9660.seenRockridge != 0 && iso9660.seenJoliet != 0
    {
        iso9660.seenJoliet = 0
    }
    if vd as *mut vd == iso9660_primary_ptr && iso9660.seenRockridge == 0 && iso9660.seenJoliet != 0
    {
        /* Switch reading data from primary to joliet. */
        vd = &mut iso9660.joliet;
        skipsize = ARCHIVE_ISO9660_DEFINED_PARAM.logical_block_size as i64 * vd.location as int64_t;
        skipsize = skipsize - iso9660.current_position as int64_t;
        skipsize = unsafe { __archive_read_consume_safe(a, skipsize) };
        if skipsize < 0 {
            return skipsize as i32;
        }
        iso9660.current_position = iso9660.current_position + skipsize as u64;
        block = unsafe { __archive_read_ahead_safe(a, vd.size as size_t, 0 as *mut ssize_t) };
        if block == 0 as *mut () {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                b"Failed to read full block when scanning ISO9660 directory list\x00" as *const u8
                    as *const u8
            );
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
        }
        iso9660.seenJoliet = 0;
        file = parse_file_info(
            a,
            0 as *mut file_info,
            block as *const u8,
            vd.size as size_t,
        );
        if file.is_null() {
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
        }
        iso9660.seenJoliet = seenJoliet
    }
    /* Store the root directory in the pending list. */
    if unsafe { heap_add_entry(a, &mut iso9660.pending_files, file, (*file).offset) }
        != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok
    {
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
    } /* Eliminate a warning. */
    if iso9660.seenRockridge != 0 {
        safe_a.archive.archive_format =
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_format_iso9660_rockridge;
        safe_a.archive.archive_format_name = b"ISO9660 with Rockridge extensions\x00" as *const u8
    }
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
}

fn archive_read_format_iso9660_read_header(a: *mut archive_read, entry: *mut archive_entry) -> i32 {
    let safe_a = unsafe { &mut *a };
    let mut file: *mut file_info = 0 as *mut file_info;
    let mut r: i32;
    let mut rd_r: i32 = ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
    let iso9660 = unsafe { &mut *((*(*a).format).data as *mut iso9660) };
    if safe_a.archive.archive_format == 0 {
        safe_a.archive.archive_format = ARCHIVE_ISO9660_DEFINED_PARAM.archive_format_iso9660;
        safe_a.archive.archive_format_name = b"ISO9660\x00" as *const u8
    }
    if iso9660.current_position == 0 {
        r = choose_volume(a, iso9660);
        if r != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok {
            return r;
        }
    }
    file = 0 as *mut file_info;
    /* Get the next entry that appears after the current offset. */
    r = next_entry_seek(a, iso9660, &mut file);
    let file = unsafe { &mut *file };
    if r != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok {
        return r;
    }
    if iso9660.seenJoliet != 0 {
        /*
         * Convert UTF-16BE of a filename to local locale MBS
         * and store the result into a filename field.
         */
        if iso9660.sconv_utf16be.is_null() {
            iso9660.sconv_utf16be = unsafe {
                archive_string_conversion_from_charset_safe(
                    &mut safe_a.archive,
                    b"UTF-16BE\x00" as *const u8,
                    1,
                )
            };
            if iso9660.sconv_utf16be.is_null() {
                /* Couldn't allocate memory */
                return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
            }
        }
        if iso9660.utf16be_path.is_null() {
            iso9660.utf16be_path =
                unsafe { malloc_safe(ARCHIVE_ISO9660_DEFINED_PARAM.utf16_name_max as u64) }
                    as *mut u8;
            if iso9660.utf16be_path.is_null() {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                    b"No memory\x00" as *const u8
                );
                return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
            }
        }
        if iso9660.utf16be_previous_path.is_null() {
            iso9660.utf16be_previous_path =
                unsafe { malloc_safe(ARCHIVE_ISO9660_DEFINED_PARAM.utf16_name_max as u64) }
                    as *mut u8;
            if iso9660.utf16be_previous_path.is_null() {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                    b"No memory\x00" as *const u8
                );
                return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
            }
        }
        iso9660.utf16be_path_len = 0;
        if build_pathname_utf16be(
            iso9660.utf16be_path,
            ARCHIVE_ISO9660_DEFINED_PARAM.utf16_name_max as size_t,
            &mut iso9660.utf16be_path_len,
            file,
        ) != 0
        {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
                b"Pathname is too long\x00" as *const u8
            );
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
        }
        r = unsafe {
            _archive_entry_copy_pathname_l_safe(
                entry,
                iso9660.utf16be_path as *const u8,
                iso9660.utf16be_path_len,
                iso9660.sconv_utf16be,
            )
        };
        if r != 0 {
            if unsafe { *__errno_location_safe() } == ARCHIVE_ISO9660_DEFINED_PARAM.enomem {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                    b"No memory for Pathname\x00" as *const u8
                );
                return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
            }
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
                b"Pathname cannot be converted from %s to current locale.\x00" as *const u8
                    as *const u8,
                archive_string_conversion_charset_name(iso9660.sconv_utf16be)
            );
            rd_r = ARCHIVE_ISO9660_DEFINED_PARAM.archive_warn
        }
    } else {
        let mut path: *const u8 = build_pathname(&mut iso9660.pathname, file, 0);
        if path.is_null() {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
                b"Pathname is too long\x00" as *const u8
            );
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
        } else {
            iso9660.pathname.length = 0;
            unsafe { archive_entry_set_pathname_safe(entry, path) };
        }
    }
    iso9660.entry_bytes_remaining = file.size as int64_t;
    /* Offset for sparse-file-aware clients. */
    iso9660.entry_sparse_offset = 0 as int64_t;
    if file.offset + file.size > iso9660.volume_size {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
            b"File is beyond end-of-media: %s\x00" as *const u8,
            archive_entry_pathname(entry)
        );
        iso9660.entry_bytes_remaining = 0 as int64_t;
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_warn;
    }
    /* Set up the entry structure with information about this entry. */
    unsafe { archive_entry_set_mode_safe(entry, file.mode) };
    unsafe { archive_entry_set_uid_safe(entry, file.uid as la_int64_t) };
    unsafe { archive_entry_set_gid_safe(entry, file.gid as la_int64_t) };
    unsafe { archive_entry_set_nlink_safe(entry, file.nlinks as u32) };
    if file.birthtime_is_set != 0 {
        unsafe { archive_entry_set_birthtime_safe(entry, file.birthtime, 0) };
    } else {
        unsafe { archive_entry_unset_birthtime_safe(entry) };
    }
    unsafe { archive_entry_set_mtime_safe(entry, file.mtime, 0) };
    unsafe { archive_entry_set_ctime_safe(entry, file.ctime, 0) };
    unsafe { archive_entry_set_atime_safe(entry, file.atime, 0) };
    /* N.B.: Rock Ridge supports 64-bit device numbers. */
    unsafe { archive_entry_set_rdev_safe(entry, file.rdev) };
    unsafe { archive_entry_set_size_safe(entry, iso9660.entry_bytes_remaining) };
    if !file.symlink.s.is_null() {
        unsafe { archive_entry_copy_symlink_safe(entry, file.symlink.s) };
    }
    /* Note: If the input isn't seekable, we can't rewind to
     * return the same body again, so if the next entry refers to
     * the same data, we have to return it as a hardlink to the
     * original entry. */
    if file.number != -1 as i64 && file.number == iso9660.previous_number {
        if iso9660.seenJoliet != 0 {
            r = unsafe {
                _archive_entry_copy_hardlink_l_safe(
                    entry,
                    iso9660.utf16be_previous_path as *const u8,
                    iso9660.utf16be_previous_path_len,
                    iso9660.sconv_utf16be,
                )
            };
            if r != 0 {
                if unsafe { *__errno_location_safe() } == ARCHIVE_ISO9660_DEFINED_PARAM.enomem {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                        b"No memory for Linkname\x00" as *const u8
                    );
                    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                }
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
                    b"Linkname cannot be converted from %s to current locale.\x00" as *const u8
                        as *const u8,
                    archive_string_conversion_charset_name(iso9660.sconv_utf16be)
                );
                rd_r = ARCHIVE_ISO9660_DEFINED_PARAM.archive_warn
            }
        } else {
            unsafe { archive_entry_set_hardlink_safe(entry, iso9660.previous_pathname.s) };
        }
        unsafe { archive_entry_unset_size_safe(entry) };
        iso9660.entry_bytes_remaining = 0 as int64_t;
        return rd_r;
    }
    if file.mode & ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifmt as mode_t
        != ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifdir as mode_t
        && file.offset < iso9660.current_position
    {
        let mut r64: int64_t = 0;
        r64 = unsafe {
            __archive_read_seek_safe(
                a,
                file.offset as int64_t,
                ARCHIVE_ISO9660_DEFINED_PARAM.seek_set,
            )
        };
        if r64 != file.offset as int64_t {
            /* We can't seek backwards to extract it, so issue
             * a warning.  Note that this can only happen if
             * this entry was added to the heap after we passed
             * this offset, that is, only if the directory
             * mentioning this entry is later than the body of
             * the entry. Such layouts are very unusual; most
             * ISO9660 writers lay out and record all directory
             * information first, then store all file bodies. */
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                b"Ignoring out-of-order file @%jx (%s) %jd < %jd\x00" as *const u8,
                file.number,
                iso9660.pathname.s,
                file.offset as intmax_t,
                iso9660.current_position as intmax_t
            );
            iso9660.entry_bytes_remaining = 0 as int64_t;
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_warn;
        }
        iso9660.current_position = r64 as uint64_t
    }
    /* Initialize zisofs variables. */
    iso9660.entry_zisofs.pz = file.pz;
    if file.pz != 0 {
        match () {
            #[cfg(HAVE_ZLIB_H)]
            _ => {
                let zisofs = &mut iso9660.entry_zisofs;
                zisofs.initialized = 0;
                zisofs.pz_log2_bs = file.pz_log2_bs;
                zisofs.pz_uncompressed_size = file.pz_uncompressed_size;
                zisofs.pz_offset = 0 as uint32_t;
                zisofs.header_avail = 0 as size_t;
                zisofs.header_passed = 0;
                zisofs.block_pointers_avail = 0 as size_t;
            }
            #[cfg(not(HAVE_ZLIB_H))]
            _ => {}
        };
        unsafe { archive_entry_set_size_safe(entry, file.pz_uncompressed_size as la_int64_t) };
    }
    iso9660.previous_number = file.number;
    if iso9660.seenJoliet != 0 {
        unsafe {
            memcpy_safe(
                iso9660.utf16be_previous_path as *mut (),
                iso9660.utf16be_path as *const (),
                iso9660.utf16be_path_len,
            )
        };
        iso9660.utf16be_previous_path_len = iso9660.utf16be_path_len
    } else {
        iso9660.previous_pathname.length = 0 as size_t;
        unsafe {
            archive_strncat_safe(
                &mut iso9660.previous_pathname,
                iso9660.pathname.s as *const (),
                if iso9660.pathname.s.is_null() {
                    0
                } else {
                    strlen_safe(iso9660.pathname.s)
                },
            )
        };
    }
    /* Reset entry_bytes_remaining if the file is multi extent. */
    iso9660.entry_content = file.contents.first;
    if !iso9660.entry_content.is_null() {
        iso9660.entry_bytes_remaining = unsafe { (*iso9660.entry_content).size } as int64_t
    }
    if unsafe { archive_entry_filetype_safe(entry) }
        == ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifdir as mode_t
    {
        /* Overwrite nlinks by proper link number which is
         * calculated from number of sub directories. */
        unsafe { archive_entry_set_nlink_safe(entry, (2 + file.subdirs) as u32) };
        /* Directory data has been read completely. */
        iso9660.entry_bytes_remaining = 0 as int64_t
    }
    if rd_r != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok {
        return rd_r;
    }
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
}

fn archive_read_format_iso9660_read_data_skip(a: *mut archive_read) -> i32 {
    /* Because read_next_header always does an explicit skip
     * to the next entry, we don't need to do anything here. */
    /* UNUSED */
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
}

/* HAVE_ZLIB_H */
#[cfg(HAVE_ZLIB_H)]
fn zisofs_read_data(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let safe_buff = unsafe { &mut *buff };
    let safe_size = unsafe { &mut *size };
    let safe_offset = unsafe { &mut *offset };
    let current_block: u64;
    let mut p: *const u8 = 0 as *const u8;
    let mut avail: size_t;
    let mut bytes_read: ssize_t = 0;
    let mut uncompressed_size: size_t;
    let mut r: i32;
    let iso9660 = unsafe { &mut *((*(*a).format).data as *mut iso9660) };
    let zisofs = &mut iso9660.entry_zisofs;
    p = unsafe { __archive_read_ahead_safe(a, 1, &mut bytes_read) } as *const u8;
    if bytes_read <= 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
            b"Truncated zisofs file body\x00" as *const u8
        );
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
    }
    if bytes_read > iso9660.entry_bytes_remaining {
        bytes_read = iso9660.entry_bytes_remaining
    }
    avail = bytes_read as size_t;
    uncompressed_size = 0 as size_t;
    if zisofs.initialized == 0 {
        let ceil: size_t;
        let mut xsize: size_t;
        /* We need more data. */
        /* Allocate block pointers buffer. */
        ceil = zisofs.pz_uncompressed_size + (((1 as int64_t) << zisofs.pz_log2_bs) as u64 - 1)
            >> zisofs.pz_log2_bs;
        xsize = (ceil + 1) * 4;
        if zisofs.block_pointers_alloc < xsize {
            let mut alloc: size_t = 0;
            if !zisofs.block_pointers.is_null() {
                unsafe { free_safe(zisofs.block_pointers as *mut ()) };
            }
            alloc = ((xsize >> 10) + 1) << 10;
            zisofs.block_pointers = unsafe { malloc_safe(alloc) } as *mut u8;
            if zisofs.block_pointers.is_null() {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                    b"No memory for zisofs decompression\x00" as *const u8
                );
                return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
            }
            zisofs.block_pointers_alloc = alloc
        }
        zisofs.block_pointers_size = xsize;
        /* Allocate uncompressed data buffer. */
        xsize = (1) << zisofs.pz_log2_bs;
        if zisofs.uncompressed_buffer_size < xsize {
            if !zisofs.uncompressed_buffer.is_null() {
                unsafe { free_safe(zisofs.uncompressed_buffer as *mut ()) };
            }
            zisofs.uncompressed_buffer = unsafe { malloc_safe(xsize) } as *mut u8;
            if zisofs.uncompressed_buffer.is_null() {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                    b"No memory for zisofs decompression\x00" as *const u8
                );
                return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
            }
        }
        zisofs.uncompressed_buffer_size = xsize;
        /*
         * Read the file header, and check the magic code of zisofs.
         */
        if zisofs.header_avail < size_of::<[u8; 16]>() as u64 {
            xsize = (size_of::<[u8; 16]>() as u64) - zisofs.header_avail;
            if avail < xsize {
                xsize = avail
            }
            unsafe {
                memcpy_safe(
                    zisofs
                        .header
                        .as_mut_ptr()
                        .offset(zisofs.header_avail as isize) as *mut (),
                    p as *const (),
                    xsize,
                )
            };
            zisofs.header_avail = zisofs.header_avail + xsize;
            avail = avail - xsize;
            unsafe { p = p.offset(xsize as isize) }
        }
        if zisofs.header_passed == 0 && zisofs.header_avail == size_of::<[u8; 16]>() as u64 {
            let mut err: i32 = 0;
            if unsafe {
                memcmp_safe(
                    zisofs.header.as_mut_ptr() as *const (),
                    zisofs_magic.as_ptr() as *const (),
                    size_of::<[u8; 8]>() as u64,
                )
            } != 0
            {
                err = 1
            }
            if archive_le32dec(unsafe { zisofs.header.as_mut_ptr().offset(8 as isize) } as *const ())
                as u64
                != zisofs.pz_uncompressed_size
            {
                err = 1
            }
            if zisofs.header[12 as usize] as i32 != 4 {
                err = 1
            }
            if zisofs.header[13 as usize] as i32 != zisofs.pz_log2_bs {
                err = 1
            }
            if err != 0 {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
                    b"Illegal zisofs file body\x00" as *const u8
                );
                return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
            }
            zisofs.header_passed = 1
        }
        /*
         * Read block pointers.
         */
        if zisofs.header_passed != 0 && zisofs.block_pointers_avail < zisofs.block_pointers_size {
            xsize = zisofs.block_pointers_size - zisofs.block_pointers_avail;
            if avail < xsize {
                xsize = avail
            }
            unsafe {
                memcpy_safe(
                    zisofs
                        .block_pointers
                        .offset(zisofs.block_pointers_avail as isize)
                        as *mut (),
                    p as *const (),
                    xsize,
                )
            };
            zisofs.block_pointers_avail = zisofs.block_pointers_avail + xsize;
            avail = avail - xsize;
            unsafe {
                p = p.offset(xsize as isize);
            }
            if zisofs.block_pointers_avail == zisofs.block_pointers_size {
                /* We've got all block pointers and initialize
                 * related variables.	*/
                zisofs.block_off = 0 as size_t;
                zisofs.block_avail = 0 as uint32_t;
                /* Complete a initialization */
                zisofs.initialized = 1
            }
        }
        if zisofs.initialized == 0 {
            current_block = 0;
        } else {
            current_block = 1;
        }
    } else {
        current_block = 1;
    }
    match current_block {
        1 => {
            /*
             * Get block offsets from block pointers.
             */
            if zisofs.block_avail == 0 {
                let bst: uint32_t;
                let bed: uint32_t;
                if zisofs.block_off + 4 >= zisofs.block_pointers_size {
                    /* There isn't a pair of offsets. */
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
                        b"Illegal zisofs block pointers\x00" as *const u8
                    );
                    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                }
                bst = archive_le32dec(unsafe {
                    zisofs.block_pointers.offset(zisofs.block_off as isize)
                } as *const ());
                if bst as u64 != (zisofs.pz_offset as u64) + (bytes_read as u64) - avail {
                    /* TODO: Should we seek offset of current file
                     * by bst ? */
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
                        b"Illegal zisofs block pointers(cannot seek)\x00" as *const u8
                    );
                    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                }
                bed = archive_le32dec(unsafe {
                    zisofs
                        .block_pointers
                        .offset(zisofs.block_off as isize)
                        .offset(4 as isize)
                } as *const ());
                if bed < bst {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
                        b"Illegal zisofs block pointers\x00" as *const u8
                    );
                    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                }
                zisofs.block_avail = bed - bst;
                zisofs.block_off = zisofs.block_off + 4;
                /* Initialize compression library for new block. */
                if zisofs.stream_valid != 0 {
                    r = unsafe { libz_sys::inflateReset(&mut zisofs.stream) }
                } else {
                    r = unsafe {
                        libz_sys::inflateInit_(
                            &mut zisofs.stream,
                            b"1.2.7\x00" as *const u8 as *const libc::c_char,
                            size_of::<z_stream>() as i32,
                        )
                    }
                }
                if r != libz_sys::Z_OK {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                        b"Can\'t initialize zisofs decompression.\x00" as *const u8
                    );
                    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                }
                zisofs.stream_valid = 1;
                zisofs.stream.total_in = 0 as uLong;
                zisofs.stream.total_out = 0 as uLong
            }
            /*
             * Make uncompressed data.
             */
            if zisofs.block_avail == 0 {
                unsafe {
                    memset_safe(
                        zisofs.uncompressed_buffer as *mut (),
                        0,
                        zisofs.uncompressed_buffer_size,
                    )
                };
                uncompressed_size = zisofs.uncompressed_buffer_size
            } else {
                zisofs.stream.next_in = p as *const () as uintptr_t as *mut Bytef;
                if avail > zisofs.block_avail as u64 {
                    zisofs.stream.avail_in = zisofs.block_avail
                } else {
                    zisofs.stream.avail_in = avail as uInt
                }
                zisofs.stream.next_out = zisofs.uncompressed_buffer;
                zisofs.stream.avail_out = zisofs.uncompressed_buffer_size as uInt;
                r = unsafe { libz_sys::inflate(&mut zisofs.stream, 0) };
                if r == libz_sys::Z_OK || r == libz_sys::Z_STREAM_END {
                } else {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                        b"zisofs decompression failed (%d)\x00" as *const u8,
                        r
                    );
                    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                }
                uncompressed_size =
                    zisofs.uncompressed_buffer_size - zisofs.stream.avail_out as u64;
                avail = (avail - unsafe { zisofs.stream.next_in.offset_from(p) } as u64) as size_t;
                zisofs.block_avail = (zisofs.block_avail
                    - unsafe { zisofs.stream.next_in.offset_from(p) } as uint32_t)
                    as uint32_t
            }
        }
        _ => {}
    }
    bytes_read = ((bytes_read as u64) - avail) as ssize_t;
    *safe_buff = zisofs.uncompressed_buffer as *const ();
    *safe_size = uncompressed_size;
    *safe_offset = iso9660.entry_sparse_offset;
    iso9660.entry_sparse_offset =
        (iso9660.entry_sparse_offset as u64 + uncompressed_size) as int64_t;
    iso9660.entry_bytes_remaining -= bytes_read;
    iso9660.current_position = iso9660.current_position + bytes_read as u64;
    zisofs.pz_offset = zisofs.pz_offset + bytes_read as uint32_t;
    iso9660.entry_bytes_unconsumed = iso9660.entry_bytes_unconsumed + bytes_read as u64;
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
}

#[cfg(not(HAVE_ZLIB_H))]
fn zisofs_read_data(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    /* UNUSED */
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
        b"zisofs is not supported on this platform.\x00" as *const u8
    );
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_failed;
}

/* HAVE_ZLIB_H */
fn archive_read_format_iso9660_read_data(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let safe_buff = unsafe { &mut *buff };
    let safe_size = unsafe { &mut *size };
    let safe_offset = unsafe { &mut *offset };
    let mut bytes_read: ssize_t = 0;
    let iso9660 = unsafe { &mut *((*(*a).format).data as *mut iso9660) };
    let iso9660_entry_content = unsafe { &mut *iso9660.entry_content };
    if iso9660.entry_bytes_unconsumed != 0 {
        unsafe { __archive_read_consume_safe(a, iso9660.entry_bytes_unconsumed as int64_t) };
        iso9660.entry_bytes_unconsumed = 0 as size_t
    }
    if iso9660.entry_bytes_remaining <= 0 {
        if !iso9660.entry_content.is_null() {
            iso9660.entry_content = iso9660_entry_content.next
        }
        if iso9660.entry_content.is_null() {
            *safe_buff = 0 as *const ();
            *safe_size = 0 as size_t;
            *safe_offset = iso9660.entry_sparse_offset;
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_eof;
        }
        /* Seek forward to the start of the entry. */
        if iso9660.current_position < iso9660_entry_content.offset {
            let mut step: int64_t = 0;
            step = (iso9660_entry_content.offset - iso9660.current_position) as int64_t;
            step = unsafe { __archive_read_consume_safe(a, step) };
            if step < 0 {
                return step as i32;
            }
            iso9660.current_position = iso9660_entry_content.offset
        }
        if iso9660_entry_content.offset < iso9660.current_position {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                b"Ignoring out-of-order file (%s) %jd < %jd\x00" as *const u8,
                iso9660.pathname.s,
                iso9660_entry_content.offset as intmax_t,
                iso9660.current_position as intmax_t
            );
            *safe_buff = 0 as *const ();
            *safe_size = 0 as size_t;
            *safe_offset = iso9660.entry_sparse_offset;
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_warn;
        }
        iso9660.entry_bytes_remaining = iso9660_entry_content.size as int64_t
    }
    if iso9660.entry_zisofs.pz != 0 {
        return zisofs_read_data(a, buff, size, offset);
    }
    *safe_buff = unsafe { __archive_read_ahead_safe(a, 1 as size_t, &mut bytes_read) };
    if bytes_read == 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
            b"Truncated input file\x00" as *const u8
        );
    }
    if *safe_buff == 0 as *mut () {
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
    }
    if bytes_read > iso9660.entry_bytes_remaining {
        bytes_read = iso9660.entry_bytes_remaining
    }
    *safe_size = bytes_read as size_t;
    *safe_offset = iso9660.entry_sparse_offset;
    iso9660.entry_sparse_offset += bytes_read;
    iso9660.entry_bytes_remaining -= bytes_read;
    iso9660.entry_bytes_unconsumed = bytes_read as size_t;
    iso9660.current_position = iso9660.current_position + bytes_read as u64;
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
}

fn archive_read_format_iso9660_cleanup(a: *mut archive_read) -> i32 {
    let mut r: i32 = ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
    let iso9660 = unsafe { &mut *((*(*a).format).data as *mut iso9660) };
    release_files(iso9660);
    unsafe { free_safe(iso9660.read_ce_req.reqs as *mut ()) };
    unsafe { archive_string_free_safe(&mut iso9660.pathname) };
    unsafe { archive_string_free_safe(&mut iso9660.previous_pathname) };
    unsafe { free_safe(iso9660.pending_files.files as *mut ()) };
    match () {
        #[cfg(HAVE_ZLIB_H)]
        _ => {
            unsafe { free_safe(iso9660.entry_zisofs.uncompressed_buffer as *mut ()) };
            unsafe { free_safe(iso9660.entry_zisofs.block_pointers as *mut ()) };
            if iso9660.entry_zisofs.stream_valid != 0 {
                if unsafe { libz_sys::inflateEnd(&mut iso9660.entry_zisofs.stream) }
                    != libz_sys::Z_OK
                {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                        b"Failed to clean up zlib decompressor\x00" as *const u8
                    );
                    r = ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                }
            }
        }
        #[cfg(not(HAVE_ZLIB_H))]
        _ => {}
    }
    unsafe { free_safe(iso9660.utf16be_path as *mut ()) };
    unsafe { free_safe(iso9660.utf16be_previous_path as *mut ()) };
    unsafe { free_safe(iso9660 as *mut iso9660 as *mut ()) };
    unsafe {
        (*(*a).format).data = 0 as *mut ();
    }
    return r;
}

/*
 * This routine parses a single ISO directory record, makes sense
 * of any extensions, and stores the result in memory.
 */
fn parse_file_info(
    a: *mut archive_read,
    parent: *mut file_info,
    isodirrec: *const u8,
    reclen: size_t,
) -> *mut file_info {
    let safe_parent = unsafe { &mut *parent };
    let mut current_block: u64;
    let mut file = unsafe { &mut *(0 as *mut file_info) };
    let mut filep = 0 as *mut file_info;
    let mut name_len: size_t;
    let mut rr_start: *const u8 = 0 as *const u8;
    let mut rr_end: *const u8 = 0 as *const u8;
    let mut p: *const u8 = 0 as *const u8;
    let mut dr_len: size_t = 0;
    let fsize: uint64_t;
    let offset: uint64_t;
    let location: int32_t;
    let flags: i32;
    let iso9660 = unsafe { &mut *((*(*a).format).data as *mut iso9660) };
    if reclen != 0 {
        dr_len =
            unsafe { *isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_length_offset as isize) }
                as size_t
    }
    /*
     * Sanity check that reclen is not zero and dr_len is greater than
     * reclen but at least 34
     */
    if reclen == 0 || reclen < dr_len || dr_len < 34 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
            b"Invalid length of directory record\x00" as *const u8
        );
        return 0 as *mut file_info;
    }
    name_len =
        unsafe { *isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_name_len_offset as isize) }
            as size_t;
    location = archive_le32dec(unsafe {
        isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_extent_offset as isize)
    } as *const ()) as int32_t;
    fsize = unsafe {
        toi(
            isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_size_offset as isize) as *const (),
            ARCHIVE_ISO9660_DEFINED_PARAM.dr_size_size,
        )
    } as uint64_t;
    /* Sanity check that name_len doesn't exceed dr_len. */
    if dr_len - 33 < name_len || name_len == 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
            b"Invalid length of file identifier\x00" as *const u8
        );
        return 0 as *mut file_info;
    }
    /* Sanity check that location doesn't exceed volume block.
     * Don't check lower limit of location; it's possibility
     * the location has negative value when file type is symbolic
     * link or file size is zero. As far as I know latest mkisofs
     * do that.
     */
    if location > 0
        && (location as u64
            + (fsize + iso9660.logical_block_size as u64 - 1) / iso9660.logical_block_size as u64)
            > iso9660.volume_block as u64
    {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
            b"Invalid location of extent of file\x00" as *const u8
        );
        return 0 as *mut file_info;
    }
    /* Sanity check that location doesn't have a negative value
     * when the file is not empty. it's too large. */
    if fsize != 0 && location < 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
            b"Invalid location of extent of file\x00" as *const u8
        );
        return 0 as *mut file_info;
    }
    /* Sanity check that this entry does not create a cycle. */
    offset = iso9660.logical_block_size as u64 * location as uint64_t;
    filep = parent;
    while !filep.is_null() {
        let safe_filep = unsafe { &mut *filep };
        if safe_filep.offset == offset {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
                b"Directory structure contains loop\x00" as *const u8
            );
            return 0 as *mut file_info;
        }
        filep = safe_filep.parent
    }
    /* Create a new file entry and copy data from the ISO dir record. */
    file = unsafe { &mut *(calloc_safe(1, size_of::<file_info>() as u64) as *mut file_info) };
    if (file as *mut file_info).is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
            b"No memory for file entry\x00" as *const u8
        );
        return 0 as *mut file_info;
    }
    file.parent = parent;
    file.offset = offset;
    file.size = fsize;
    file.mtime = unsafe {
        isodate7(isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_date_offset as isize))
    };
    file.atime = file.mtime;
    file.ctime = file.atime;
    file.rede_files.first = 0 as *mut file_info;
    file.rede_files.last = &mut file.rede_files.first;
    unsafe {
        p = isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_name_offset as isize);
        /* Rockridge extensions (if any) follow name.  Compute this
         * before fidgeting the name_len below. */
        rr_start = p
            .offset(name_len as isize)
            .offset((if name_len & 1 != 0 { 0 } else { 1 }) as isize);
        rr_end = isodirrec.offset(dr_len as isize);
    }
    if iso9660.seenJoliet != 0 {
        /* Joliet names are max 64 chars (128 bytes) according to spec,
         * but genisoimage/mkisofs allows recording longer Joliet
         * names which are 103 UCS2 characters(206 bytes) by their
         * option '-joliet-long'.
         */
        if name_len > 206 {
            name_len = 206
        }
        name_len &= !(1) as u64;
        /* trim trailing first version and dot from filename.
         *
         * Remember we were in UTF-16BE land!
         * SEPARATOR 1 (.) and SEPARATOR 2 (;) are both
         * 16 bits big endian characters on Joliet.
         *
         * TODO: sanitize filename?
         *       Joliet allows any UCS-2 char except:
         *       *, /, :, ;, ? and \.
         */
        /* Chop off trailing ';1' from files. */
        if name_len > 4
            && unsafe { *p.offset((name_len - 4) as isize) } == 0
            && unsafe { *p.offset((name_len - 3) as isize) } == ';' as u8
            && unsafe { *p.offset((name_len - 2) as isize) } == 0
            && unsafe { *p.offset((name_len - 1) as isize) } == '1' as u8
        {
            name_len = name_len - 4;
        }
        file.utf16be_name = unsafe { malloc_safe(name_len) } as *mut u8;
        if file.utf16be_name.is_null() {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                b"No memory for file name\x00" as *const u8
            );
            current_block = 0;
        } else {
            unsafe { memcpy_safe(file.utf16be_name as *mut (), p as *const (), name_len) };
            file.utf16be_bytes = name_len;
            current_block = 1;
        }
    } else {
        /* Chop off trailing ';1' from files. */
        if name_len > 2
            && unsafe { *p.offset((name_len - 2) as isize) } == ';' as u8
            && unsafe { *p.offset((name_len - 1) as isize) } == '1' as u8
        {
            name_len = name_len - 2;
        }
        /* Chop off trailing '.' from filenames. */
        if name_len > 1 && unsafe { *p.offset((name_len - 1) as isize) } == '.' as u8 {
            name_len = name_len - 1;
        }
        file.name.length = 0;
        unsafe { archive_strncat_safe(&mut file.name, p as *const u8 as *const (), name_len) };
        current_block = 1;
    }
    match current_block {
        1 => {
            flags = unsafe {
                *isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_flags_offset as isize)
            } as i32;
            if flags & 0x2 != 0 {
                file.mode = ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifdir as mode_t | 0o700 as u32
            } else {
                file.mode = ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifreg as mode_t | 0o400 as u32
            }
            if flags & 0x80 != 0 {
                file.multi_extent = 1
            } else {
                file.multi_extent = 0
            }
            /*
             * Use a location for the file number, which is treated as an inode
             * number to find out hardlink target. If Rockridge extensions is
             * being used, the file number will be overwritten by FILE SERIAL
             * NUMBER of RRIP "PX" extension.
             * Note: Old mkisofs did not record that FILE SERIAL NUMBER
             * in ISO images.
             * Note2: xorriso set 0 to the location of a symlink file.
             */
            if file.size == 0 && location >= 0 {
                /* If file->size is zero, its location points wrong place,
                 * and so we should not use it for the file number.
                 * When the location has negative value, it can be used
                 * for the file number.
                 */
                file.number = -1;
                /* Do not appear before any directory entries. */
                file.offset = -(1 as i32) as uint64_t
            } else {
                file.number = location as int64_t
            }
            /* Rockridge extensions overwrite information from above. */
            if iso9660.opt_support_rockridge != 0 {
                if (safe_parent as *mut file_info).is_null()
                    && unsafe { rr_end.offset_from(rr_start) } as i64 >= 7
                {
                    p = rr_start;
                    if unsafe {
                        memcmp_safe(
                            p as *const (),
                            b"SP\x07\x01\xbe\xef\x00" as *const u8 as *const (),
                            6,
                        )
                    } == 0
                    {
                        /*
                         * SP extension stores the suspOffset
                         * (Number of bytes to skip between
                         * filename and SUSP records.)
                         * It is mandatory by the SUSP standard
                         * (IEEE 1281).
                         *
                         * It allows SUSP to coexist with
                         * non-SUSP uses of the System
                         * Use Area by placing non-SUSP data
                         * before SUSP data.
                         *
                         * SP extension must be in the root
                         * directory entry, disable all SUSP
                         * processing if not found.
                         */
                        unsafe { iso9660.suspOffset = *p.offset(6 as isize) };
                        iso9660.seenSUSP = 1;
                        unsafe { rr_start = rr_start.offset(7 as isize) }
                    }
                }
                if iso9660.seenSUSP != 0 {
                    let mut r: i32 = 0;
                    file.name_continues = 0;
                    file.symlink_continues = 0;
                    unsafe { rr_start = rr_start.offset(iso9660.suspOffset as isize) };
                    r = parse_rockridge(a, file, rr_start, rr_end);
                    if r != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok {
                        current_block = 0;
                    } else {
                        /*
                         * A file size of symbolic link files in ISO images
                         * made by makefs is not zero and its location is
                         * the same as those of next regular file. That is
                         * the same as hard like file and it causes unexpected
                         * error.
                         */
                        if file.size > 0
                            && file.mode & ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifmt as mode_t
                                == ARCHIVE_ISO9660_DEFINED_PARAM.ae_iflnk as mode_t
                        {
                            file.size = 0;
                            file.number = -1;
                            file.offset = -(1 as i32) as uint64_t
                        }
                        current_block = 1;
                    }
                } else {
                    /* If there isn't SUSP, disable parsing
                     * rock ridge extensions. */
                    iso9660.opt_support_rockridge = 0; /* Reset nlink. we'll calculate it later. */
                    current_block = 1;
                }
            } else {
                current_block = 1;
            }
            match current_block {
                0 => {}
                _ => {
                    file.nlinks = 1;
                    /* Tell file's parent how many children that parent has. */
                    if !(safe_parent as *mut file_info).is_null() && flags & 0x2 != 0 {
                        safe_parent.subdirs += 1
                    }
                    if iso9660.seenRockridge != 0 {
                        if !(safe_parent as *mut file_info).is_null()
                            && safe_parent.parent.is_null()
                            && flags & 0x2 != 0
                            && iso9660.rr_moved.is_null()
                            && !file.name.s.is_null()
                            && (unsafe { strcmp_safe(file.name.s, b"rr_moved\x00" as *const u8) }
                                == 0
                                || unsafe {
                                    strcmp_safe(file.name.s, b".rr_moved\x00" as *const u8)
                                } == 0)
                        {
                            iso9660.rr_moved = file;
                            file.rr_moved = 1;
                            file.rr_moved_has_re_only = 1;
                            file.re = 0;
                            safe_parent.subdirs -= 1;
                            current_block = 1;
                        } else if file.re != 0 {
                            /*
                             * Sanity check: file's parent is rr_moved.
                             */
                            if (safe_parent as *mut file_info).is_null()
                                || safe_parent.rr_moved == 0
                            {
                                archive_set_error_safe!(
                                    &mut (*a).archive as *mut archive,
                                    ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                                    b"Invalid Rockridge RE\x00" as *const u8
                                );
                                current_block = 0;
                            } else if file.cl_offset != 0 {
                                archive_set_error_safe!(
                                    &mut (*a).archive as *mut archive,
                                    ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                                    b"Invalid Rockridge RE and CL\x00" as *const u8
                                );
                                current_block = 0;
                            } else if flags & 0x2 == 0 {
                                archive_set_error_safe!(
                                    &mut (*a).archive as *mut archive,
                                    ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                                    b"Invalid Rockridge RE\x00" as *const u8
                                );
                                current_block = 0;
                            } else {
                                current_block = 1;
                            }
                        } else {
                            if !(safe_parent as *mut file_info).is_null()
                                && safe_parent.rr_moved != 0
                            {
                                file.rr_moved_has_re_only = 0
                            } else if !(safe_parent as *mut file_info).is_null()
                                && flags & 0x2 != 0
                                && (safe_parent.re != 0 || safe_parent.re_descendant != 0)
                            {
                                file.re_descendant = 1
                            }
                            current_block = 1;
                        }
                        match current_block {
                            0 => {}
                            _ => {
                                if file.cl_offset != 0 {
                                    let mut r_0 = 0 as *mut file_info;
                                    if (safe_parent as *mut file_info).is_null()
                                        || safe_parent.parent.is_null()
                                        || flags & 0x2 != 0
                                    {
                                        archive_set_error_safe!(
                                            &mut (*a).archive as *mut archive,
                                            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                                            b"Invalid Rockridge CL\x00" as *const u8
                                        );
                                        current_block = 0;
                                    } else {
                                        safe_parent.subdirs += 1;
                                        /*
                                         * Sanity check: file does not have "CL" extension.
                                         */
                                        /*
                                         * Sanity check: The file type must be a directory.
                                         */
                                        /*
                                         * Sanity check: The file type must be a regular file.
                                         */
                                        /* Overwrite an offset and a number of this "CL" entry
                                         * to appear before other dirs. "+1" to those is to
                                         * make sure to appear after "RE" entry which this
                                         * "CL" entry should be connected with. */
                                        file.number = (file.cl_offset + 1) as int64_t;
                                        file.offset = file.number as uint64_t;
                                        /*
                                         * Sanity check: cl_offset does not point at its
                                         * the parents or itself.
                                         */
                                        r_0 = parent;
                                        loop {
                                            let safe_r_0 = unsafe { &mut *r_0 };
                                            if r_0.is_null() {
                                                current_block = 1;
                                                break;
                                            }
                                            if safe_r_0.offset == file.cl_offset {
                                                archive_set_error_safe!(
                                                    &mut (*a).archive as *mut archive,
                                                    ARCHIVE_ISO9660_DEFINED_PARAM
                                                        .archive_errno_misc,
                                                    b"Invalid Rockridge CL\x00" as *const u8
                                                        as *const u8
                                                );
                                                current_block = 0;
                                                break;
                                            } else {
                                                r_0 = safe_r_0.parent
                                            }
                                        }
                                        match current_block {
                                            0 => {}
                                            _ => {
                                                if file.cl_offset == file.offset
                                                    || safe_parent.rr_moved != 0
                                                {
                                                    archive_set_error_safe!(
                                                        &mut (*a).archive as *mut archive,
                                                        ARCHIVE_ISO9660_DEFINED_PARAM
                                                            .archive_errno_misc,
                                                        b"Invalid Rockridge CL\x00" as *const u8
                                                            as *const u8
                                                    );
                                                    current_block = 0;
                                                } else {
                                                    current_block = 1;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    current_block = 1;
                                }
                            }
                        }
                    } else {
                        current_block = 1;
                    }
                    match current_block {
                        0 => {}
                        _ => {
                            match () {
                                #[cfg(C_DEBUG)]
                                _ => {
                                    /* DEBUGGING: Warn about attributes I don't yet fully support. */
                                    if flags & !0x2 != 0 {
                                        eprintln!("\n ** Unrecognized flag: ");
                                        dump_isodirrec(isodirrec);
                                        eprintln!("\n");
                                    } else if toi(
                                        unsafe {
                                            isodirrec.offset(
                                                ARCHIVE_ISO9660_DEFINED_PARAM
                                                    .dr_volume_sequence_number_offset
                                                    as isize,
                                            )
                                        } as *const (),
                                        2,
                                    ) != 1
                                    {
                                        eprintln!("\n ** Unrecognized sequence number: ");
                                        dump_isodirrec(isodirrec);
                                        eprintln!("\n");
                                    } else if (unsafe {
                                        *isodirrec.offset(
                                            ARCHIVE_ISO9660_DEFINED_PARAM.dr_file_unit_size_offset
                                                as isize,
                                        )
                                    } as i32
                                        != 0)
                                    {
                                        eprintln!("\n ** Unexpected file unit size: ");
                                        dump_isodirrec(isodirrec);
                                        eprintln!("\n");
                                    } else if (unsafe {
                                        *isodirrec.offset(
                                            ARCHIVE_ISO9660_DEFINED_PARAM.dr_interleave_offset
                                                as isize,
                                        )
                                    } as i32
                                        != 0)
                                    {
                                        eprintln!("\n ** Unexpected interleave: ");
                                        dump_isodirrec(isodirrec);
                                        eprintln!("\n");
                                    } else if (unsafe {
                                        *isodirrec.offset(
                                            ARCHIVE_ISO9660_DEFINED_PARAM.dr_ext_attr_length_offset
                                                as isize,
                                        )
                                    } as i32
                                        != 0)
                                    {
                                        eprintln!("\n ** Unexpected extended attribute length: ");
                                        dump_isodirrec(isodirrec);
                                        eprintln!("\n");
                                    }
                                }
                                #[cfg(not(C_DEBUG))]
                                _ => {}
                            }
                            register_file(iso9660, file);
                            return file;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    unsafe { archive_string_free_safe(&mut file.name) };
    unsafe { free_safe(file as *mut file_info as *mut ()) };
    return 0 as *mut file_info;
}

fn parse_rockridge(
    mut a: *mut archive_read,
    mut file: *mut file_info,
    mut p: *const u8,
    mut end: *const u8,
) -> i32 {
    let file = unsafe { &mut *file };
    let mut entry_seen: i32 = 0;
    let iso9660 = unsafe { &mut *((*(*a).format).data as *mut iso9660) };
    while unsafe { p.offset(4 as isize) } <= end
        && unsafe { *p.offset(0 as isize) } >= 'A' as u8
        && unsafe { *p.offset(0 as isize) } <= 'Z' as u8
        && unsafe { *p.offset(1 as isize) } >= 'A' as u8
        && unsafe { *p.offset(1 as isize) } <= 'Z' as u8
        && unsafe { *p.offset(2 as isize) } >= 4
        && unsafe { p.offset(*p.offset(2 as isize) as isize) } <= end
    {
        /* Sanity-check length. */
        let mut data: *const u8 = unsafe { p.offset(4 as isize) };
        let data_length: i32 = unsafe { *p.offset(2 as isize) } as i32 - 4;
        let version: i32 = unsafe { *p.offset(3 as isize) } as i32;
        let p_char = unsafe { *p.offset(0 as isize) } as char;
        match p_char {
            'C' => {
                if unsafe { *p.offset(1 as isize) } == 'E' as u8 {
                    if version == 1 && data_length == 24 {
                        /*
                         * CE extension comprises:
                         *   8 byte sector containing extension
                         *   8 byte offset w/in above sector
                         *   8 byte length of continuation
                         */
                        let mut location: int32_t = archive_le32dec(data as *const ()) as int32_t;
                        file.ce_offset =
                            archive_le32dec(unsafe { data.offset(8 as isize) } as *const ());
                        file.ce_size =
                            archive_le32dec(unsafe { data.offset(16 as isize) } as *const ());
                        if register_CE(a, location, file)
                            != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok
                        {
                            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
                        }
                    }
                } else if unsafe { *p.offset(1 as isize) } == 'L' as u8 {
                    if version == 1 && data_length == 8 {
                        file.cl_offset = (iso9660.logical_block_size as uint64_t)
                            * (archive_le32dec(data as *const ()) as uint64_t);
                        iso9660.seenRockridge = 1;
                    }
                }
            }
            'N' => {
                if unsafe { *p.offset(1 as isize) } == 'M' as u8 {
                    if version == 1 {
                        parse_rockridge_NM1(file, data, data_length);
                        iso9660.seenRockridge = 1;
                    }
                }
            }
            'P' => {
                /*
                 * PD extension is padding;
                 * contents are always ignored.
                 *
                 * PL extension won't appear;
                 * contents are always ignored.
                 */
                if unsafe { *p.offset(1 as isize) } == 'N' as u8 {
                    if version == 1 && data_length == 16 {
                        file.rdev = toi(data as *const (), 4) as uint64_t;
                        file.rdev <<= 32;
                        file.rdev |= toi(unsafe { data.offset(8 as isize) } as *const (), 4) as u64;
                        iso9660.seenRockridge = 1;
                    }
                } else if unsafe { *p.offset(1 as isize) } == 'X' as u8 {
                    /*
                     * PX extension comprises:
                     *   8 bytes for mode,
                     *   8 bytes for nlinks,
                     *   8 bytes for uid,
                     *   8 bytes for gid,
                     *   8 bytes for inode.
                     */
                    if version == 1 {
                        if data_length >= 8 {
                            file.mode = toi(data as *const (), 4)
                        }
                        if data_length >= 16 {
                            file.nlinks =
                                toi(unsafe { data.offset(8 as isize) } as *const (), 4) as i32
                        }
                        if data_length >= 24 {
                            file.uid = toi(unsafe { data.offset(16 as isize) } as *const (), 4)
                        }
                        if data_length >= 32 {
                            file.gid = toi(unsafe { data.offset(24 as isize) } as *const (), 4)
                        }
                        if data_length >= 40 {
                            file.number =
                                toi(unsafe { data.offset(32 as isize) } as *const (), 4) as int64_t
                        }
                        iso9660.seenRockridge = 1;
                    }
                }
            }
            'R' => {
                if unsafe { *p.offset(1 as isize) } == 'E' as u8 && version == 1 {
                    file.re = 1;
                    iso9660.seenRockridge = 1;
                } else {
                    (unsafe { *p.offset(1 as isize) } == 'R' as u8) && version == 1;
                }
            }
            'S' => {
                if unsafe { *p.offset(1 as isize) } == 'L' as u8 {
                    if version == 1 {
                        parse_rockridge_SL1(file, data, data_length);
                        iso9660.seenRockridge = 1;
                    }
                } else if unsafe { *p.offset(1 as isize) } == 'T' as u8
                    && data_length == 0
                    && version == 1
                {
                    /*
                     * ST extension marks end of this
                     * block of SUSP entries.
                     *
                     * It allows SUSP to coexist with
                     * non-SUSP uses of the System
                     * Use Area by placing non-SUSP data
                     * after SUSP data.
                     */
                    iso9660.seenSUSP = 0;
                    iso9660.seenRockridge = 0;
                    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
                }
            }
            'T' => {
                if unsafe { *p.offset(1 as isize) } == 'F' as u8 {
                    if version == 1 {
                        parse_rockridge_TF1(file, data, data_length);
                        iso9660.seenRockridge = 1;
                    }
                }
            }
            'Z' => {
                if unsafe { *p.offset(1 as isize) } == 'F' as u8 {
                    if version == 1 {
                        parse_rockridge_ZF1(file, data, data_length);
                    }
                }
            }
            _ => {}
        }
        unsafe {
            p = p.offset(*p.offset(2 as isize) as isize);
        }
        entry_seen = 1
    }
    if entry_seen != 0 {
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
    } else {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
            b"Tried to parse Rockridge extensions, but none found\x00" as *const u8
        );
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_warn;
    };
}

fn register_CE(mut a: *mut archive_read, mut location: int32_t, mut file: *mut file_info) -> i32 {
    let file = unsafe { &mut *file };
    let mut iso9660: *mut iso9660 = 0 as *mut iso9660;
    let mut p: *mut read_ce_req = 0 as *mut read_ce_req;
    let offset: uint64_t;
    let mut parent_offset: uint64_t = 0;
    let mut hole: i32 = 0;
    let mut parent: i32 = 0;
    iso9660 = unsafe { (*(*a).format).data as *mut iso9660 };
    let safe_iso9660 = unsafe { &mut *iso9660 };
    offset = (location as uint64_t) * (safe_iso9660.logical_block_size as uint64_t);
    if file.mode & ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifmt as mode_t
        == ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifreg as mode_t
        && offset >= file.offset
        || offset < safe_iso9660.current_position
        || (file.ce_offset as uint64_t + file.ce_size as u64)
            > safe_iso9660.logical_block_size as uint64_t
        || offset + file.ce_offset as u64 + file.ce_size as u64 > safe_iso9660.volume_size
    {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
            b"Invalid parameter in SUSP \"CE\" extension\x00" as *const u8
        );
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
    }
    /* Expand our CE list as necessary. */
    let heap = unsafe { &mut (*iso9660).read_ce_req };
    if heap.cnt >= heap.allocated {
        let mut new_size: i32 = 0;
        if heap.allocated < 16 {
            new_size = 16
        } else {
            new_size = heap.allocated * 2
        }
        /* Overflow might keep us from growing the list. */
        if new_size <= heap.allocated {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                b"Out of memory\x00" as *const u8
            );
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
        }
        p = unsafe {
            calloc_safe(new_size as u64, size_of::<read_ce_req>() as u64) as *mut read_ce_req
        };
        if p.is_null() {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                b"Out of memory\x00" as *const u8
            );
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
        }
        if !heap.reqs.is_null() {
            unsafe {
                memcpy_safe(
                    p as *mut (),
                    heap.reqs as *const (),
                    (heap.cnt as u64) * (size_of::<read_ce_req>() as u64),
                );
                free_safe(heap.reqs as *mut ());
            }
        }
        heap.reqs = p;
        heap.allocated = new_size
    }
    /*
     * Start with hole at end, walk it up tree to find insertion point.
     */
    let cnt_old = heap.cnt;
    heap.cnt = heap.cnt + 1;
    hole = cnt_old;
    while hole > 0 {
        parent = (hole - 1) / 2;
        parent_offset = unsafe { (*heap.reqs.offset(parent as isize)).offset };
        if offset >= parent_offset {
            unsafe {
                (*heap.reqs.offset(hole as isize)).offset = offset;
                let ref mut reqs_file = (*heap.reqs.offset(hole as isize)).file;
                *reqs_file = file;
            }
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
        }
        /* Move parent into hole <==> move hole up tree. */
        unsafe { *heap.reqs.offset(hole as isize) = *heap.reqs.offset(parent as isize) };
        hole = parent
    }
    unsafe {
        (*heap.reqs.offset(0 as isize)).offset = offset;
        let ref mut reqs_file = (*heap.reqs.offset(0 as isize)).file;
        *reqs_file = file;
    }
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
}

fn next_CE(mut heap: *mut read_ce_queue) {
    let heap_safe = unsafe { &mut *heap };
    let a_offset: uint64_t;
    let mut b_offset: uint64_t = 0;
    let mut c_offset: uint64_t = 0;
    let mut a: i32 = 0;
    let mut b: i32 = 0;
    let mut c: i32 = 0;
    let mut tmp: read_ce_req = read_ce_req {
        offset: 0,
        file: 0 as *mut file_info,
    };
    if heap_safe.cnt < 1 {
        return;
    }
    /*
     * Move the last item in the heap to the root of the tree
     */
    heap_safe.cnt -= 1;
    unsafe {
        *heap_safe.reqs.offset(0 as isize) = *heap_safe.reqs.offset(heap_safe.cnt as isize);
    }
    /*
     * Rebalance the heap.
     */
    a = 0; /* Starting element and its offset */
    a_offset = unsafe { (*heap_safe.reqs.offset(a as isize)).offset }; /* First child */
    loop {
        b = a + a + 1; /* Use second child if it is smaller. */
        if b >= heap_safe.cnt {
            return;
        }
        b_offset = unsafe { (*heap_safe.reqs.offset(b as isize)).offset };
        c = b + 1;
        if c < heap_safe.cnt {
            c_offset = unsafe { (*heap_safe.reqs.offset(c as isize)).offset };
            if c_offset < b_offset {
                b = c;
                b_offset = c_offset
            }
        }
        if a_offset <= b_offset {
            return;
        }
        unsafe {
            tmp = *heap_safe.reqs.offset(a as isize);
            *heap_safe.reqs.offset(a as isize) = *heap_safe.reqs.offset(b as isize);
            *heap_safe.reqs.offset(b as isize) = tmp;
        }
        a = b
    }
}

fn read_CE(mut a: *mut archive_read, mut iso9660: *mut iso9660) -> i32 {
    let iso9660_safe = unsafe { &mut *iso9660 };
    let mut b: *const u8 = 0 as *const u8;
    let mut p: *const u8 = 0 as *const u8;
    let mut end: *const u8 = 0 as *const u8;
    let mut file = unsafe { &mut *(0 as *mut file_info) };
    let mut step: size_t = 0;
    let mut r: i32 = 0;
    /* Read data which RRIP "CE" extension points. */
    let heap = &mut iso9660_safe.read_ce_req;
    step = iso9660_safe.logical_block_size as size_t;
    while heap.cnt != 0
        && unsafe { (*heap.reqs.offset(0 as isize)).offset } == iso9660_safe.current_position
    {
        b = unsafe { __archive_read_ahead_safe(a, step, 0 as *mut ssize_t) } as *const u8;
        if b.is_null() {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                b"Failed to read full block when scanning ISO9660 directory list\x00" as *const u8
                    as *const u8
            );
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
        }
        loop {
            file = unsafe { &mut *(*heap.reqs.offset(0 as isize)).file };
            if (file.ce_offset + file.ce_size) as u64 > step {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_file_format,
                    b"Malformed CE information\x00" as *const u8
                );
                return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
            }
            unsafe {
                p = b.offset(file.ce_offset as isize);
                end = p.offset(file.ce_size as isize);
            }
            next_CE(heap);
            r = parse_rockridge(a, file, p, end);
            if r != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok {
                return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
            }
            if !(heap.cnt != 0
                && unsafe { (*heap.reqs.offset(0 as isize)).offset }
                    == iso9660_safe.current_position)
            {
                break;
            }
        }
        /* NOTE: Do not move this consume's code to front of
         * do-while loop. Registration of nested CE extension
         * might cause error because of current position. */
        unsafe { __archive_read_consume_safe(a, step as int64_t) };
        iso9660_safe.current_position = iso9660_safe.current_position + step
    }
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
}

fn parse_rockridge_NM1(mut file: *mut file_info, mut data: *const u8, mut data_length: i32) {
    let mut file_safe = unsafe { &mut *file };
    if file_safe.name_continues == 0 {
        file_safe.name.length = 0 as size_t
    }
    file_safe.name_continues = 0;
    if data_length < 1 {
        return;
    }
    /*
     * NM version 1 extension comprises:
     *   1 byte flag, value is one of:
     *     = 0: remainder is name
     *     = 1: remainder is name, next NM entry continues name
     *     = 2: "."
     *     = 4: ".."
     *     = 32: Implementation specific
     *     All other values are reserved.
     */
    match unsafe { *data.offset(0 as isize) } as i32 {
        0 => {
            if data_length < 2 {
                return;
            }
            unsafe {
                archive_strncat_safe(
                    &mut file_safe.name,
                    (data as *const u8).offset(1 as isize) as *const (),
                    (data_length - 1) as size_t,
                )
            };
        }
        1 => {
            if data_length < 2 {
                return;
            }
            unsafe {
                archive_strncat_safe(
                    &mut file_safe.name,
                    (data as *const u8).offset(1 as isize) as *const (),
                    (data_length - 1) as size_t,
                )
            };
            file_safe.name_continues = 1
        }
        2 => {
            unsafe { archive_strcat_safe(&mut file_safe.name, b".\x00" as *const u8 as *const ()) };
        }
        4 => {
            unsafe {
                archive_strcat_safe(&mut file_safe.name, b"..\x00" as *const u8 as *const ())
            };
        }
        _ => return,
    };
}

fn parse_rockridge_TF1(mut file: *mut file_info, mut data: *const u8, mut data_length: i32) {
    let mut file_safe = unsafe { &mut *file };
    let flag: i8;
    /*
     * TF extension comprises:
     *   one byte flag
     *   create time (optional)
     *   modify time (optional)
     *   access time (optional)
     *   attribute time (optional)
     *  Time format and presence of fields
     *  is controlled by flag bits.
     */
    if data_length < 1 {
        return;
    }
    flag = unsafe { *data.offset(0 as isize) } as i8;
    unsafe {
        data = data.offset(1);
    }
    data_length -= 1;
    if flag as i32 & 0x80 != 0 {
        /* Use 17-byte time format. */
        if flag & 1 != 0 && data_length >= 17 {
            /* Create time. */
            file_safe.birthtime_is_set = 1;
            file_safe.birthtime = isodate17(data);
            unsafe {
                data = data.offset(17 as isize);
            }
            data_length -= 17
        }
        if flag & 2 != 0 && data_length >= 17 {
            /* Modify time. */
            file_safe.mtime = isodate17(data);
            unsafe {
                data = data.offset(17 as isize);
            }
            data_length -= 17
        }
        if flag & 4 != 0 && data_length >= 17 {
            /* Access time. */
            file_safe.atime = isodate17(data);
            unsafe {
                data = data.offset(17 as isize);
            }
            data_length -= 17
        }
        if flag & 8 != 0 && data_length >= 17 {
            /* Attribute change time. */
            file_safe.ctime = isodate17(data)
        }
    } else {
        /* Use 7-byte time format. */
        if flag & 1 != 0 && data_length >= 7 {
            /* Create time. */
            file_safe.birthtime_is_set = 1;
            file_safe.birthtime = isodate7(data);
            unsafe {
                data = data.offset(7 as isize);
            }
            data_length -= 7
        }
        if flag & 2 != 0 && data_length >= 7 {
            /* Modify time. */
            file_safe.mtime = isodate7(data);
            unsafe {
                data = data.offset(7 as isize);
            }
            data_length -= 7
        }
        if flag & 4 != 0 && data_length >= 7 {
            /* Access time. */
            file_safe.atime = isodate7(data);
            unsafe {
                data = data.offset(7 as isize);
            }
            data_length -= 7
        }
        if flag & 8 != 0 && data_length >= 7 {
            /* Attribute change time. */
            file_safe.ctime = isodate7(data)
        }
    };
}

fn parse_rockridge_SL1(mut file: *mut file_info, mut data: *const u8, mut data_length: i32) {
    let mut file_safe = unsafe { &mut *file };
    let mut separator: *const u8 = b"\x00" as *const u8;
    if file_safe.symlink_continues == 0 || file_safe.symlink.length < 1 {
        file_safe.symlink.length = 0 as size_t
    }
    file_safe.symlink_continues = 0;
    /*
     * Defined flag values:
     *  0: This is the last SL record for this symbolic link
     *  1: this symbolic link field continues in next SL entry
     *  All other values are reserved.
     */
    if data_length < 1 {
        return;
    } /* Skip flag byte. */
    match unsafe { *data } as i32 {
        0 => {}
        1 => file_safe.symlink_continues = 1,
        _ => return,
    }
    unsafe {
        data = data.offset(1);
    }
    data_length -= 1;
    /*
     * SL extension body stores "components".
     * Basically, this is a complicated way of storing
     * a POSIX path.  It also interferes with using
     * symlinks for storing non-path data. <sigh>
     *
     * Each component is 2 bytes (flag and length)
     * possibly followed by name data.
     */
    while data_length >= 2 {
        let data_old_1 = data;
        unsafe {
            data = data.offset(1);
        }
        let flag: u8 = unsafe { *data_old_1 };
        let data_old_2 = data;
        unsafe {
            data = data.offset(1);
        }
        let nlen: u8 = unsafe { *data_old_2 };
        data_length -= 2;
        unsafe { archive_strcat_safe(&mut file_safe.symlink, separator as *const ()) };
        separator = b"/\x00" as *const u8;
        match flag {
            0 => {
                /* Usual case, this is text. */
                if data_length < nlen as i32 {
                    return;
                }
                unsafe {
                    archive_strncat_safe(
                        &mut file_safe.symlink,
                        data as *const u8 as *const (),
                        nlen as size_t,
                    )
                };
            }
            1 => {
                /* Text continues in next component. */
                if data_length < nlen as i32 {
                    return;
                }
                unsafe {
                    archive_strncat_safe(
                        &mut file_safe.symlink,
                        data as *const u8 as *const (),
                        nlen as size_t,
                    )
                };
                separator = b"\x00" as *const u8
            }
            2 => {
                /* Current dir. */
                unsafe {
                    archive_strcat_safe(&mut file_safe.symlink, b".\x00" as *const u8 as *const ())
                };
            }
            4 => {
                /* Parent dir. */
                unsafe {
                    archive_strcat_safe(&mut file_safe.symlink, b"..\x00" as *const u8 as *const ())
                };
            }
            8 => {
                /* Root of filesystem. */
                unsafe {
                    archive_strcat_safe(&mut file_safe.symlink, b"/\x00" as *const u8 as *const ())
                };
                separator = b"\x00" as *const u8
            }
            16 => {
                /* Undefined (historically "volume root" */
                file_safe.symlink.length = 0 as size_t;
                unsafe {
                    archive_strcat_safe(
                        &mut file_safe.symlink,
                        b"ROOT\x00" as *const u8 as *const (),
                    )
                };
            }
            32 => {
                /* Undefined (historically "hostname") */
                unsafe {
                    archive_strcat_safe(
                        &mut file_safe.symlink,
                        b"hostname\x00" as *const u8 as *const (),
                    )
                };
            }
            _ => {
                /* TODO: issue a warning ? */
                return;
            }
        }
        unsafe {
            data = data.offset(nlen as isize);
        }
        data_length -= nlen as i32
    }
}

fn parse_rockridge_ZF1(mut file: *mut file_info, mut data: *const u8, mut data_length: i32) {
    let mut file_safe = unsafe { &mut *file };
    if unsafe { *data.offset(0 as isize) } as i32 == 0x70
        && unsafe { *data.offset(1 as isize) } as i32 == 0x7a
        && data_length == 12
    {
        /* paged zlib */
        file_safe.pz = 1;
        file_safe.pz_log2_bs = unsafe { *data.offset(3 as isize) } as i32;
        file_safe.pz_uncompressed_size =
            archive_le32dec(unsafe { &*data.offset(4 as isize) } as *const u8 as *const ())
                as uint64_t
    };
}

fn register_file(mut iso9660: *mut iso9660, mut file: *mut file_info) {
    let mut iso9660_safe = unsafe { &mut *iso9660 };
    let mut file_safe = unsafe { &mut *file };
    file_safe.use_next = iso9660_safe.use_files;
    iso9660_safe.use_files = file_safe;
}

fn release_files(mut iso9660: *mut iso9660) {
    let mut iso9660_safe = unsafe { &mut *iso9660 };
    let mut con = 0 as *mut content;
    let mut connext: *mut content = 0 as *mut content;
    let mut file = iso9660_safe.use_files;
    while !file.is_null() {
        let safe_file = unsafe { &mut *file };
        let mut next: *mut file_info = safe_file.use_next;
        unsafe {
            archive_string_free_safe(&mut safe_file.name);
            archive_string_free_safe(&mut safe_file.symlink);
            free_safe(safe_file.utf16be_name as *mut ());
        }
        con = safe_file.contents.first;
        while !con.is_null() {
            connext = unsafe { (*con).next };
            unsafe { free_safe(con as *mut ()) };
            con = connext
        }
        unsafe { free_safe(file as *mut file_info as *mut ()) };
        file = next;
    }
}

fn next_entry_seek(
    mut a: *mut archive_read,
    mut iso9660: *mut iso9660,
    mut pfile: *mut *mut file_info,
) -> i32 {
    let mut iso9660_safe = unsafe { &mut *iso9660 };
    let r: i32;
    r = next_cache_entry(a, iso9660, pfile);
    if r != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok {
        return r;
    }
    let mut file = unsafe { &mut **pfile };
    /* Don't waste time seeking for zero-length bodies. */
    if file.size == 0 {
        file.offset = iso9660_safe.current_position
    }
    /* flush any remaining bytes from the last round to ensure
     * we're positioned */
    if iso9660_safe.entry_bytes_unconsumed != 0 {
        unsafe { __archive_read_consume_safe(a, iso9660_safe.entry_bytes_unconsumed as int64_t) };
        iso9660_safe.entry_bytes_unconsumed = 0 as size_t
    }
    /* Seek forward to the start of the entry. */
    if iso9660_safe.current_position < file.offset {
        let mut step: int64_t = 0;
        step = (file.offset - iso9660_safe.current_position) as int64_t;
        step = unsafe { __archive_read_consume_safe(a, step) };
        if step < 0 {
            return step as i32;
        }
        iso9660_safe.current_position = file.offset
    }
    /* We found body of file; handle it now. */
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
}

fn next_cache_entry(
    mut a: *mut archive_read,
    mut iso9660: *mut iso9660,
    mut pfile: *mut *mut file_info,
) -> i32 {
    let iso9660_safe = unsafe { &mut *iso9660 };
    let pfile_safe = unsafe { &mut *pfile };
    let mut current_block: u64;
    let mut file: *mut file_info = 0 as *mut file_info;
    let mut empty_files: archvie_temporary_empty_files = archvie_temporary_empty_files {
        first: 0 as *mut file_info,
        last: 0 as *mut *mut file_info,
    };
    let mut number: int64_t = 0;
    let mut count: i32 = 0;
    file = cache_get_entry(iso9660_safe);
    if !file.is_null() {
        *pfile_safe = file;
        return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
    }
    's_39: loop
    /*
     * Do not expose this at this time
     * because we have not gotten its full-path
     * name yet.
     */
    {
        let mut re: *mut file_info = 0 as *mut file_info;
        let mut d: *mut file_info = 0 as *mut file_info;
        file = heap_get_entry(&mut iso9660_safe.pending_files);
        *pfile_safe = file;
        if file.is_null() {
            /*
             * If directory entries all which are descendant of
             * rr_moved are still remaining, expose their.
             */
            if !iso9660_safe.re_files.first.is_null()
                && !iso9660_safe.rr_moved.is_null()
                && unsafe { (*iso9660_safe.rr_moved).rr_moved_has_re_only } != 0
            {
                /* Expose "rr_moved" entry. */
                cache_add_entry(iso9660_safe, iso9660_safe.rr_moved);
            }
            loop {
                re = re_get_entry(iso9660_safe);
                if re.is_null() {
                    break;
                }
                loop
                /* Expose its descendant dirs. */
                {
                    d = rede_get_entry(re);
                    if d.is_null() {
                        break;
                    }
                    cache_add_entry(iso9660_safe, d);
                }
            }
            if !iso9660_safe.cache_files.first.is_null() {
                return next_cache_entry(a, iso9660_safe, pfile);
            }
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_eof;
        }
        let mut safe_file = unsafe { &mut *file };
        if safe_file.cl_offset != 0 {
            let mut first_re: *mut file_info = 0 as *mut file_info;
            let mut nexted_re: i32 = 0;
            's_109: loop
            /*
             * Find "RE" dir for the current file, which
             * has "CL" flag.
             */
            {
                re = re_get_entry(iso9660_safe);
                if !(re != first_re) {
                    break;
                }
                if first_re.is_null() {
                    first_re = re
                }
                let safe_re = unsafe { &mut *re };
                if safe_re.offset == safe_file.cl_offset {
                    unsafe {
                        (*safe_re.parent).subdirs -= 1;
                    }
                    safe_re.parent = safe_file.parent;
                    safe_re.re = 0;
                    if unsafe { (*safe_re.parent).re_descendant } != 0 {
                        nexted_re = 1;
                        safe_re.re_descendant = 1;
                        if rede_add_entry(re) < 0 {
                            current_block = 0;
                            break 's_39;
                        }
                        loop
                        /* Move a list of descendants
                         * to a new ancestor. */
                        {
                            d = rede_get_entry(re);
                            if d.is_null() {
                                break 's_109;
                            }
                            if rede_add_entry(d) < 0 {
                                current_block = 0;
                                break 's_39;
                            }
                        }
                    } else {
                        /* Replace the current file
                         * with "RE" dir */
                        file = re;
                        *pfile_safe = file;
                        safe_file = unsafe { &mut *file };
                        loop
                        /* Expose its descendant */
                        {
                            d = rede_get_entry(file);
                            if d.is_null() {
                                break;
                            }
                            cache_add_entry(iso9660_safe, d);
                        }
                        break;
                    }
                } else {
                    re_add_entry(iso9660_safe, re);
                }
            }
            if !(nexted_re != 0) {
                current_block = 1;
                break;
            }
        } else {
            if !(safe_file.mode & ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifmt as mode_t
                == ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifdir as mode_t)
            {
                current_block = 1;
                break;
            }
            let mut r: i32 = 0;
            /* Read file entries in this dir. */
            r = read_children(a, file);
            if r != ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok {
                return r;
            }
            /*
             * Handle a special dir of Rockridge extensions,
             * "rr_moved".
             */
            if safe_file.rr_moved != 0 {
                /*
                 * If this has only the subdirectories which
                 * have "RE" flags, do not expose at this time.
                 */
                if !(safe_file.rr_moved_has_re_only != 0) {
                    current_block = 1;
                    break;
                }
                /* Otherwise expose "rr_moved" entry. */
            } else if safe_file.re != 0 {
                /*
                 * Do not expose this at this time
                 * because we have not gotten its full-path
                 * name yet.
                 */
                re_add_entry(iso9660_safe, file);
            } else {
                if !(safe_file.re_descendant != 0) {
                    current_block = 1;
                    break;
                }
                /*
                 * If the top level "RE" entry of this entry
                 * is not exposed, we, accordingly, should not
                 * expose this entry at this time because
                 * we cannot make its proper full-path name.
                 */
                if !(rede_add_entry(file) == 0) {
                    current_block = 1;
                    break;
                }
                /* Otherwise we can expose this entry because
                 * it seems its top level "RE" has already been
                 * exposed. */
            }
        }
    }
    let mut safe_file = unsafe { &mut *file };
    match current_block {
        0 => {
            archive_set_error_safe!(&mut (*a).archive as *mut archive,
            ARCHIVE_ISO9660_DEFINED_PARAM.archive_errno_misc,
                              b"Failed to connect \'CL\' pointer to \'RE\' rr_moved pointer of Rockridge extensions: current position = %jd, CL offset = %jd\x00"
                                  as *const u8,
                              iso9660_safe.current_position as intmax_t,
                              safe_file.cl_offset as intmax_t);
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
        }
        _ => {
            if safe_file.mode & ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifmt as mode_t
                != ARCHIVE_ISO9660_DEFINED_PARAM.ae_ifreg as mode_t
                || safe_file.number == -1
            {
                return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
            }
            count = 0;
            number = safe_file.number;
            iso9660_safe.cache_files.first = 0 as *mut file_info;
            iso9660_safe.cache_files.last = &mut iso9660_safe.cache_files.first;
            empty_files.first = 0 as *mut file_info;
            empty_files.last = &mut empty_files.first;
            /* Collect files which has the same file serial number.
             * Peek pending_files so that file which number is different
             * is not put back. */
            while iso9660_safe.pending_files.used > 0
                && (unsafe { (**iso9660_safe.pending_files.files.offset(0 as isize)).number }
                    == -1 as i64
                    || unsafe { (**iso9660_safe.pending_files.files.offset(0 as isize)).number }
                        == number)
            {
                if safe_file.number == -1 {
                    /* This file has the same offset
                     * but it's wrong offset which empty files
                     * and symlink files have.
                     * NOTE: This wrong offset was recorded by
                     * old mkisofs utility. If ISO images is
                     * created by latest mkisofs, this does not
                     * happen.
                     */
                    safe_file.next = 0 as *mut file_info;
                    unsafe {
                        *empty_files.last = file;
                    }
                    empty_files.last = &mut safe_file.next
                } else {
                    count += 1;
                    cache_add_entry(iso9660_safe, file);
                }
                file = heap_get_entry(&mut iso9660_safe.pending_files);
                safe_file = unsafe { &mut *file };
            }
            if count == 0 {
                *pfile_safe = file;
                return if file.is_null() {
                    ARCHIVE_ISO9660_DEFINED_PARAM.archive_eof
                } else {
                    ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok
                };
            }
            if safe_file.number == -1 {
                safe_file.next = 0 as *mut file_info;
                unsafe {
                    *empty_files.last = file;
                }
                empty_files.last = &mut safe_file.next
            } else {
                count += 1;
                cache_add_entry(iso9660_safe, file);
            }
            if count > 1 {
                /* The count is the same as number of hardlink,
                 * so much so that each nlinks of files in cache_file
                 * is overwritten by value of the count.
                 */
                file = iso9660_safe.cache_files.first;
                safe_file = unsafe { &mut *file };
                while !file.is_null() {
                    safe_file.nlinks = count;
                    file = safe_file.next;
                    safe_file = unsafe { &mut *file };
                }
            }
            /* If there are empty files, that files are added
             * to the tail of the cache_files. */
            if !empty_files.first.is_null() {
                unsafe {
                    *iso9660_safe.cache_files.last = empty_files.first;
                }
                iso9660_safe.cache_files.last = empty_files.last
            }
            *pfile_safe = cache_get_entry(iso9660_safe);
            return if (*pfile_safe).is_null() {
                ARCHIVE_ISO9660_DEFINED_PARAM.archive_eof
            } else {
                ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok
            };
        }
    };
}

fn re_add_entry(mut iso9660: *mut iso9660, mut file: *mut file_info) {
    let mut iso9660_safe = unsafe { &mut *iso9660 };
    let mut file_safe = unsafe { &mut *file };
    file_safe.re_next = 0 as *mut file_info;
    unsafe {
        *iso9660_safe.re_files.last = file_safe;
    }
    iso9660_safe.re_files.last = &mut file_safe.re_next;
}

fn re_get_entry(mut iso9660: *mut iso9660) -> *mut file_info {
    let mut iso9660_safe = unsafe { &mut *iso9660 };
    let mut file = unsafe { &mut *iso9660_safe.re_files.first };
    if !(file as *mut file_info).is_null() {
        iso9660_safe.re_files.first = file.re_next;
        if iso9660_safe.re_files.first.is_null() {
            iso9660_safe.re_files.last = &mut iso9660_safe.re_files.first
        }
    }
    return file;
}

fn rede_add_entry(mut file: *mut file_info) -> i32 {
    let mut safe_file = unsafe { &mut *file };
    let mut re = safe_file.parent;
    let mut safe_re = unsafe { &mut *re };
    /*
     * Find "RE" entry.
     */
    while !re.is_null() && safe_re.re == 0 {
        re = safe_re.parent;
        safe_re = unsafe { &mut *re };
    }
    if re.is_null() {
        return -1;
    }
    safe_file.re_next = 0 as *mut file_info;
    unsafe {
        *safe_re.rede_files.last = safe_file;
    }
    safe_re.rede_files.last = &mut safe_file.re_next;
    return 0;
}

fn rede_get_entry(mut re: *mut file_info) -> *mut file_info {
    let mut safe_re = unsafe { &mut *re };
    let mut file = unsafe { &mut *safe_re.rede_files.first };
    if !(file as *mut file_info).is_null() {
        safe_re.rede_files.first = file.re_next;
        if safe_re.rede_files.first.is_null() {
            safe_re.rede_files.last = &mut safe_re.rede_files.first
        }
    }
    return file;
}

fn cache_add_entry(mut iso9660: *mut iso9660, mut file: *mut file_info) {
    let mut safe_iso9660 = unsafe { &mut *iso9660 };
    let mut safe_file = unsafe { &mut *file };
    safe_file.next = 0 as *mut file_info;
    unsafe {
        *safe_iso9660.cache_files.last = safe_file;
    }
    safe_iso9660.cache_files.last = &mut safe_file.next;
}

fn cache_get_entry(mut iso9660: *mut iso9660) -> *mut file_info {
    let mut safe_iso9660 = unsafe { &mut *iso9660 };
    let mut safe_file = unsafe { &mut *safe_iso9660.cache_files.first };
    if !(safe_file as *mut file_info).is_null() {
        safe_iso9660.cache_files.first = safe_file.next;
        if safe_iso9660.cache_files.first.is_null() {
            safe_iso9660.cache_files.last = &mut safe_iso9660.cache_files.first
        }
    }
    return safe_file;
}

fn heap_add_entry(
    mut a: *mut archive_read,
    mut heap: *mut heap_queue,
    mut file: *mut file_info,
    mut key: uint64_t,
) -> i32 {
    let mut safe_heap = unsafe { &mut *heap };
    let mut safe_file = unsafe { &mut *file };
    let mut file_key: uint64_t = 0;
    let mut parent_key: uint64_t = 0;
    let mut hole: i32 = 0;
    let mut parent: i32 = 0;
    /* Expand our pending files list as necessary. */
    if safe_heap.used >= safe_heap.allocated {
        let mut new_pending_files: *mut *mut file_info = 0 as *mut *mut file_info;
        let mut new_size: i32 = safe_heap.allocated * 2;
        if safe_heap.allocated < 1024 {
            new_size = 1024
        }
        /* Overflow might keep us from growing the list. */
        if new_size <= safe_heap.allocated {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                b"Out of memory\x00" as *const u8
            );
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
        }
        new_pending_files =
            unsafe { malloc_safe((new_size as u64) * (size_of::<*mut file_info>() as u64)) }
                as *mut *mut file_info;
        if new_pending_files.is_null() {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_ISO9660_DEFINED_PARAM.enomem,
                b"Out of memory\x00" as *const u8
            );
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_fatal;
        }
        if safe_heap.allocated != 0 {
            unsafe {
                memcpy_safe(
                    new_pending_files as *mut (),
                    safe_heap.files as *const (),
                    (safe_heap.allocated as u64) * (size_of::<*mut file_info>() as u64),
                )
            };
        }
        unsafe { free_safe(safe_heap.files as *mut ()) };
        safe_heap.files = new_pending_files;
        safe_heap.allocated = new_size
    }
    safe_file.key = key;
    file_key = safe_file.key;
    /*
     * Start with hole at end, walk it up tree to find insertion point.
     */
    let used_old = safe_heap.used;
    safe_heap.used = safe_heap.used + 1;
    hole = used_old;
    while hole > 0 {
        parent = (hole - 1) / 2;
        parent_key = unsafe { (**safe_heap.files.offset(parent as isize)).key };
        if file_key >= parent_key {
            unsafe {
                let ref mut file_tmp = *safe_heap.files.offset(hole as isize);
                *file_tmp = safe_file;
            }
            return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
        }
        /* Move parent into hole <==> move hole up tree. */
        unsafe {
            let ref mut file_tmp = *safe_heap.files.offset(hole as isize);
            *file_tmp = *safe_heap.files.offset(parent as isize)
        };
        hole = parent
    }
    unsafe {
        let ref mut file_tmp = *safe_heap.files.offset(0 as isize);
        *file_tmp = safe_file;
    }
    return ARCHIVE_ISO9660_DEFINED_PARAM.archive_ok;
}

fn heap_get_entry(mut heap: *mut heap_queue) -> *mut file_info {
    let mut safe_heap = unsafe { &mut *heap };
    let a_key: uint64_t;
    let mut b_key: uint64_t = 0;
    let mut c_key: uint64_t = 0;
    let mut a: i32 = 0;
    let mut b: i32 = 0;
    let mut c: i32 = 0;
    let r: *mut file_info;
    let mut tmp: *mut file_info = 0 as *mut file_info;
    if safe_heap.used < 1 {
        return 0 as *mut file_info;
    }
    /*
     * The first file in the list is the earliest; we'll return this.
     */
    unsafe {
        r = *safe_heap.files.offset(0 as isize);
    }
    /*
     * Move the last item in the heap to the root of the tree
     */
    safe_heap.used -= 1;
    unsafe {
        let ref mut file_tmp = *safe_heap.files.offset(0 as isize);
        *file_tmp = *safe_heap.files.offset(safe_heap.used as isize)
    };
    /*
     * Rebalance the heap.
     */
    a = 0; /* Starting element and its heap key */
    a_key = unsafe { (**safe_heap.files.offset(a as isize)).key }; /* First child */
    loop {
        b = a + a + 1; /* Use second child if it is smaller. */
        if b >= safe_heap.used {
            return r;
        }
        b_key = unsafe { (**safe_heap.files.offset(b as isize)).key };
        c = b + 1;
        if c < safe_heap.used {
            c_key = unsafe { (**safe_heap.files.offset(c as isize)).key };
            if c_key < b_key {
                b = c;
                b_key = c_key
            }
        }
        if a_key <= b_key {
            return r;
        }
        unsafe {
            tmp = *safe_heap.files.offset(a as isize);
            let ref mut file_a = *safe_heap.files.offset(a as isize);
            *file_a = *safe_heap.files.offset(b as isize);
            let ref mut file_b = *safe_heap.files.offset(b as isize);
            *file_b = tmp;
        }
        a = b
    }
}

fn toi(mut p: *const (), mut n: i32) -> u32 {
    let mut v: *const u8 = p as *const u8;
    if n > 1 {
        return (unsafe { *v.offset(0 as isize) } as u32
            + 256 * toi(unsafe { v.offset(1 as isize) } as *const (), n - 1));
    }
    if n == 1 {
        return unsafe { *v.offset(0 as isize) } as u32;
    }
    return 0;
}

fn isodate7(mut v: *const u8) -> time_t {
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
    let mut offset: i32 = 0;
    let mut t: time_t = 0;
    unsafe { memset_safe(&mut tm as *mut tm as *mut (), 0, size_of::<tm>() as u64) };
    tm.tm_year = unsafe { *v.offset(0 as isize) } as i32;
    tm.tm_mon = unsafe { *v.offset(1 as isize) } as i32 - 1;
    tm.tm_mday = unsafe { *v.offset(2 as isize) } as i32;
    tm.tm_hour = unsafe { *v.offset(3 as isize) } as i32;
    tm.tm_min = unsafe { *v.offset(4 as isize) } as i32;
    tm.tm_sec = unsafe { *v.offset(5 as isize) } as i32;
    /* v[6] is the signed timezone offset, in 1/4-hour increments. */
    offset = unsafe { *(v as *const libc::c_schar).offset(6 as isize) } as i32;
    if offset > -(48) && offset < 52 {
        tm.tm_hour -= offset / 4;
        tm.tm_min -= offset % 4 * 15
    }
    t = time_from_tm(&mut tm);
    if t == -1 as time_t {
        return 0 as time_t;
    }
    return t;
}

fn isodate17(mut v: *const u8) -> time_t {
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
    let offset: i32;
    let t: time_t;
    unsafe { memset_safe(&mut tm as *mut tm as *mut (), 0, size_of::<tm>() as u64) };
    tm.tm_year = (unsafe { *v.offset(0 as isize) } - '0' as u8) as i32 * 1000
        + (unsafe { *v.offset(1 as isize) } - '0' as u8) as i32 * 100
        + (unsafe { *v.offset(2 as isize) } - '0' as u8) as i32 * 10
        + (unsafe { *v.offset(3 as isize) } - '0' as u8) as i32
        - 1900;
    tm.tm_mon = (unsafe { *v.offset(4 as isize) } - '0' as u8) as i32 * 10
        + (unsafe { *v.offset(5 as isize) } - '0' as u8) as i32;
    tm.tm_mday = (unsafe { *v.offset(6 as isize) } - '0' as u8) as i32 * 10
        + (unsafe { *v.offset(7 as isize) } - '0' as u8) as i32;
    tm.tm_hour = (unsafe { *v.offset(8 as isize) } - '0' as u8) as i32 * 10
        + (unsafe { *v.offset(9 as isize) } - '0' as u8) as i32;
    tm.tm_min = (unsafe { *v.offset(10 as isize) } - '0' as u8) as i32 * 10
        + (unsafe { *v.offset(11 as isize) } - '0' as u8) as i32;
    tm.tm_sec = (unsafe { *v.offset(12 as isize) } - '0' as u8) as i32 * 10
        + (unsafe { *v.offset(13 as isize) } - '0' as u8) as i32;
    /* v[16] is the signed timezone offset, in 1/4-hour increments. */
    offset = unsafe { *(v as *const libc::c_schar).offset(16 as isize) } as i32;
    if offset > -48 && offset < 52 {
        tm.tm_hour -= offset / 4;
        tm.tm_min -= offset % 4 * 15
    }
    t = time_from_tm(&mut tm);
    if t == -1 as time_t {
        return 0 as time_t;
    }
    return t;
}

fn time_from_tm(mut t: *mut tm) -> time_t {
    let mut safe_t = unsafe { &mut *t };
    /* Use platform timegm() if available. */
    #[cfg(HAVE_TIMEGM)]
    return timegm_safe(safe_t);
    #[cfg_attr(HAVE__MKGMTIME64, cfg(not(HAVE_TIMEGM)))]
    return _mkgmtime_safe(safe_t);
    if unsafe { mktime_safe(safe_t) } == -1 as time_t {
        return -1 as time_t;
    }

    return (safe_t.tm_sec
        + safe_t.tm_min * 60
        + safe_t.tm_hour * 3600
        + safe_t.tm_yday * 86400
        + (safe_t.tm_year - 70) * 31536000
        + (safe_t.tm_year - 69) / 4 * 86400
        - (safe_t.tm_year - 1) / 100 * 86400
        + (safe_t.tm_year + 299) / 400 * 86400) as time_t;
}

fn build_pathname(
    mut as_0: *mut archive_string,
    mut file: *mut file_info,
    mut depth: i32,
) -> *const u8 {
    let safe_as = unsafe { &mut *as_0 };
    let mut safe_file = unsafe { &mut *file };
    // Plain ISO9660 only allows 8 dir levels; if we get
    // to 1000, then something is very, very wrong.
    if depth > 1000 {
        return 0 as *const u8;
    } /* Path is too long! */
    if !(*safe_file).parent.is_null() && unsafe { (*(*safe_file).parent).name.length } > 0 as u64 {
        if build_pathname(safe_as, (*safe_file).parent, depth + 1).is_null() {
            return 0 as *const u8;
        } /* Path is too long! */
        unsafe { archive_strcat_safe(safe_as, b"/\x00" as *const u8 as *const ()) };
    }
    if (*safe_file).name.length == 0 {
        unsafe { archive_strcat_safe(safe_as, b".\x00" as *const u8 as *const ()) };
    } else {
        unsafe { archive_string_concat_safe(as_0, &mut (*safe_file).name) };
    }
    return safe_as.s;
}

fn build_pathname_utf16be(
    mut p: *mut u8,
    mut max: size_t,
    mut len: *mut size_t,
    mut file: *mut file_info,
) -> i32 {
    let mut safe_file = unsafe { &mut *file };
    let mut safe_len = unsafe { &mut *len };
    if !safe_file.parent.is_null() && unsafe { (*safe_file.parent).utf16be_bytes } > 0 {
        if build_pathname_utf16be(p, max, len, safe_file.parent) != 0 {
            return -1;
        }
        unsafe {
            *p.offset(*safe_len as isize) = 0;
            *p.offset((*safe_len + 1) as isize) = '/' as u8;
        }
        *safe_len = *safe_len + 2;
    }
    if safe_file.utf16be_bytes == 0 {
        if *safe_len + 2 > max {
            return -1;
        }
        unsafe {
            *p.offset(*len as isize) = 0;
            *p.offset((*safe_len + 1) as isize) = '.' as u8;
        }
        *safe_len = *safe_len + 2;
    } else {
        if *safe_len + safe_file.utf16be_bytes > max {
            return -1;
        }
        unsafe {
            memcpy_safe(
                p.offset(*len as isize) as *mut (),
                safe_file.utf16be_name as *const (),
                safe_file.utf16be_bytes,
            )
        };
        *safe_len = *safe_len + safe_file.utf16be_bytes;
    }
    return 0;
}

#[no_mangle]
pub fn dump_isodirrec(mut isodirrec: *const u8) {
    match () {
        #[cfg(C_DEBUG)]
        _ => {
            eprintln!(
                " l {},",
                toi(
                    unsafe {
                        isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_length_offset as isize)
                    } as *const (),
                    ARCHIVE_ISO9660_DEFINED_PARAM.dr_length_size
                )
            );
            eprintln!(
                " a {},",
                toi(
                    unsafe {
                        isodirrec.offset(
                            ARCHIVE_ISO9660_DEFINED_PARAM.dr_ext_attr_length_offset as isize,
                        )
                    } as *const (),
                    ARCHIVE_ISO9660_DEFINED_PARAM.dr_ext_attr_length_size
                )
            );
            eprintln!(
                " ext 0x{:X},",
                toi(
                    unsafe {
                        isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_extent_offset as isize)
                    } as *const (),
                    ARCHIVE_ISO9660_DEFINED_PARAM.dr_extent_size
                )
            );
            eprintln!(
                " s {},",
                toi(
                    unsafe {
                        isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_size_offset as isize)
                    } as *const (),
                    ARCHIVE_ISO9660_DEFINED_PARAM.dr_extent_size
                )
            );
            eprintln!(
                " f 0x{:X},\x00",
                toi(
                    unsafe {
                        isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_flags_offset as isize)
                    } as *const (),
                    ARCHIVE_ISO9660_DEFINED_PARAM.dr_flags_size
                )
            );
            eprintln!(
                " u {},",
                toi(
                    unsafe {
                        isodirrec
                            .offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_file_unit_size_offset as isize)
                    } as *const (),
                    ARCHIVE_ISO9660_DEFINED_PARAM.dr_file_unit_size_size
                )
            );
            eprintln!(
                " ilv {},",
                toi(
                    unsafe {
                        isodirrec
                            .offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_interleave_offset as isize)
                    } as *const (),
                    ARCHIVE_ISO9660_DEFINED_PARAM.dr_interleave_size
                )
            );
            eprintln!(
                " seq {},",
                toi(
                    unsafe {
                        isodirrec.offset(
                            ARCHIVE_ISO9660_DEFINED_PARAM.dr_volume_sequence_number_offset as isize,
                        )
                    } as *const (),
                    ARCHIVE_ISO9660_DEFINED_PARAM.dr_volume_sequence_number_size
                )
            );
            eprintln!(
                " nl {}:",
                toi(
                    unsafe {
                        isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_name_len_offset as isize)
                    } as *const (),
                    ARCHIVE_ISO9660_DEFINED_PARAM.dr_name_len_size
                )
            );
            let output_string = std::ffi::CStr::from_ptr(unsafe {
                isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_name_offset as isize)
            } as *const u8)
            .to_string_lossy()
            .into_owned();
            let format_length = toi(
                unsafe {
                    isodirrec.offset(ARCHIVE_ISO9660_DEFINED_PARAM.dr_name_len_offset as isize)
                } as *const (),
                ARCHIVE_ISO9660_DEFINED_PARAM.dr_name_len_size,
            ) as usize;
            let output_length = if format_length < output_string.len() {
                format_length
            } else {
                output_string.len()
            };
            let output_str = &output_string[0..output_length];
            eprintln!(" `{}'", output_str);
        }
        #[cfg(not(C_DEBUG))]
        _ => {}
    }
}

#[no_mangle]
fn archive_test_isNull(mut h: *const u8, mut offset: u32, mut bytes: u32) {
    let mut iso9660: *mut iso9660 = 0 as *mut iso9660;
    iso9660 = unsafe { calloc_safe(1, size_of::<iso9660>() as u64) } as *mut iso9660;
    isNull(iso9660, h, offset, bytes);
}

#[no_mangle]
fn archive_test_isVolumePartition(mut h: *const u8) {
    let mut iso9660: *mut iso9660 = 0 as *mut iso9660;
    iso9660 = unsafe { calloc_safe(1, size_of::<iso9660>() as u64) } as *mut iso9660;
    isVolumePartition(iso9660, h);
}

#[no_mangle]
fn archive_test_isodate17(mut v: *const u8) {
    isodate17(v);
}

#[no_mangle]
fn archive_test_parse_rockridge_SL1(mut data: *const u8, mut data_length: i32) {
    let mut file_info: *mut file_info = 0 as *mut file_info;
    file_info = unsafe { calloc_safe(1, size_of::<file_info>() as u64) } as *mut file_info;
    parse_rockridge_SL1(file_info, data, data_length);
}

#[no_mangle]
fn archive_test_parse_rockridge_TF1(mut data: *const u8, mut data_length: i32) {
    let mut file_info: *mut file_info = 0 as *mut file_info;
    file_info = unsafe { calloc_safe(1, size_of::<file_info>() as u64) } as *mut file_info;
    parse_rockridge_TF1(file_info, data, data_length);
}

#[no_mangle]
fn archive_test_parse_rockridge_NM1(mut data: *const u8, mut data_length: i32) {
    let mut file_info: *mut file_info = 0 as *mut file_info;
    file_info = unsafe { calloc_safe(1, size_of::<file_info>() as u64) } as *mut file_info;
    parse_rockridge_NM1(file_info, data, data_length);
}

#[no_mangle]
fn archive_test_parse_rockridge(mut _a: *mut archive, mut p: *const u8, mut end: *const u8) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut file_info: *mut file_info = 0 as *mut file_info;
    file_info = unsafe { calloc_safe(1, size_of::<file_info>() as u64) } as *mut file_info;
    parse_rockridge(a, file_info, p, end);
}

#[no_mangle]
pub fn archive_test_archive_read_support_format_iso9660() {
    let mut archive_read: *mut archive_read = 0 as *mut archive_read;
    archive_read = unsafe { calloc_safe(1, size_of::<archive_read>() as u64) } as *mut archive_read;
    unsafe {
        (*archive_read).archive.magic = ARCHIVE_AR_DEFINED_PARAM.archive_read_magic;
        (*archive_read).archive.state = ARCHIVE_AR_DEFINED_PARAM.archive_state_new;
        archive_read_support_format_iso9660(&mut (*archive_read).archive as *mut archive)
    };
}

#[no_mangle]
pub fn archive_test_archive_read_format_iso9660_read_data(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut iso9660: *mut iso9660 = 0 as *mut iso9660;
    iso9660 = unsafe { calloc_safe(1, size_of::<iso9660>() as u64) } as *mut iso9660;
    let mut content: *mut content = 0 as *mut content;
    content = unsafe { calloc_safe(1, size_of::<content>() as u64) } as *mut content;
    let mut content2: *mut content = 0 as *mut content;
    content2 = unsafe { calloc_safe(1, size_of::<content>() as u64) } as *mut content;
    let mut content3: *mut content = 0 as *mut content;
    content3 = unsafe { calloc_safe(1, size_of::<content>() as u64) } as *mut content;
    unsafe {
        (*iso9660).entry_bytes_remaining = 0;
        (*iso9660).entry_bytes_unconsumed = 0;
        (*iso9660).entry_content = content as *mut content;
        (*iso9660).current_position = 0;
        (*(*iso9660).entry_content).offset = 2;
        (*content).next = content2 as *mut content;
        (*content2).next = content3 as *mut content;
        (*content2).offset = 1;
        (*(*a).format).data = iso9660 as *mut ();
    }
    let mut size: size_t = 0;
    let mut size2: *mut size_t = &size as *const size_t as *mut size_t;
    let mut offset: int64_t = 0;
    let mut offset2: *mut int64_t = &offset as *const int64_t as *mut int64_t;
    let mut buff: *mut () = 0 as *const () as *mut ();
    let mut buff2: *mut *const () =
        unsafe { &buff as *const *mut () as *mut *mut () as *mut *const () };
    archive_read_format_iso9660_read_data(a, buff2, size2, offset2);
    unsafe {
        (*content2).offset = 0;
        (*content3).offset = 0;
        (*iso9660).current_position = 1;
    }
    archive_read_format_iso9660_read_data(a, buff2, size2, offset2);
}
