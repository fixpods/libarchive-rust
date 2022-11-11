use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct raw_info {
    pub offset: int64_t,
    pub unconsumed: int64_t,
    pub end_of_file: i32,
}

#[no_mangle]
pub unsafe fn archive_read_support_format_raw(mut _a: *mut archive) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut r: i32 = 0;
    let mut magic_test: i32 = __archive_check_magic_safe(
        _a,
        ARCHIVE_RAW_DEFINED_PARAM.archive_read_magic,
        ARCHIVE_RAW_DEFINED_PARAM.archive_state_new,
        b"archive_read_support_format_raw\x00" as *const u8 as *const i8,
    );
    if magic_test == -(30 as i32) {
        return -(30 as i32);
    }
    let info = unsafe {
        &mut *(calloc_safe(1 as i32 as u64, ::std::mem::size_of::<raw_info>() as u64)
            as *mut raw_info)
    };
    if (info as *mut raw_info).is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAW_DEFINED_PARAM.enomem,
            b"Can\'t allocate raw_info data\x00" as *const u8 as *const i8
        );
        return ARCHIVE_RAW_DEFINED_PARAM.archive_fatal;
    }
    r = __archive_read_register_format_safe(
        a,
        info as *mut raw_info as *mut (),
        b"raw\x00" as *const u8 as *const i8,
        Some(archive_read_format_raw_bid as unsafe fn(_: *mut archive_read, _: i32) -> i32),
        None,
        Some(
            archive_read_format_raw_read_header
                as unsafe fn(_: *mut archive_read, _: *mut archive_entry) -> i32,
        ),
        Some(
            archive_read_format_raw_read_data
                as unsafe fn(
                    _: *mut archive_read,
                    _: *mut *const (),
                    _: *mut size_t,
                    _: *mut int64_t,
                ) -> i32,
        ),
        Some(archive_read_format_raw_read_data_skip as unsafe fn(_: *mut archive_read) -> i32),
        None,
        Some(archive_read_format_raw_cleanup as unsafe fn(_: *mut archive_read) -> i32),
        None,
        None,
    );
    if r != ARCHIVE_RAW_DEFINED_PARAM.archive_ok {
        free_safe(info as *mut raw_info as *mut ());
    }
    return r;
}

unsafe fn archive_read_format_raw_bid(mut a: *mut archive_read, mut best_bid: i32) -> i32 {
    if best_bid < 1 as i32
        && __archive_read_ahead_safe(a, 1 as i32 as size_t, 0 as *mut ssize_t) != 0 as *mut ()
    {
        return 1 as i32;
    }
    return -(1 as i32);
}

unsafe fn archive_read_format_raw_read_header(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
) -> i32 {
    let safe_a = unsafe { &mut *a };
    let info = unsafe { &mut *((*safe_a.format).data as *mut raw_info) };
    if info.end_of_file != 0 {
        return ARCHIVE_RAW_DEFINED_PARAM.archive_eof;
    }
    safe_a.archive.archive_format = ARCHIVE_RAW_DEFINED_PARAM.archive_format_raw;
    safe_a.archive.archive_format_name = b"raw\x00" as *const u8 as *const i8;
    archive_entry_set_pathname_safe(entry, b"data\x00" as *const u8 as *const i8);
    archive_entry_set_filetype_safe(entry, ARCHIVE_RAW_DEFINED_PARAM.ae_ifreg);
    archive_entry_set_perm_safe(entry, 0o644 as i32 as mode_t);
    /* I'm deliberately leaving most fields unset here. */
    /* Let the filter fill out any fields it might have. */
    return __archive_read_header_safe(a, entry);
}

unsafe fn archive_read_format_raw_read_data(
    mut a: *mut archive_read,
    mut buff: *mut *const (),
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) -> i32 {
    let safe_a = unsafe { &mut *a };
    let safe_buff = unsafe { &mut *buff };
    let safe_size = unsafe { &mut *size };
    let safe_offset = unsafe { &mut *offset };
    let mut avail: ssize_t = 0;
    let info = unsafe { &mut *((*safe_a.format).data as *mut raw_info) };
    /* Consume the bytes we read last time. */
    if info.unconsumed != 0 {
        __archive_read_consume_safe(a, info.unconsumed);
        info.unconsumed = 0 as i32 as int64_t
    }
    if info.end_of_file != 0 {
        return ARCHIVE_RAW_DEFINED_PARAM.archive_eof;
    }
    /* Get whatever bytes are immediately available. */
    *safe_buff = __archive_read_ahead_safe(a, 1 as i32 as size_t, &mut avail);
    if avail > 0 as i32 as i64 {
        /* Return the bytes we just read */
        *safe_size = avail as size_t;
        *safe_offset = info.offset;
        info.offset = (info.offset as u64).wrapping_add(*safe_size) as int64_t as int64_t;
        info.unconsumed = avail;
        return ARCHIVE_RAW_DEFINED_PARAM.archive_ok;
    } else if 0 as i32 as i64 == avail {
        /* Record and return end-of-file. */
        info.end_of_file = 1 as i32;
        *safe_size = 0 as i32 as size_t;
        *safe_offset = info.offset;
        return ARCHIVE_RAW_DEFINED_PARAM.archive_eof;
    } else {
        /* Record and return an error. */
        *safe_size = 0 as i32 as size_t;
        *safe_offset = info.offset;
        return avail as i32;
    };
}

unsafe fn archive_read_format_raw_read_data_skip(mut a: *mut archive_read) -> i32 {
    let info = unsafe { &mut *((*(*a).format).data as *mut raw_info) };
    /* Consume the bytes we read last time. */
    if info.unconsumed != 0 {
        __archive_read_consume_safe(a, info.unconsumed);
        info.unconsumed = 0 as i32 as int64_t
    }
    info.end_of_file = 1 as i32;
    return ARCHIVE_RAW_DEFINED_PARAM.archive_ok;
}

unsafe fn archive_read_format_raw_cleanup(mut a: *mut archive_read) -> i32 {
    let safe_a_format = unsafe { &mut *(*a).format };
    let info = unsafe { &mut *((*(*a).format).data as *mut raw_info) };
    free_safe(info as *mut raw_info as *mut ());
    safe_a_format.data = 0 as *mut ();
    return ARCHIVE_RAW_DEFINED_PARAM.archive_ok;
}

#[no_mangle]
pub unsafe fn archive_test_archive_read_format_raw_read_data_skip(mut _a: *mut archive) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut raw_info: *mut raw_info = 0 as *mut raw_info;
    raw_info = unsafe { calloc_safe(1 as i32 as u64, ::std::mem::size_of::<raw_info>() as u64) }
        as *mut raw_info;
    (*(*a).format).data = raw_info as *mut ();
    (*raw_info).unconsumed = 1;
    archive_read_format_raw_read_data_skip(a);
}
