use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

#[no_mangle]
pub unsafe fn archive_read_support_format_empty(mut _a: *mut archive) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut r: i32 = 0;
    let mut magic_test: i32 = __archive_check_magic_safe(
        _a,
        ARCHIVE_EMPTY_DEFINED_PARAM.archive_read_magic,
        ARCHIVE_EMPTY_DEFINED_PARAM.archive_state_new,
        b"archive_read_support_format_empty\x00" as *const u8 as *const i8,
    );
    if magic_test == -(30 as i32) {
        return -(30 as i32);
    }
    r = __archive_read_register_format_safe(
        a,
        0 as *mut (),
        b"empty\x00" as *const u8 as *const i8,
        Some(archive_read_format_empty_bid as unsafe fn(_: *mut archive_read, _: i32) -> i32),
        None,
        Some(
            archive_read_format_empty_read_header
                as unsafe fn(_: *mut archive_read, _: *mut archive_entry) -> i32,
        ),
        Some(
            archive_read_format_empty_read_data
                as unsafe fn(
                    _: *mut archive_read,
                    _: *mut *const (),
                    _: *mut size_t,
                    _: *mut int64_t,
                ) -> i32,
        ),
        None,
        None,
        None,
        None,
        None,
    );
    return r;
}

unsafe fn archive_read_format_empty_bid(mut a: *mut archive_read, mut best_bid: i32) -> i32 {
    if best_bid < 1 as i32
        && __archive_read_ahead_safe(a, 1 as i32 as size_t, 0 as *mut ssize_t) == 0 as *mut ()
    {
        return 1 as i32;
    }
    return -(1 as i32);
}

unsafe fn archive_read_format_empty_read_header(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
) -> i32 {
    /* UNUSED */
    let safe_a = unsafe { &mut *a };
    safe_a.archive.archive_format = ARCHIVE_EMPTY_DEFINED_PARAM.archive_format_empty;
    safe_a.archive.archive_format_name = b"Empty file\x00" as *const u8 as *const i8;
    return ARCHIVE_EMPTY_DEFINED_PARAM.archive_eof;
}

unsafe fn archive_read_format_empty_read_data(
    mut a: *mut archive_read,
    mut buff: *mut *const (),
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) -> i32 {
    /* UNUSED */
    return ARCHIVE_EMPTY_DEFINED_PARAM.archive_eof;
}
