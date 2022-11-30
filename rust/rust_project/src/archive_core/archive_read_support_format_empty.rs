use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

#[no_mangle]
pub fn archive_read_support_format_empty(_a: *mut archive) -> i32 {
    let a: *mut archive_read = _a as *mut archive_read;
    let r: i32;
    let magic_test: i32 = unsafe {
        __archive_check_magic_safe(
            _a,
            ARCHIVE_EMPTY_DEFINED_PARAM.archive_read_magic,
            ARCHIVE_EMPTY_DEFINED_PARAM.archive_state_new,
            b"archive_read_support_format_empty\x00" as *const u8,
        )
    };
    if magic_test == ARCHIVE_ALL_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_ALL_DEFINED_PARAM.archive_fatal;
    }
    r = unsafe {
        __archive_read_register_format_safe(
            a,
            0 as *mut (),
            b"empty\x00" as *const u8,
            Some(archive_read_format_empty_bid),
            None,
            Some(archive_read_format_empty_read_header),
            Some(archive_read_format_empty_read_data),
            None,
            None,
            None,
            None,
            None,
        )
    };
    return r;
}

fn archive_read_format_empty_bid(a: *mut archive_read, best_bid: i32) -> i32 {
    if best_bid < 1
        && unsafe { __archive_read_ahead_safe(a, 1 as size_t, 0 as *mut ssize_t) == 0 as *mut () }
    {
        return 1;
    }
    return -1;
}

fn archive_read_format_empty_read_header(a: *mut archive_read, entry: *mut archive_entry) -> i32 {
    /* UNUSED */
    let safe_a = unsafe { &mut *a };
    safe_a.archive.archive_format = ARCHIVE_EMPTY_DEFINED_PARAM.archive_format_empty;
    safe_a.archive.archive_format_name = b"Empty file\x00" as *const u8;
    return ARCHIVE_EMPTY_DEFINED_PARAM.archive_eof;
}

fn archive_read_format_empty_read_data(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    /* UNUSED */
    return ARCHIVE_EMPTY_DEFINED_PARAM.archive_eof;
}
