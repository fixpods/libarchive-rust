use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

#[no_mangle]
pub extern "C" fn archive_read_support_format_empty(mut _a: *mut archive) -> libc::c_int {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut r: libc::c_int = 0;
    let mut magic_test: libc::c_int = __archive_check_magic_safe(
        _a,
        ARCHIVE_EMPTY_DEFINED_PARAM.archive_read_magic,
        ARCHIVE_EMPTY_DEFINED_PARAM.archive_state_new,
        b"archive_read_support_format_empty\x00" as *const u8 as *const libc::c_char,
    );
    if magic_test == -(30 as libc::c_int) {
        return -(30 as libc::c_int);
    }
    r = __archive_read_register_format_safe(
        a,
        0 as *mut libc::c_void,
        b"empty\x00" as *const u8 as *const libc::c_char,
        Some(
            archive_read_format_empty_bid
                as extern "C" fn(_: *mut archive_read, _: libc::c_int) -> libc::c_int,
        ),
        None,
        Some(
            archive_read_format_empty_read_header
                as extern "C" fn(_: *mut archive_read, _: *mut archive_entry) -> libc::c_int,
        ),
        Some(
            archive_read_format_empty_read_data
                as extern "C" fn(
                    _: *mut archive_read,
                    _: *mut *const libc::c_void,
                    _: *mut size_t,
                    _: *mut int64_t,
                ) -> libc::c_int,
        ),
        None,
        None,
        None,
        None,
        None,
    );
    return r;
}

extern "C" fn archive_read_format_empty_bid(
    mut a: *mut archive_read,
    mut best_bid: libc::c_int,
) -> libc::c_int {
    if best_bid < 1 as libc::c_int
        && __archive_read_ahead_safe(a, 1 as libc::c_int as size_t, 0 as *mut ssize_t)
            == 0 as *mut libc::c_void
    {
        return 1 as libc::c_int;
    }
    return -(1 as libc::c_int);
}

extern "C" fn archive_read_format_empty_read_header(
    mut a: *mut archive_read,
    mut entry: *mut archive_entry,
) -> libc::c_int {
    /* UNUSED */
    let safe_a = unsafe { &mut *a };
    safe_a.archive.archive_format = ARCHIVE_EMPTY_DEFINED_PARAM.archive_format_empty;
    safe_a.archive.archive_format_name = b"Empty file\x00" as *const u8 as *const libc::c_char;
    return ARCHIVE_EMPTY_DEFINED_PARAM.archive_eof;
}

extern "C" fn archive_read_format_empty_read_data(
    mut a: *mut archive_read,
    mut buff: *mut *const libc::c_void,
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) -> libc::c_int {
    /* UNUSED */
    return ARCHIVE_EMPTY_DEFINED_PARAM.archive_eof;
}
