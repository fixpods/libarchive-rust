use archive_core::{
    archive_read_support_format_7zip::*, archive_read_support_format_ar::*,
    archive_read_support_format_cab::*, archive_read_support_format_cpio::*,
    archive_read_support_format_empty::*, archive_read_support_format_iso9660::*,
    archive_read_support_format_lha::*, archive_read_support_format_mtree::*,
    archive_read_support_format_rar::*, archive_read_support_format_rar5::*,
    archive_read_support_format_tar::*, archive_read_support_format_warc::*,
    archive_read_support_format_xar::*, archive_read_support_format_zip::*,
};
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

#[no_mangle]
pub extern "C" fn archive_read_support_format_all(a: *mut archive) -> i32 {
    let magic_test: i32 = unsafe {
        __archive_check_magic_safe(
            a,
            ARCHIVE_ALL_DEFINED_PARAM.archive_read_magic,
            ARCHIVE_ALL_DEFINED_PARAM.archive_state_new,
            b"archive_read_support_format_all\x00" as *const u8,
        )
    };
    if magic_test == -30 {
        return -30;
    }

    unsafe { archive_read_support_format_ar(a) };
    unsafe { archive_read_support_format_cpio(a) };
    unsafe { archive_read_support_format_empty(a) };
    unsafe { archive_read_support_format_lha(a) };
    unsafe { archive_read_support_format_mtree(a) };
    unsafe { archive_read_support_format_tar(a) };
    unsafe { archive_read_support_format_xar(a) };
    unsafe { archive_read_support_format_warc(a) };
    unsafe { archive_read_support_format_7zip(a) };
    unsafe { archive_read_support_format_cab(a) };
    unsafe { archive_read_support_format_rar(a) };
    unsafe { archive_read_support_format_rar5(a) };
    unsafe { archive_read_support_format_iso9660(a) };
    unsafe { archive_read_support_format_zip(a) };
    unsafe { archive_clear_error_safe(a) };
    return 0;
}
