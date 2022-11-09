use archive_core::{
    archive_read_support_format_7zip::*, archive_read_support_format_ar::*,
    archive_read_support_format_cab::*, archive_read_support_format_cpio::*,
    archive_read_support_format_empty::*, archive_read_support_format_iso9660::*,
    archive_read_support_format_lha::*, archive_read_support_format_mtree::*,
    archive_read_support_format_rar::*, archive_read_support_format_rar5::*,
    archive_read_support_format_tar::*, archive_read_support_format_warc::*,
    archive_read_support_format_xar::*, archive_read_support_format_zip::*,
};
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

#[no_mangle]
pub unsafe extern "C" fn archive_read_support_format_all(mut a: *mut archive) -> i32 {
    let mut magic_test: i32 = __archive_check_magic_safe(
        a,
        0xdeb0c5 as u32,
        1 as u32,
        b"archive_read_support_format_all\x00" as *const u8 as *const i8,
    );
    if magic_test == -(30 as i32) {
        return -(30 as i32);
    }

    archive_read_support_format_ar(a);
    archive_read_support_format_cpio(a);
    archive_read_support_format_empty(a);
    archive_read_support_format_lha(a);
    archive_read_support_format_mtree(a);
    archive_read_support_format_tar(a);
    archive_read_support_format_xar(a);
    archive_read_support_format_warc(a);
    archive_read_support_format_7zip(a);
    archive_read_support_format_cab(a);
    archive_read_support_format_rar(a);
    archive_read_support_format_rar5(a);
    archive_read_support_format_iso9660(a);
    archive_read_support_format_zip(a);
    archive_clear_error_safe(a);
    return 0 as i32;
}
