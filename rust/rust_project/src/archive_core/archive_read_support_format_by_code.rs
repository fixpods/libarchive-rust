use archive_core::{
    archive_read_support_format_7zip::*, archive_read_support_format_ar::*,
    archive_read_support_format_cab::*, archive_read_support_format_cpio::*,
    archive_read_support_format_empty::*, archive_read_support_format_iso9660::*,
    archive_read_support_format_lha::*, archive_read_support_format_mtree::*,
    archive_read_support_format_rar::*, archive_read_support_format_rar5::*,
    archive_read_support_format_raw::*, archive_read_support_format_tar::*,
    archive_read_support_format_warc::*, archive_read_support_format_xar::*,
    archive_read_support_format_zip::*,
};
use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

#[no_mangle]
pub extern "C" fn archive_read_support_format_by_code(a: *mut archive, format_code: i32) -> i32 {
    let magic_test: i32 = unsafe {
        __archive_check_magic_safe(
            a,
            ARCHIVE_BY_CODE_DEFINED_PARAM.archive_read_magic,
            ARCHIVE_BY_CODE_DEFINED_PARAM.archive_state_new,
            b"archive_read_support_format_by_code\x00" as *const u8,
        )
    };
    if magic_test == -30 {
        return -30;
    }
    let p: i32 = format_code & ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_base_mask as i32;
    if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_7zip {
        return unsafe { archive_read_support_format_7zip(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_ar {
        return unsafe { archive_read_support_format_ar(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_cab {
        return unsafe { archive_read_support_format_cab(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_cpio {
        return unsafe { archive_read_support_format_cpio(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_empty {
        return unsafe { archive_read_support_format_empty(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_iso9660 {
        return unsafe { archive_read_support_format_iso9660(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_lha {
        return unsafe { archive_read_support_format_lha(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_mtree {
        return unsafe { archive_read_support_format_mtree(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_rar {
        return unsafe { archive_read_support_format_rar(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_rar_v5 {
        return unsafe { archive_read_support_format_rar5(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_raw {
        return unsafe { archive_read_support_format_raw(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_tar {
        return unsafe { archive_read_support_format_tar(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_warc {
        return unsafe { archive_read_support_format_warc(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_xar {
        return unsafe { archive_read_support_format_xar(a) };
    } else if p == ARCHIVE_BY_CODE_DEFINED_PARAM.archive_format_zip {
        return unsafe { archive_read_support_format_zip(a) };
    }
    archive_set_error_safe!(
        a,
        ARCHIVE_BY_CODE_DEFINED_PARAM.archive_errno_programmer,
        b"Invalid format code specified\x00" as *const u8
    );
    return ARCHIVE_BY_CODE_DEFINED_PARAM.archive_fatal;
}
