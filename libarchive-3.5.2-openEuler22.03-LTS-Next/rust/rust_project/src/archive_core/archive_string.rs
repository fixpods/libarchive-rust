use rust_ffi::ffi_struct::struct_transfer::* ;
use rust_ffi::ffi_alias::alias_set::*;


#[no_mangle]
pub extern "C" fn  archive_array_append(mut as_0: *mut archive_string,
                                         mut p: *const libc::c_char,
                                         mut s: size_t)
-> *mut archive_string {
    return 0 as *mut archive_string;
}


#[no_mangle]
pub extern "C" fn  archive_string_concat(mut dest: *mut archive_string,
                                          mut src: *mut archive_string) {

}

#[no_mangle]
pub extern "C" fn  archive_wstring_concat(mut dest:
                                               *mut archive_wstring,
                                           mut src:
                                               *mut archive_wstring) {

}

#[no_mangle]
pub extern "C" fn  archive_string_free(mut as_0: *mut archive_string) {

}

#[no_mangle]
pub extern "C" fn  archive_wstring_free(mut as_0:
                                             *mut archive_wstring) {

}

#[no_mangle]
pub unsafe extern "C" fn archive_wstring_ensure(mut as_0:
                                               *mut archive_wstring,
                                           mut s: size_t)
-> *mut archive_wstring {
    return 0 as *mut archive_wstring;
}
/* Returns NULL on any allocation failure. */

#[no_mangle]
pub unsafe extern "C" fn archive_string_ensure(mut as_0: *mut archive_string,
                                          mut s: size_t)
-> *mut archive_string {
    return 0 as *mut archive_string;
}

#[no_mangle]
pub unsafe extern "C" fn archive_strncat(mut as_0: *mut archive_string,
                                    mut _p: *const libc::c_void,
                                    mut n: size_t)
-> *mut archive_string {
    return 0 as *mut archive_string;
}

#[no_mangle]
pub unsafe extern "C" fn archive_wstrncat(mut as_0: *mut archive_wstring,
                                     mut p: *const wchar_t,
                                     mut n: size_t)
-> *mut archive_wstring {
    return 0 as *mut archive_wstring;
}

#[no_mangle]
pub unsafe extern "C" fn archive_strcat(mut as_0: *mut archive_string,
                                   mut p: *const libc::c_void)
-> *mut archive_string {
    return 0 as *mut archive_string;
}

#[no_mangle]
pub unsafe extern "C" fn archive_wstrcat(mut as_0: *mut archive_wstring,
                                    mut p: *const wchar_t)
-> *mut archive_wstring {
    return 0 as *mut archive_wstring;
}

#[no_mangle]
pub unsafe extern "C" fn archive_strappend_char(mut as_0: *mut archive_string,
                                           mut c: libc::c_char)
-> *mut archive_string {
    return 0 as *mut archive_string;
}

#[no_mangle]
pub unsafe extern "C" fn archive_wstrappend_wchar(mut as_0:
                                                 *mut archive_wstring,
                                             mut c: wchar_t)
-> *mut archive_wstring {
    return 0 as *mut archive_wstring;
}

/*
* Convert MBS to WCS.
* Note: returns -1 if conversion fails.
*/

#[no_mangle]
pub unsafe extern "C" fn archive_wstring_append_from_mbs(mut dest:
                                                        *mut archive_wstring,
                                                    mut p:
                                                        *const libc::c_char,
                                                    mut len: size_t)
-> libc::c_int {
    return 0 as libc::c_int;
}
/*
* Translates a wide character string into current locale character set
* and appends to the archive_string.  Note: returns -1 if conversion
* fails.
*/

#[no_mangle]
pub unsafe extern "C" fn archive_string_append_from_wcs(mut as_0:
                                                       *mut archive_string,
                                                   mut w: *const wchar_t,
                                                   mut len: size_t)
-> libc::c_int {
    return 0 as libc::c_int;
}

/*
* Make and Return a string conversion object.
* Return NULL if the platform does not support the specified conversion
* and best_effort is 0.
* If best_effort is set, A string conversion object must be returned
* unless memory allocation for the object fails, but the conversion
* might fail when non-ASCII code is found.
*/
#[no_mangle]
pub unsafe extern "C" fn archive_string_conversion_to_charset(mut a:
                                                             *mut archive,
                                                         mut charset:
                                                             *const libc::c_char,
                                                         mut best_effort:
                                                             libc::c_int)
-> *mut archive_string_conv {
    return 0 as *mut archive_string_conv;
}

#[no_mangle]
pub unsafe extern "C" fn archive_string_conversion_from_charset(mut a:
                                                               *mut archive,
                                                           mut charset:
                                                               *const libc::c_char,
                                                           mut best_effort:
                                                               libc::c_int)
-> *mut archive_string_conv {
    return 0 as *mut archive_string_conv;
}

/*
* archive_string_default_conversion_*_archive() are provided for Windows
* platform because other archiver application use CP_OEMCP for
* MultiByteToWideChar() and WideCharToMultiByte() for the filenames
* in tar or zip files. But mbstowcs/wcstombs(CRT) usually use CP_ACP
* unless you use setlocale(LC_ALL, ".OCP")(specify CP_OEMCP).
* So we should make a string conversion between CP_ACP and CP_OEMCP
* for compatibility.
*/
#[no_mangle]
pub unsafe extern "C" fn archive_string_default_conversion_for_read(mut a:
                                                                   *mut archive)
-> *mut archive_string_conv {
    /* UNUSED */
    return 0 as *mut archive_string_conv;
}

#[no_mangle]
pub unsafe extern "C" fn archive_string_default_conversion_for_write(mut a:
                                                                    *mut archive)
-> *mut archive_string_conv {
    /* UNUSED */
    return 0 as *mut archive_string_conv;
}

/*
* Dispose of all character conversion objects in the archive object.
*/
#[no_mangle]
pub unsafe extern "C" fn archive_string_conversion_free(mut a: *mut archive) {

}

/*
* Return a conversion charset name.
*/
#[no_mangle]
pub unsafe extern "C" fn archive_string_conversion_charset_name(mut sc:
                                                               *mut archive_string_conv)
-> *const libc::c_char {
    return 0 as *const libc::c_char;
}

/*
* Change the behavior of a string conversion.
*/
#[no_mangle]
pub unsafe extern "C" fn archive_string_conversion_set_opt(mut sc:
                                                          *mut archive_string_conv,
                                                      mut opt:
                                                          libc::c_int) {

}


#[no_mangle]
pub unsafe extern "C" fn archive_strncpy_l(mut as_0: *mut archive_string,
                                      mut _p: *const libc::c_void,
                                      mut n: size_t,
                                      mut sc: *mut archive_string_conv)
-> libc::c_int {
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn archive_strncat_l(mut as_0: *mut archive_string,
                                      mut _p: *const libc::c_void,
                                      mut n: size_t,
                                      mut sc: *mut archive_string_conv)
-> libc::c_int {
    return 0 as libc::c_int;
}


#[no_mangle]
pub unsafe extern "C" fn archive_mstring_clean(mut aes:
                                              *mut archive_mstring) {

}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy(mut dest: *mut archive_mstring,
                                         mut src: *mut archive_mstring) {

}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_get_utf8(mut a: *mut archive,
                                             mut aes:
                                                 *mut archive_mstring,
                                             mut p:
                                                 *mut *const libc::c_char)
-> libc::c_int {
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_get_mbs(mut a: *mut archive,
                                            mut aes:
                                                *mut archive_mstring,
                                            mut p:
                                                *mut *const libc::c_char)
-> libc::c_int {
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_get_wcs(mut a: *mut archive,
                                            mut aes:
                                                *mut archive_mstring,
                                            mut wp: *mut *const wchar_t)
-> libc::c_int {
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_get_mbs_l(mut a: *mut archive,
                                              mut aes:
                                                  *mut archive_mstring,
                                              mut p:
                                                  *mut *const libc::c_char,
                                              mut length: *mut size_t,
                                              mut sc:
                                                  *mut archive_string_conv)
-> libc::c_int {
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_mbs(mut aes:
                                                 *mut archive_mstring,
                                             mut mbs:
                                                 *const libc::c_char)
-> libc::c_int {
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_mbs_len(mut aes:
                                                     *mut archive_mstring,
                                                 mut mbs:
                                                     *const libc::c_char,
                                                 mut len: size_t)
-> libc::c_int {
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_wcs(mut aes:
                                                 *mut archive_mstring,
                                             mut wcs: *const wchar_t)
-> libc::c_int {
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_utf8(mut aes:
                                                  *mut archive_mstring,
                                              mut utf8:
                                                  *const libc::c_char)
-> libc::c_int {
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_wcs_len(mut aes:
                                                     *mut archive_mstring,
                                                 mut wcs: *const wchar_t,
                                                 mut len: size_t)
-> libc::c_int {
    return 0 as libc::c_int;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_mbs_len_l(mut aes:
                                                       *mut archive_mstring,
                                                   mut mbs:
                                                       *const libc::c_char,
                                                   mut len: size_t,
                                                   mut sc:
                                                       *mut archive_string_conv)
-> libc::c_int {
    return 0 as libc::c_int;
}

/*
* The 'update' form tries to proactively update all forms of
* this string (WCS and MBS) and returns an error if any of
* them fail.  This is used by the 'pax' handler, for instance,
* to detect and report character-conversion failures early while
* still allowing clients to get potentially useful values from
* the more tolerant lazy conversions.  (get_mbs and get_wcs will
* strive to give the user something useful, so you can get hopefully
* usable values even if some of the character conversions are failing.)
*/
#[no_mangle]
pub unsafe extern "C" fn archive_mstring_update_utf8(mut a: *mut archive,
                                                mut aes:
                                                    *mut archive_mstring,
                                                mut utf8:
                                                    *const libc::c_char)
-> libc::c_int {
    return 0 as libc::c_int;
}