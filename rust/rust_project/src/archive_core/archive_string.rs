use archive_core::archive_endian::*;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

extern "C" {
    fn get_u_composition_table() -> *mut unicode_composition_table;
    fn get_u_decomposable_blocks() -> *mut i8;
    fn get_ccc_val() -> *mut u8;
    fn get_ccc_val_index() -> *mut u8;
    fn get_ccc_index() -> *mut u8;
    fn get_u_decomposition_table() -> *mut unicode_decomposition_table;
}

lazy_static! {
    pub static ref u_composition_table: [unicode_composition_table; 931] = unsafe {
        let mut res: [unicode_composition_table; 931] = [unicode_composition_table {
            cp1: 0x0 as i32 as uint32_t,
            cp2: 0x0 as i32 as uint32_t,
            nfc: 0x0 as i32 as uint32_t,
        }; 931];
        let ptr: *mut unicode_composition_table = get_u_composition_table();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
    pub static ref u_decomposable_blocks: [i8; 467] = unsafe {
        let mut res: [i8; 467] = [0 as i32 as i8; 467];
        let ptr: *mut i8 = get_u_decomposable_blocks();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
    pub static ref ccc_val: [u8; 16 * 115] = unsafe {
        let mut res: [u8; 16 * 115] = [0 as i32 as u8; 16 * 115];
        let ptr: *mut u8 = get_ccc_val();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
    pub static ref ccc_val_index: [u8; 16 * 39] = unsafe {
        let mut res: [u8; 16 * 39] = [0 as i32 as u8; 16 * 39];
        let ptr: *mut u8 = get_ccc_val_index();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
    pub static ref ccc_index: [u8; 467] = unsafe {
        let mut res: [u8; 467] = [0 as i32 as u8; 467];
        let ptr: *mut u8 = get_ccc_index();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
    pub static ref u_decomposition_table: [unicode_decomposition_table; 931] = unsafe {
        let mut res: [unicode_decomposition_table; 931] = [unicode_decomposition_table {
            nfc: 0x0 as i32 as uint32_t,
            cp1: 0x0 as i32 as uint32_t,
            cp2: 0x0 as i32 as uint32_t,
        }; 931];
        let ptr: *mut unicode_decomposition_table = get_u_decomposition_table();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
}

/* Replacement character. */
/* Set U+FFFD(Replacement character) in UTF-8. */
static mut utf8_replacement_char: [i8; 3] = [
    0xef as i32 as i8,
    0xbf as i32 as i8,
    0xbd as i32 as i8,
];
unsafe extern "C" fn archive_string_append(
    mut as_0: *mut archive_string,
    mut p: *const i8,
    mut s: size_t,
) -> *mut archive_string {
    if archive_string_ensure(
        as_0,
        (*as_0)
            .length
            .wrapping_add(s)
            .wrapping_add(1 as i32 as u64),
    )
    .is_null()
    {
        return 0 as *mut archive_string;
    }
    if s != 0 {
        memmove_safe(
            (*as_0).s.offset((*as_0).length as isize) as *mut (),
            p as *const (),
            s,
        );
    }
    (*as_0).length = ((*as_0).length as u64).wrapping_add(s) as size_t as size_t;
    *(*as_0).s.offset((*as_0).length as isize) = 0 as i32 as i8;
    return as_0;
}
unsafe extern "C" fn archive_wstring_append(
    mut as_0: *mut archive_wstring,
    mut p: *const wchar_t,
    mut s: size_t,
) -> *mut archive_wstring {
    if archive_wstring_ensure(
        as_0,
        (*as_0)
            .length
            .wrapping_add(s)
            .wrapping_add(1 as i32 as u64),
    )
    .is_null()
    {
        return 0 as *mut archive_wstring;
    }
    if s != 0 {
        wmemmove((*as_0).s.offset((*as_0).length as isize), p, s);
    }
    (*as_0).length = ((*as_0).length as u64).wrapping_add(s) as size_t as size_t;
    *(*as_0).s.offset((*as_0).length as isize) = 0 as wchar_t;
    return as_0;
}

#[no_mangle]
pub unsafe extern "C" fn archive_array_append(
    mut as_0: *mut archive_string,
    mut p: *const i8,
    mut s: size_t,
) -> *mut archive_string {
    return unsafe { archive_string_append(as_0, p, s) };
}

#[no_mangle]
pub unsafe extern "C" fn archive_string_concat(
    mut dest: *mut archive_string,
    mut src: *mut archive_string,
) {
    let safe_dest = unsafe { &mut *dest };
    let safe_src = unsafe { &mut *src };
    if unsafe { archive_string_append(safe_dest, safe_src.s, safe_src.length).is_null() } {
        unsafe {
            __archive_errx(
                1 as i32,
                b"Out of memory\x00" as *const u8 as *const i8,
            )
        };
    };
}

#[no_mangle]
pub unsafe extern "C" fn archive_wstring_concat(
    mut dest: *mut archive_wstring,
    mut src: *mut archive_wstring,
) {
    let safe_dest = unsafe { &mut *dest };
    let safe_src = unsafe { &mut *src };
    if unsafe { archive_wstring_append(safe_dest, safe_src.s, safe_src.length).is_null() } {
        unsafe {
            __archive_errx(
                1 as i32,
                b"Out of memory\x00" as *const u8 as *const i8,
            )
        };
    };
}

#[no_mangle]
pub unsafe extern "C" fn archive_string_free(mut as_0: *mut archive_string) {
    let safe_as_0 = unsafe { &mut *as_0 };
    (safe_as_0).length = 0 as i32 as size_t;
    (safe_as_0).buffer_length = 0 as i32 as size_t;
    unsafe { free_safe((safe_as_0).s as *mut ()) };
    (safe_as_0).s = 0 as *mut i8;
}

#[no_mangle]
pub unsafe extern "C" fn archive_wstring_free(mut as_0: *mut archive_wstring) {
    let safe_as_0 = unsafe { &mut *as_0 };
    (safe_as_0).length = 0 as i32 as size_t;
    (safe_as_0).buffer_length = 0 as i32 as size_t;
    unsafe { free_safe((safe_as_0).s as *mut ()) };
    (safe_as_0).s = 0 as *mut wchar_t;
}

#[no_mangle]
pub unsafe extern "C" fn archive_wstring_ensure(
    mut as_0: *mut archive_wstring,
    mut s: size_t,
) -> *mut archive_wstring {
    return archive_string_ensure(
        as_0 as *mut archive_string,
        s.wrapping_mul(::std::mem::size_of::<wchar_t>() as u64),
    ) as *mut archive_wstring;
}
/* Returns NULL on any allocation failure. */

#[no_mangle]
pub unsafe extern "C" fn archive_string_ensure(
    mut as_0: *mut archive_string,
    mut s: size_t,
) -> *mut archive_string {
    let safe_as_0 = unsafe { &mut *as_0 };
    let mut p: *mut i8 = 0 as *mut i8;
    let mut new_length: size_t = 0;
    /* If buffer is already big enough, don't reallocate. */
    if !(*as_0).s.is_null() && s <= (*as_0).buffer_length {
        return as_0;
    }
    /*
     * Growing the buffer at least exponentially ensures that
     * append operations are always linear in the number of
     * characters appended.  Using a smaller growth rate for
     * larger buffers reduces memory waste somewhat at the cost of
     * a larger constant factor.
     */
    if (*as_0).buffer_length < 32 as i32 as u64 {
        /* Start with a minimum 32-character buffer. */
        new_length = 32 as i32 as size_t
    } else if (*as_0).buffer_length < 8192 as i32 as u64 {
        /* Buffers under 8k are doubled for speed. */
        new_length = (*as_0).buffer_length.wrapping_add((*as_0).buffer_length)
    } else {
        /* Buffers 8k and over grow by at least 25% each time. */
        new_length = (*as_0).buffer_length.wrapping_add(
            (*as_0)
                .buffer_length
                .wrapping_div(4 as i32 as u64),
        );
        /* Be safe: If size wraps, fail. */
        if new_length < (*as_0).buffer_length {
            /* On failure, wipe the string and return NULL. */
            archive_string_free(as_0); /* Make sure errno has ENOMEM. */
            *__errno_location_safe() = 12 as i32;
            return 0 as *mut archive_string;
        }
    }
    /*
     * The computation above is a lower limit to how much we'll
     * grow the buffer.  In any case, we have to grow it enough to
     * hold the request.
     */
    if new_length < s {
        new_length = s
    }
    /* Now we can reallocate the buffer. */
    p = realloc_safe((*as_0).s as *mut (), new_length) as *mut i8;
    if p.is_null() {
        /* On failure, wipe the string and return NULL. */
        archive_string_free(as_0); /* Make sure errno has ENOMEM. */
        *__errno_location_safe() = 12 as i32;
        return 0 as *mut archive_string;
    }
    (*as_0).s = p;
    (*as_0).buffer_length = new_length;
    return as_0;
}
/*
* TODO: See if there's a way to avoid scanning
* the source string twice.  Then test to see
* if it actually helps (remember that we're almost
* always called with pretty short arguments, so
* such an optimization might not help).
*/

#[no_mangle]
pub unsafe extern "C" fn archive_strncat(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut n: size_t,
) -> *mut archive_string {
    let mut s: size_t = 0;
    let mut p: *const i8 = 0 as *const i8;
    let mut pp: *const i8 = 0 as *const i8;
    p = _p as *const i8;
    /* Like strlen(p), except won't examine positions beyond p[n]. */
    s = 0 as i32 as size_t;
    pp = p;
    while s < n && *pp as i32 != 0 {
        pp = pp.offset(1);
        s = s.wrapping_add(1)
    }
    as_0 = archive_string_append(as_0, p, s);
    if as_0.is_null() {
        __archive_errx(
            1 as i32,
            b"Out of memory\x00" as *const u8 as *const i8,
        );
    }
    return as_0;
}

#[no_mangle]
pub unsafe extern "C" fn archive_wstrncat(
    mut as_0: *mut archive_wstring,
    mut p: *const wchar_t,
    mut n: size_t,
) -> *mut archive_wstring {
    let mut s: size_t = 0;
    let mut pp: *const wchar_t = 0 as *const wchar_t;
    /* Like strlen(p), except won't examine positions beyond p[n]. */
    s = 0 as i32 as size_t;
    pp = p;
    while s < n && *pp != 0 {
        pp = pp.offset(1);
        s = s.wrapping_add(1)
    }
    as_0 = archive_wstring_append(as_0, p, s);
    if as_0.is_null() {
        __archive_errx(
            1 as i32,
            b"Out of memory\x00" as *const u8 as *const i8,
        );
    }
    return as_0;
}

#[no_mangle]
pub unsafe extern "C" fn archive_strcat(
    mut as_0: *mut archive_string,
    mut p: *const (),
) -> *mut archive_string {
    /* strcat is just strncat without an effective limit.
     * Assert that we'll never get called with a source
     * string over 16MB.
     * TODO: Review all uses of strcat in the source
     * and try to replace them with strncat().
     */
    return archive_strncat(as_0, p, 0x1000000 as i32 as size_t);
}

#[no_mangle]
pub unsafe extern "C" fn archive_wstrcat(
    mut as_0: *mut archive_wstring,
    mut p: *const wchar_t,
) -> *mut archive_wstring {
    /* Ditto. */
    return archive_wstrncat(as_0, p, 0x1000000 as i32 as size_t);
}

#[no_mangle]
pub unsafe extern "C" fn archive_strappend_char(
    mut as_0: *mut archive_string,
    mut c: i8,
) -> *mut archive_string {
    as_0 = archive_string_append(as_0, &mut c, 1 as i32 as size_t);
    if as_0.is_null() {
        __archive_errx(
            1 as i32,
            b"Out of memory\x00" as *const u8 as *const i8,
        );
    }
    return as_0;
}

#[no_mangle]
pub unsafe extern "C" fn archive_wstrappend_wchar(
    mut as_0: *mut archive_wstring,
    mut c: wchar_t,
) -> *mut archive_wstring {
    as_0 = archive_wstring_append(as_0, &mut c, 1 as i32 as size_t);
    if as_0.is_null() {
        __archive_errx(
            1 as i32,
            b"Out of memory\x00" as *const u8 as *const i8,
        );
    }
    return as_0;
}
/*
* Get the "current character set" name to use with iconv.
* On FreeBSD, the empty character set name "" chooses
* the correct character encoding for the current locale,
* so this isn't necessary.
* But iconv on Mac OS 10.6 doesn't seem to handle this correctly;
* on that system, we have to explicitly call nl_langinfo()
* to get the right name.  Not sure about other platforms.
*
* NOTE: GNU libiconv does not recognize the character-set name
* which some platform nl_langinfo(CODESET) returns, so we should
* use locale_charset() instead of nl_langinfo(CODESET) for GNU libiconv.
*/
unsafe extern "C" fn default_iconv_charset(
    mut charset: *const i8,
) -> *const i8 {
    if !charset.is_null()
        && *charset.offset(0 as i32 as isize) as i32 != '\u{0}' as i32
    {
        return charset;
    }
    return nl_langinfo_safe(CODESET as i32);
}
/*
* Convert MBS to WCS.
* Note: returns -1 if conversion fails.
*/

#[no_mangle]
pub unsafe extern "C" fn archive_wstring_append_from_mbs(
    mut dest: *mut archive_wstring,
    mut p: *const i8,
    mut len: size_t,
) -> i32 {
    let mut r: size_t = 0;
    let mut ret_val: i32 = 0 as i32;
    /*
     * No single byte will be more than one wide character,
     * so this length estimate will always be big enough.
     */
    // size_t wcs_length = len;
    let mut mbs_length: size_t = len;
    let mut mbs: *const i8 = p;
    let mut wcs: *mut wchar_t = 0 as *mut wchar_t;
    let mut shift_state: mbstate_t = mbstate_t {
        __count: 0,
        __value: archive_string_shift_state { __wch: 0 },
    };
    memset_safe(
        &mut shift_state as *mut mbstate_t as *mut (),
        0 as i32,
        ::std::mem::size_of::<mbstate_t>() as u64,
    );
    /*
     * As we decided to have wcs_length == mbs_length == len
     * we can use len here instead of wcs_length
     */
    if archive_wstring_ensure(
        dest,
        (*dest)
            .length
            .wrapping_add(len)
            .wrapping_add(1 as i32 as u64),
    )
    .is_null()
    {
        return -(1 as i32);
    }
    wcs = (*dest).s.offset((*dest).length as isize);
    /*
     * We cannot use mbsrtowcs/mbstowcs here because those may convert
     * extra MBS when strlen(p) > len and one wide character consists of
     * multi bytes.
     */
    while *mbs as i32 != 0 && mbs_length > 0 as i32 as u64 {
        /*
         * The buffer we allocated is always big enough.
         * Keep this code path in a comment if we decide to choose
         * smaller wcs_length in the future
         */
        /*
           if (wcs_length == 0) {
               dest->length = wcs - dest->s;
               dest->s[dest->length] = L'\0';
               wcs_length = mbs_length;
               if (NULL == archive_wstring_ensure(dest,
                   dest->length + wcs_length + 1))
                   return (-1);
               wcs = dest->s + dest->length;
           }
        */
        r = mbrtowc(wcs, mbs, mbs_length, &mut shift_state);
        if r == -(1 as i32) as size_t || r == -(2 as i32) as size_t {
            ret_val = -(1 as i32);
            break;
        } else {
            if r == 0 as i32 as u64 || r > mbs_length {
                break;
            }
            wcs = wcs.offset(1);
            // wcs_length--;
            mbs = mbs.offset(r as isize);
            mbs_length = (mbs_length as u64).wrapping_sub(r) as size_t as size_t
        }
    }
    (*dest).length = wcs.offset_from((*dest).s) as i64 as size_t;
    *(*dest).s.offset((*dest).length as isize) = '\u{0}' as wchar_t;
    return ret_val;
}
/*
* Translates a wide character string into current locale character set
* and appends to the archive_string.  Note: returns -1 if conversion
* fails.
*/

#[no_mangle]
pub unsafe extern "C" fn archive_string_append_from_wcs(
    mut as_0: *mut archive_string,
    mut w: *const wchar_t,
    mut len: size_t,
) -> i32 {
    /* We cannot use the standard wcstombs() here because it
     * cannot tell us how big the output buffer should be.  So
     * I've built a loop around wcrtomb() or wctomb() that
     * converts a character at a time and resizes the string as
     * needed.  We prefer wcrtomb() when it's available because
     * it's thread-safe. */
    let mut n: i32 = 0;
    let mut ret_val: i32 = 0 as i32;
    let mut p: *mut i8 = 0 as *mut i8;
    let mut end: *mut i8 = 0 as *mut i8;
    let mut shift_state: mbstate_t = mbstate_t {
        __count: 0,
        __value: archive_string_shift_state { __wch: 0 },
    };
    memset_safe(
        &mut shift_state as *mut mbstate_t as *mut (),
        0 as i32,
        ::std::mem::size_of::<mbstate_t>() as u64,
    );
    /*
     * Allocate buffer for MBS.
     * We need this allocation here since it is possible that
     * as->s is still NULL.
     */
    if archive_string_ensure(
        as_0,
        (*as_0)
            .length
            .wrapping_add(len)
            .wrapping_add(1 as i32 as u64),
    )
    .is_null()
    {
        return -(1 as i32);
    }
    p = (*as_0).s.offset((*as_0).length as isize);
    end = (*as_0)
        .s
        .offset((*as_0).buffer_length as isize)
        .offset(-(__ctype_get_mb_cur_max_safe() as isize))
        .offset(-(1 as i32 as isize));
    while *w != '\u{0}' as wchar_t && len > 0 as i32 as u64 {
        if p >= end {
            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
            *(*as_0).s.offset((*as_0).length as isize) = '\u{0}' as i32 as i8;
            /* Re-allocate buffer for MBS. */
            if archive_string_ensure(
                as_0,
                (*as_0)
                    .length
                    .wrapping_add(
                        (if len.wrapping_mul(2 as i32 as u64)
                            > __ctype_get_mb_cur_max_safe()
                        {
                            len.wrapping_mul(2 as i32 as u64)
                        } else {
                            __ctype_get_mb_cur_max_safe()
                        }),
                    )
                    .wrapping_add(1 as i32 as u64),
            )
            .is_null()
            {
                return -(1 as i32);
            }
            p = (*as_0).s.offset((*as_0).length as isize);
            end = (*as_0)
                .s
                .offset((*as_0).buffer_length as isize)
                .offset(-(__ctype_get_mb_cur_max_safe() as isize))
                .offset(-(1 as i32 as isize))
        }
        let fresh0 = w;
        w = w.offset(1);
        n = wcrtomb(p, *fresh0, &mut shift_state) as i32;
        if n == -(1 as i32) {
            if *__errno_location_safe() == 84 as i32 {
                /* Skip an illegal wide char. */
                let fresh1 = p;
                p = p.offset(1);
                *fresh1 = '?' as i32 as i8;
                ret_val = -(1 as i32)
            } else {
                ret_val = -(1 as i32);
                break;
            }
        } else {
            p = p.offset(n as isize)
        }
        len = len.wrapping_sub(1)
    }
    (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
    *(*as_0).s.offset((*as_0).length as isize) = '\u{0}' as i32 as i8;
    return ret_val;
}
/* HAVE_WCTOMB || HAVE_WCRTOMB */
/* HAVE_WCTOMB || HAVE_WCRTOMB */
/*
* Find a string conversion object by a pair of 'from' charset name
* and 'to' charset name from an archive object.
* Return NULL if not found.
*/
unsafe extern "C" fn find_sconv_object(
    mut a: *mut archive,
    mut fc: *const i8,
    mut tc: *const i8,
) -> *mut archive_string_conv {
    let mut sc: *mut archive_string_conv = 0 as *mut archive_string_conv;
    if a.is_null() {
        return 0 as *mut archive_string_conv;
    }
    sc = (*a).sconv;
    while !sc.is_null() {
        if strcmp((*sc).from_charset, fc) == 0 as i32
            && strcmp((*sc).to_charset, tc) == 0 as i32
        {
            break;
        }
        sc = (*sc).next
    }
    return sc;
}
/*
* Register a string object to an archive object.
*/
unsafe extern "C" fn add_sconv_object(mut a: *mut archive, mut sc: *mut archive_string_conv) {
    let mut psc: *mut *mut archive_string_conv = 0 as *mut *mut archive_string_conv;
    /* Add a new sconv to sconv list. */
    psc = &mut (*a).sconv;
    while !(*psc).is_null() {
        psc = &mut (**psc).next
    }
    *psc = sc;
}
unsafe extern "C" fn add_converter(
    mut sc: *mut archive_string_conv,
    mut converter: Option<
        unsafe extern "C" fn(
            _: *mut archive_string,
            _: *const (),
            _: size_t,
            _: *mut archive_string_conv,
        ) -> i32,
    >,
) {
    if sc.is_null() || (*sc).nconverter >= 2 as i32 {
        __archive_errx(
            1 as i32,
            b"Programming error\x00" as *const u8 as *const i8,
        );
    }
    let fresh2 = (*sc).nconverter;
    (*sc).nconverter = (*sc).nconverter + 1;
    (*sc).converter[fresh2 as usize] = converter;
}
unsafe extern "C" fn setup_converter(mut sc: *mut archive_string_conv) {
    /* Reset. */
    (*sc).nconverter = 0 as i32;
    /*
     * Perform special sequence for the incorrect UTF-8 filenames
     * made by libarchive2.x.
     */
    if (*sc).flag & (1 as i32) << 4 as i32 != 0 {
        add_converter(
            sc,
            Some(
                strncat_from_utf8_libarchive2
                    as unsafe extern "C" fn(
                        _: *mut archive_string,
                        _: *const (),
                        _: size_t,
                        _: *mut archive_string_conv,
                    ) -> i32,
            ),
        );
        return;
    }
    /*
     * Convert a string to UTF-16BE/LE.
     */
    if (*sc).flag
        & ((1 as i32) << 10 as i32 | (1 as i32) << 12 as i32)
        != 0
    {
        /*
         * If the current locale is UTF-8, we can translate
         * a UTF-8 string into a UTF-16BE string.
         */
        if (*sc).flag & (1 as i32) << 9 as i32 != 0 {
            add_converter(
                sc,
                Some(
                    archive_string_append_unicode
                        as unsafe extern "C" fn(
                            _: *mut archive_string,
                            _: *const (),
                            _: size_t,
                            _: *mut archive_string_conv,
                        ) -> i32,
                ),
            );
            return;
        }
        if (*sc).cd != -(1 as i32) as iconv_t {
            add_converter(
                sc,
                Some(
                    iconv_strncat_in_locale
                        as unsafe extern "C" fn(
                            _: *mut archive_string,
                            _: *const (),
                            _: size_t,
                            _: *mut archive_string_conv,
                        ) -> i32,
                ),
            );
            return;
        }
        if (*sc).flag & (1 as i32) << 2 as i32 != 0 {
            if (*sc).flag & (1 as i32) << 10 as i32 != 0 {
                add_converter(
                    sc,
                    Some(
                        best_effort_strncat_to_utf16be
                            as unsafe extern "C" fn(
                                _: *mut archive_string,
                                _: *const (),
                                _: size_t,
                                _: *mut archive_string_conv,
                            ) -> i32,
                    ),
                );
            } else {
                add_converter(
                    sc,
                    Some(
                        best_effort_strncat_to_utf16le
                            as unsafe extern "C" fn(
                                _: *mut archive_string,
                                _: *const (),
                                _: size_t,
                                _: *mut archive_string_conv,
                            ) -> i32,
                    ),
                );
            }
        } else {
            /* Make sure we have no converter. */
            (*sc).nconverter = 0 as i32
        }
        return;
    }
    /*
     * Convert a string from UTF-16BE/LE.
     */
    if (*sc).flag
        & ((1 as i32) << 11 as i32 | (1 as i32) << 13 as i32)
        != 0
    {
        /*
         * At least we should normalize a UTF-16BE string.
         */
        if (*sc).flag & (1 as i32) << 7 as i32 != 0 {
            add_converter(
                sc,
                Some(
                    archive_string_normalize_D
                        as unsafe extern "C" fn(
                            _: *mut archive_string,
                            _: *const (),
                            _: size_t,
                            _: *mut archive_string_conv,
                        ) -> i32,
                ),
            );
        } else if (*sc).flag & (1 as i32) << 6 as i32 != 0 {
            add_converter(
                sc,
                Some(
                    archive_string_normalize_C
                        as unsafe extern "C" fn(
                            _: *mut archive_string,
                            _: *const (),
                            _: size_t,
                            _: *mut archive_string_conv,
                        ) -> i32,
                ),
            );
        }
        if (*sc).flag & (1 as i32) << 8 as i32 != 0 {
            /*
             * If the current locale is UTF-8, we can translate
             * a UTF-16BE/LE string into a UTF-8 string directly.
             */
            if (*sc).flag
                & ((1 as i32) << 7 as i32 | (1 as i32) << 6 as i32)
                == 0
            {
                add_converter(
                    sc,
                    Some(
                        archive_string_append_unicode
                            as unsafe extern "C" fn(
                                _: *mut archive_string,
                                _: *const (),
                                _: size_t,
                                _: *mut archive_string_conv,
                            ) -> i32,
                    ),
                );
            }
            return;
        }
        if (*sc).cd != -(1 as i32) as iconv_t {
            add_converter(
                sc,
                Some(
                    iconv_strncat_in_locale
                        as unsafe extern "C" fn(
                            _: *mut archive_string,
                            _: *const (),
                            _: size_t,
                            _: *mut archive_string_conv,
                        ) -> i32,
                ),
            );
            return;
        }
        if (*sc).flag
            & ((1 as i32) << 2 as i32 | (1 as i32) << 11 as i32)
            == (1 as i32) << 2 as i32 | (1 as i32) << 11 as i32
        {
            add_converter(
                sc,
                Some(
                    best_effort_strncat_from_utf16be
                        as unsafe extern "C" fn(
                            _: *mut archive_string,
                            _: *const (),
                            _: size_t,
                            _: *mut archive_string_conv,
                        ) -> i32,
                ),
            );
        } else if (*sc).flag
            & ((1 as i32) << 2 as i32 | (1 as i32) << 13 as i32)
            == (1 as i32) << 2 as i32 | (1 as i32) << 13 as i32
        {
            add_converter(
                sc,
                Some(
                    best_effort_strncat_from_utf16le
                        as unsafe extern "C" fn(
                            _: *mut archive_string,
                            _: *const (),
                            _: size_t,
                            _: *mut archive_string_conv,
                        ) -> i32,
                ),
            );
        } else {
            /* Make sure we have no converter. */
            (*sc).nconverter = 0 as i32
        }
        return;
    }
    if (*sc).flag & (1 as i32) << 9 as i32 != 0 {
        /*
         * At least we should normalize a UTF-8 string.
         */
        if (*sc).flag & (1 as i32) << 7 as i32 != 0 {
            add_converter(
                sc,
                Some(
                    archive_string_normalize_D
                        as unsafe extern "C" fn(
                            _: *mut archive_string,
                            _: *const (),
                            _: size_t,
                            _: *mut archive_string_conv,
                        ) -> i32,
                ),
            );
        } else if (*sc).flag & (1 as i32) << 6 as i32 != 0 {
            add_converter(
                sc,
                Some(
                    archive_string_normalize_C
                        as unsafe extern "C" fn(
                            _: *mut archive_string,
                            _: *const (),
                            _: size_t,
                            _: *mut archive_string_conv,
                        ) -> i32,
                ),
            );
        }
        /*
         * Copy UTF-8 string with a check of CESU-8.
         * Apparently, iconv does not check surrogate pairs in UTF-8
         * when both from-charset and to-charset are UTF-8, and then
         * we use our UTF-8 copy code.
         */
        if (*sc).flag & (1 as i32) << 8 as i32 != 0 {
            /*
             * If the current locale is UTF-8, we can translate
             * a UTF-16BE string into a UTF-8 string directly.
             */
            if (*sc).flag
                & ((1 as i32) << 7 as i32 | (1 as i32) << 6 as i32)
                == 0
            {
                add_converter(
                    sc,
                    Some(
                        strncat_from_utf8_to_utf8
                            as unsafe extern "C" fn(
                                _: *mut archive_string,
                                _: *const (),
                                _: size_t,
                                _: *mut archive_string_conv,
                            ) -> i32,
                    ),
                );
            }
            return;
        }
    }
    if (*sc).cd != -(1 as i32) as iconv_t {
        add_converter(
            sc,
            Some(
                iconv_strncat_in_locale
                    as unsafe extern "C" fn(
                        _: *mut archive_string,
                        _: *const (),
                        _: size_t,
                        _: *mut archive_string_conv,
                    ) -> i32,
            ),
        );
        /*
         * iconv generally does not support UTF-8-MAC and so
         * we have to the output of iconv from NFC to NFD if
         * need.
         */
        if (*sc).flag & (1 as i32) << 1 as i32 != 0
            && (*sc).flag & (1 as i32) << 8 as i32 != 0
        {
            if (*sc).flag & (1 as i32) << 7 as i32 != 0 {
                add_converter(
                    sc,
                    Some(
                        archive_string_normalize_D
                            as unsafe extern "C" fn(
                                _: *mut archive_string,
                                _: *const (),
                                _: size_t,
                                _: *mut archive_string_conv,
                            ) -> i32,
                    ),
                );
            }
        }
        return;
    }
    /*
     * Try conversion in the best effort or no conversion.
     */
    if (*sc).flag & (1 as i32) << 2 as i32 != 0 || (*sc).same != 0 {
        add_converter(
            sc,
            Some(
                best_effort_strncat_in_locale
                    as unsafe extern "C" fn(
                        _: *mut archive_string,
                        _: *const (),
                        _: size_t,
                        _: *mut archive_string_conv,
                    ) -> i32,
            ),
        );
    } else {
        /* Make sure we have no converter. */
        (*sc).nconverter = 0 as i32
    };
}
/*
* Return canonicalized charset-name but this supports just UTF-8, UTF-16BE
* and CP932 which are referenced in create_sconv_object().
*/
unsafe extern "C" fn canonical_charset_name(
    mut charset: *const i8,
) -> *const i8 {
    let mut cs: [i8; 16] = [0; 16];
    let mut p: *mut i8 = 0 as *mut i8;
    let mut s: *const i8 = 0 as *const i8;
    if charset.is_null()
        || *charset.offset(0 as i32 as isize) as i32 == '\u{0}' as i32
        || strlen(charset) > 15 as i32 as u64
    {
        return charset;
    }
    /* Copy name to uppercase. */
    p = cs.as_mut_ptr();
    s = charset;
    while *s != 0 {
        let fresh3 = s;
        s = s.offset(1);
        let mut c: i8 = *fresh3;
        if c as i32 >= 'a' as i32 && c as i32 <= 'z' as i32 {
            c = (c as i32 - ('a' as i32 - 'A' as i32)) as i8
        }
        let fresh4 = p;
        p = p.offset(1);
        *fresh4 = c
    }
    let fresh5 = p;
    p = p.offset(1);
    *fresh5 = '\u{0}' as i32 as i8;
    if strcmp(
        cs.as_mut_ptr(),
        b"UTF-8\x00" as *const u8 as *const i8,
    ) == 0 as i32
        || strcmp(
            cs.as_mut_ptr(),
            b"UTF8\x00" as *const u8 as *const i8,
        ) == 0 as i32
    {
        return b"UTF-8\x00" as *const u8 as *const i8;
    }
    if strcmp(
        cs.as_mut_ptr(),
        b"UTF-16BE\x00" as *const u8 as *const i8,
    ) == 0 as i32
        || strcmp(
            cs.as_mut_ptr(),
            b"UTF16BE\x00" as *const u8 as *const i8,
        ) == 0 as i32
    {
        return b"UTF-16BE\x00" as *const u8 as *const i8;
    }
    if strcmp(
        cs.as_mut_ptr(),
        b"UTF-16LE\x00" as *const u8 as *const i8,
    ) == 0 as i32
        || strcmp(
            cs.as_mut_ptr(),
            b"UTF16LE\x00" as *const u8 as *const i8,
        ) == 0 as i32
    {
        return b"UTF-16LE\x00" as *const u8 as *const i8;
    }
    if strcmp(
        cs.as_mut_ptr(),
        b"CP932\x00" as *const u8 as *const i8,
    ) == 0 as i32
    {
        return b"CP932\x00" as *const u8 as *const i8;
    }
    return charset;
}
/*
* Create a string conversion object.
*/
unsafe extern "C" fn create_sconv_object(
    mut fc: *const i8,
    mut tc: *const i8,
    mut current_codepage: u32,
    mut flag: i32,
) -> *mut archive_string_conv {
    let mut sc: *mut archive_string_conv = 0 as *mut archive_string_conv;
    sc = calloc_safe(
        1 as i32 as u64,
        ::std::mem::size_of::<archive_string_conv>() as u64,
    ) as *mut archive_string_conv;
    if sc.is_null() {
        return 0 as *mut archive_string_conv;
    }
    (*sc).next = 0 as *mut archive_string_conv;
    (*sc).from_charset = strdup_safe(fc);
    if (*sc).from_charset.is_null() {
        free_safe(sc as *mut ());
        return 0 as *mut archive_string_conv;
    }
    (*sc).to_charset = strdup_safe(tc);
    if (*sc).to_charset.is_null() {
        free_safe((*sc).from_charset as *mut ());
        free_safe(sc as *mut ());
        return 0 as *mut archive_string_conv;
    }
    (*sc).utftmp.s = 0 as *mut i8;
    (*sc).utftmp.length = 0 as i32 as size_t;
    (*sc).utftmp.buffer_length = 0 as i32 as size_t;
    if flag & 1 as i32 != 0 {
        /*
         * Convert characters from the current locale charset to
         * a specified charset.
         */
        (*sc).from_cp = current_codepage;
        (*sc).to_cp = make_codepage_from_charset(tc)
    } else if flag & (1 as i32) << 1 as i32 != 0 {
        /*
         * Convert characters from a specified charset to
         * the current locale charset.
         */
        (*sc).to_cp = current_codepage;
        (*sc).from_cp = make_codepage_from_charset(fc)
    }
    /*
     * Check if "from charset" and "to charset" are the same.
     */
    if strcmp(fc, tc) == 0 as i32
        || (*sc).from_cp != -(1 as i32) as u32 && (*sc).from_cp == (*sc).to_cp
    {
        (*sc).same = 1 as i32
    } else {
        (*sc).same = 0 as i32
    }
    /*
     * Mark if "from charset" or "to charset" are UTF-8 or UTF-16BE/LE.
     */
    if strcmp(tc, b"UTF-8\x00" as *const u8 as *const i8) == 0 as i32 {
        flag |= (1 as i32) << 8 as i32
    } else if strcmp(tc, b"UTF-16BE\x00" as *const u8 as *const i8) == 0 as i32 {
        flag |= (1 as i32) << 10 as i32
    } else if strcmp(tc, b"UTF-16LE\x00" as *const u8 as *const i8) == 0 as i32 {
        flag |= (1 as i32) << 12 as i32
    }
    if strcmp(fc, b"UTF-8\x00" as *const u8 as *const i8) == 0 as i32 {
        flag |= (1 as i32) << 9 as i32
    } else if strcmp(fc, b"UTF-16BE\x00" as *const u8 as *const i8) == 0 as i32 {
        flag |= (1 as i32) << 11 as i32
    } else if strcmp(fc, b"UTF-16LE\x00" as *const u8 as *const i8) == 0 as i32 {
        flag |= (1 as i32) << 13 as i32
    }
    /*
     * Set a flag for Unicode NFD. Usually iconv cannot correctly
     * handle it. So we have to translate NFD characters to NFC ones
     * ourselves before iconv handles. Another reason is to prevent
     * that the same sight of two filenames, one is NFC and other
     * is NFD, would be in its directory.
     * On Mac OS X, although its filesystem layer automatically
     * convert filenames to NFD, it would be useful for filename
     * comparing to find out the same filenames that we normalize
     * that to be NFD ourselves.
     */
    if flag & (1 as i32) << 1 as i32 != 0
        && flag
            & ((1 as i32) << 11 as i32
                | (1 as i32) << 13 as i32
                | (1 as i32) << 9 as i32)
            != 0
    {
        flag |= (1 as i32) << 6 as i32
    }
    (*sc).cd_w = -(1 as i32) as iconv_t;
    /*
     * Create an iconv object.
     */
    if flag
        & ((1 as i32) << 8 as i32
            | ((1 as i32) << 10 as i32 | (1 as i32) << 12 as i32))
        != 0
        && flag
            & ((1 as i32) << 9 as i32
                | ((1 as i32) << 11 as i32
                    | (1 as i32) << 13 as i32))
            != 0
        || flag & (1 as i32) << 3 as i32 != 0
    {
        /* This case we won't use iconv. */
        (*sc).cd = -(1 as i32) as iconv_t
    } else {
        (*sc).cd = iconv_open_safe(tc, fc);
        if (*sc).cd == -(1 as i32) as iconv_t
            && (*sc).flag & (1 as i32) << 2 as i32 != 0
        {
            /* _WIN32 && !__CYGWIN__ */
            /*
             * Unfortunately, all of iconv implements do support
             * "CP932" character-set, so we should use "SJIS"
             * instead if iconv_open_safe failed.
             */
            if strcmp(tc, b"CP932\x00" as *const u8 as *const i8) == 0 as i32 {
                (*sc).cd = iconv_open_safe(b"SJIS\x00" as *const u8 as *const i8, fc)
            } else if strcmp(fc, b"CP932\x00" as *const u8 as *const i8)
                == 0 as i32
            {
                (*sc).cd = iconv_open_safe(tc, b"SJIS\x00" as *const u8 as *const i8)
            }
        }
    }
    /* HAVE_ICONV */
    (*sc).flag = flag;
    /*
     * Set up converters.
     */
    setup_converter(sc);
    return sc;
}
/*
* Free a string conversion object.
*/
unsafe extern "C" fn free_sconv_object(mut sc: *mut archive_string_conv) {
    free_safe((*sc).from_charset as *mut ());
    free_safe((*sc).to_charset as *mut ());
    archive_string_free(&mut (*sc).utftmp);
    if (*sc).cd != -(1 as i32) as iconv_t {
        iconv_close_safe((*sc).cd);
    }
    if (*sc).cd_w != -(1 as i32) as iconv_t {
        iconv_close_safe((*sc).cd_w);
    }
    free_safe(sc as *mut ());
}
/*
* POSIX platform does not use CodePage.
*/
unsafe extern "C" fn get_current_codepage() -> u32 {
    return -(1 as i32) as u32;
    /* Unknown */
}
unsafe extern "C" fn make_codepage_from_charset(mut charset: *const i8) -> u32 {
    /* UNUSED */
    return -(1 as i32) as u32;
    /* Unknown */
}
unsafe extern "C" fn get_current_oemcp() -> u32 {
    return -(1 as i32) as u32;
    /* Unknown */
}
/* defined(_WIN32) && !defined(__CYGWIN__) */
/*
* Return a string conversion object.
*/
unsafe extern "C" fn get_sconv_object(
    mut a: *mut archive,
    mut fc: *const i8,
    mut tc: *const i8,
    mut flag: i32,
) -> *mut archive_string_conv {
    let mut sc: *mut archive_string_conv = 0 as *mut archive_string_conv;
    let mut current_codepage: u32 = 0;
    /* Check if we have made the sconv object. */
    sc = find_sconv_object(a, fc, tc);
    if !sc.is_null() {
        return sc;
    }
    if a.is_null() {
        current_codepage = get_current_codepage()
    } else {
        current_codepage = (*a).current_codepage
    }
    sc = create_sconv_object(
        canonical_charset_name(fc),
        canonical_charset_name(tc),
        current_codepage,
        flag,
    );
    if sc.is_null() {
        if !a.is_null() {
            archive_set_error(
                a,
                12 as i32,
                b"Could not allocate memory for a string conversion object\x00" as *const u8
                    as *const i8,
            );
        }
        return 0 as *mut archive_string_conv;
    }
    /*
     * If there is no converter for current string conversion object,
     * we cannot handle this conversion.
     */
    if (*sc).nconverter == 0 as i32 {
        if !a.is_null() {
            archive_set_error(
                a,
                -(1 as i32),
                b"iconv_open_safe failed : Cannot handle ``%s\'\'\x00" as *const u8
                    as *const i8,
                if flag & 1 as i32 != 0 { tc } else { fc },
            );
        }
        /* Failed; free a sconv object. */
        free_sconv_object(sc);
        return 0 as *mut archive_string_conv;
    }
    /*
     * Success!
     */
    if !a.is_null() {
        add_sconv_object(a, sc);
    }
    return sc;
}
unsafe extern "C" fn get_current_charset(mut a: *mut archive) -> *const i8 {
    let mut cur_charset: *const i8 = 0 as *const i8;
    if a.is_null() {
        cur_charset = default_iconv_charset(b"\x00" as *const u8 as *const i8)
    } else {
        cur_charset = default_iconv_charset((*a).current_code);
        if (*a).current_code.is_null() {
            (*a).current_code = strdup_safe(cur_charset);
            (*a).current_codepage = get_current_codepage();
            (*a).current_oemcp = get_current_oemcp()
        }
    }
    return cur_charset;
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
pub unsafe extern "C" fn archive_string_conversion_to_charset(
    mut a: *mut archive,
    mut charset: *const i8,
    mut best_effort: i32,
) -> *mut archive_string_conv {
    let mut flag: i32 = 1 as i32;
    if best_effort != 0 {
        flag |= (1 as i32) << 2 as i32
    }
    return get_sconv_object(a, get_current_charset(a), charset, flag);
}

#[no_mangle]
pub unsafe extern "C" fn archive_string_conversion_from_charset(
    mut a: *mut archive,
    mut charset: *const i8,
    mut best_effort: i32,
) -> *mut archive_string_conv {
    let mut flag: i32 = (1 as i32) << 1 as i32;
    if best_effort != 0 {
        flag |= (1 as i32) << 2 as i32
    }
    return get_sconv_object(a, charset, get_current_charset(a), flag);
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
pub unsafe extern "C" fn archive_string_default_conversion_for_read(
    mut a: *mut archive,
) -> *mut archive_string_conv {
    /* UNUSED */
    return 0 as *mut archive_string_conv;
}

#[no_mangle]
pub unsafe extern "C" fn archive_string_default_conversion_for_write(
    mut a: *mut archive,
) -> *mut archive_string_conv {
    /* UNUSED */
    return 0 as *mut archive_string_conv;
}
/*
* Dispose of all character conversion objects in the archive object.
*/

#[no_mangle]
pub unsafe extern "C" fn archive_string_conversion_free(mut a: *mut archive) {
    let mut sc: *mut archive_string_conv = 0 as *mut archive_string_conv;
    let mut sc_next: *mut archive_string_conv = 0 as *mut archive_string_conv;
    sc = (*a).sconv;
    while !sc.is_null() {
        sc_next = (*sc).next;
        free_sconv_object(sc);
        sc = sc_next
    }
    (*a).sconv = 0 as *mut archive_string_conv;
    free_safe((*a).current_code as *mut ());
    (*a).current_code = 0 as *mut i8;
}
/*
* Return a conversion charset name.
*/

#[no_mangle]
pub unsafe extern "C" fn archive_string_conversion_charset_name(
    mut sc: *mut archive_string_conv,
) -> *const i8 {
    if (*sc).flag & 1 as i32 != 0 {
        return (*sc).to_charset;
    } else {
        return (*sc).from_charset;
    };
}
/*
* Change the behavior of a string conversion.
*/

#[no_mangle]
pub unsafe extern "C" fn archive_string_conversion_set_opt(
    mut sc: *mut archive_string_conv,
    mut opt: i32,
) {
    match opt {
        1 => {}
        2 => {
            if (*sc).flag & (1 as i32) << 6 as i32 == 0 as i32 {
                (*sc).flag |= (1 as i32) << 6 as i32;
                (*sc).flag &= !((1 as i32) << 7 as i32);
                /* Set up string converters. */
                setup_converter(sc);
            }
        }
        4 => {
            /*
             * If iconv will take the string, do not change the
             * setting of the normalization.
             */
            if !((*sc).flag & (1 as i32) << 3 as i32 == 0
                && (*sc).flag
                    & ((1 as i32) << 11 as i32
                        | (1 as i32) << 13 as i32
                        | (1 as i32) << 9 as i32)
                    != 0
                && (*sc).flag
                    & ((1 as i32) << 10 as i32
                        | (1 as i32) << 12 as i32
                        | (1 as i32) << 8 as i32)
                    == 0)
            {
                if (*sc).flag & (1 as i32) << 7 as i32 == 0 as i32 {
                    (*sc).flag |= (1 as i32) << 7 as i32;
                    (*sc).flag &= !((1 as i32) << 6 as i32);
                    /* Set up string converters. */
                    setup_converter(sc);
                }
            }
        }
        _ => {}
    };
}
/*
*
* Copy one archive_string to another in locale conversion.
*
*   archive_strncat_l();
*   archive_strncpy_l();
*
*/
unsafe extern "C" fn mbsnbytes(mut _p: *const (), mut n: size_t) -> size_t {
    let mut s: size_t = 0;
    let mut p: *const i8 = 0 as *const i8;
    let mut pp: *const i8 = 0 as *const i8;
    if _p == 0 as *mut () {
        return 0 as i32 as size_t;
    }
    p = _p as *const i8;
    /* Like strlen(p), except won't examine positions beyond p[n]. */
    s = 0 as i32 as size_t;
    pp = p;
    while s < n && *pp as i32 != 0 {
        pp = pp.offset(1);
        s = s.wrapping_add(1)
    }
    return s;
}
unsafe extern "C" fn utf16nbytes(mut _p: *const (), mut n: size_t) -> size_t {
    let mut s: size_t = 0;
    let mut p: *const i8 = 0 as *const i8;
    let mut pp: *const i8 = 0 as *const i8;
    if _p == 0 as *mut () {
        return 0 as i32 as size_t;
    }
    p = _p as *const i8;
    /* Like strlen(p), except won't examine positions beyond p[n]. */
    s = 0 as i32 as size_t;
    pp = p;
    n >>= 1 as i32;
    while s < n
        && (*pp.offset(0 as i32 as isize) as i32 != 0
            || *pp.offset(1 as i32 as isize) as i32 != 0)
    {
        pp = pp.offset(2 as i32 as isize);
        s = s.wrapping_add(1)
    }
    return s << 1 as i32;
}

#[no_mangle]
pub unsafe extern "C" fn archive_strncpy_l(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut n: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    (*as_0).length = 0 as i32 as size_t;
    return archive_strncat_l(as_0, _p, n, sc);
}

#[no_mangle]
pub unsafe extern "C" fn archive_strncat_l(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut n: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut s: *const () = 0 as *const ();
    let mut length: size_t = 0 as i32 as size_t;
    let mut i: i32 = 0;
    let mut r: i32 = 0 as i32;
    let mut r2: i32 = 0;
    if _p != 0 as *mut () && n > 0 as i32 as u64 {
        if !sc.is_null()
            && (*sc).flag
                & ((1 as i32) << 11 as i32
                    | (1 as i32) << 13 as i32)
                != 0
        {
            length = utf16nbytes(_p, n)
        } else {
            length = mbsnbytes(_p, n)
        }
    }
    /* We must allocate memory even if there is no data for conversion
     * or copy. This simulates archive_string_append behavior. */
    if length == 0 as i32 as u64 {
        let mut tn: i32 = 1 as i32;
        if !sc.is_null()
            && (*sc).flag
                & ((1 as i32) << 10 as i32
                    | (1 as i32) << 12 as i32)
                != 0
        {
            tn = 2 as i32
        }
        if archive_string_ensure(as_0, (*as_0).length.wrapping_add(tn as u64)).is_null() {
            return -(1 as i32);
        }
        *(*as_0).s.offset((*as_0).length as isize) = 0 as i32 as i8;
        if tn == 2 as i32 {
            *(*as_0).s.offset(
                (*as_0)
                    .length
                    .wrapping_add(1 as i32 as u64) as isize,
            ) = 0 as i32 as i8
        }
        return 0 as i32;
    }
    /*
     * If sc is NULL, we just make a copy.
     */
    if sc.is_null() {
        if archive_string_append(as_0, _p as *const i8, length).is_null() {
            return -(1 as i32);
        } /* No memory */
        return 0 as i32;
    }
    s = _p;
    i = 0 as i32;
    if (*sc).nconverter > 1 as i32 {
        (*sc).utftmp.length = 0 as i32 as size_t;
        r2 = (*sc).converter[0 as i32 as usize].expect("non-null function pointer")(
            &mut (*sc).utftmp,
            s,
            length,
            sc,
        );
        if r2 != 0 as i32 && *__errno_location_safe() == 12 as i32 {
            return r2;
        }
        if r > r2 {
            r = r2
        }
        s = (*sc).utftmp.s as *const ();
        length = (*sc).utftmp.length;
        i += 1
    }
    r2 = (*sc).converter[i as usize].expect("non-null function pointer")(as_0, s, length, sc);
    if r > r2 {
        r = r2
    }
    return r;
}
/*
* Return -1 if conversion fails.
*/
unsafe extern "C" fn iconv_strncat_in_locale(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut length: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut itp: *mut i8 = 0 as *mut i8; /* success */
    let mut remaining: size_t = 0; /* Conversion completed. */
    let mut cd: iconv_t = 0 as *mut ();
    let mut outp: *mut i8 = 0 as *mut i8;
    let mut avail: size_t = 0;
    let mut bs: size_t = 0;
    let mut return_value: i32 = 0 as i32;
    let mut to_size: i32 = 0;
    let mut from_size: i32 = 0;
    if (*sc).flag
        & ((1 as i32) << 10 as i32 | (1 as i32) << 12 as i32)
        != 0
    {
        to_size = 2 as i32
    } else {
        to_size = 1 as i32
    }
    if (*sc).flag
        & ((1 as i32) << 11 as i32 | (1 as i32) << 13 as i32)
        != 0
    {
        from_size = 2 as i32
    } else {
        from_size = 1 as i32
    }
    if archive_string_ensure(
        as_0,
        (*as_0)
            .length
            .wrapping_add(length.wrapping_mul(2 as i32 as u64))
            .wrapping_add(to_size as u64),
    )
    .is_null()
    {
        return -(1 as i32);
    }
    cd = (*sc).cd;
    itp = _p as uintptr_t as *mut i8;
    remaining = length;
    outp = (*as_0).s.offset((*as_0).length as isize);
    avail = (*as_0)
        .buffer_length
        .wrapping_sub((*as_0).length)
        .wrapping_sub(to_size as u64);
    while remaining >= from_size as size_t {
        let mut result: size_t = iconv_safe(cd, &mut itp, &mut remaining, &mut outp, &mut avail);
        if result != -(1 as i32) as size_t {
            break;
        }
        if *__errno_location_safe() == 84 as i32
            || *__errno_location_safe() == 22 as i32
        {
            /*
             * If an output charset is UTF-8 or UTF-16BE/LE,
             * unknown character should be U+FFFD
             * (replacement character).
             */
            if (*sc).flag
                & ((1 as i32) << 8 as i32
                    | ((1 as i32) << 10 as i32
                        | (1 as i32) << 12 as i32))
                != 0
            {
                let mut rbytes: size_t = 0;
                if (*sc).flag & (1 as i32) << 8 as i32 != 0 {
                    rbytes = ::std::mem::size_of::<[i8; 3]>() as u64
                } else {
                    rbytes = 2 as i32 as size_t
                }
                if avail < rbytes {
                    (*as_0).length = outp.offset_from((*as_0).s) as i64 as size_t;
                    bs = (*as_0)
                        .buffer_length
                        .wrapping_add(remaining.wrapping_mul(to_size as u64))
                        .wrapping_add(rbytes);
                    if archive_string_ensure(as_0, bs).is_null() {
                        return -(1 as i32);
                    }
                    outp = (*as_0).s.offset((*as_0).length as isize);
                    avail = (*as_0)
                        .buffer_length
                        .wrapping_sub((*as_0).length)
                        .wrapping_sub(to_size as u64)
                }
                if (*sc).flag & (1 as i32) << 8 as i32 != 0 {
                    memcpy_safe(
                        outp as *mut (),
                        utf8_replacement_char.as_ptr() as *const (),
                        ::std::mem::size_of::<[i8; 3]>() as u64,
                    );
                } else if (*sc).flag & (1 as i32) << 10 as i32 != 0 {
                    archive_be16enc(outp as *mut (), 0xfffd as i32 as uint16_t);
                } else {
                    archive_le16enc(outp as *mut (), 0xfffd as i32 as uint16_t);
                }
                outp = outp.offset(rbytes as isize);
                avail = (avail as u64).wrapping_sub(rbytes) as size_t as size_t
            } else {
                /* Skip the illegal input bytes. */
                let fresh6 = outp;
                outp = outp.offset(1);
                *fresh6 = '?' as i32 as i8;
                avail = avail.wrapping_sub(1)
            }
            itp = itp.offset(from_size as isize);
            remaining = (remaining as u64).wrapping_sub(from_size as u64)
                as size_t as size_t;
            return_value = -(1 as i32)
            /* failure */
        } else {
            /* E2BIG no output buffer,
             * Increase an output buffer.  */
            (*as_0).length = outp.offset_from((*as_0).s) as i64 as size_t;
            bs = (*as_0)
                .buffer_length
                .wrapping_add(remaining.wrapping_mul(2 as i32 as u64));
            if archive_string_ensure(as_0, bs).is_null() {
                return -(1 as i32);
            }
            outp = (*as_0).s.offset((*as_0).length as isize);
            avail = (*as_0)
                .buffer_length
                .wrapping_sub((*as_0).length)
                .wrapping_sub(to_size as u64)
        }
    }
    (*as_0).length = outp.offset_from((*as_0).s) as i64 as size_t;
    *(*as_0).s.offset((*as_0).length as isize) = 0 as i32 as i8;
    if to_size == 2 as i32 {
        *(*as_0).s.offset(
            (*as_0)
                .length
                .wrapping_add(1 as i32 as u64) as isize,
        ) = 0 as i32 as i8
    }
    return return_value;
}
/* HAVE_ICONV */
/*
* Test whether MBS ==> WCS is okay.
*/
unsafe extern "C" fn invalid_mbs(
    mut _p: *const (),
    mut n: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut p: *const i8 = _p as *const i8; /* Invalid. */
    let mut r: size_t = 0;
    let mut shift_state: mbstate_t = mbstate_t {
        __count: 0,
        __value: archive_string_shift_state { __wch: 0 },
    };
    memset_safe(
        &mut shift_state as *mut mbstate_t as *mut (),
        0 as i32,
        ::std::mem::size_of::<mbstate_t>() as u64,
    );
    while n != 0 {
        let mut wc: wchar_t = 0;
        r = mbrtowc(&mut wc, p, n, &mut shift_state);
        if r == -(1 as i32) as size_t || r == -(2 as i32) as size_t {
            return -(1 as i32);
        }
        if r == 0 as i32 as u64 {
            break;
        }
        p = p.offset(r as isize);
        n = (n as u64).wrapping_sub(r) as size_t as size_t
    }
    /* UNUSED */
    return 0 as i32;
    /* All Okey. */
}
/* defined(_WIN32) && !defined(__CYGWIN__) */
/*
* Basically returns -1 because we cannot make a conversion of charset
* without iconv but in some cases this would return 0.
* Returns 0 if all copied characters are ASCII.
* Returns 0 if both from-locale and to-locale are the same and those
* can be WCS with no error.
*/
unsafe extern "C" fn best_effort_strncat_in_locale(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut length: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut remaining: size_t = 0; /* success */
    let mut itp: *const uint8_t = 0 as *const uint8_t;
    let mut return_value: i32 = 0 as i32;
    /*
     * If both from-locale and to-locale is the same, this makes a copy.
     * And then this checks all copied MBS can be WCS if so returns 0.
     */
    if (*sc).same != 0 {
        if archive_string_append(as_0, _p as *const i8, length).is_null() {
            return -(1 as i32);
        } /* No memory */
        return invalid_mbs(_p, length, sc);
    }
    /*
     * If a character is ASCII, this just copies it. If not, this
     * assigns '?' character instead but in UTF-8 locale this assigns
     * byte sequence 0xEF 0xBD 0xBD, which are code point U+FFFD,
     * a Replacement Character in Unicode.
     */
    remaining = length;
    itp = _p as *const uint8_t;
    while *itp as i32 != 0 && remaining > 0 as i32 as u64 {
        if *itp as i32 > 127 as i32 {
            // Non-ASCII: Substitute with suitable replacement
            if (*sc).flag & (1 as i32) << 8 as i32 != 0 {
                if archive_string_append(
                    as_0,
                    utf8_replacement_char.as_ptr(),
                    ::std::mem::size_of::<[i8; 3]>() as u64,
                )
                .is_null()
                {
                    __archive_errx(
                        1 as i32,
                        b"Out of memory\x00" as *const u8 as *const i8,
                    );
                }
            } else {
                archive_strappend_char(as_0, '?' as i32 as i8);
            }
            return_value = -(1 as i32)
        } else {
            archive_strappend_char(as_0, *itp as i8);
        }
        itp = itp.offset(1)
    }
    return return_value;
}
/*
* Unicode conversion functions.
*   - UTF-8 <===> UTF-8 in removing surrogate pairs.
*   - UTF-8 NFD ===> UTF-8 NFC in removing surrogate pairs.
*   - UTF-8 made by libarchive 2.x ===> UTF-8.
*   - UTF-16BE <===> UTF-8.
*
*/
/*
* Utility to convert a single UTF-8 sequence.
*
* Usually return used bytes, return used byte in negative value when
* a unicode character is replaced with U+FFFD.
* See also http://unicode.org/review/pr-121.html Public Review Issue #121
* Recommended Practice for Replacement Characters.
*/
unsafe extern "C" fn _utf8_to_unicode(
    mut pwc: *mut uint32_t,
    mut s: *const i8,
    mut n: size_t,
) -> i32 {
    let mut current_block: u64;
    static mut utf8_count: [i8; 256] = [
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        1 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        2 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        3 as i32 as i8,
        4 as i32 as i8,
        4 as i32 as i8,
        4 as i32 as i8,
        4 as i32 as i8,
        4 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
        0 as i32 as i8,
    ];
    let mut ch: i32 = 0;
    let mut i: i32 = 0;
    let mut cnt: i32 = 0;
    let mut wc: uint32_t = 0;
    /* Sanity check. */
    if n == 0 as i32 as u64 {
        return 0 as i32;
    }
    /*
     * Decode 1-4 bytes depending on the value of the first byte.
     */
    ch = *s as u8 as i32; /* Standard:  return 0 for end-of-string. */
    if ch == 0 as i32 {
        return 0 as i32;
    }
    cnt = utf8_count[ch as usize] as i32;
    /* Invalid sequence or there are not plenty bytes. */
    if (n as i32) < cnt {
        cnt = n as i32;
        i = 1 as i32;
        while i < cnt {
            if *s.offset(i as isize) as i32 & 0xc0 as i32 != 0x80 as i32 {
                cnt = i;
                break;
            } else {
                i += 1
            }
        }
    } else {
        /* Make a Unicode code point from a single UTF-8 sequence. */
        match cnt {
            1 => {
                /* 1 byte sequence. */
                *pwc = (ch & 0x7f as i32) as uint32_t;
                return cnt;
            }
            2 => {
                /* 2 bytes sequence. */
                if *s.offset(1 as i32 as isize) as i32 & 0xc0 as i32
                    != 0x80 as i32
                {
                    cnt = 1 as i32
                } else {
                    *pwc = ((ch & 0x1f as i32) << 6 as i32
                        | *s.offset(1 as i32 as isize) as i32 & 0x3f as i32)
                        as uint32_t;
                    return cnt;
                }
                current_block = 10888481095818132869;
            }
            3 => {
                /* 3 bytes sequence. */
                if *s.offset(1 as i32 as isize) as i32 & 0xc0 as i32
                    != 0x80 as i32
                {
                    cnt = 1 as i32; /* Overlong sequence. */
                    current_block = 10888481095818132869;
                } else if *s.offset(2 as i32 as isize) as i32 & 0xc0 as i32
                    != 0x80 as i32
                {
                    cnt = 2 as i32;
                    current_block = 10888481095818132869;
                } else {
                    wc = ((ch & 0xf as i32) << 12 as i32
                        | (*s.offset(1 as i32 as isize) as i32
                            & 0x3f as i32)
                            << 6 as i32
                        | *s.offset(2 as i32 as isize) as i32 & 0x3f as i32)
                        as uint32_t;
                    if wc < 0x800 as i32 as u32 {
                        current_block = 10888481095818132869;
                    } else {
                        current_block = 2520131295878969859;
                    }
                }
            }
            4 => {
                /* 4 bytes sequence. */
                if *s.offset(1 as i32 as isize) as i32 & 0xc0 as i32
                    != 0x80 as i32
                {
                    cnt = 1 as i32; /* Overlong sequence. */
                    current_block = 10888481095818132869;
                } else if *s.offset(2 as i32 as isize) as i32 & 0xc0 as i32
                    != 0x80 as i32
                {
                    cnt = 2 as i32;
                    current_block = 10888481095818132869;
                } else if *s.offset(3 as i32 as isize) as i32 & 0xc0 as i32
                    != 0x80 as i32
                {
                    cnt = 3 as i32;
                    current_block = 10888481095818132869;
                } else {
                    wc = ((ch & 0x7 as i32) << 18 as i32
                        | (*s.offset(1 as i32 as isize) as i32
                            & 0x3f as i32)
                            << 12 as i32
                        | (*s.offset(2 as i32 as isize) as i32
                            & 0x3f as i32)
                            << 6 as i32
                        | *s.offset(3 as i32 as isize) as i32 & 0x3f as i32)
                        as uint32_t;
                    if wc < 0x10000 as i32 as u32 {
                        current_block = 10888481095818132869;
                    } else {
                        current_block = 2520131295878969859;
                    }
                }
            }
            _ => {
                /* Others are all invalid sequence. */
                if ch == 0xc0 as i32 || ch == 0xc1 as i32 {
                    cnt = 2 as i32
                } else if ch >= 0xf5 as i32 && ch <= 0xf7 as i32 {
                    cnt = 4 as i32
                } else if ch >= 0xf8 as i32 && ch <= 0xfb as i32 {
                    cnt = 5 as i32
                } else if ch == 0xfc as i32 || ch == 0xfd as i32 {
                    cnt = 6 as i32
                } else {
                    cnt = 1 as i32
                }
                if (n as i32) < cnt {
                    cnt = n as i32
                }
                i = 1 as i32;
                while i < cnt {
                    if *s.offset(i as isize) as i32 & 0xc0 as i32
                        != 0x80 as i32
                    {
                        cnt = i;
                        break;
                    } else {
                        i += 1
                    }
                }
                current_block = 10888481095818132869;
            }
        }
        match current_block {
            10888481095818132869 => {}
            _ =>
            /* The code point larger than 0x10FFFF is not legal
             * Unicode values. */
            {
                if !(wc > 0x10ffff as i32 as u32) {
                    /* Correctly gets a Unicode, returns used bytes. */
                    *pwc = wc; /* set the Replacement Character instead. */
                    return cnt;
                }
            }
        }
    }
    *pwc = 0xfffd as i32 as uint32_t;
    return cnt * -(1 as i32);
}
unsafe extern "C" fn utf8_to_unicode(
    mut pwc: *mut uint32_t,
    mut s: *const i8,
    mut n: size_t,
) -> i32 {
    let mut cnt: i32 = 0;
    cnt = _utf8_to_unicode(pwc, s, n);
    /* Any of Surrogate pair is not legal Unicode values. */
    if cnt == 3 as i32
        && (*pwc >= 0xd800 as i32 as u32
            && *pwc <= 0xdfff as i32 as u32)
    {
        return -(3 as i32);
    }
    return cnt;
}
#[inline]
unsafe extern "C" fn combine_surrogate_pair(mut uc: uint32_t, mut uc2: uint32_t) -> uint32_t {
    uc = (uc as u32).wrapping_sub(0xd800 as i32 as u32) as uint32_t
        as uint32_t;
    uc = (uc as u32).wrapping_mul(0x400 as i32 as u32) as uint32_t
        as uint32_t;
    uc = (uc as u32).wrapping_add(uc2.wrapping_sub(0xdc00 as i32 as u32))
        as uint32_t as uint32_t;
    uc = (uc as u32).wrapping_add(0x10000 as i32 as u32) as uint32_t
        as uint32_t;
    return uc;
}
/*
* Convert a single UTF-8/CESU-8 sequence to a Unicode code point in
* removing surrogate pairs.
*
* CESU-8: The Compatibility Encoding Scheme for UTF-16.
*
* Usually return used bytes, return used byte in negative value when
* a unicode character is replaced with U+FFFD.
*/
unsafe extern "C" fn cesu8_to_unicode(
    mut pwc: *mut uint32_t,
    mut s: *const i8,
    mut n: size_t,
) -> i32 {
    let mut current_block: u64;
    let mut wc: uint32_t = 0 as i32 as uint32_t;
    let mut cnt: i32 = 0;
    cnt = _utf8_to_unicode(&mut wc, s, n);
    if cnt == 3 as i32
        && (wc >= 0xd800 as i32 as u32
            && wc <= 0xdbff as i32 as u32)
    {
        let mut wc2: uint32_t = 0 as i32 as uint32_t;
        if n.wrapping_sub(3 as i32 as u64) < 3 as i32 as u64 {
            /* Invalid byte sequence. */
            current_block = 2846206098543151513;
        } else {
            cnt = _utf8_to_unicode(
                &mut wc2,
                s.offset(3 as i32 as isize),
                n.wrapping_sub(3 as i32 as u64),
            );
            if cnt != 3 as i32
                || !(wc2 >= 0xdc00 as i32 as u32
                    && wc2 <= 0xdfff as i32 as u32)
            {
                /* Invalid byte sequence. */
                current_block = 2846206098543151513;
            } else {
                wc = combine_surrogate_pair(wc, wc2);
                cnt = 6 as i32;
                current_block = 12209867499936983673;
            }
        }
    } else if cnt == 3 as i32
        && (wc >= 0xdc00 as i32 as u32
            && wc <= 0xdfff as i32 as u32)
    {
        /* Invalid byte sequence. */
        current_block = 2846206098543151513; /* set the Replacement Character instead. */
    } else {
        current_block = 12209867499936983673;
    }
    match current_block {
        2846206098543151513 => {
            *pwc = 0xfffd as i32 as uint32_t;
            if cnt > 0 as i32 {
                cnt *= -(1 as i32)
            }
            return cnt;
        }
        _ => {
            *pwc = wc;
            return cnt;
        }
    };
}
/*
* Convert a Unicode code point to a single UTF-8 sequence.
*
* NOTE:This function does not check if the Unicode is legal or not.
* Please you definitely check it before calling this.
*/
unsafe extern "C" fn unicode_to_utf8(
    mut p: *mut i8,
    mut remaining: size_t,
    mut uc: uint32_t,
) -> size_t {
    let mut _p: *mut i8 = p;
    /* Invalid Unicode char maps to Replacement character */
    if uc > 0x10ffff as i32 as u32 {
        uc = 0xfffd as i32 as uint32_t
    }
    /* Translate code point to UTF8 */
    if uc <= 0x7f as i32 as u32 {
        if remaining == 0 as i32 as u64 {
            return 0 as i32 as size_t;
        }
        let fresh7 = p;
        p = p.offset(1);
        *fresh7 = uc as i8
    } else if uc <= 0x7ff as i32 as u32 {
        if remaining < 2 as i32 as u64 {
            return 0 as i32 as size_t;
        }
        let fresh8 = p;
        p = p.offset(1);
        *fresh8 = (0xc0 as i32 as u32
            | uc >> 6 as i32 & 0x1f as i32 as u32)
            as i8;
        let fresh9 = p;
        p = p.offset(1);
        *fresh9 = (0x80 as i32 as u32 | uc & 0x3f as i32 as u32)
            as i8
    } else if uc <= 0xffff as i32 as u32 {
        if remaining < 3 as i32 as u64 {
            return 0 as i32 as size_t;
        }
        let fresh10 = p;
        p = p.offset(1);
        *fresh10 = (0xe0 as i32 as u32
            | uc >> 12 as i32 & 0xf as i32 as u32)
            as i8;
        let fresh11 = p;
        p = p.offset(1);
        *fresh11 = (0x80 as i32 as u32
            | uc >> 6 as i32 & 0x3f as i32 as u32)
            as i8;
        let fresh12 = p;
        p = p.offset(1);
        *fresh12 = (0x80 as i32 as u32 | uc & 0x3f as i32 as u32)
            as i8
    } else {
        if remaining < 4 as i32 as u64 {
            return 0 as i32 as size_t;
        }
        let fresh13 = p;
        p = p.offset(1);
        *fresh13 = (0xf0 as i32 as u32
            | uc >> 18 as i32 & 0x7 as i32 as u32)
            as i8;
        let fresh14 = p;
        p = p.offset(1);
        *fresh14 = (0x80 as i32 as u32
            | uc >> 12 as i32 & 0x3f as i32 as u32)
            as i8;
        let fresh15 = p;
        p = p.offset(1);
        *fresh15 = (0x80 as i32 as u32
            | uc >> 6 as i32 & 0x3f as i32 as u32)
            as i8;
        let fresh16 = p;
        p = p.offset(1);
        *fresh16 = (0x80 as i32 as u32 | uc & 0x3f as i32 as u32)
            as i8
    }
    return p.offset_from(_p) as i64 as size_t;
}
unsafe extern "C" fn utf16be_to_unicode(
    mut pwc: *mut uint32_t,
    mut s: *const i8,
    mut n: size_t,
) -> i32 {
    return utf16_to_unicode(pwc, s, n, 1 as i32);
}
unsafe extern "C" fn utf16le_to_unicode(
    mut pwc: *mut uint32_t,
    mut s: *const i8,
    mut n: size_t,
) -> i32 {
    return utf16_to_unicode(pwc, s, n, 0 as i32);
}
unsafe extern "C" fn utf16_to_unicode(
    mut pwc: *mut uint32_t,
    mut s: *const i8,
    mut n: size_t,
    mut be: i32,
) -> i32 {
    let mut utf16: *const i8 = s;
    let mut uc: u32 = 0;
    if n == 0 as i32 as u64 {
        return 0 as i32;
    }
    if n == 1 as i32 as u64 {
        /* set the Replacement Character instead. */
        *pwc = 0xfffd as i32 as uint32_t;
        return -(1 as i32);
    }
    if be != 0 {
        uc = archive_be16dec(utf16 as *const ()) as u32
    } else {
        uc = archive_le16dec(utf16 as *const ()) as u32
    }
    utf16 = utf16.offset(2 as i32 as isize);
    /* If this is a surrogate pair, assemble the full code point.*/
    if uc >= 0xd800 as i32 as u32 && uc <= 0xdbff as i32 as u32 {
        let mut uc2: u32 = 0;
        if n >= 4 as i32 as u64 {
            if be != 0 {
                uc2 = archive_be16dec(utf16 as *const ()) as u32
            } else {
                uc2 = archive_le16dec(utf16 as *const ()) as u32
            }
        } else {
            uc2 = 0 as i32 as u32
        }
        if uc2 >= 0xdc00 as i32 as u32
            && uc2 <= 0xdfff as i32 as u32
        {
            uc = combine_surrogate_pair(uc, uc2);
            utf16 = utf16.offset(2 as i32 as isize)
        } else {
            /* Undescribed code point should be U+FFFD
             * (replacement character). */
            *pwc = 0xfffd as i32 as uint32_t;
            return -(2 as i32);
        }
    }
    /*
     * Surrogate pair values(0xd800 through 0xdfff) are only
     * used by UTF-16, so, after above calculation, the code
     * must not be surrogate values, and Unicode has no codes
     * larger than 0x10ffff. Thus, those are not legal Unicode
     * values.
     */
    if uc >= 0xd800 as i32 as u32 && uc <= 0xdfff as i32 as u32
        || uc > 0x10ffff as i32 as u32
    {
        /* Undescribed code point should be U+FFFD
         * (replacement character). */
        *pwc = 0xfffd as i32 as uint32_t;
        return utf16.offset_from(s) as i64 as i32 * -(1 as i32);
    }
    *pwc = uc;
    return utf16.offset_from(s) as i64 as i32;
}
unsafe extern "C" fn unicode_to_utf16be(
    mut p: *mut i8,
    mut remaining: size_t,
    mut uc: uint32_t,
) -> size_t {
    let mut utf16: *mut i8 = p;
    if uc > 0xffff as i32 as u32 {
        /* We have a code point that won't fit into a
         * wchar_t; convert it to a surrogate pair. */
        if remaining < 4 as i32 as u64 {
            return 0 as i32 as size_t;
        }
        uc = (uc as u32).wrapping_sub(0x10000 as i32 as u32) as uint32_t
            as uint32_t;
        archive_be16enc(
            utf16 as *mut (),
            (uc >> 10 as i32 & 0x3ff as i32 as u32)
                .wrapping_add(0xd800 as i32 as u32) as uint16_t,
        );
        archive_be16enc(
            utf16.offset(2 as i32 as isize) as *mut (),
            (uc & 0x3ff as i32 as u32)
                .wrapping_add(0xdc00 as i32 as u32) as uint16_t,
        );
        return 4 as i32 as size_t;
    } else {
        if remaining < 2 as i32 as u64 {
            return 0 as i32 as size_t;
        }
        archive_be16enc(utf16 as *mut (), uc as uint16_t);
        return 2 as i32 as size_t;
    };
}
unsafe extern "C" fn unicode_to_utf16le(
    mut p: *mut i8,
    mut remaining: size_t,
    mut uc: uint32_t,
) -> size_t {
    let mut utf16: *mut i8 = p;
    if uc > 0xffff as i32 as u32 {
        /* We have a code point that won't fit into a
         * wchar_t; convert it to a surrogate pair. */
        if remaining < 4 as i32 as u64 {
            return 0 as i32 as size_t;
        }
        uc = (uc as u32).wrapping_sub(0x10000 as i32 as u32) as uint32_t
            as uint32_t;
        archive_le16enc(
            utf16 as *mut (),
            (uc >> 10 as i32 & 0x3ff as i32 as u32)
                .wrapping_add(0xd800 as i32 as u32) as uint16_t,
        );
        archive_le16enc(
            utf16.offset(2 as i32 as isize) as *mut (),
            (uc & 0x3ff as i32 as u32)
                .wrapping_add(0xdc00 as i32 as u32) as uint16_t,
        );
        return 4 as i32 as size_t;
    } else {
        if remaining < 2 as i32 as u64 {
            return 0 as i32 as size_t;
        }
        archive_le16enc(utf16 as *mut (), uc as uint16_t);
        return 2 as i32 as size_t;
    };
}
/*
* Copy UTF-8 string in checking surrogate pair.
* If any surrogate pair are found, it would be canonicalized.
*/
unsafe extern "C" fn strncat_from_utf8_to_utf8(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut len: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut s: *const i8 = 0 as *const i8;
    let mut p: *mut i8 = 0 as *mut i8;
    let mut endp: *mut i8 = 0 as *mut i8;
    let mut n: i32 = 0;
    let mut ret: i32 = 0 as i32;
    /* UNUSED */
    if archive_string_ensure(
        as_0,
        (*as_0)
            .length
            .wrapping_add(len)
            .wrapping_add(1 as i32 as u64),
    )
    .is_null()
    {
        return -(1 as i32);
    }
    s = _p as *const i8;
    p = (*as_0).s.offset((*as_0).length as isize);
    endp = (*as_0)
        .s
        .offset((*as_0).buffer_length as isize)
        .offset(-(1 as i32 as isize));
    loop {
        let mut uc: uint32_t = 0;
        let mut ss: *const i8 = s;
        let mut w: size_t = 0;
        loop
        /*
         * Forward byte sequence until a conversion of that is needed.
         */
        {
            n = utf8_to_unicode(&mut uc, s, len);
            if !(n > 0 as i32) {
                break;
            }
            s = s.offset(n as isize);
            len = (len as u64).wrapping_sub(n as u64) as size_t as size_t
        }
        if ss < s {
            if p.offset(s.offset_from(ss) as i64 as isize) > endp {
                (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                if archive_string_ensure(
                    as_0,
                    (*as_0)
                        .buffer_length
                        .wrapping_add(len)
                        .wrapping_add(1 as i32 as u64),
                )
                .is_null()
                {
                    return -(1 as i32);
                }
                p = (*as_0).s.offset((*as_0).length as isize);
                endp = (*as_0)
                    .s
                    .offset((*as_0).buffer_length as isize)
                    .offset(-(1 as i32 as isize))
            }
            memcpy_safe(
                p as *mut (),
                ss as *const (),
                s.offset_from(ss) as i64 as u64,
            );
            p = p.offset(s.offset_from(ss) as i64 as isize)
        }
        /*
         * If n is negative, current byte sequence needs a replacement.
         */
        if n < 0 as i32 {
            if n == -(3 as i32)
                && (uc >= 0xd800 as i32 as u32
                    && uc <= 0xdfff as i32 as u32)
            {
                /* Current byte sequence may be CESU-8. */
                n = cesu8_to_unicode(&mut uc, s, len)
            }
            if n < 0 as i32 {
                ret = -(1 as i32);
                n *= -(1 as i32)
                /* Use a replaced unicode character. */
            }
            loop
            /* Rebuild UTF-8 byte sequence. */
            {
                w = unicode_to_utf8(p, endp.offset_from(p) as i64 as size_t, uc);
                if !(w == 0 as i32 as u64) {
                    break;
                }
                (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                if archive_string_ensure(
                    as_0,
                    (*as_0)
                        .buffer_length
                        .wrapping_add(len)
                        .wrapping_add(1 as i32 as u64),
                )
                .is_null()
                {
                    return -(1 as i32);
                }
                p = (*as_0).s.offset((*as_0).length as isize);
                endp = (*as_0)
                    .s
                    .offset((*as_0).buffer_length as isize)
                    .offset(-(1 as i32 as isize))
            }
            p = p.offset(w as isize);
            s = s.offset(n as isize);
            len = (len as u64).wrapping_sub(n as u64) as size_t as size_t
        }
        if !(n > 0 as i32) {
            break;
        }
    }
    (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
    *(*as_0).s.offset((*as_0).length as isize) = '\u{0}' as i32 as i8;
    return ret;
}
unsafe extern "C" fn archive_string_append_unicode(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut len: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut s: *const i8 = 0 as *const i8;
    let mut p: *mut i8 = 0 as *mut i8;
    let mut endp: *mut i8 = 0 as *mut i8;
    let mut uc: uint32_t = 0;
    let mut w: size_t = 0;
    let mut n: i32 = 0;
    let mut ret: i32 = 0 as i32;
    let mut ts: i32 = 0;
    let mut tm: i32 = 0;
    let mut parse: Option<
        unsafe extern "C" fn(_: *mut uint32_t, _: *const i8, _: size_t) -> i32,
    > = None;
    let mut unparse: Option<
        unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
    > = None;
    if (*sc).flag & (1 as i32) << 10 as i32 != 0 {
        unparse = Some(
            unicode_to_utf16be
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        ts = 2 as i32
    } else if (*sc).flag & (1 as i32) << 12 as i32 != 0 {
        unparse = Some(
            unicode_to_utf16le
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        ts = 2 as i32
    } else if (*sc).flag & (1 as i32) << 8 as i32 != 0 {
        unparse = Some(
            unicode_to_utf8
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        ts = 1 as i32
    } else if (*sc).flag & (1 as i32) << 11 as i32 != 0 {
        unparse = Some(
            unicode_to_utf16be
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        ts = 2 as i32
    } else if (*sc).flag & (1 as i32) << 13 as i32 != 0 {
        unparse = Some(
            unicode_to_utf16le
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        ts = 2 as i32
    } else {
        unparse = Some(
            unicode_to_utf8
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        ts = 1 as i32
    }
    if (*sc).flag & (1 as i32) << 11 as i32 != 0 {
        parse = Some(
            utf16be_to_unicode
                as unsafe extern "C" fn(
                    _: *mut uint32_t,
                    _: *const i8,
                    _: size_t,
                ) -> i32,
        );
        tm = 1 as i32
    } else if (*sc).flag & (1 as i32) << 13 as i32 != 0 {
        parse = Some(
            utf16le_to_unicode
                as unsafe extern "C" fn(
                    _: *mut uint32_t,
                    _: *const i8,
                    _: size_t,
                ) -> i32,
        );
        tm = 1 as i32
    } else {
        parse = Some(
            cesu8_to_unicode
                as unsafe extern "C" fn(
                    _: *mut uint32_t,
                    _: *const i8,
                    _: size_t,
                ) -> i32,
        );
        tm = ts
    }
    if archive_string_ensure(
        as_0,
        (*as_0)
            .length
            .wrapping_add(len.wrapping_mul(tm as u64))
            .wrapping_add(ts as u64),
    )
    .is_null()
    {
        return -(1 as i32);
    }
    s = _p as *const i8;
    p = (*as_0).s.offset((*as_0).length as isize);
    endp = (*as_0)
        .s
        .offset((*as_0).buffer_length as isize)
        .offset(-(ts as isize));
    loop {
        n = parse.expect("non-null function pointer")(&mut uc, s, len);
        if !(n != 0 as i32) {
            break;
        }
        if n < 0 as i32 {
            /*
             * This case is going to be converted to another
             * character-set through iconv.
             */
            /* Use a replaced unicode character. */
            n *= -(1 as i32);
            ret = -(1 as i32)
        }
        s = s.offset(n as isize);
        len = (len as u64).wrapping_sub(n as u64) as size_t as size_t;
        loop {
            w = unparse.expect("non-null function pointer")(
                p,
                endp.offset_from(p) as i64 as size_t,
                uc,
            );
            if !(w == 0 as i32 as u64) {
                break;
            }
            /* There is not enough output buffer so
             * we have to expand it. */
            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
            if archive_string_ensure(
                as_0,
                (*as_0)
                    .buffer_length
                    .wrapping_add(len.wrapping_mul(tm as u64))
                    .wrapping_add(ts as u64),
            )
            .is_null()
            {
                return -(1 as i32);
            }
            p = (*as_0).s.offset((*as_0).length as isize);
            endp = (*as_0)
                .s
                .offset((*as_0).buffer_length as isize)
                .offset(-(ts as isize))
        }
        p = p.offset(w as isize)
    }
    (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
    *(*as_0).s.offset((*as_0).length as isize) = '\u{0}' as i32 as i8;
    if ts == 2 as i32 {
        *(*as_0).s.offset(
            (*as_0)
                .length
                .wrapping_add(1 as i32 as u64) as isize,
        ) = '\u{0}' as i32 as i8
    }
    return ret;
}
unsafe extern "C" fn get_nfc(mut uc: uint32_t, mut uc2: uint32_t) -> uint32_t {
    let mut t: i32 = 0;
    let mut b: i32 = 0;
    t = 0 as i32;
    b = (::std::mem::size_of::<[unicode_composition_table; 931]>() as u64)
        .wrapping_div(::std::mem::size_of::<unicode_composition_table>() as u64)
        .wrapping_sub(1 as i32 as u64) as i32;
    while b >= t {
        let mut m: i32 = (t + b) / 2 as i32;
        if u_composition_table[m as usize].cp1 < uc {
            t = m + 1 as i32
        } else if u_composition_table[m as usize].cp1 > uc {
            b = m - 1 as i32
        } else if u_composition_table[m as usize].cp2 < uc2 {
            t = m + 1 as i32
        } else if u_composition_table[m as usize].cp2 > uc2 {
            b = m - 1 as i32
        } else {
            return u_composition_table[m as usize].nfc;
        }
    }
    return 0 as i32 as uint32_t;
}
/* The maximum number of Following Decomposable
 * Characters. */
/*
* Update first code point.
*/
/*
* Replace first code point with second code point.
*/
/*
* Write first code point.
* If the code point has not be changed from its original code,
* this just copies it from its original buffer pointer.
* If not, this converts it to UTF-8 byte sequence and copies it.
*/
/* FALL THROUGH */
/* FALL THROUGH */
/* FALL THROUGH */
/*
* Collect following decomposable code points.
*/
/*
* Normalize UTF-8/UTF-16BE characters to Form C and copy the result.
*
* TODO: Convert composition exclusions, which are never converted
* from NFC,NFD,NFKC and NFKD, to Form C.
*/
unsafe extern "C" fn archive_string_normalize_C(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut len: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut s: *const i8 = _p as *const i8; /* text size. */
    let mut p: *mut i8 = 0 as *mut i8;
    let mut endp: *mut i8 = 0 as *mut i8;
    let mut uc: uint32_t = 0;
    let mut uc2: uint32_t = 0;
    let mut w: size_t = 0;
    let mut always_replace: i32 = 0;
    let mut n: i32 = 0;
    let mut n2: i32 = 0;
    let mut ret: i32 = 0 as i32;
    let mut spair: i32 = 0;
    let mut ts: i32 = 0;
    let mut tm: i32 = 0;
    let mut parse: Option<
        unsafe extern "C" fn(_: *mut uint32_t, _: *const i8, _: size_t) -> i32,
    > = None;
    let mut unparse: Option<
        unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
    > = None;
    always_replace = 1 as i32;
    ts = 1 as i32;
    if (*sc).flag & (1 as i32) << 10 as i32 != 0 {
        unparse = Some(
            unicode_to_utf16be
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        ts = 2 as i32;
        if (*sc).flag & (1 as i32) << 11 as i32 != 0 {
            always_replace = 0 as i32
        }
    } else if (*sc).flag & (1 as i32) << 12 as i32 != 0 {
        unparse = Some(
            unicode_to_utf16le
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        ts = 2 as i32;
        if (*sc).flag & (1 as i32) << 13 as i32 != 0 {
            always_replace = 0 as i32
        }
    } else if (*sc).flag & (1 as i32) << 8 as i32 != 0 {
        unparse = Some(
            unicode_to_utf8
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        if (*sc).flag & (1 as i32) << 9 as i32 != 0 {
            always_replace = 0 as i32
        }
    } else {
        /*
         * This case is going to be converted to another
         * character-set through iconv.
         */
        always_replace = 0 as i32;
        if (*sc).flag & (1 as i32) << 11 as i32 != 0 {
            unparse = Some(
                unicode_to_utf16be
                    as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
            );
            ts = 2 as i32
        } else if (*sc).flag & (1 as i32) << 13 as i32 != 0 {
            unparse = Some(
                unicode_to_utf16le
                    as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
            );
            ts = 2 as i32
        } else {
            unparse = Some(
                unicode_to_utf8
                    as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
            )
        }
    }
    if (*sc).flag & (1 as i32) << 11 as i32 != 0 {
        parse = Some(
            utf16be_to_unicode
                as unsafe extern "C" fn(
                    _: *mut uint32_t,
                    _: *const i8,
                    _: size_t,
                ) -> i32,
        );
        tm = 1 as i32;
        spair = 4 as i32
        /* surrogate pair size in UTF-16. */
    } else if (*sc).flag & (1 as i32) << 13 as i32 != 0 {
        parse = Some(
            utf16le_to_unicode
                as unsafe extern "C" fn(
                    _: *mut uint32_t,
                    _: *const i8,
                    _: size_t,
                ) -> i32,
        );
        tm = 1 as i32;
        spair = 4 as i32
        /* surrogate pair size in UTF-16. */
    } else {
        parse = Some(
            cesu8_to_unicode
                as unsafe extern "C" fn(
                    _: *mut uint32_t,
                    _: *const i8,
                    _: size_t,
                ) -> i32,
        );
        tm = ts;
        spair = 6 as i32
        /* surrogate pair size in UTF-8. */
    }
    if archive_string_ensure(
        as_0,
        (*as_0)
            .length
            .wrapping_add(len.wrapping_mul(tm as u64))
            .wrapping_add(ts as u64),
    )
    .is_null()
    {
        return -(1 as i32);
    }
    p = (*as_0).s.offset((*as_0).length as isize);
    endp = (*as_0)
        .s
        .offset((*as_0).buffer_length as isize)
        .offset(-(ts as isize));
    loop {
        n = parse.expect("non-null function pointer")(&mut uc, s, len);
        if !(n != 0 as i32) {
            break;
        }
        let mut ucptr: *const i8 = 0 as *const i8;
        let mut uc2ptr: *const i8 = 0 as *const i8;
        if n < 0 as i32 {
            /* Use a replaced unicode character. */
            loop {
                w = unparse.expect("non-null function pointer")(
                    p,
                    endp.offset_from(p) as i64 as size_t,
                    uc,
                );
                if !(w == 0 as i32 as u64) {
                    break;
                }
                (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                if archive_string_ensure(
                    as_0,
                    (*as_0)
                        .buffer_length
                        .wrapping_add(len.wrapping_mul(tm as u64))
                        .wrapping_add(ts as u64),
                )
                .is_null()
                {
                    return -(1 as i32);
                }
                p = (*as_0).s.offset((*as_0).length as isize);
                endp = (*as_0)
                    .s
                    .offset((*as_0).buffer_length as isize)
                    .offset(-(ts as isize))
            }
            p = p.offset(w as isize);
            s = s.offset((n * -(1 as i32)) as isize);
            len = (len as u64).wrapping_sub((n * -(1 as i32)) as u64)
                as size_t as size_t;
            ret = -(1 as i32)
        } else {
            if n == spair || always_replace != 0 {
                /* uc is converted from a surrogate pair.
                 * this should be treated as a changed code. */
                ucptr = 0 as *const i8
            } else {
                ucptr = s
            }
            s = s.offset(n as isize);
            len = (len as u64).wrapping_sub(n as u64) as size_t as size_t;
            loop
            /* Read second code point. */
            {
                n2 = parse.expect("non-null function pointer")(&mut uc2, s, len);
                if !(n2 > 0 as i32) {
                    break;
                }
                let mut ucx: [uint32_t; 10] = [0; 10];
                let mut ccx: [i32; 10] = [0; 10];
                let mut cl: i32 = 0;
                let mut cx: i32 = 0;
                let mut i: i32 = 0;
                let mut nx: i32 = 0;
                let mut ucx_size: i32 = 0;
                let mut LIndex: i32 = 0;
                let mut SIndex: i32 = 0;
                let mut nfc: uint32_t = 0;
                if n2 == spair || always_replace != 0 {
                    /* uc2 is converted from a surrogate pair.
                     * this should be treated as a changed code. */
                    uc2ptr = 0 as *const i8
                } else {
                    uc2ptr = s
                }
                s = s.offset(n2 as isize);
                len = (len as u64).wrapping_sub(n2 as u64) as size_t as size_t;
                /*
                 * If current second code point is out of decomposable
                 * code points, finding compositions is unneeded.
                 */
                if !(uc2 >> 8 as i32 <= 0x1d2 as i32 as u32
                    && u_decomposable_blocks[(uc2 >> 8 as i32) as usize] as i32
                        != 0)
                {
                    if !ucptr.is_null() {
                        if p.offset(n as isize) > endp {
                            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                            if archive_string_ensure(
                                as_0,
                                (*as_0)
                                    .buffer_length
                                    .wrapping_add(len.wrapping_mul(tm as u64))
                                    .wrapping_add(ts as u64),
                            )
                            .is_null()
                            {
                                return -(1 as i32);
                            }
                            p = (*as_0).s.offset((*as_0).length as isize);
                            endp = (*as_0)
                                .s
                                .offset((*as_0).buffer_length as isize)
                                .offset(-(ts as isize))
                        }
                        let mut current_block_85: u64;
                        match n {
                            4 => {
                                let fresh17 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh18 = p;
                                p = p.offset(1);
                                *fresh18 = *fresh17;
                                current_block_85 = 7097572078640228219;
                            }
                            3 => {
                                current_block_85 = 7097572078640228219;
                            }
                            2 => {
                                current_block_85 = 3239503646190857518;
                            }
                            1 => {
                                current_block_85 = 4212176911995692010;
                            }
                            _ => {
                                current_block_85 = 7301440000599063274;
                            }
                        }
                        match current_block_85 {
                            7097572078640228219 => {
                                let fresh19 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh20 = p;
                                p = p.offset(1);
                                *fresh20 = *fresh19;
                                current_block_85 = 3239503646190857518;
                            }
                            _ => {}
                        }
                        match current_block_85 {
                            3239503646190857518 => {
                                let fresh21 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh22 = p;
                                p = p.offset(1);
                                *fresh22 = *fresh21;
                                current_block_85 = 4212176911995692010;
                            }
                            _ => {}
                        }
                        match current_block_85 {
                            4212176911995692010 => {
                                let fresh23 = p;
                                p = p.offset(1);
                                *fresh23 = *ucptr
                            }
                            _ => {}
                        }
                        ucptr = 0 as *const i8
                    } else {
                        loop {
                            w = unparse.expect("non-null function pointer")(
                                p,
                                endp.offset_from(p) as i64 as size_t,
                                uc,
                            );
                            if !(w == 0 as i32 as u64) {
                                break;
                            }
                            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                            if archive_string_ensure(
                                as_0,
                                (*as_0)
                                    .buffer_length
                                    .wrapping_add(len.wrapping_mul(tm as u64))
                                    .wrapping_add(ts as u64),
                            )
                            .is_null()
                            {
                                return -(1 as i32);
                            }
                            p = (*as_0).s.offset((*as_0).length as isize);
                            endp = (*as_0)
                                .s
                                .offset((*as_0).buffer_length as isize)
                                .offset(-(ts as isize))
                        }
                        p = p.offset(w as isize)
                    }
                    uc = uc2;
                    ucptr = uc2ptr;
                    n = n2
                } else {
                    /*
                     * Try to combine current code points.
                     */
                    /*
                     * We have to combine Hangul characters according to
                     * http://uniicode.org/reports/tr15/#Hangul
                     */
                    LIndex = uc.wrapping_sub(0x1100 as i32 as u32) as i32;
                    if 0 as i32 <= LIndex && LIndex < 19 as i32 {
                        /*
                         * Hangul Composition.
                         * 1. Two current code points are L and V.
                         */
                        let mut VIndex: i32 =
                            uc2.wrapping_sub(0x1161 as i32 as u32) as i32;
                        if 0 as i32 <= VIndex && VIndex < 21 as i32 {
                            /* Make syllable of form LV. */
                            uc = (0xac00 as i32
                                + (LIndex * 21 as i32 + VIndex) * 28 as i32)
                                as uint32_t;
                            ucptr = 0 as *const i8
                        } else {
                            if !ucptr.is_null() {
                                if p.offset(n as isize) > endp {
                                    (*as_0).length =
                                        p.offset_from((*as_0).s) as i64 as size_t;
                                    if archive_string_ensure(
                                        as_0,
                                        (*as_0)
                                            .buffer_length
                                            .wrapping_add(len.wrapping_mul(tm as u64))
                                            .wrapping_add(ts as u64),
                                    )
                                    .is_null()
                                    {
                                        return -(1 as i32);
                                    }
                                    p = (*as_0).s.offset((*as_0).length as isize);
                                    endp = (*as_0)
                                        .s
                                        .offset((*as_0).buffer_length as isize)
                                        .offset(-(ts as isize))
                                }
                                let mut current_block_126: u64;
                                match n {
                                    4 => {
                                        let fresh24 = ucptr;
                                        ucptr = ucptr.offset(1);
                                        let fresh25 = p;
                                        p = p.offset(1);
                                        *fresh25 = *fresh24;
                                        current_block_126 = 4836364342735439733;
                                    }
                                    3 => {
                                        current_block_126 = 4836364342735439733;
                                    }
                                    2 => {
                                        current_block_126 = 9831359549883350336;
                                    }
                                    1 => {
                                        current_block_126 = 7853011364949082690;
                                    }
                                    _ => {
                                        current_block_126 = 7293850626974290116;
                                    }
                                }
                                match current_block_126 {
                                    4836364342735439733 => {
                                        let fresh26 = ucptr;
                                        ucptr = ucptr.offset(1);
                                        let fresh27 = p;
                                        p = p.offset(1);
                                        *fresh27 = *fresh26;
                                        current_block_126 = 9831359549883350336;
                                    }
                                    _ => {}
                                }
                                match current_block_126 {
                                    9831359549883350336 => {
                                        let fresh28 = ucptr;
                                        ucptr = ucptr.offset(1);
                                        let fresh29 = p;
                                        p = p.offset(1);
                                        *fresh29 = *fresh28;
                                        current_block_126 = 7853011364949082690;
                                    }
                                    _ => {}
                                }
                                match current_block_126 {
                                    7853011364949082690 => {
                                        let fresh30 = p;
                                        p = p.offset(1);
                                        *fresh30 = *ucptr
                                    }
                                    _ => {}
                                }
                                ucptr = 0 as *const i8
                            } else {
                                loop {
                                    w = unparse.expect("non-null function pointer")(
                                        p,
                                        endp.offset_from(p) as i64 as size_t,
                                        uc,
                                    );
                                    if !(w == 0 as i32 as u64) {
                                        break;
                                    }
                                    (*as_0).length =
                                        p.offset_from((*as_0).s) as i64 as size_t;
                                    if archive_string_ensure(
                                        as_0,
                                        (*as_0)
                                            .buffer_length
                                            .wrapping_add(len.wrapping_mul(tm as u64))
                                            .wrapping_add(ts as u64),
                                    )
                                    .is_null()
                                    {
                                        return -(1 as i32);
                                    }
                                    p = (*as_0).s.offset((*as_0).length as isize);
                                    endp = (*as_0)
                                        .s
                                        .offset((*as_0).buffer_length as isize)
                                        .offset(-(ts as isize))
                                }
                                p = p.offset(w as isize)
                            }
                            uc = uc2;
                            ucptr = uc2ptr;
                            n = n2
                        }
                    } else {
                        SIndex =
                            uc.wrapping_sub(0xac00 as i32 as u32) as i32;
                        if 0 as i32 <= SIndex
                            && SIndex < 19 as i32 * (21 as i32 * 28 as i32)
                            && SIndex % 28 as i32 == 0 as i32
                        {
                            /*
                             * Hangul Composition.
                             * 2. Two current code points are LV and T.
                             */
                            let mut TIndex: i32 = uc2
                                .wrapping_sub(0x11a7 as i32 as u32)
                                as i32;
                            if (0 as i32) < TIndex && TIndex < 28 as i32 {
                                /* Make syllable of form LVT. */
                                uc = uc.wrapping_add(TIndex as u32);
                                ucptr = 0 as *const i8
                            } else {
                                if !ucptr.is_null() {
                                    if p.offset(n as isize) > endp {
                                        (*as_0).length =
                                            p.offset_from((*as_0).s) as i64 as size_t;
                                        if archive_string_ensure(
                                            as_0,
                                            (*as_0)
                                                .buffer_length
                                                .wrapping_add(len.wrapping_mul(tm as u64))
                                                .wrapping_add(ts as u64),
                                        )
                                        .is_null()
                                        {
                                            return -(1 as i32);
                                        }
                                        p = (*as_0).s.offset((*as_0).length as isize);
                                        endp = (*as_0)
                                            .s
                                            .offset((*as_0).buffer_length as isize)
                                            .offset(-(ts as isize))
                                    }
                                    let mut current_block_169: u64;
                                    match n {
                                        4 => {
                                            let fresh31 = ucptr;
                                            ucptr = ucptr.offset(1);
                                            let fresh32 = p;
                                            p = p.offset(1);
                                            *fresh32 = *fresh31;
                                            current_block_169 = 12324466122364098067;
                                        }
                                        3 => {
                                            current_block_169 = 12324466122364098067;
                                        }
                                        2 => {
                                            current_block_169 = 2793525517544005515;
                                        }
                                        1 => {
                                            current_block_169 = 14954118662474697770;
                                        }
                                        _ => {
                                            current_block_169 = 857031028540284188;
                                        }
                                    }
                                    match current_block_169 {
                                        12324466122364098067 => {
                                            let fresh33 = ucptr;
                                            ucptr = ucptr.offset(1);
                                            let fresh34 = p;
                                            p = p.offset(1);
                                            *fresh34 = *fresh33;
                                            current_block_169 = 2793525517544005515;
                                        }
                                        _ => {}
                                    }
                                    match current_block_169 {
                                        2793525517544005515 => {
                                            let fresh35 = ucptr;
                                            ucptr = ucptr.offset(1);
                                            let fresh36 = p;
                                            p = p.offset(1);
                                            *fresh36 = *fresh35;
                                            current_block_169 = 14954118662474697770;
                                        }
                                        _ => {}
                                    }
                                    match current_block_169 {
                                        14954118662474697770 => {
                                            let fresh37 = p;
                                            p = p.offset(1);
                                            *fresh37 = *ucptr
                                        }
                                        _ => {}
                                    }
                                    ucptr = 0 as *const i8
                                } else {
                                    loop {
                                        w = unparse.expect("non-null function pointer")(
                                            p,
                                            endp.offset_from(p) as i64 as size_t,
                                            uc,
                                        );
                                        if !(w == 0 as i32 as u64) {
                                            break;
                                        }
                                        (*as_0).length =
                                            p.offset_from((*as_0).s) as i64 as size_t;
                                        if archive_string_ensure(
                                            as_0,
                                            (*as_0)
                                                .buffer_length
                                                .wrapping_add(len.wrapping_mul(tm as u64))
                                                .wrapping_add(ts as u64),
                                        )
                                        .is_null()
                                        {
                                            return -(1 as i32);
                                        }
                                        p = (*as_0).s.offset((*as_0).length as isize);
                                        endp = (*as_0)
                                            .s
                                            .offset((*as_0).buffer_length as isize)
                                            .offset(-(ts as isize))
                                    }
                                    p = p.offset(w as isize)
                                }
                                uc = uc2;
                                ucptr = uc2ptr;
                                n = n2
                            }
                        } else {
                            nfc = get_nfc(uc, uc2);
                            if nfc != 0 as i32 as u32 {
                                /* A composition to current code points
                                 * is found. */
                                uc = nfc;
                                ucptr = 0 as *const i8
                            } else {
                                cl = (if uc2 > 0x1d244 as i32 as u32 {
                                    0 as i32
                                } else {
                                    ccc_val[(ccc_val_index[(ccc_index
                                        [(uc2 >> 8 as i32) as usize]
                                        as usize)
                                        * (16 as usize)
                                        + ((uc2 >> 4 as i32
                                            & 0xf as i32 as u32)
                                            as usize)]
                                        as usize)
                                        * (16 as usize)
                                        + ((uc2 & 0xf as i32 as u32) as usize)]
                                        as i32
                                });
                                if cl == 0 as i32 {
                                    /* Clearly 'uc2' the second code point is not
                                     * a decomposable code. */
                                    if !ucptr.is_null() {
                                        if p.offset(n as isize) > endp {
                                            (*as_0).length =
                                                p.offset_from((*as_0).s) as i64 as size_t;
                                            if archive_string_ensure(
                                                as_0,
                                                (*as_0)
                                                    .buffer_length
                                                    .wrapping_add(
                                                        len.wrapping_mul(tm as u64),
                                                    )
                                                    .wrapping_add(ts as u64),
                                            )
                                            .is_null()
                                            {
                                                return -(1 as i32);
                                            }
                                            p = (*as_0).s.offset((*as_0).length as isize);
                                            endp = (*as_0)
                                                .s
                                                .offset((*as_0).buffer_length as isize)
                                                .offset(-(ts as isize))
                                        }
                                        let mut current_block_211: u64;
                                        match n {
                                            4 => {
                                                let fresh38 = ucptr;
                                                ucptr = ucptr.offset(1);
                                                let fresh39 = p;
                                                p = p.offset(1);
                                                *fresh39 = *fresh38;
                                                current_block_211 = 17815729426413574898;
                                            }
                                            3 => {
                                                current_block_211 = 17815729426413574898;
                                            }
                                            2 => {
                                                current_block_211 = 1622300673798121472;
                                            }
                                            1 => {
                                                current_block_211 = 11107048155855281638;
                                            }
                                            _ => {
                                                current_block_211 = 10644040035716118461;
                                            }
                                        }
                                        match current_block_211 {
                                            17815729426413574898 => {
                                                let fresh40 = ucptr;
                                                ucptr = ucptr.offset(1);
                                                let fresh41 = p;
                                                p = p.offset(1);
                                                *fresh41 = *fresh40;
                                                current_block_211 = 1622300673798121472;
                                            }
                                            _ => {}
                                        }
                                        match current_block_211 {
                                            1622300673798121472 => {
                                                let fresh42 = ucptr;
                                                ucptr = ucptr.offset(1);
                                                let fresh43 = p;
                                                p = p.offset(1);
                                                *fresh43 = *fresh42;
                                                current_block_211 = 11107048155855281638;
                                            }
                                            _ => {}
                                        }
                                        match current_block_211 {
                                            11107048155855281638 => {
                                                let fresh44 = p;
                                                p = p.offset(1);
                                                *fresh44 = *ucptr
                                            }
                                            _ => {}
                                        }
                                        ucptr = 0 as *const i8
                                    } else {
                                        loop {
                                            w = unparse.expect("non-null function pointer")(
                                                p,
                                                endp.offset_from(p) as i64 as size_t,
                                                uc,
                                            );
                                            if !(w == 0 as i32 as u64) {
                                                break;
                                            }
                                            (*as_0).length =
                                                p.offset_from((*as_0).s) as i64 as size_t;
                                            if archive_string_ensure(
                                                as_0,
                                                (*as_0)
                                                    .buffer_length
                                                    .wrapping_add(
                                                        len.wrapping_mul(tm as u64),
                                                    )
                                                    .wrapping_add(ts as u64),
                                            )
                                            .is_null()
                                            {
                                                return -(1 as i32);
                                            }
                                            p = (*as_0).s.offset((*as_0).length as isize);
                                            endp = (*as_0)
                                                .s
                                                .offset((*as_0).buffer_length as isize)
                                                .offset(-(ts as isize))
                                        }
                                        p = p.offset(w as isize)
                                    }
                                    uc = uc2;
                                    ucptr = uc2ptr;
                                    n = n2
                                } else {
                                    /*
                                     * Collect following decomposable code points.
                                     */
                                    cx = 0 as i32;
                                    ucx[0 as i32 as usize] = uc2;
                                    ccx[0 as i32 as usize] = cl;
                                    let mut _i: i32 = 0;
                                    _i = 1 as i32;
                                    while _i < 10 as i32 {
                                        nx = parse.expect("non-null function pointer")(
                                            &mut *ucx.as_mut_ptr().offset(_i as isize),
                                            s,
                                            len,
                                        );
                                        if nx <= 0 as i32 {
                                            break;
                                        }
                                        cx = if ucx[_i as usize]
                                            > 0x1d244 as i32 as u32
                                        {
                                            0 as i32
                                        } else {
                                            ccc_val[(ccc_val_index[(ccc_index
                                                [(ucx[_i as usize] >> 8 as i32) as usize]
                                                as usize)
                                                * (16 as usize)
                                                + ((ucx[_i as usize] >> 4 as i32
                                                    & 0xf as i32 as u32)
                                                    as usize)]
                                                as usize)
                                                * (16 as usize)
                                                + ((ucx[_i as usize]
                                                    & 0xf as i32 as u32)
                                                    as usize)]
                                                as i32
                                        };
                                        if cl >= cx
                                            && cl != 228 as i32
                                            && cx != 228 as i32
                                        {
                                            break;
                                        }
                                        s = s.offset(nx as isize);
                                        len = (len as u64)
                                            .wrapping_sub(nx as u64)
                                            as size_t
                                            as size_t;
                                        cl = cx;
                                        ccx[_i as usize] = cx;
                                        _i += 1
                                    }
                                    if _i >= 10 as i32 {
                                        ret = -(1 as i32);
                                        ucx_size = 10 as i32
                                    } else {
                                        ucx_size = _i
                                    }
                                    /*
                                     * Find a composed code in the collected code points.
                                     */
                                    i = 1 as i32;
                                    while i < ucx_size {
                                        let mut j: i32 = 0;
                                        nfc = get_nfc(uc, ucx[i as usize]);
                                        if nfc == 0 as i32 as u32 {
                                            i += 1
                                        } else {
                                            /*
                                             * nfc is composed of uc and ucx[i].
                                             */
                                            uc = nfc;
                                            ucptr = 0 as *const i8;
                                            /*
                                             * Remove ucx[i] by shifting
                                             * following code points.
                                             */
                                            j = i;
                                            while (j + 1 as i32) < ucx_size {
                                                ucx[j as usize] =
                                                    ucx[(j + 1 as i32) as usize];
                                                ccx[j as usize] =
                                                    ccx[(j + 1 as i32) as usize];
                                                j += 1
                                            }
                                            ucx_size -= 1;
                                            /*
                                             * Collect following code points blocked
                                             * by ucx[i] the removed code point.
                                             */
                                            if ucx_size > 0 as i32
                                                && i == ucx_size
                                                && nx > 0 as i32
                                                && cx == cl
                                            {
                                                cl = ccx[(ucx_size - 1 as i32) as usize];
                                                let mut _i_0: i32 = 0;
                                                _i_0 = ucx_size;
                                                while _i_0 < 10 as i32 {
                                                    nx = parse.expect("non-null function pointer")(
                                                        &mut *ucx
                                                            .as_mut_ptr()
                                                            .offset(_i_0 as isize),
                                                        s,
                                                        len,
                                                    );
                                                    if nx <= 0 as i32 {
                                                        break;
                                                    }
                                                    cx = if ucx[_i_0 as usize]
                                                        > 0x1d244 as i32 as u32
                                                    {
                                                        0 as i32
                                                    } else {
                                                        ccc_val[(ccc_val_index[(ccc_index[(ucx
                                                            [_i_0 as usize]
                                                            >> 8 as i32)
                                                            as usize]
                                                            as usize)
                                                            * (16 as usize)
                                                            + ((ucx[_i_0 as usize]
                                                                >> 4 as i32
                                                                & 0xf as i32
                                                                    as u32)
                                                                as usize)]
                                                            as usize)
                                                            * (16 as usize)
                                                            + ((ucx[_i_0 as usize]
                                                                & 0xf as i32
                                                                    as u32)
                                                                as usize)]
                                                            as i32
                                                    };
                                                    if cl >= cx
                                                        && cl != 228 as i32
                                                        && cx != 228 as i32
                                                    {
                                                        break;
                                                    }
                                                    s = s.offset(nx as isize);
                                                    len = (len as u64)
                                                        .wrapping_sub(nx as u64)
                                                        as size_t
                                                        as size_t;
                                                    cl = cx;
                                                    ccx[_i_0 as usize] = cx;
                                                    _i_0 += 1
                                                }
                                                if _i_0 >= 10 as i32 {
                                                    ret = -(1 as i32);
                                                    ucx_size = 10 as i32
                                                } else {
                                                    ucx_size = _i_0
                                                }
                                            }
                                            /*
                                             * Restart finding a composed code with
                                             * the updated uc from the top of the
                                             * collected code points.
                                             */
                                            i = 0 as i32
                                        }
                                    }
                                    /*
                                     * Apparently the current code points are not
                                     * decomposed characters or already composed.
                                     */
                                    if !ucptr.is_null() {
                                        if p.offset(n as isize) > endp {
                                            (*as_0).length =
                                                p.offset_from((*as_0).s) as i64 as size_t;
                                            if archive_string_ensure(
                                                as_0,
                                                (*as_0)
                                                    .buffer_length
                                                    .wrapping_add(
                                                        len.wrapping_mul(tm as u64),
                                                    )
                                                    .wrapping_add(ts as u64),
                                            )
                                            .is_null()
                                            {
                                                return -(1 as i32);
                                            }
                                            p = (*as_0).s.offset((*as_0).length as isize);
                                            endp = (*as_0)
                                                .s
                                                .offset((*as_0).buffer_length as isize)
                                                .offset(-(ts as isize))
                                        }
                                        let mut current_block_297: u64;
                                        match n {
                                            4 => {
                                                let fresh45 = ucptr;
                                                ucptr = ucptr.offset(1);
                                                let fresh46 = p;
                                                p = p.offset(1);
                                                *fresh46 = *fresh45;
                                                current_block_297 = 13074264284986775319;
                                            }
                                            3 => {
                                                current_block_297 = 13074264284986775319;
                                            }
                                            2 => {
                                                current_block_297 = 7422398550536973736;
                                            }
                                            1 => {
                                                current_block_297 = 17173725837442240300;
                                            }
                                            _ => {
                                                current_block_297 = 6632235551759984864;
                                            }
                                        }
                                        match current_block_297 {
                                            13074264284986775319 => {
                                                let fresh47 = ucptr;
                                                ucptr = ucptr.offset(1);
                                                let fresh48 = p;
                                                p = p.offset(1);
                                                *fresh48 = *fresh47;
                                                current_block_297 = 7422398550536973736;
                                            }
                                            _ => {}
                                        }
                                        match current_block_297 {
                                            7422398550536973736 => {
                                                let fresh49 = ucptr;
                                                ucptr = ucptr.offset(1);
                                                let fresh50 = p;
                                                p = p.offset(1);
                                                *fresh50 = *fresh49;
                                                current_block_297 = 17173725837442240300;
                                            }
                                            _ => {}
                                        }
                                        match current_block_297 {
                                            17173725837442240300 => {
                                                let fresh51 = p;
                                                p = p.offset(1);
                                                *fresh51 = *ucptr
                                            }
                                            _ => {}
                                        }
                                        ucptr = 0 as *const i8
                                    } else {
                                        loop {
                                            w = unparse.expect("non-null function pointer")(
                                                p,
                                                endp.offset_from(p) as i64 as size_t,
                                                uc,
                                            );
                                            if !(w == 0 as i32 as u64) {
                                                break;
                                            }
                                            (*as_0).length =
                                                p.offset_from((*as_0).s) as i64 as size_t;
                                            if archive_string_ensure(
                                                as_0,
                                                (*as_0)
                                                    .buffer_length
                                                    .wrapping_add(
                                                        len.wrapping_mul(tm as u64),
                                                    )
                                                    .wrapping_add(ts as u64),
                                            )
                                            .is_null()
                                            {
                                                return -(1 as i32);
                                            }
                                            p = (*as_0).s.offset((*as_0).length as isize);
                                            endp = (*as_0)
                                                .s
                                                .offset((*as_0).buffer_length as isize)
                                                .offset(-(ts as isize))
                                        }
                                        p = p.offset(w as isize)
                                    }
                                    i = 0 as i32;
                                    while i < ucx_size {
                                        loop {
                                            w = unparse.expect("non-null function pointer")(
                                                p,
                                                endp.offset_from(p) as i64 as size_t,
                                                ucx[i as usize],
                                            );
                                            if !(w == 0 as i32 as u64) {
                                                break;
                                            }
                                            (*as_0).length =
                                                p.offset_from((*as_0).s) as i64 as size_t;
                                            if archive_string_ensure(
                                                as_0,
                                                (*as_0)
                                                    .buffer_length
                                                    .wrapping_add(
                                                        len.wrapping_mul(tm as u64),
                                                    )
                                                    .wrapping_add(ts as u64),
                                            )
                                            .is_null()
                                            {
                                                return -(1 as i32);
                                            }
                                            p = (*as_0).s.offset((*as_0).length as isize);
                                            endp = (*as_0)
                                                .s
                                                .offset((*as_0).buffer_length as isize)
                                                .offset(-(ts as isize))
                                        }
                                        p = p.offset(w as isize);
                                        i += 1
                                    }
                                    /*
                                     * Flush out remaining canonical combining characters.
                                     */
                                    if nx > 0 as i32
                                        && cx == cl
                                        && len > 0 as i32 as u64
                                    {
                                        loop {
                                            nx = parse.expect("non-null function pointer")(
                                                &mut *ucx
                                                    .as_mut_ptr()
                                                    .offset(0 as i32 as isize),
                                                s,
                                                len,
                                            );
                                            if !(nx > 0 as i32) {
                                                break;
                                            }
                                            cx = if ucx[0 as i32 as usize]
                                                > 0x1d244 as i32 as u32
                                            {
                                                0 as i32
                                            } else {
                                                ccc_val[(ccc_val_index[(ccc_index[(ucx
                                                    [0 as i32 as usize]
                                                    >> 8 as i32)
                                                    as usize]
                                                    as usize)
                                                    * (16 as usize)
                                                    + ((ucx[0 as i32 as usize]
                                                        >> 4 as i32
                                                        & 0xf as i32 as u32)
                                                        as usize)]
                                                    as usize)
                                                    * (16 as usize)
                                                    + ((ucx[0 as i32 as usize]
                                                        & 0xf as i32 as u32)
                                                        as usize)]
                                                    as i32
                                            };
                                            if cl > cx {
                                                break;
                                            }
                                            s = s.offset(nx as isize);
                                            len = (len as u64)
                                                .wrapping_sub(nx as u64)
                                                as size_t
                                                as size_t;
                                            cl = cx;
                                            loop {
                                                w = unparse.expect("non-null function pointer")(
                                                    p,
                                                    endp.offset_from(p) as i64 as size_t,
                                                    ucx[0 as i32 as usize],
                                                );
                                                if !(w == 0 as i32 as u64) {
                                                    break;
                                                }
                                                (*as_0).length = p.offset_from((*as_0).s)
                                                    as i64
                                                    as size_t;
                                                if archive_string_ensure(
                                                    as_0,
                                                    (*as_0)
                                                        .buffer_length
                                                        .wrapping_add(
                                                            len.wrapping_mul(tm as u64),
                                                        )
                                                        .wrapping_add(ts as u64),
                                                )
                                                .is_null()
                                                {
                                                    return -(1 as i32);
                                                }
                                                p = (*as_0).s.offset((*as_0).length as isize);
                                                endp = (*as_0)
                                                    .s
                                                    .offset((*as_0).buffer_length as isize)
                                                    .offset(-(ts as isize))
                                            }
                                            p = p.offset(w as isize)
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            if n2 < 0 as i32 {
                if !ucptr.is_null() {
                    if p.offset(n as isize) > endp {
                        (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                        if archive_string_ensure(
                            as_0,
                            (*as_0)
                                .buffer_length
                                .wrapping_add(len.wrapping_mul(tm as u64))
                                .wrapping_add(ts as u64),
                        )
                        .is_null()
                        {
                            return -(1 as i32);
                        }
                        p = (*as_0).s.offset((*as_0).length as isize);
                        endp = (*as_0)
                            .s
                            .offset((*as_0).buffer_length as isize)
                            .offset(-(ts as isize))
                    }
                    let mut current_block_362: u64;
                    match n {
                        4 => {
                            let fresh52 = ucptr;
                            ucptr = ucptr.offset(1);
                            let fresh53 = p;
                            p = p.offset(1);
                            *fresh53 = *fresh52;
                            current_block_362 = 3991391797406386710;
                        }
                        3 => {
                            current_block_362 = 3991391797406386710;
                        }
                        2 => {
                            current_block_362 = 14279400483080654501;
                        }
                        1 => {
                            current_block_362 = 12619937364747372903;
                        }
                        _ => {
                            current_block_362 = 16953886395775657100;
                        }
                    }
                    match current_block_362 {
                        3991391797406386710 => {
                            let fresh54 = ucptr;
                            ucptr = ucptr.offset(1);
                            let fresh55 = p;
                            p = p.offset(1);
                            *fresh55 = *fresh54;
                            current_block_362 = 14279400483080654501;
                        }
                        _ => {}
                    }
                    match current_block_362 {
                        14279400483080654501 => {
                            let fresh56 = ucptr;
                            ucptr = ucptr.offset(1);
                            let fresh57 = p;
                            p = p.offset(1);
                            *fresh57 = *fresh56;
                            current_block_362 = 12619937364747372903;
                        }
                        _ => {}
                    }
                    match current_block_362 {
                        12619937364747372903 => {
                            let fresh58 = p;
                            p = p.offset(1);
                            *fresh58 = *ucptr
                        }
                        _ => {}
                    }
                    ucptr = 0 as *const i8
                } else {
                    loop {
                        w = unparse.expect("non-null function pointer")(
                            p,
                            endp.offset_from(p) as i64 as size_t,
                            uc,
                        );
                        if !(w == 0 as i32 as u64) {
                            break;
                        }
                        (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                        if archive_string_ensure(
                            as_0,
                            (*as_0)
                                .buffer_length
                                .wrapping_add(len.wrapping_mul(tm as u64))
                                .wrapping_add(ts as u64),
                        )
                        .is_null()
                        {
                            return -(1 as i32);
                        }
                        p = (*as_0).s.offset((*as_0).length as isize);
                        endp = (*as_0)
                            .s
                            .offset((*as_0).buffer_length as isize)
                            .offset(-(ts as isize))
                    }
                    p = p.offset(w as isize)
                }
                /* Use a replaced unicode character. */
                loop {
                    w = unparse.expect("non-null function pointer")(
                        p,
                        endp.offset_from(p) as i64 as size_t,
                        uc2,
                    );
                    if !(w == 0 as i32 as u64) {
                        break;
                    }
                    (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                    if archive_string_ensure(
                        as_0,
                        (*as_0)
                            .buffer_length
                            .wrapping_add(len.wrapping_mul(tm as u64))
                            .wrapping_add(ts as u64),
                    )
                    .is_null()
                    {
                        return -(1 as i32);
                    }
                    p = (*as_0).s.offset((*as_0).length as isize);
                    endp = (*as_0)
                        .s
                        .offset((*as_0).buffer_length as isize)
                        .offset(-(ts as isize))
                }
                p = p.offset(w as isize);
                s = s.offset((n2 * -(1 as i32)) as isize);
                len = (len as u64)
                    .wrapping_sub((n2 * -(1 as i32)) as u64)
                    as size_t as size_t;
                ret = -(1 as i32)
            } else {
                if !(n2 == 0 as i32) {
                    continue;
                }
                if !ucptr.is_null() {
                    if p.offset(n as isize) > endp {
                        (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                        if archive_string_ensure(
                            as_0,
                            (*as_0)
                                .buffer_length
                                .wrapping_add(len.wrapping_mul(tm as u64))
                                .wrapping_add(ts as u64),
                        )
                        .is_null()
                        {
                            return -(1 as i32);
                        }
                        p = (*as_0).s.offset((*as_0).length as isize);
                        endp = (*as_0)
                            .s
                            .offset((*as_0).buffer_length as isize)
                            .offset(-(ts as isize))
                    }
                    let mut current_block_408: u64;
                    match n {
                        4 => {
                            let fresh59 = ucptr;
                            ucptr = ucptr.offset(1);
                            let fresh60 = p;
                            p = p.offset(1);
                            *fresh60 = *fresh59;
                            current_block_408 = 804933807915524214;
                        }
                        3 => {
                            current_block_408 = 804933807915524214;
                        }
                        2 => {
                            current_block_408 = 16839940683546283140;
                        }
                        1 => {
                            current_block_408 = 9498948812011783314;
                        }
                        _ => {
                            current_block_408 = 4637513635194184052;
                        }
                    }
                    match current_block_408 {
                        804933807915524214 => {
                            let fresh61 = ucptr;
                            ucptr = ucptr.offset(1);
                            let fresh62 = p;
                            p = p.offset(1);
                            *fresh62 = *fresh61;
                            current_block_408 = 16839940683546283140;
                        }
                        _ => {}
                    }
                    match current_block_408 {
                        16839940683546283140 => {
                            let fresh63 = ucptr;
                            ucptr = ucptr.offset(1);
                            let fresh64 = p;
                            p = p.offset(1);
                            *fresh64 = *fresh63;
                            current_block_408 = 9498948812011783314;
                        }
                        _ => {}
                    }
                    match current_block_408 {
                        9498948812011783314 => {
                            let fresh65 = p;
                            p = p.offset(1);
                            *fresh65 = *ucptr
                        }
                        _ => {}
                    }
                    ucptr = 0 as *const i8
                } else {
                    loop {
                        w = unparse.expect("non-null function pointer")(
                            p,
                            endp.offset_from(p) as i64 as size_t,
                            uc,
                        );
                        if !(w == 0 as i32 as u64) {
                            break;
                        }
                        (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                        if archive_string_ensure(
                            as_0,
                            (*as_0)
                                .buffer_length
                                .wrapping_add(len.wrapping_mul(tm as u64))
                                .wrapping_add(ts as u64),
                        )
                        .is_null()
                        {
                            return -(1 as i32);
                        }
                        p = (*as_0).s.offset((*as_0).length as isize);
                        endp = (*as_0)
                            .s
                            .offset((*as_0).buffer_length as isize)
                            .offset(-(ts as isize))
                    }
                    p = p.offset(w as isize)
                }
                break;
            }
        }
    }
    (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
    *(*as_0).s.offset((*as_0).length as isize) = '\u{0}' as i32 as i8;
    if ts == 2 as i32 {
        *(*as_0).s.offset(
            (*as_0)
                .length
                .wrapping_add(1 as i32 as u64) as isize,
        ) = '\u{0}' as i32 as i8
    }
    return ret;
}
unsafe extern "C" fn get_nfd(
    mut cp1: *mut uint32_t,
    mut cp2: *mut uint32_t,
    mut uc: uint32_t,
) -> i32 {
    let mut t: i32 = 0;
    let mut b: i32 = 0;
    /*
     * These are not converted to NFD on Mac OS.
     */
    if uc >= 0x2000 as i32 as u32 && uc <= 0x2fff as i32 as u32
        || uc >= 0xf900 as i32 as u32
            && uc <= 0xfaff as i32 as u32
        || uc >= 0x2f800 as i32 as u32
            && uc <= 0x2faff as i32 as u32
    {
        return 0 as i32;
    }
    /*
     * Those code points are not converted to NFD on Mac OS.
     * I do not know the reason because it is undocumented.
     *   NFC        NFD
     *   1109A  ==> 11099 110BA
     *   1109C  ==> 1109B 110BA
     *   110AB  ==> 110A5 110BA
     */
    if uc == 0x1109a as i32 as u32
        || uc == 0x1109c as i32 as u32
        || uc == 0x110ab as i32 as u32
    {
        return 0 as i32;
    }
    t = 0 as i32;
    b = (::std::mem::size_of::<[unicode_decomposition_table; 931]>() as u64)
        .wrapping_div(::std::mem::size_of::<unicode_decomposition_table>() as u64)
        .wrapping_sub(1 as i32 as u64) as i32;
    while b >= t {
        let mut m: i32 = (t + b) / 2 as i32;
        if u_decomposition_table[m as usize].nfc < uc {
            t = m + 1 as i32
        } else if u_decomposition_table[m as usize].nfc > uc {
            b = m - 1 as i32
        } else {
            *cp1 = u_decomposition_table[m as usize].cp1;
            *cp2 = u_decomposition_table[m as usize].cp2;
            return 1 as i32;
        }
    }
    return 0 as i32;
}
/*
* Normalize UTF-8 characters to Form D and copy the result.
*/
unsafe extern "C" fn archive_string_normalize_D(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut len: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut s: *const i8 = _p as *const i8; /* text size. */
    let mut p: *mut i8 = 0 as *mut i8;
    let mut endp: *mut i8 = 0 as *mut i8;
    let mut uc: uint32_t = 0;
    let mut uc2: uint32_t = 0;
    let mut w: size_t = 0;
    let mut always_replace: i32 = 0;
    let mut n: i32 = 0;
    let mut n2: i32 = 0;
    let mut ret: i32 = 0 as i32;
    let mut spair: i32 = 0;
    let mut ts: i32 = 0;
    let mut tm: i32 = 0;
    let mut parse: Option<
        unsafe extern "C" fn(_: *mut uint32_t, _: *const i8, _: size_t) -> i32,
    > = None;
    let mut unparse: Option<
        unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
    > = None;
    always_replace = 1 as i32;
    ts = 1 as i32;
    if (*sc).flag & (1 as i32) << 10 as i32 != 0 {
        unparse = Some(
            unicode_to_utf16be
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        ts = 2 as i32;
        if (*sc).flag & (1 as i32) << 11 as i32 != 0 {
            always_replace = 0 as i32
        }
    } else if (*sc).flag & (1 as i32) << 12 as i32 != 0 {
        unparse = Some(
            unicode_to_utf16le
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        ts = 2 as i32;
        if (*sc).flag & (1 as i32) << 13 as i32 != 0 {
            always_replace = 0 as i32
        }
    } else if (*sc).flag & (1 as i32) << 8 as i32 != 0 {
        unparse = Some(
            unicode_to_utf8
                as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
        );
        if (*sc).flag & (1 as i32) << 9 as i32 != 0 {
            always_replace = 0 as i32
        }
    } else {
        /*
         * This case is going to be converted to another
         * character-set through iconv.
         */
        always_replace = 0 as i32;
        if (*sc).flag & (1 as i32) << 11 as i32 != 0 {
            unparse = Some(
                unicode_to_utf16be
                    as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
            );
            ts = 2 as i32
        } else if (*sc).flag & (1 as i32) << 13 as i32 != 0 {
            unparse = Some(
                unicode_to_utf16le
                    as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
            );
            ts = 2 as i32
        } else {
            unparse = Some(
                unicode_to_utf8
                    as unsafe extern "C" fn(_: *mut i8, _: size_t, _: uint32_t) -> size_t,
            )
        }
    }
    if (*sc).flag & (1 as i32) << 11 as i32 != 0 {
        parse = Some(
            utf16be_to_unicode
                as unsafe extern "C" fn(
                    _: *mut uint32_t,
                    _: *const i8,
                    _: size_t,
                ) -> i32,
        );
        tm = 1 as i32;
        spair = 4 as i32
        /* surrogate pair size in UTF-16. */
    } else if (*sc).flag & (1 as i32) << 13 as i32 != 0 {
        parse = Some(
            utf16le_to_unicode
                as unsafe extern "C" fn(
                    _: *mut uint32_t,
                    _: *const i8,
                    _: size_t,
                ) -> i32,
        );
        tm = 1 as i32;
        spair = 4 as i32
        /* surrogate pair size in UTF-16. */
    } else {
        parse = Some(
            cesu8_to_unicode
                as unsafe extern "C" fn(
                    _: *mut uint32_t,
                    _: *const i8,
                    _: size_t,
                ) -> i32,
        );
        tm = ts;
        spair = 6 as i32
        /* surrogate pair size in UTF-8. */
    }
    if archive_string_ensure(
        as_0,
        (*as_0)
            .length
            .wrapping_add(len.wrapping_mul(tm as u64))
            .wrapping_add(ts as u64),
    )
    .is_null()
    {
        return -(1 as i32);
    }
    p = (*as_0).s.offset((*as_0).length as isize);
    endp = (*as_0)
        .s
        .offset((*as_0).buffer_length as isize)
        .offset(-(ts as isize));
    's_239: loop {
        n = parse.expect("non-null function pointer")(&mut uc, s, len);
        if !(n != 0 as i32) {
            break;
        }
        let mut ucptr: *const i8 = 0 as *const i8;
        let mut cp1: uint32_t = 0;
        let mut cp2: uint32_t = 0;
        let mut SIndex: i32 = 0;
        let mut fdc: [archive_string_fdc; 10] = [archive_string_fdc { uc: 0, ccc: 0 }; 10];
        let mut fdi: i32 = 0;
        let mut fdj: i32 = 0;
        let mut ccc: i32 = 0;
        loop {
            if n < 0 as i32 {
                /* Use a replaced unicode character. */
                loop {
                    w = unparse.expect("non-null function pointer")(
                        p,
                        endp.offset_from(p) as i64 as size_t,
                        uc,
                    );
                    if !(w == 0 as i32 as u64) {
                        break;
                    }
                    (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                    if archive_string_ensure(
                        as_0,
                        (*as_0)
                            .buffer_length
                            .wrapping_add(len.wrapping_mul(tm as u64))
                            .wrapping_add(ts as u64),
                    )
                    .is_null()
                    {
                        return -(1 as i32);
                    }
                    p = (*as_0).s.offset((*as_0).length as isize);
                    endp = (*as_0)
                        .s
                        .offset((*as_0).buffer_length as isize)
                        .offset(-(ts as isize))
                }
                p = p.offset(w as isize);
                s = s.offset((n * -(1 as i32)) as isize);
                len = (len as u64)
                    .wrapping_sub((n * -(1 as i32)) as u64)
                    as size_t as size_t;
                ret = -(1 as i32);
                break;
            } else {
                if n == spair || always_replace != 0 {
                    /* uc is converted from a surrogate pair.
                     * this should be treated as a changed code. */
                    ucptr = 0 as *const i8
                } else {
                    ucptr = s
                }
                s = s.offset(n as isize);
                len = (len as u64).wrapping_sub(n as u64) as size_t as size_t;
                /* Hangul Decomposition. */
                SIndex = uc.wrapping_sub(0xac00 as i32 as u32) as i32;
                if SIndex >= 0 as i32
                    && SIndex < 19 as i32 * (21 as i32 * 28 as i32)
                {
                    let mut L: i32 =
                        0x1100 as i32 + SIndex / (21 as i32 * 28 as i32);
                    let mut V: i32 = 0x1161 as i32
                        + SIndex % (21 as i32 * 28 as i32) / 28 as i32;
                    let mut T: i32 = 0x11a7 as i32 + SIndex % 28 as i32;
                    uc = L as uint32_t;
                    ucptr = 0 as *const i8;
                    if !ucptr.is_null() {
                        if p.offset(n as isize) > endp {
                            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                            if archive_string_ensure(
                                as_0,
                                (*as_0)
                                    .buffer_length
                                    .wrapping_add(len.wrapping_mul(tm as u64))
                                    .wrapping_add(ts as u64),
                            )
                            .is_null()
                            {
                                return -(1 as i32);
                            }
                            p = (*as_0).s.offset((*as_0).length as isize);
                            endp = (*as_0)
                                .s
                                .offset((*as_0).buffer_length as isize)
                                .offset(-(ts as isize))
                        }
                        let mut current_block_84: u64;
                        match n {
                            4 => {
                                let fresh66 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh67 = p;
                                p = p.offset(1);
                                *fresh67 = *fresh66;
                                current_block_84 = 10535158022184288841;
                            }
                            3 => {
                                current_block_84 = 10535158022184288841;
                            }
                            2 => {
                                current_block_84 = 15881180934339525083;
                            }
                            1 => {
                                current_block_84 = 17578101850656618887;
                            }
                            _ => {
                                current_block_84 = 16313536926714486912;
                            }
                        }
                        match current_block_84 {
                            10535158022184288841 => {
                                let fresh68 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh69 = p;
                                p = p.offset(1);
                                *fresh69 = *fresh68;
                                current_block_84 = 15881180934339525083;
                            }
                            _ => {}
                        }
                        match current_block_84 {
                            15881180934339525083 => {
                                let fresh70 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh71 = p;
                                p = p.offset(1);
                                *fresh71 = *fresh70;
                                current_block_84 = 17578101850656618887;
                            }
                            _ => {}
                        }
                        match current_block_84 {
                            17578101850656618887 => {
                                let fresh72 = p;
                                p = p.offset(1);
                                *fresh72 = *ucptr
                            }
                            _ => {}
                        }
                        ucptr = 0 as *const i8
                    } else {
                        loop {
                            w = unparse.expect("non-null function pointer")(
                                p,
                                endp.offset_from(p) as i64 as size_t,
                                uc,
                            );
                            if !(w == 0 as i32 as u64) {
                                break;
                            }
                            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                            if archive_string_ensure(
                                as_0,
                                (*as_0)
                                    .buffer_length
                                    .wrapping_add(len.wrapping_mul(tm as u64))
                                    .wrapping_add(ts as u64),
                            )
                            .is_null()
                            {
                                return -(1 as i32);
                            }
                            p = (*as_0).s.offset((*as_0).length as isize);
                            endp = (*as_0)
                                .s
                                .offset((*as_0).buffer_length as isize)
                                .offset(-(ts as isize))
                        }
                        p = p.offset(w as isize)
                    }
                    uc = V as uint32_t;
                    ucptr = 0 as *const i8;
                    if !ucptr.is_null() {
                        if p.offset(n as isize) > endp {
                            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                            if archive_string_ensure(
                                as_0,
                                (*as_0)
                                    .buffer_length
                                    .wrapping_add(len.wrapping_mul(tm as u64))
                                    .wrapping_add(ts as u64),
                            )
                            .is_null()
                            {
                                return -(1 as i32);
                            }
                            p = (*as_0).s.offset((*as_0).length as isize);
                            endp = (*as_0)
                                .s
                                .offset((*as_0).buffer_length as isize)
                                .offset(-(ts as isize))
                        }
                        let mut current_block_119: u64;
                        match n {
                            4 => {
                                let fresh73 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh74 = p;
                                p = p.offset(1);
                                *fresh74 = *fresh73;
                                current_block_119 = 652883618805845336;
                            }
                            3 => {
                                current_block_119 = 652883618805845336;
                            }
                            2 => {
                                current_block_119 = 10885381508539941565;
                            }
                            1 => {
                                current_block_119 = 1748720607929988918;
                            }
                            _ => {
                                current_block_119 = 17212496701767205014;
                            }
                        }
                        match current_block_119 {
                            652883618805845336 => {
                                let fresh75 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh76 = p;
                                p = p.offset(1);
                                *fresh76 = *fresh75;
                                current_block_119 = 10885381508539941565;
                            }
                            _ => {}
                        }
                        match current_block_119 {
                            10885381508539941565 => {
                                let fresh77 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh78 = p;
                                p = p.offset(1);
                                *fresh78 = *fresh77;
                                current_block_119 = 1748720607929988918;
                            }
                            _ => {}
                        }
                        match current_block_119 {
                            1748720607929988918 => {
                                let fresh79 = p;
                                p = p.offset(1);
                                *fresh79 = *ucptr
                            }
                            _ => {}
                        }
                        ucptr = 0 as *const i8
                    } else {
                        loop {
                            w = unparse.expect("non-null function pointer")(
                                p,
                                endp.offset_from(p) as i64 as size_t,
                                uc,
                            );
                            if !(w == 0 as i32 as u64) {
                                break;
                            }
                            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                            if archive_string_ensure(
                                as_0,
                                (*as_0)
                                    .buffer_length
                                    .wrapping_add(len.wrapping_mul(tm as u64))
                                    .wrapping_add(ts as u64),
                            )
                            .is_null()
                            {
                                return -(1 as i32);
                            }
                            p = (*as_0).s.offset((*as_0).length as isize);
                            endp = (*as_0)
                                .s
                                .offset((*as_0).buffer_length as isize)
                                .offset(-(ts as isize))
                        }
                        p = p.offset(w as isize)
                    }
                    if T != 0x11a7 as i32 {
                        uc = T as uint32_t;
                        ucptr = 0 as *const i8;
                        if !ucptr.is_null() {
                            if p.offset(n as isize) > endp {
                                (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                                if archive_string_ensure(
                                    as_0,
                                    (*as_0)
                                        .buffer_length
                                        .wrapping_add(len.wrapping_mul(tm as u64))
                                        .wrapping_add(ts as u64),
                                )
                                .is_null()
                                {
                                    return -(1 as i32);
                                }
                                p = (*as_0).s.offset((*as_0).length as isize);
                                endp = (*as_0)
                                    .s
                                    .offset((*as_0).buffer_length as isize)
                                    .offset(-(ts as isize))
                            }
                            let mut current_block_154: u64;
                            match n {
                                4 => {
                                    let fresh80 = ucptr;
                                    ucptr = ucptr.offset(1);
                                    let fresh81 = p;
                                    p = p.offset(1);
                                    *fresh81 = *fresh80;
                                    current_block_154 = 11334115477782272202;
                                }
                                3 => {
                                    current_block_154 = 11334115477782272202;
                                }
                                2 => {
                                    current_block_154 = 13290801189948907371;
                                }
                                1 => {
                                    current_block_154 = 3884795544804557996;
                                }
                                _ => {
                                    current_block_154 = 4183419379601546972;
                                }
                            }
                            match current_block_154 {
                                11334115477782272202 => {
                                    let fresh82 = ucptr;
                                    ucptr = ucptr.offset(1);
                                    let fresh83 = p;
                                    p = p.offset(1);
                                    *fresh83 = *fresh82;
                                    current_block_154 = 13290801189948907371;
                                }
                                _ => {}
                            }
                            match current_block_154 {
                                13290801189948907371 => {
                                    let fresh84 = ucptr;
                                    ucptr = ucptr.offset(1);
                                    let fresh85 = p;
                                    p = p.offset(1);
                                    *fresh85 = *fresh84;
                                    current_block_154 = 3884795544804557996;
                                }
                                _ => {}
                            }
                            match current_block_154 {
                                3884795544804557996 => {
                                    let fresh86 = p;
                                    p = p.offset(1);
                                    *fresh86 = *ucptr
                                }
                                _ => {}
                            }
                            ucptr = 0 as *const i8
                        } else {
                            loop {
                                w = unparse.expect("non-null function pointer")(
                                    p,
                                    endp.offset_from(p) as i64 as size_t,
                                    uc,
                                );
                                if !(w == 0 as i32 as u64) {
                                    break;
                                }
                                (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                                if archive_string_ensure(
                                    as_0,
                                    (*as_0)
                                        .buffer_length
                                        .wrapping_add(len.wrapping_mul(tm as u64))
                                        .wrapping_add(ts as u64),
                                )
                                .is_null()
                                {
                                    return -(1 as i32);
                                }
                                p = (*as_0).s.offset((*as_0).length as isize);
                                endp = (*as_0)
                                    .s
                                    .offset((*as_0).buffer_length as isize)
                                    .offset(-(ts as isize))
                            }
                            p = p.offset(w as isize)
                        }
                    }
                    break;
                } else if uc >> 8 as i32 <= 0x1d2 as i32 as u32
                    && u_decomposable_blocks[(uc >> 8 as i32) as usize] as i32 != 0
                    && (if uc > 0x1d244 as i32 as u32 {
                        0 as i32
                    } else {
                        ccc_val[(ccc_val_index[(ccc_index[(uc >> 8 as i32) as usize]
                            as usize)
                            * (16 as usize)
                            + ((uc >> 4 as i32 & 0xf as i32 as u32)
                                as usize)] as usize)
                            * (16 as usize)
                            + ((uc & 0xf as i32 as u32) as usize)]
                            as i32
                    }) != 0 as i32
                {
                    if !ucptr.is_null() {
                        if p.offset(n as isize) > endp {
                            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                            if archive_string_ensure(
                                as_0,
                                (*as_0)
                                    .buffer_length
                                    .wrapping_add(len.wrapping_mul(tm as u64))
                                    .wrapping_add(ts as u64),
                            )
                            .is_null()
                            {
                                return -(1 as i32);
                            }
                            p = (*as_0).s.offset((*as_0).length as isize);
                            endp = (*as_0)
                                .s
                                .offset((*as_0).buffer_length as isize)
                                .offset(-(ts as isize))
                        }
                        let mut current_block_187: u64;
                        match n {
                            4 => {
                                let fresh87 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh88 = p;
                                p = p.offset(1);
                                *fresh88 = *fresh87;
                                current_block_187 = 15076157755807638962;
                            }
                            3 => {
                                current_block_187 = 15076157755807638962;
                            }
                            2 => {
                                current_block_187 = 8544706183542245510;
                            }
                            1 => {
                                current_block_187 = 13594670467416856355;
                            }
                            _ => {
                                current_block_187 = 11577926782275222206;
                            }
                        }
                        match current_block_187 {
                            15076157755807638962 => {
                                let fresh89 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh90 = p;
                                p = p.offset(1);
                                *fresh90 = *fresh89;
                                current_block_187 = 8544706183542245510;
                            }
                            _ => {}
                        }
                        match current_block_187 {
                            8544706183542245510 => {
                                let fresh91 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh92 = p;
                                p = p.offset(1);
                                *fresh92 = *fresh91;
                                current_block_187 = 13594670467416856355;
                            }
                            _ => {}
                        }
                        match current_block_187 {
                            13594670467416856355 => {
                                let fresh93 = p;
                                p = p.offset(1);
                                *fresh93 = *ucptr
                            }
                            _ => {}
                        }
                        ucptr = 0 as *const i8
                    } else {
                        loop {
                            w = unparse.expect("non-null function pointer")(
                                p,
                                endp.offset_from(p) as i64 as size_t,
                                uc,
                            );
                            if !(w == 0 as i32 as u64) {
                                break;
                            }
                            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                            if archive_string_ensure(
                                as_0,
                                (*as_0)
                                    .buffer_length
                                    .wrapping_add(len.wrapping_mul(tm as u64))
                                    .wrapping_add(ts as u64),
                            )
                            .is_null()
                            {
                                return -(1 as i32);
                            }
                            p = (*as_0).s.offset((*as_0).length as isize);
                            endp = (*as_0)
                                .s
                                .offset((*as_0).buffer_length as isize)
                                .offset(-(ts as isize))
                        }
                        p = p.offset(w as isize)
                    }
                    break;
                } else {
                    fdi = 0 as i32;
                    while get_nfd(&mut cp1, &mut cp2, uc) != 0 && fdi < 10 as i32 {
                        let mut k: i32 = 0;
                        k = fdi;
                        while k > 0 as i32 {
                            fdc[k as usize] = fdc[(k - 1 as i32) as usize];
                            k -= 1
                        }
                        fdc[0 as i32 as usize].ccc = if cp2
                            > 0x1d244 as i32 as u32
                        {
                            0 as i32
                        } else {
                            ccc_val[(ccc_val_index[(ccc_index[(cp2 >> 8 as i32) as usize]
                                as usize)
                                * (16 as usize)
                                + ((cp2 >> 4 as i32 & 0xf as i32 as u32)
                                    as usize)] as usize)
                                * (16 as usize)
                                + ((cp2 & 0xf as i32 as u32) as usize)]
                                as i32
                        };
                        fdc[0 as i32 as usize].uc = cp2;
                        fdi += 1;
                        uc = cp1;
                        ucptr = 0 as *const i8
                    }
                    loop
                    /* Read following code points. */
                    {
                        n2 = parse.expect("non-null function pointer")(&mut uc2, s, len);
                        if !(n2 > 0 as i32
                            && {
                                ccc = (if uc2 > 0x1d244 as i32 as u32 {
                                    0 as i32
                                } else {
                                    ccc_val[(ccc_val_index[(ccc_index
                                        [(uc2 >> 8 as i32) as usize]
                                        as usize)
                                        * (16 as usize)
                                        + ((uc2 >> 4 as i32
                                            & 0xf as i32 as u32)
                                            as usize)]
                                        as usize)
                                        * (16 as usize)
                                        + ((uc2 & 0xf as i32 as u32) as usize)]
                                        as i32
                                });
                                (ccc) != 0 as i32
                            }
                            && fdi < 10 as i32)
                        {
                            break;
                        }
                        let mut j: i32 = 0;
                        let mut k_0: i32 = 0;
                        s = s.offset(n2 as isize);
                        len = (len as u64).wrapping_sub(n2 as u64) as size_t
                            as size_t;
                        j = 0 as i32;
                        while j < fdi {
                            if fdc[j as usize].ccc > ccc {
                                break;
                            }
                            j += 1
                        }
                        if j < fdi {
                            k_0 = fdi;
                            while k_0 > j {
                                fdc[k_0 as usize] = fdc[(k_0 - 1 as i32) as usize];
                                k_0 -= 1
                            }
                            fdc[j as usize].ccc = ccc;
                            fdc[j as usize].uc = uc2
                        } else {
                            fdc[fdi as usize].ccc = ccc;
                            fdc[fdi as usize].uc = uc2
                        }
                        fdi += 1
                    }
                    if !ucptr.is_null() {
                        if p.offset(n as isize) > endp {
                            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                            if archive_string_ensure(
                                as_0,
                                (*as_0)
                                    .buffer_length
                                    .wrapping_add(len.wrapping_mul(tm as u64))
                                    .wrapping_add(ts as u64),
                            )
                            .is_null()
                            {
                                return -(1 as i32);
                            }
                            p = (*as_0).s.offset((*as_0).length as isize);
                            endp = (*as_0)
                                .s
                                .offset((*as_0).buffer_length as isize)
                                .offset(-(ts as isize))
                        }
                        let mut current_block_248: u64;
                        match n {
                            4 => {
                                let fresh94 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh95 = p;
                                p = p.offset(1);
                                *fresh95 = *fresh94;
                                current_block_248 = 5730170476962647712;
                            }
                            3 => {
                                current_block_248 = 5730170476962647712;
                            }
                            2 => {
                                current_block_248 = 6046738488882787953;
                            }
                            1 => {
                                current_block_248 = 14641881900868759609;
                            }
                            _ => {
                                current_block_248 = 5564518856185825108;
                            }
                        }
                        match current_block_248 {
                            5730170476962647712 => {
                                let fresh96 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh97 = p;
                                p = p.offset(1);
                                *fresh97 = *fresh96;
                                current_block_248 = 6046738488882787953;
                            }
                            _ => {}
                        }
                        match current_block_248 {
                            6046738488882787953 => {
                                let fresh98 = ucptr;
                                ucptr = ucptr.offset(1);
                                let fresh99 = p;
                                p = p.offset(1);
                                *fresh99 = *fresh98;
                                current_block_248 = 14641881900868759609;
                            }
                            _ => {}
                        }
                        match current_block_248 {
                            14641881900868759609 => {
                                let fresh100 = p;
                                p = p.offset(1);
                                *fresh100 = *ucptr
                            }
                            _ => {}
                        }
                        ucptr = 0 as *const i8
                    } else {
                        loop {
                            w = unparse.expect("non-null function pointer")(
                                p,
                                endp.offset_from(p) as i64 as size_t,
                                uc,
                            );
                            if !(w == 0 as i32 as u64) {
                                break;
                            }
                            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                            if archive_string_ensure(
                                as_0,
                                (*as_0)
                                    .buffer_length
                                    .wrapping_add(len.wrapping_mul(tm as u64))
                                    .wrapping_add(ts as u64),
                            )
                            .is_null()
                            {
                                return -(1 as i32);
                            }
                            p = (*as_0).s.offset((*as_0).length as isize);
                            endp = (*as_0)
                                .s
                                .offset((*as_0).buffer_length as isize)
                                .offset(-(ts as isize))
                        }
                        p = p.offset(w as isize)
                    }
                    fdj = 0 as i32;
                    while fdj < fdi {
                        uc = fdc[fdj as usize].uc;
                        ucptr = 0 as *const i8;
                        if !ucptr.is_null() {
                            if p.offset(n as isize) > endp {
                                (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                                if archive_string_ensure(
                                    as_0,
                                    (*as_0)
                                        .buffer_length
                                        .wrapping_add(len.wrapping_mul(tm as u64))
                                        .wrapping_add(ts as u64),
                                )
                                .is_null()
                                {
                                    return -(1 as i32);
                                }
                                p = (*as_0).s.offset((*as_0).length as isize);
                                endp = (*as_0)
                                    .s
                                    .offset((*as_0).buffer_length as isize)
                                    .offset(-(ts as isize))
                            }
                            let mut current_block_284: u64;
                            match n {
                                4 => {
                                    let fresh101 = ucptr;
                                    ucptr = ucptr.offset(1);
                                    let fresh102 = p;
                                    p = p.offset(1);
                                    *fresh102 = *fresh101;
                                    current_block_284 = 2175997127793452133;
                                }
                                3 => {
                                    current_block_284 = 2175997127793452133;
                                }
                                2 => {
                                    current_block_284 = 16996603591816194332;
                                }
                                1 => {
                                    current_block_284 = 3495754285402390224;
                                }
                                _ => {
                                    current_block_284 = 16070719095729554596;
                                }
                            }
                            match current_block_284 {
                                2175997127793452133 => {
                                    let fresh103 = ucptr;
                                    ucptr = ucptr.offset(1);
                                    let fresh104 = p;
                                    p = p.offset(1);
                                    *fresh104 = *fresh103;
                                    current_block_284 = 16996603591816194332;
                                }
                                _ => {}
                            }
                            match current_block_284 {
                                16996603591816194332 => {
                                    let fresh105 = ucptr;
                                    ucptr = ucptr.offset(1);
                                    let fresh106 = p;
                                    p = p.offset(1);
                                    *fresh106 = *fresh105;
                                    current_block_284 = 3495754285402390224;
                                }
                                _ => {}
                            }
                            match current_block_284 {
                                3495754285402390224 => {
                                    let fresh107 = p;
                                    p = p.offset(1);
                                    *fresh107 = *ucptr
                                }
                                _ => {}
                            }
                            ucptr = 0 as *const i8
                        } else {
                            loop {
                                w = unparse.expect("non-null function pointer")(
                                    p,
                                    endp.offset_from(p) as i64 as size_t,
                                    uc,
                                );
                                if !(w == 0 as i32 as u64) {
                                    break;
                                }
                                (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
                                if archive_string_ensure(
                                    as_0,
                                    (*as_0)
                                        .buffer_length
                                        .wrapping_add(len.wrapping_mul(tm as u64))
                                        .wrapping_add(ts as u64),
                                )
                                .is_null()
                                {
                                    return -(1 as i32);
                                }
                                p = (*as_0).s.offset((*as_0).length as isize);
                                endp = (*as_0)
                                    .s
                                    .offset((*as_0).buffer_length as isize)
                                    .offset(-(ts as isize))
                            }
                            p = p.offset(w as isize)
                        }
                        fdj += 1
                    }
                    if n2 == 0 as i32 {
                        break 's_239;
                    }
                    uc = uc2;
                    ucptr = 0 as *const i8;
                    n = n2
                }
            }
        }
    }
    (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
    *(*as_0).s.offset((*as_0).length as isize) = '\u{0}' as i32 as i8;
    if ts == 2 as i32 {
        *(*as_0).s.offset(
            (*as_0)
                .length
                .wrapping_add(1 as i32 as u64) as isize,
        ) = '\u{0}' as i32 as i8
    }
    return ret;
}
/*
* libarchive 2.x made incorrect UTF-8 strings in the wrong assumption
* that WCS is Unicode. It is true for several platforms but some are false.
* And then people who did not use UTF-8 locale on the non Unicode WCS
* platform and made a tar file with libarchive(mostly bsdtar) 2.x. Those
* now cannot get right filename from libarchive 3.x and later since we
* fixed the wrong assumption and it is incompatible to older its versions.
* So we provide special option, "compat-2x.x", for resolving it.
* That option enable the string conversion of libarchive 2.x.
*
* Translates the wrong UTF-8 string made by libarchive 2.x into current
* locale character set and appends to the archive_string.
* Note: returns -1 if conversion fails.
*/
unsafe extern "C" fn strncat_from_utf8_libarchive2(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut len: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut s: *const i8 = 0 as *const i8;
    let mut n: i32 = 0;
    let mut p: *mut i8 = 0 as *mut i8;
    let mut end: *mut i8 = 0 as *mut i8;
    let mut unicode: uint32_t = 0;
    let mut shift_state: mbstate_t = mbstate_t {
        __count: 0,
        __value: archive_string_shift_state { __wch: 0 },
    };
    memset_safe(
        &mut shift_state as *mut mbstate_t as *mut (),
        0 as i32,
        ::std::mem::size_of::<mbstate_t>() as u64,
    );
    /* UNUSED */
    /*
     * Allocate buffer for MBS.
     * We need this allocation here since it is possible that
     * as->s is still NULL.
     */
    if archive_string_ensure(
        as_0,
        (*as_0)
            .length
            .wrapping_add(len)
            .wrapping_add(1 as i32 as u64),
    )
    .is_null()
    {
        return -(1 as i32);
    }
    s = _p as *const i8;
    p = (*as_0).s.offset((*as_0).length as isize);
    end = (*as_0)
        .s
        .offset((*as_0).buffer_length as isize)
        .offset(-(__ctype_get_mb_cur_max_safe() as isize))
        .offset(-(1 as i32 as isize));
    loop {
        n = _utf8_to_unicode(&mut unicode, s, len);
        if !(n != 0 as i32) {
            break;
        }
        let mut wc: wchar_t = 0;
        if p >= end {
            (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
            /* Re-allocate buffer for MBS. */
            if archive_string_ensure(
                as_0,
                (*as_0)
                    .length
                    .wrapping_add(
                        (if len.wrapping_mul(2 as i32 as u64)
                            > __ctype_get_mb_cur_max_safe()
                        {
                            len.wrapping_mul(2 as i32 as u64)
                        } else {
                            __ctype_get_mb_cur_max_safe()
                        }),
                    )
                    .wrapping_add(1 as i32 as u64),
            )
            .is_null()
            {
                return -(1 as i32);
            }
            p = (*as_0).s.offset((*as_0).length as isize);
            end = (*as_0)
                .s
                .offset((*as_0).buffer_length as isize)
                .offset(-(__ctype_get_mb_cur_max_safe() as isize))
                .offset(-(1 as i32 as isize))
        }
        /*
         * As libarchive 2.x, translates the UTF-8 characters into
         * wide-characters in the assumption that WCS is Unicode.
         */
        if n < 0 as i32 {
            n *= -(1 as i32);
            wc = '?' as wchar_t
        } else {
            wc = unicode as wchar_t
        }
        s = s.offset(n as isize);
        len = (len as u64).wrapping_sub(n as u64) as size_t as size_t;
        /*
         * Translates the wide-character into the current locale MBS.
         */
        n = wcrtomb(p, wc, &mut shift_state) as i32;
        if n == -(1 as i32) {
            return -(1 as i32);
        }
        p = p.offset(n as isize)
    }
    (*as_0).length = p.offset_from((*as_0).s) as i64 as size_t;
    *(*as_0).s.offset((*as_0).length as isize) = '\u{0}' as i32 as i8;
    return 0 as i32;
}
/*
* Conversion functions between current locale dependent MBS and UTF-16BE.
*   strncat_from_utf16be() : UTF-16BE --> MBS
*   strncat_to_utf16be()   : MBS --> UTF16BE
*/
/* _WIN32 && !__CYGWIN__ */
/*
* Do the best effort for conversions.
* We cannot handle UTF-16BE character-set without such iconv,
* but there is a chance if a string consists just ASCII code or
* a current locale is UTF-8.
*/
/*
* Convert a UTF-16BE string to current locale and copy the result.
* Return -1 if conversion fails.
*/
unsafe extern "C" fn best_effort_strncat_from_utf16(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut bytes: size_t,
    mut sc: *mut archive_string_conv,
    mut be: i32,
) -> i32 {
    let mut utf16: *const i8 = _p as *const i8;
    let mut mbs: *mut i8 = 0 as *mut i8;
    let mut uc: uint32_t = 0;
    let mut n: i32 = 0;
    let mut ret: i32 = 0;
    /* UNUSED */
    /*
     * Other case, we should do the best effort.
     * If all character are ASCII(<0x7f), we can convert it.
     * if not , we set a alternative character and return -1.
     */
    ret = 0 as i32;
    if archive_string_ensure(
        as_0,
        (*as_0)
            .length
            .wrapping_add(bytes)
            .wrapping_add(1 as i32 as u64),
    )
    .is_null()
    {
        return -(1 as i32);
    }
    mbs = (*as_0).s.offset((*as_0).length as isize);
    loop {
        n = utf16_to_unicode(&mut uc, utf16, bytes, be);
        if !(n != 0 as i32) {
            break;
        }
        if n < 0 as i32 {
            n *= -(1 as i32);
            ret = -(1 as i32)
        }
        bytes = (bytes as u64).wrapping_sub(n as u64) as size_t as size_t;
        utf16 = utf16.offset(n as isize);
        if uc > 127 as i32 as u32 {
            /* We cannot handle it. */
            let fresh108 = mbs;
            mbs = mbs.offset(1);
            *fresh108 = '?' as i32 as i8;
            ret = -(1 as i32)
        } else {
            let fresh109 = mbs;
            mbs = mbs.offset(1);
            *fresh109 = uc as i8
        }
    }
    (*as_0).length = mbs.offset_from((*as_0).s) as i64 as size_t;
    *(*as_0).s.offset((*as_0).length as isize) = '\u{0}' as i32 as i8;
    return ret;
}
unsafe extern "C" fn best_effort_strncat_from_utf16be(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut bytes: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    return best_effort_strncat_from_utf16(as_0, _p, bytes, sc, 1 as i32);
}
unsafe extern "C" fn best_effort_strncat_from_utf16le(
    mut as_0: *mut archive_string,
    mut _p: *const (),
    mut bytes: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    return best_effort_strncat_from_utf16(as_0, _p, bytes, sc, 0 as i32);
}
/*
* Convert a current locale string to UTF-16BE/LE and copy the result.
* Return -1 if conversion fails.
*/
unsafe extern "C" fn best_effort_strncat_to_utf16(
    mut as16: *mut archive_string,
    mut _p: *const (),
    mut length: size_t,
    mut sc: *mut archive_string_conv,
    mut bigendian: i32,
) -> i32 {
    let mut s: *const i8 = _p as *const i8;
    let mut utf16: *mut i8 = 0 as *mut i8;
    let mut remaining: size_t = 0;
    let mut ret: i32 = 0;
    /* UNUSED */
    /*
     * Other case, we should do the best effort.
     * If all character are ASCII(<0x7f), we can convert it.
     * if not , we set a alternative character and return -1.
     */
    ret = 0 as i32;
    remaining = length;
    if archive_string_ensure(
        as16,
        (*as16).length.wrapping_add(
            length
                .wrapping_add(1 as i32 as u64)
                .wrapping_mul(2 as i32 as u64),
        ),
    )
    .is_null()
    {
        return -(1 as i32);
    }
    utf16 = (*as16).s.offset((*as16).length as isize);
    loop {
        let fresh110 = remaining;
        remaining = remaining.wrapping_sub(1);
        if !(fresh110 != 0) {
            break;
        }
        let fresh111 = s;
        s = s.offset(1);
        let mut c: u32 = *fresh111 as u32;
        if c > 127 as i32 as u32 {
            /* We cannot handle it. */
            c = 0xfffd as i32 as u32;
            ret = -(1 as i32)
        }
        if bigendian != 0 {
            archive_be16enc(utf16 as *mut (), c as uint16_t);
        } else {
            archive_le16enc(utf16 as *mut (), c as uint16_t);
        }
        utf16 = utf16.offset(2 as i32 as isize)
    }
    (*as16).length = utf16.offset_from((*as16).s) as i64 as size_t;
    *(*as16).s.offset((*as16).length as isize) = 0 as i32 as i8;
    *(*as16).s.offset(
        (*as16)
            .length
            .wrapping_add(1 as i32 as u64) as isize,
    ) = 0 as i32 as i8;
    return ret;
}
unsafe extern "C" fn best_effort_strncat_to_utf16be(
    mut as16: *mut archive_string,
    mut _p: *const (),
    mut length: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    return best_effort_strncat_to_utf16(as16, _p, length, sc, 1 as i32);
}
unsafe extern "C" fn best_effort_strncat_to_utf16le(
    mut as16: *mut archive_string,
    mut _p: *const (),
    mut length: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    return best_effort_strncat_to_utf16(as16, _p, length, sc, 0 as i32);
}
/*
* Multistring operations.
*/

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_clean(mut aes: *mut archive_mstring) {
    archive_wstring_free(&mut (*aes).aes_wcs);
    archive_string_free(&mut (*aes).aes_mbs);
    archive_string_free(&mut (*aes).aes_utf8);
    archive_string_free(&mut (*aes).aes_mbs_in_locale);
    (*aes).aes_set = 0 as i32;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy(
    mut dest: *mut archive_mstring,
    mut src: *mut archive_mstring,
) {
    (*dest).aes_set = (*src).aes_set;
    (*dest).aes_mbs.length = 0 as i32 as size_t;
    archive_string_concat(&mut (*dest).aes_mbs, &mut (*src).aes_mbs);
    (*dest).aes_utf8.length = 0 as i32 as size_t;
    archive_string_concat(&mut (*dest).aes_utf8, &mut (*src).aes_utf8);
    (*dest).aes_wcs.length = 0 as i32 as size_t;
    archive_wstring_concat(&mut (*dest).aes_wcs, &mut (*src).aes_wcs);
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_get_utf8(
    mut a: *mut archive,
    mut aes: *mut archive_mstring,
    mut p: *mut *const i8,
) -> i32 {
    let mut sc: *mut archive_string_conv = 0 as *mut archive_string_conv;
    let mut r: i32 = 0;
    /* If we already have a UTF8 form, return that immediately. */
    if (*aes).aes_set & 2 as i32 != 0 {
        *p = (*aes).aes_utf8.s;
        return 0 as i32;
    }
    *p = 0 as *const i8;
    /* Try converting WCS to MBS first if MBS does not exist yet. */
    if (*aes).aes_set & 1 as i32 == 0 as i32 {
        let mut pm: *const i8 = 0 as *const i8; /* unused */
        archive_mstring_get_mbs(a, aes, &mut pm);
    }
    if (*aes).aes_set & 1 as i32 != 0 {
        sc = archive_string_conversion_to_charset(
            a,
            b"UTF-8\x00" as *const u8 as *const i8,
            1 as i32,
        );
        /* failure. */
        if sc.is_null() {
            return -(1 as i32);
        } /* Couldn't allocate memory for sc. */
        r = archive_strncpy_l(
            &mut (*aes).aes_utf8,
            (*aes).aes_mbs.s as *const (),
            (*aes).aes_mbs.length,
            sc,
        );
        if a.is_null() {
            free_sconv_object(sc);
        }
        if r == 0 as i32 {
            (*aes).aes_set |= 2 as i32;
            *p = (*aes).aes_utf8.s;
            return 0 as i32;
            /* success. */
        } else {
            return -(1 as i32);
        }
    }
    return 0 as i32;
    /* success. */
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_get_mbs(
    mut a: *mut archive,
    mut aes: *mut archive_mstring,
    mut p: *mut *const i8,
) -> i32 {
    let mut sc: *mut archive_string_conv = 0 as *mut archive_string_conv;
    let mut r: i32 = 0;
    let mut ret: i32 = 0 as i32;
    /* If we already have an MBS form, return that immediately. */
    if (*aes).aes_set & 1 as i32 != 0 {
        *p = (*aes).aes_mbs.s;
        return ret;
    }
    *p = 0 as *const i8;
    /* If there's a WCS form, try converting with the native locale. */
    if (*aes).aes_set & 4 as i32 != 0 {
        (*aes).aes_mbs.length = 0 as i32 as size_t;
        r = archive_string_append_from_wcs(
            &mut (*aes).aes_mbs,
            (*aes).aes_wcs.s,
            (*aes).aes_wcs.length,
        );
        *p = (*aes).aes_mbs.s;
        if r == 0 as i32 {
            (*aes).aes_set |= 1 as i32;
            return ret;
        } else {
            ret = -(1 as i32)
        }
    }
    /* If there's a UTF-8 form, try converting with the native locale. */
    if (*aes).aes_set & 2 as i32 != 0 {
        (*aes).aes_mbs.length = 0 as i32 as size_t;
        sc = archive_string_conversion_from_charset(
            a,
            b"UTF-8\x00" as *const u8 as *const i8,
            1 as i32,
        );
        /* failure. */
        if sc.is_null() {
            return -(1 as i32);
        } /* Couldn't allocate memory for sc. */
        r = archive_strncpy_l(
            &mut (*aes).aes_mbs,
            (*aes).aes_utf8.s as *const (),
            (*aes).aes_utf8.length,
            sc,
        );
        if a.is_null() {
            free_sconv_object(sc);
        }
        *p = (*aes).aes_mbs.s;
        if r == 0 as i32 {
            (*aes).aes_set |= 1 as i32;
            ret = 0 as i32
            /* success; overwrite previous error. */
        } else {
            ret = -(1 as i32)
        }
    }
    return ret;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_get_wcs(
    mut a: *mut archive,
    mut aes: *mut archive_mstring,
    mut wp: *mut *const wchar_t,
) -> i32 {
    let mut r: i32 = 0;
    let mut ret: i32 = 0 as i32;
    /* UNUSED */
    /* Return WCS form if we already have it. */
    if (*aes).aes_set & 4 as i32 != 0 {
        *wp = (*aes).aes_wcs.s;
        return ret;
    }
    *wp = 0 as *const wchar_t;
    /* Try converting UTF8 to MBS first if MBS does not exist yet. */
    if (*aes).aes_set & 1 as i32 == 0 as i32 {
        let mut p: *const i8 = 0 as *const i8; /* unused */
        archive_mstring_get_mbs(a, aes, &mut p);
    }
    /* Try converting MBS to WCS using native locale. */
    if (*aes).aes_set & 1 as i32 != 0 {
        (*aes).aes_wcs.length = 0 as i32 as size_t;
        r = archive_wstring_append_from_mbs(
            &mut (*aes).aes_wcs,
            (*aes).aes_mbs.s,
            (*aes).aes_mbs.length,
        );
        if r == 0 as i32 {
            (*aes).aes_set |= 4 as i32;
            *wp = (*aes).aes_wcs.s
        } else {
            ret = -(1 as i32)
        }
        /* failure. */
    }
    return ret;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_get_mbs_l(
    mut a: *mut archive,
    mut aes: *mut archive_mstring,
    mut p: *mut *const i8,
    mut length: *mut size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut r: i32 = 0;
    let mut ret: i32 = 0 as i32;
    /* UNUSED */
    /* If there is not an MBS form but there is a WCS or UTF8 form, try converting
     * with the native locale to be used for translating it to specified
     * character-set. */
    if (*aes).aes_set & 1 as i32 == 0 as i32 {
        let mut pm: *const i8 = 0 as *const i8; /* unused */
        archive_mstring_get_mbs(a, aes, &mut pm);
    }
    /* If we already have an MBS form, use it to be translated to
     * specified character-set. */
    if (*aes).aes_set & 1 as i32 != 0 {
        if sc.is_null() {
            /* Conversion is unneeded. */
            *p = (*aes).aes_mbs.s; /* Only MBS form is set now. */
            if !length.is_null() {
                *length = (*aes).aes_mbs.length
            } /* Only WCS form set. */
            return 0 as i32;
        } /* Only MBS form is set now. */
        ret = archive_strncpy_l(
            &mut (*aes).aes_mbs_in_locale,
            (*aes).aes_mbs.s as *const (),
            (*aes).aes_mbs.length,
            sc,
        );
        *p = (*aes).aes_mbs_in_locale.s;
        if !length.is_null() {
            *length = (*aes).aes_mbs_in_locale.length
        }
    } else {
        *p = 0 as *const i8;
        if !length.is_null() {
            *length = 0 as i32 as size_t
        }
    }
    return ret;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_mbs(
    mut aes: *mut archive_mstring,
    mut mbs: *const i8,
) -> i32 {
    if mbs.is_null() {
        (*aes).aes_set = 0 as i32;
        return 0 as i32;
    }
    return archive_mstring_copy_mbs_len(aes, mbs, strlen(mbs));
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_mbs_len(
    mut aes: *mut archive_mstring,
    mut mbs: *const i8,
    mut len: size_t,
) -> i32 {
    if mbs.is_null() {
        (*aes).aes_set = 0 as i32;
        return 0 as i32;
    }
    (*aes).aes_set = 1 as i32;
    (*aes).aes_mbs.length = 0 as i32 as size_t;
    archive_strncat(&mut (*aes).aes_mbs, mbs as *const (), len);
    (*aes).aes_utf8.length = 0 as i32 as size_t;
    (*aes).aes_wcs.length = 0 as i32 as size_t;
    return 0 as i32;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_wcs(
    mut aes: *mut archive_mstring,
    mut wcs: *const wchar_t,
) -> i32 {
    return archive_mstring_copy_wcs_len(
        aes,
        wcs,
        if wcs.is_null() {
            0 as i32 as u64
        } else {
            wcslen_safe(wcs)
        },
    );
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_utf8(
    mut aes: *mut archive_mstring,
    mut utf8: *const i8,
) -> i32 {
    if utf8.is_null() {
        (*aes).aes_set = 0 as i32;
        return 0 as i32;
    }
    (*aes).aes_set = 2 as i32;
    (*aes).aes_mbs.length = 0 as i32 as size_t;
    (*aes).aes_wcs.length = 0 as i32 as size_t;
    (*aes).aes_utf8.length = 0 as i32 as size_t;
    archive_strncat(
        &mut (*aes).aes_utf8,
        utf8 as *const (),
        strlen(utf8),
    );
    return strlen(utf8) as i32;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_wcs_len(
    mut aes: *mut archive_mstring,
    mut wcs: *const wchar_t,
    mut len: size_t,
) -> i32 {
    if wcs.is_null() {
        (*aes).aes_set = 0 as i32;
        return 0 as i32;
    }
    (*aes).aes_set = 4 as i32;
    (*aes).aes_mbs.length = 0 as i32 as size_t;
    (*aes).aes_utf8.length = 0 as i32 as size_t;
    (*aes).aes_wcs.length = 0 as i32 as size_t;
    archive_wstrncat(&mut (*aes).aes_wcs, wcs, len);
    return 0 as i32;
}

#[no_mangle]
pub unsafe extern "C" fn archive_mstring_copy_mbs_len_l(
    mut aes: *mut archive_mstring,
    mut mbs: *const i8,
    mut len: size_t,
    mut sc: *mut archive_string_conv,
) -> i32 {
    let mut r: i32 = 0;
    if mbs.is_null() {
        (*aes).aes_set = 0 as i32;
        return 0 as i32;
    }
    (*aes).aes_mbs.length = 0 as i32 as size_t;
    (*aes).aes_wcs.length = 0 as i32 as size_t;
    (*aes).aes_utf8.length = 0 as i32 as size_t;
    r = archive_strncpy_l(&mut (*aes).aes_mbs, mbs as *const (), len, sc);
    if r == 0 as i32 {
        (*aes).aes_set = 1 as i32
    } else {
        (*aes).aes_set = 0 as i32
    }
    return r;
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
pub unsafe extern "C" fn archive_mstring_update_utf8(
    mut a: *mut archive,
    mut aes: *mut archive_mstring,
    mut utf8: *const i8,
) -> i32 {
    let mut sc: *mut archive_string_conv = 0 as *mut archive_string_conv;
    let mut r: i32 = 0;
    if utf8.is_null() {
        (*aes).aes_set = 0 as i32;
        return 0 as i32;
        /* Succeeded in clearing everything. */
    }
    /* Save the UTF8 string. */
    (*aes).aes_utf8.length = 0 as i32 as size_t;
    archive_strncat(
        &mut (*aes).aes_utf8,
        utf8 as *const (),
        (if utf8.is_null() {
            0 as i32 as u64
        } else {
            strlen(utf8)
        }),
    );
    /* Empty the mbs and wcs strings. */
    (*aes).aes_mbs.length = 0 as i32 as size_t; /* Only UTF8 is set now. */
    (*aes).aes_wcs.length = 0 as i32 as size_t;
    (*aes).aes_set = 2 as i32;
    /* Try converting UTF-8 to MBS, return false on failure. */
    sc = archive_string_conversion_from_charset(
        a,
        b"UTF-8\x00" as *const u8 as *const i8,
        1 as i32,
    ); /* Couldn't allocate memory for sc. */
    if sc.is_null() {
        return -(1 as i32);
    } /* Both UTF8 and MBS set. */
    r = archive_strncpy_l(
        &mut (*aes).aes_mbs,
        utf8 as *const (),
        if utf8.is_null() {
            0 as i32 as u64
        } else {
            strlen(utf8)
        },
        sc,
    );
    if a.is_null() {
        free_sconv_object(sc);
    }
    if r != 0 as i32 {
        return -(1 as i32);
    }
    (*aes).aes_set = 2 as i32 | 1 as i32;
    /* Try converting MBS to WCS, return false on failure. */
    if archive_wstring_append_from_mbs(&mut (*aes).aes_wcs, (*aes).aes_mbs.s, (*aes).aes_mbs.length)
        != 0
    {
        return -(1 as i32);
    }
    (*aes).aes_set = 2 as i32 | 4 as i32 | 1 as i32;
    /* All conversions succeeded. */
    return 0 as i32;
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_best_effort_strncat_utf16(
    mut _p: *const (),
    mut bytes: size_t,
) {
    let mut archive_string: *mut archive_string = 0 as *mut archive_string;
    archive_string = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string>() as u64,
        )
    } as *mut archive_string;
    let mut archive_string_conv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    archive_string_conv = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string_conv>() as u64,
        )
    } as *mut archive_string_conv;
    best_effort_strncat_from_utf16be(archive_string, _p, bytes, archive_string_conv);
    best_effort_strncat_from_utf16le(archive_string, _p, bytes, archive_string_conv);
    best_effort_strncat_to_utf16be(archive_string, _p, bytes, archive_string_conv);
    best_effort_strncat_to_utf16le(archive_string, _p, bytes, archive_string_conv);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_strncat_from_utf8_libarchive2(
    mut _p: *const (),
    mut bytes: size_t,
) {
    let mut archive_string: *mut archive_string = 0 as *mut archive_string;
    archive_string = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string>() as u64,
        )
    } as *mut archive_string;
    let mut archive_string_conv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    archive_string_conv = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string_conv>() as u64,
        )
    } as *mut archive_string_conv;
    strncat_from_utf8_libarchive2(archive_string, _p, bytes, archive_string_conv);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_archive_string_append_unicode(
    mut _p: *const (),
    mut bytes: size_t,
) {
    let mut archive_string: *mut archive_string = 0 as *mut archive_string;
    archive_string = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string>() as u64,
        )
    } as *mut archive_string;
    let mut archive_string_conv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    archive_string_conv = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string_conv>() as u64,
        )
    } as *mut archive_string_conv;
    archive_string_append_unicode(archive_string, _p, bytes, archive_string_conv);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_invalid_mbs(mut _p: *const (), mut bytes: size_t) {
    let mut archive_string: *mut archive_string = 0 as *mut archive_string;
    archive_string = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string>() as u64,
        )
    } as *mut archive_string;
    let mut archive_string_conv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    archive_string_conv = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string_conv>() as u64,
        )
    } as *mut archive_string_conv;
    invalid_mbs(_p, bytes, archive_string_conv);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_unicode_to_utf16be(
    mut p: *mut i8,
    mut remaining: size_t,
    mut uc: uint32_t,
) -> size_t {
    return unicode_to_utf16be(p, remaining, uc);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_unicode_to_utf16le(
    mut p: *mut i8,
    mut remaining: size_t,
    mut uc: uint32_t,
) -> size_t {
    return unicode_to_utf16le(p, remaining, uc);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_best_effort_strncat_in_locale(
    mut _p: *const (),
    mut length: size_t,
) {
    let mut archive_string: *mut archive_string = 0 as *mut archive_string;
    archive_string = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string>() as u64,
        )
    } as *mut archive_string;
    let mut archive_string_conv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    archive_string_conv = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string_conv>() as u64,
        )
    } as *mut archive_string_conv;
    (*archive_string_conv).same = 1;
    best_effort_strncat_in_locale(archive_string, _p, length, archive_string_conv);
    (*archive_string_conv).same = 0;
    best_effort_strncat_in_locale(archive_string, _p, length, archive_string_conv);
    (*archive_string_conv).flag = (1 << 8);
    best_effort_strncat_in_locale(archive_string, _p, length, archive_string_conv);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_setup_converter() {
    let mut archive_string_conv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    archive_string_conv = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string_conv>() as u64,
        )
    } as *mut archive_string_conv;
    (*archive_string_conv).flag = (1 << 4);
    setup_converter(archive_string_conv);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_archive_string_normalize_D(
    mut _p: *const (),
    mut len: size_t,
) {
    let mut archive_string: *mut archive_string = 0 as *mut archive_string;
    archive_string = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string>() as u64,
        )
    } as *mut archive_string;
    let mut archive_string_conv: *mut archive_string_conv = 0 as *mut archive_string_conv;
    archive_string_conv = unsafe {
        calloc_safe(
            1 as i32 as u64,
            ::std::mem::size_of::<archive_string_conv>() as u64,
        )
    } as *mut archive_string_conv;
    (*archive_string_conv).flag = (1 << 10) | (1 << 11);
    archive_string_normalize_D(archive_string, _p, len, archive_string_conv);
    (*archive_string_conv).flag = (1 << 12) | (1 << 13);
    archive_string_normalize_D(archive_string, _p, len, archive_string_conv);
    (*archive_string_conv).flag = (1 << 11);
    archive_string_normalize_D(archive_string, _p, len, archive_string_conv);
    (*archive_string_conv).flag = (1 << 13);
    archive_string_normalize_D(archive_string, _p, len, archive_string_conv);
}

#[no_mangle]
pub unsafe extern "C" fn archive_test_utf16_to_unicode(
    mut pwc: *mut uint32_t,
    mut s: *const i8,
    mut n: size_t,
    mut be: i32,
) -> i32 {
    return utf16_to_unicode(pwc, s, n, be);
}
