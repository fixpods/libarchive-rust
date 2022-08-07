use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

extern "C" {
    #[cfg(HAVE_TIMEGM)]
    fn timegm(__tp: *mut tm) -> time_t;
    #[cfg_attr(HAVE__MKGMTIME64, cfg(not(HAVE_TIMEGM)))]
    fn _mkgmtime(__tp: *mut tm) -> time_t;
}
#[cfg(HAVE_TIMEGM)]
fn timegm_safe(__tp: *mut tm) -> time_t {
    return unsafe { timegm(__tp) };
}

#[cfg_attr(HAVE__MKGMTIME64, cfg(not(HAVE_TIMEGM)))]
fn _mkgmtime_safe(__tp: *mut tm) -> time_t {
    return unsafe { _mkgmtime(__tp) };
}
#[no_mangle]
pub extern "C" fn archive_read_support_format_warc(mut _a: *mut archive) -> libc::c_int {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut w: *mut warc_s = 0 as *mut warc_s;
    let mut r: libc::c_int = 0;
    let mut safe_a = unsafe { &mut *a };
    let mut magic_test: libc::c_int = __archive_check_magic_safe(
        _a,
        ARCHIVE_WARC_DEFINED_PARAM.archive_read_magic,
        ARCHIVE_WARC_DEFINED_PARAM.archive_state_new,
        b"archive_read_support_format_warc\x00" as *const u8 as *const libc::c_char,
    );
    if magic_test == ARCHIVE_WARC_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
    }
    w = calloc_safe(
        1 as libc::c_int as libc::c_ulong,
        ::std::mem::size_of::<warc_s>() as libc::c_ulong,
    ) as *mut warc_s;
    if w.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_WARC_DEFINED_PARAM.enomem,
            b"Can\'t allocate warc data\x00" as *const u8 as *const libc::c_char
        );
        return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
    }
    r = __archive_read_register_format_safe(
        a,
        w as *mut libc::c_void,
        b"warc\x00" as *const u8 as *const libc::c_char,
        Some(_warc_bid as extern "C" fn(_: *mut archive_read, _: libc::c_int) -> libc::c_int),
        None,
        Some(
            _warc_rdhdr
                as extern "C" fn(_: *mut archive_read, _: *mut archive_entry) -> libc::c_int,
        ),
        Some(
            _warc_read
                as extern "C" fn(
                    _: *mut archive_read,
                    _: *mut *const libc::c_void,
                    _: *mut size_t,
                    _: *mut int64_t,
                ) -> libc::c_int,
        ),
        Some(_warc_skip as extern "C" fn(_: *mut archive_read) -> libc::c_int),
        None,
        Some(_warc_cleanup as extern "C" fn(_: *mut archive_read) -> libc::c_int),
        None,
        None,
    );
    if r != ARCHIVE_WARC_DEFINED_PARAM.archive_ok {
        free_safe(w as *mut libc::c_void);
        return r;
    }
    return 0 as libc::c_int;
}
extern "C" fn _warc_cleanup(mut a: *mut archive_read) -> libc::c_int {
    let mut w: *mut warc_s = unsafe { (*(*a).format).data as *mut warc_s };
    let mut safe_w = unsafe { &mut *w };
    let mut safe_a = unsafe { &mut *a };
    if safe_w.pool.len > 0 as libc::c_uint as libc::c_ulong {
        free_safe(safe_w.pool.str_0 as *mut libc::c_void);
    }
    archive_string_free_safe(&mut safe_w.sver);
    free_safe(w as *mut libc::c_void);
    unsafe { (*safe_a.format).data = 0 as *mut libc::c_void };
    return ARCHIVE_WARC_DEFINED_PARAM.archive_ok;
}
extern "C" fn _warc_bid(mut a: *mut archive_read, mut best_bid: libc::c_int) -> libc::c_int {
    let mut hdr: *const libc::c_char = 0 as *const libc::c_char;
    let mut nrd: ssize_t = 0;
    let mut ver: libc::c_uint = 0;
    /* UNUSED */
    /* check first line of file, it should be a record already */
    hdr =
        __archive_read_ahead_safe(a, 12 as libc::c_uint as size_t, &mut nrd) as *const libc::c_char;
    if hdr.is_null() {
        /* no idea what to do */
        return -(1 as libc::c_int);
    } else {
        if nrd < 12 as libc::c_int as libc::c_long {
            /* nah, not for us, our magic cookie is at least 12 bytes */
            return -(1 as libc::c_int);
        }
    }
    /* otherwise snarf the record's version number */
    ver = _warc_rdver(hdr, nrd as size_t);
    if ver < 1200 as libc::c_uint || ver > 10000 as libc::c_uint {
        /* we only support WARC 0.12 to 1.0 */
        return -(1 as libc::c_int);
    }
    /* otherwise be confident */
    return 64 as libc::c_int;
}
extern "C" fn _warc_rdhdr(mut a: *mut archive_read, mut entry: *mut archive_entry) -> libc::c_int {
    let mut w: *mut warc_s = unsafe { (*(*a).format).data as *mut warc_s };
    let mut ver: libc::c_uint = 0;
    let mut buf: *const libc::c_char = 0 as *const libc::c_char;
    let mut nrd: ssize_t = 0;
    let mut eoh: *const libc::c_char = 0 as *const libc::c_char;
    /* for the file name, saves some strndup()'ing */
    let mut fnam: warc_string_t = warc_string_t {
        len: 0,
        str_0: 0 as *const libc::c_char,
    };
    /* warc record type, not that we really use it a lot */
    let mut ftyp: warc_type_t = WT_NONE;
    /* content-length+error monad */
    let mut cntlen: ssize_t = 0;
    /* record time is the WARC-Date time we reinterpret it as ctime */
    let mut rtime: time_t = 0;
    /* mtime is the Last-Modified time which will be the entry's mtime */
    let mut mtime: time_t = 0;
    let mut safe_a = unsafe { &mut *a };
    let mut safe_w = unsafe { &mut *w };
    loop {
        /* just use read_ahead() they keep track of unconsumed
         * bits and bobs for us; no need to put an extra shift in
         * and reproduce that functionality here */
        buf = __archive_read_ahead_safe(a, 12 as libc::c_uint as size_t, &mut nrd)
            as *const libc::c_char;
        if nrd < 0 as libc::c_int as libc::c_long {
            /* no good */
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_WARC_DEFINED_PARAM.archive_errno_misc,
                b"Bad record header\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
        } else {
            if buf.is_null() {
                /* there should be room for at least WARC/bla\r\n
                 * must be EOF therefore */
                return ARCHIVE_WARC_DEFINED_PARAM.archive_eof;
            }
        }
        /* looks good so far, try and find the end of the header now */
        eoh = _warc_find_eoh(buf, nrd as size_t);
        if eoh.is_null() {
            /* still no good, the header end might be beyond the
             * probe we've requested, but then again who'd cram
             * so much stuff into the header *and* be 28500-compliant */
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_WARC_DEFINED_PARAM.archive_errno_misc,
                b"Bad record header\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
        }
        ver = _warc_rdver(buf, unsafe {
            eoh.offset_from(buf) as libc::c_long as size_t
        });
        /* we currently support WARC 0.12 to 1.0 */
        if ver == 0 as libc::c_uint {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_WARC_DEFINED_PARAM.archive_errno_misc,
                b"Invalid record version\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
        } else {
            if ver < 1200 as libc::c_uint || ver > 10000 as libc::c_uint {
                archive_set_error_safe!(
                    &mut safe_a.archive as *mut archive,
                    ARCHIVE_WARC_DEFINED_PARAM.archive_errno_misc,
                    b"Unsupported record version: %u.%u\x00" as *const u8 as *const libc::c_char,
                    ver.wrapping_div(10000 as libc::c_int as libc::c_uint),
                    ver.wrapping_rem(10000 as libc::c_int as libc::c_uint)
                        .wrapping_div(100 as libc::c_int as libc::c_uint)
                );
                return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
            }
        }
        cntlen = _warc_rdlen(buf, unsafe {
            eoh.offset_from(buf) as libc::c_long as size_t
        });
        if cntlen < 0 as libc::c_int as libc::c_long {
            /* nightmare!  the specs say content-length is mandatory
             * so I don't feel overly bad stopping the reader here */
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_WARC_DEFINED_PARAM.einval,
                b"Bad content length\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
        }
        rtime = _warc_rdrtm(buf, unsafe {
            eoh.offset_from(buf) as libc::c_long as size_t
        });
        if rtime == -(1 as libc::c_int) as time_t {
            /* record time is mandatory as per WARC/1.0,
             * so just barf here, fast and loud */
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_WARC_DEFINED_PARAM.einval,
                b"Bad record time\x00" as *const u8 as *const libc::c_char
            );
            return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
        }
        /* let the world know we're a WARC archive */
        safe_a.archive.archive_format = ARCHIVE_WARC_DEFINED_PARAM.archive_format_warc;
        if ver != safe_w.pver {
            /* stringify this entry's version */
            unsafe {
                archive_string_sprintf(
                    &mut safe_w.sver as *mut archive_string,
                    b"WARC/%u.%u\x00" as *const u8 as *const libc::c_char,
                    ver.wrapping_div(10000 as libc::c_int as libc::c_uint),
                    ver.wrapping_rem(10000 as libc::c_int as libc::c_uint)
                        .wrapping_div(100 as libc::c_int as libc::c_uint),
                )
            };
            /* remember the version */
            safe_w.pver = ver
        }
        /* start off with the type */
        ftyp = _warc_rdtyp(buf, unsafe {
            eoh.offset_from(buf) as libc::c_long as size_t
        }) as warc_type_t;
        /* and let future calls know about the content */
        safe_w.cntlen = cntlen as size_t; /* Avoid compiling error on some platform. */
        safe_w.cntoff = 0 as libc::c_uint as size_t;
        mtime = 0 as libc::c_int as time_t;
        match ftyp as libc::c_uint {
            WT_RSRC | WT_RSP => {
                /* only try and read the filename in the cases that are
                 * guaranteed to have one */
                fnam = _warc_rduri(buf, unsafe {
                    eoh.offset_from(buf) as libc::c_long as size_t
                });
                /* check the last character in the URI to avoid creating
                 * directory endpoints as files, see Todo above */
                if unsafe {
                    fnam.len == 0 as libc::c_int as libc::c_ulong
                        || *fnam.str_0.offset(
                            fnam.len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                        ) as libc::c_int
                            == '/' as i32
                } {
                    /* break here for now */
                    fnam.len = 0 as libc::c_uint as size_t;
                    fnam.str_0 = 0 as *const libc::c_char
                } else {
                    /* bang to our string pool, so we save a
                     * malloc()+free() roundtrip */
                    if fnam.len.wrapping_add(1 as libc::c_uint as libc::c_ulong) > safe_w.pool.len {
                        safe_w.pool.len = fnam
                            .len
                            .wrapping_add(64 as libc::c_uint as libc::c_ulong)
                            .wrapping_div(64 as libc::c_uint as libc::c_ulong)
                            .wrapping_mul(64 as libc::c_uint as libc::c_ulong);
                        safe_w.pool.str_0 =
                            realloc_safe(safe_w.pool.str_0 as *mut libc::c_void, safe_w.pool.len)
                                as *mut libc::c_char
                    }
                    memcpy_safe(
                        safe_w.pool.str_0 as *mut libc::c_void,
                        fnam.str_0 as *const libc::c_void,
                        fnam.len,
                    );
                    unsafe {
                        *safe_w.pool.str_0.offset(fnam.len as isize) =
                            '\u{0}' as i32 as libc::c_char
                    };
                    /* let no one else know about the pool, it's a secret, shhh */
                    fnam.str_0 = safe_w.pool.str_0;
                    /* snarf mtime or deduce from rtime
                     * this is a custom header added by our writer, it's quite
                     * hard to believe anyone else would go through with it
                     * (apart from being part of some http responses of course) */
                    mtime = _warc_rdmtm(buf, unsafe {
                        eoh.offset_from(buf) as libc::c_long as size_t
                    });
                    if mtime == -(1 as libc::c_int) as time_t {
                        mtime = rtime
                    }
                }
            }
            WT_NONE | WT_INFO | WT_META | WT_REQ | WT_RVIS | WT_CONV | WT_CONT | LAST_WT | _ => {
                fnam.len = 0 as libc::c_uint as size_t;
                fnam.str_0 = 0 as *const libc::c_char
            }
        }
        /* now eat some of those delicious buffer bits */
        __archive_read_consume_safe(a, unsafe { eoh.offset_from(buf) as libc::c_long });
        match ftyp as libc::c_uint {
            WT_RSRC | WT_RSP => {
                if fnam.len > 0 as libc::c_uint as libc::c_ulong {
                    break;
                }
            }
            WT_NONE | WT_INFO | WT_META | WT_REQ | WT_RVIS | WT_CONV | WT_CONT | LAST_WT | _ => {}
        }
        /* FALLTHROUGH */
        /* consume the content and start over */
        _warc_skip(a);
    }
    /* populate entry object */
    archive_entry_set_filetype_safe(entry, ARCHIVE_WARC_DEFINED_PARAM.ae_ifreg as mode_t);
    archive_entry_copy_pathname_safe(entry, fnam.str_0);
    archive_entry_set_size_safe(entry, cntlen);
    archive_entry_set_perm_safe(entry, 0o644 as libc::c_int as mode_t);
    /* rtime is the new ctime, mtime stays mtime */
    archive_entry_set_ctime_safe(entry, rtime, 0 as libc::c_long);
    archive_entry_set_mtime_safe(entry, mtime, 0 as libc::c_long);
    return ARCHIVE_WARC_DEFINED_PARAM.archive_ok;
}
extern "C" fn _warc_read(
    mut a: *mut archive_read,
    mut buf: *mut *const libc::c_void,
    mut bsz: *mut size_t,
    mut off: *mut int64_t,
) -> libc::c_int {
    let mut w: *mut warc_s = unsafe { (*(*a).format).data as *mut warc_s };
    let mut rab: *const libc::c_char = 0 as *const libc::c_char;
    let mut nrd: ssize_t = 0;
    let mut safe_off = unsafe { &mut *off };
    let mut safe_w = unsafe { &mut *w };
    let mut safe_bsz = unsafe { &mut *bsz };
    let mut safe_buf = unsafe { &mut *buf };
    if !(safe_w.cntoff >= safe_w.cntlen) {
        if safe_w.unconsumed != 0 {
            __archive_read_consume_safe(a, safe_w.unconsumed as int64_t);
            safe_w.unconsumed = 0 as libc::c_uint as size_t
        }
        rab = __archive_read_ahead_safe(a, 1 as libc::c_uint as size_t, &mut nrd)
            as *const libc::c_char;
        if nrd < 0 as libc::c_int as libc::c_long {
            unsafe { *bsz = 0 as libc::c_uint as size_t };
            /* big catastrophe */
            return nrd as libc::c_int;
        } else if !(nrd == 0 as libc::c_int as libc::c_long) {
            if nrd as size_t > safe_w.cntlen.wrapping_sub(safe_w.cntoff) {
                /* clamp to content-length */
                nrd = safe_w.cntlen.wrapping_sub(safe_w.cntoff) as ssize_t
            }
            *safe_off = safe_w.cntoff as int64_t;
            *safe_bsz = nrd as size_t;
            *safe_buf = rab as *const libc::c_void;
            safe_w.cntoff = (safe_w.cntoff as libc::c_ulong).wrapping_add(nrd as libc::c_ulong)
                as size_t as size_t;
            safe_w.unconsumed = nrd as size_t;
            return ARCHIVE_WARC_DEFINED_PARAM.archive_ok;
        }
    }
    /* it's our lucky day, no work, we can leave early */
    *safe_buf = 0 as *const libc::c_void; /*for \r\n\r\n separator*/
    *safe_bsz = 0 as libc::c_uint as size_t;
    *safe_off = safe_w
        .cntoff
        .wrapping_add(4 as libc::c_uint as libc::c_ulong) as int64_t;
    safe_w.unconsumed = 0 as libc::c_uint as size_t;
    return ARCHIVE_WARC_DEFINED_PARAM.archive_eof;
}
extern "C" fn _warc_skip(mut a: *mut archive_read) -> libc::c_int {
    let mut w: *mut warc_s = unsafe { (*(*a).format).data as *mut warc_s };
    let mut safe_w = unsafe { &mut *w };
    __archive_read_consume_safe(
        a,
        safe_w
            .cntlen
            .wrapping_add(4 as libc::c_uint as libc::c_ulong) as int64_t,
    );
    safe_w.cntlen = 0 as libc::c_uint as size_t;
    safe_w.cntoff = 0 as libc::c_uint as size_t;
    return ARCHIVE_WARC_DEFINED_PARAM.archive_ok;
}
/* private routines */
extern "C" fn deconst(mut c: *const libc::c_void) -> *mut libc::c_void {
    return c as uintptr_t as *mut libc::c_void;
}
extern "C" fn xmemmem(
    mut hay: *const libc::c_char,
    haysize: size_t,
    mut needle: *const libc::c_char,
    needlesize: size_t,
) -> *mut libc::c_char {
    let eoh: *const libc::c_char = unsafe { hay.offset(haysize as isize) };
    let eon: *const libc::c_char = unsafe { needle.offset(needlesize as isize) };
    let mut hp: *const libc::c_char = 0 as *const libc::c_char;
    let mut np: *const libc::c_char = 0 as *const libc::c_char;
    let mut cand: *const libc::c_char = 0 as *const libc::c_char;
    let mut hsum: libc::c_uint = 0;
    let mut nsum: libc::c_uint = 0;
    let mut eqp: libc::c_uint = 0;
    /* trivial checks first
     * a 0-sized needle is defined to be found anywhere in haystack
     * then run strchr() to find a candidate in HAYSTACK (i.e. a portion
     * that happens to begin with *NEEDLE) */
    if needlesize == 0 as libc::c_ulong {
        return deconst(hay as *const libc::c_void) as *mut libc::c_char;
    } else {
        hay = memchr_safe(
            hay as *const libc::c_void,
            unsafe { *needle as libc::c_int },
            haysize,
        ) as *const libc::c_char;
        if hay.is_null() {
            /* trivial */
            return 0 as *mut libc::c_char;
        }
    }
    /* First characters of haystack and needle are the same now. Both are
     * guaranteed to be at least one character long.  Now computes the sum
     * of characters values of needle together with the sum of the first
     * needle_len characters of haystack. */
    hp = unsafe { hay.offset(1 as libc::c_uint as isize) };
    np = unsafe { needle.offset(1 as libc::c_uint as isize) };
    hsum = unsafe { *hay as libc::c_uint };
    nsum = unsafe { *hay as libc::c_uint };
    eqp = 1 as libc::c_uint;
    while hp < eoh && np < eon {
        hsum ^= unsafe { *hp as libc::c_uint };
        nsum ^= unsafe { *np as libc::c_uint };
        eqp &= unsafe { (*hp as libc::c_int == *np as libc::c_int) as libc::c_int as libc::c_uint };
        unsafe {
            hp = hp.offset(1);
            np = np.offset(1)
        }
    }
    /* HP now references the (NEEDLESIZE + 1)-th character. */
    if np < eon {
        /* haystack is smaller than needle, :O */
        return 0 as *mut libc::c_char;
    } else {
        if eqp != 0 {
            /* found a match */
            return deconst(hay as *const libc::c_void) as *mut libc::c_char;
        }
    }
    /* now loop through the rest of haystack,
     * updating the sum iteratively */
    cand = hay;
    while hp < eoh {
        let fresh0 = cand;
        cand = unsafe { cand.offset(1) };
        hsum ^= unsafe { *fresh0 as libc::c_uint };
        hsum ^= unsafe { *hp as libc::c_uint };
        /* Since the sum of the characters is already known to be
         * equal at that point, it is enough to check just NEEDLESIZE - 1
         * characters for equality,
         * also CAND is by design < HP, so no need for range checks */
        if hsum == nsum
            && memcmp_safe(
                cand as *const libc::c_void,
                needle as *const libc::c_void,
                needlesize.wrapping_sub(1 as libc::c_uint as libc::c_ulong),
            ) == 0 as libc::c_int
        {
            return deconst(cand as *const libc::c_void) as *mut libc::c_char;
        }
        hp = unsafe { hp.offset(1) }
    }
    return 0 as *mut libc::c_char;
}
extern "C" fn strtoi_lim(
    mut str: *const libc::c_char,
    mut ep: *mut *const libc::c_char,
    mut llim: libc::c_int,
    mut ulim: libc::c_int,
) -> libc::c_int {
    let mut res: libc::c_int = 0 as libc::c_int;
    let mut sp: *const libc::c_char = 0 as *const libc::c_char;
    /* we keep track of the number of digits via rulim */
    let mut rulim: libc::c_int = 0;
    sp = str;
    rulim = (if ulim > 10 as libc::c_int {
        ulim
    } else {
        10 as libc::c_int
    });
    while unsafe {
        res * 10 as libc::c_int <= ulim
            && rulim != 0
            && *sp as libc::c_int >= '0' as i32
            && *sp as libc::c_int <= '9' as i32
    } {
        res *= 10 as libc::c_int;
        unsafe {
            res += *sp as libc::c_int - '0' as i32;
            sp = sp.offset(1)
        };
        rulim /= 10 as libc::c_int
    }
    if sp == str {
        res = -(1 as libc::c_int)
    } else if res < llim || res > ulim {
        res = -(2 as libc::c_int)
    }
    unsafe { *ep = sp };
    return res;
}
extern "C" fn time_from_tm(mut t: *mut tm) -> time_t {
    /* Use platform timegm() if available. */
    /* Use platform timegm() if available. */
    #[cfg(HAVE_TIMEGM)]
    return timegm_safe(t);
    #[cfg_attr(HAVE__MKGMTIME64, cfg(not(HAVE_TIMEGM)))]
    return _mkgmtime_safe(t);
    if mktime_safe(t) == -(1 as libc::c_int) as time_t {
        return -(1 as libc::c_int) as time_t;
    }
    let mut safe_t = unsafe { &mut *t };
    return (safe_t.tm_sec
        + safe_t.tm_min * 60 as libc::c_int
        + safe_t.tm_hour * 3600 as libc::c_int
        + safe_t.tm_yday * 86400 as libc::c_int
        + (safe_t.tm_year - 70 as libc::c_int) * 31536000 as libc::c_int
        + (safe_t.tm_year - 69 as libc::c_int) / 4 as libc::c_int * 86400 as libc::c_int
        - (safe_t.tm_year - 1 as libc::c_int) / 100 as libc::c_int * 86400 as libc::c_int
        + (safe_t.tm_year + 299 as libc::c_int) / 400 as libc::c_int * 86400 as libc::c_int)
        as time_t;
}
extern "C" fn xstrpisotime(
    mut s: *const libc::c_char,
    mut endptr: *mut *mut libc::c_char,
) -> time_t {
    /* * like strptime() but strictly for ISO 8601 Zulu strings */
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
        tm_zone: 0 as *const libc::c_char,
    };
    let mut res: time_t = -(1 as libc::c_int) as time_t;
    /* make sure tm is clean */
    memset_safe(
        &mut tm as *mut tm as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<tm>() as libc::c_ulong,
    );
    /* as a courtesy to our callers, and since this is a non-standard
     * routine, we skip leading whitespace */
    while unsafe { *s as libc::c_int == ' ' as i32 || *s as libc::c_int == '\t' as i32 } {
        unsafe { s = s.offset(1) }
    }
    /* read year */
    tm.tm_year = strtoi_lim(s, &mut s, 1583 as libc::c_int, 4095 as libc::c_int);
    if !(tm.tm_year < 0 as libc::c_int || {
        unsafe {
            let fresh1 = s;
            s = s.offset(1);
            (*fresh1 as libc::c_int) != '-' as i32
        }
    }) {
        /* read month */
        tm.tm_mon = strtoi_lim(s, &mut s, 1 as libc::c_int, 12 as libc::c_int);
        if !(tm.tm_mon < 0 as libc::c_int || {
            unsafe {
                let fresh2 = s;
                s = s.offset(1);
                (*fresh2 as libc::c_int) != '-' as i32
            }
        }) {
            /* read day-of-month */
            tm.tm_mday = strtoi_lim(s, &mut s, 1 as libc::c_int, 31 as libc::c_int);
            if !(tm.tm_mday < 0 as libc::c_int || {
                unsafe {
                    let fresh3 = s;
                    s = s.offset(1);
                    (*fresh3 as libc::c_int) != 'T' as i32
                }
            }) {
                /* read hour */
                tm.tm_hour = strtoi_lim(s, &mut s, 0 as libc::c_int, 23 as libc::c_int);
                if !(tm.tm_hour < 0 as libc::c_int || {
                    unsafe {
                        let fresh4 = s;
                        s = s.offset(1);
                        (*fresh4 as libc::c_int) != ':' as i32
                    }
                }) {
                    /* read minute */
                    tm.tm_min = strtoi_lim(s, &mut s, 0 as libc::c_int, 59 as libc::c_int);
                    if !(tm.tm_min < 0 as libc::c_int || {
                        unsafe {
                            let fresh5 = s;
                            s = s.offset(1);
                            (*fresh5 as libc::c_int) != ':' as i32
                        }
                    }) {
                        /* read second */
                        tm.tm_sec = strtoi_lim(s, &mut s, 0 as libc::c_int, 60 as libc::c_int);
                        if !(tm.tm_sec < 0 as libc::c_int || {
                            unsafe {
                                let fresh6 = s;
                                s = s.offset(1);
                                (*fresh6 as libc::c_int) != 'Z' as i32
                            }
                        }) {
                            /* massage TM to fulfill some of POSIX' constraints */
                            tm.tm_year -= 1900 as libc::c_int;
                            tm.tm_mon -= 1;
                            /* now convert our custom tm struct to a unix stamp using UTC */
                            res = time_from_tm(&mut tm)
                        }
                    }
                }
            }
        }
    }
    if !endptr.is_null() {
        unsafe { *endptr = deconst(s as *const libc::c_void) as *mut libc::c_char }
    }
    return res;
}
/* private routines */
extern "C" fn _warc_rdver(mut buf: *const libc::c_char, mut bsz: size_t) -> libc::c_uint {
    static mut magic: [libc::c_char; 6] =
        unsafe { *::std::mem::transmute::<&[u8; 6], &[libc::c_char; 6]>(b"WARC/\x00") };
    let mut c: *const libc::c_char = 0 as *const libc::c_char;
    let mut ver: libc::c_uint = 0 as libc::c_uint;
    let mut end: libc::c_uint = 0 as libc::c_uint;
    if bsz < 12 as libc::c_int as libc::c_ulong
        || memcmp_safe(
            buf as *const libc::c_void,
            unsafe { magic.as_ptr() as *const libc::c_void },
            (::std::mem::size_of::<[libc::c_char; 6]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_uint as libc::c_ulong),
        ) != 0 as libc::c_int
    {
        /* buffer too small or invalid magic */
        return ver;
    }
    /* looks good so far, read the version number for a laugh */
    buf = unsafe {
        buf.offset(
            (::std::mem::size_of::<[libc::c_char; 6]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_uint as libc::c_ulong) as isize,
        )
    };
    if unsafe {
        *(*__ctype_b_loc()).offset(
            *buf.offset(0 as libc::c_uint as isize) as libc::c_uchar as libc::c_int as isize
        ) as libc::c_int
            & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int
            != 0
            && *buf.offset(1 as libc::c_uint as isize) as libc::c_int == '.' as i32
            && *(*__ctype_b_loc()).offset(
                *buf.offset(2 as libc::c_uint as isize) as libc::c_uchar as libc::c_int as isize
            ) as libc::c_int
                & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int
                != 0
    } {
        /* we support a maximum of 2 digits in the minor version */
        if unsafe {
            *(*__ctype_b_loc()).offset(
                *buf.offset(3 as libc::c_uint as isize) as libc::c_uchar as libc::c_int as isize
            ) as libc::c_int
                & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int
                != 0
        } {
            end = 1 as libc::c_uint
        }
        /* set up major version */
        ver = unsafe {
            ((*buf.offset(0 as libc::c_uint as isize) as libc::c_int - '0' as i32) as libc::c_uint)
                .wrapping_mul(10000 as libc::c_uint)
        };
        /* set up minor version */
        if end == 1 as libc::c_uint {
            ver = ver.wrapping_add(
                ((unsafe { *buf.offset(2 as libc::c_uint as isize) as libc::c_int - '0' as i32 })
                    as libc::c_uint)
                    .wrapping_mul(1000 as libc::c_uint),
            );
            ver = ver.wrapping_add(
                ((unsafe { *buf.offset(3 as libc::c_uint as isize) as libc::c_int - '0' as i32 })
                    as libc::c_uint)
                    .wrapping_mul(100 as libc::c_uint),
            )
        } else {
            ver = ver.wrapping_add(
                ((unsafe { *buf.offset(2 as libc::c_uint as isize) as libc::c_int - '0' as i32 })
                    as libc::c_uint)
                    .wrapping_mul(100 as libc::c_uint),
            )
        }
        /*
         * WARC below version 0.12 has a space-separated header
         * WARC 0.12 and above terminates the version with a CRLF
         */
        c = unsafe { buf.offset(3 as libc::c_uint as isize).offset(end as isize) };
        if ver >= 1200 as libc::c_uint {
            if memcmp_safe(
                c as *const libc::c_void,
                b"\r\n\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
                2 as libc::c_uint as libc::c_ulong,
            ) != 0 as libc::c_int
            {
                ver = 0 as libc::c_uint
            }
        } else if unsafe { *c as libc::c_int != ' ' as i32 && *c as libc::c_int != '\t' as i32 } {
            ver = 0 as libc::c_uint
        }
    }
    return ver;
}
extern "C" fn _warc_rdtyp(mut buf: *const libc::c_char, mut bsz: size_t) -> libc::c_uint {
    static mut _key: [libc::c_char; 13] =
        unsafe { *::std::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"\r\nWARC-Type:\x00") };
    let mut val: *const libc::c_char = 0 as *const libc::c_char;
    let mut eol: *const libc::c_char = 0 as *const libc::c_char;
    val = xmemmem(
        buf,
        bsz,
        unsafe { _key.as_ptr() },
        (::std::mem::size_of::<[libc::c_char; 13]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_uint as libc::c_ulong),
    );
    if val.is_null() {
        /* ver < 1200U */
        /* no bother */
        return WT_NONE as libc::c_int as libc::c_uint;
    }
    val = unsafe {
        val.offset(
            (::std::mem::size_of::<[libc::c_char; 13]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_uint as libc::c_ulong) as isize,
        )
    };
    eol = _warc_find_eol(val, unsafe {
        buf.offset(bsz as isize).offset_from(val) as libc::c_long as size_t
    });
    if eol.is_null() {
        /* no end of line */
        return WT_NONE as libc::c_int as libc::c_uint;
    }
    /* overread whitespace */
    while unsafe {
        val < eol && (*val as libc::c_int == ' ' as i32 || *val as libc::c_int == '\t' as i32)
    } {
        unsafe { val = val.offset(1) }
    }
    if unsafe { val.offset(8 as libc::c_uint as isize) } == eol {
        if memcmp_safe(
            val as *const libc::c_void,
            b"resource\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
            8 as libc::c_uint as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            return WT_RSRC as libc::c_int as libc::c_uint;
        } else {
            if memcmp_safe(
                val as *const libc::c_void,
                b"response\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
                8 as libc::c_uint as libc::c_ulong,
            ) == 0 as libc::c_int
            {
                return WT_RSP as libc::c_int as libc::c_uint;
            }
        }
    }
    return WT_NONE as libc::c_int as libc::c_uint;
}
extern "C" fn _warc_rduri(mut buf: *const libc::c_char, mut bsz: size_t) -> warc_string_t {
    static mut _key: [libc::c_char; 19] = unsafe {
        *::std::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"\r\nWARC-Target-URI:\x00")
    };
    let mut val: *const libc::c_char = 0 as *const libc::c_char;
    let mut uri: *const libc::c_char = 0 as *const libc::c_char;
    let mut eol: *const libc::c_char = 0 as *const libc::c_char;
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut res: warc_string_t = {
        let mut init = warc_string_t {
            len: 0 as libc::c_uint as size_t,
            str_0: 0 as *const libc::c_char,
        };
        init
    };
    val = xmemmem(
        buf,
        bsz,
        unsafe { _key.as_ptr() },
        (::std::mem::size_of::<[libc::c_char; 19]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_uint as libc::c_ulong),
    );
    if val.is_null() {
        /* no bother */
        return res;
    }
    /* overread whitespace */
    val = unsafe {
        val.offset(
            (::std::mem::size_of::<[libc::c_char; 19]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_uint as libc::c_ulong) as isize,
        )
    };
    eol = _warc_find_eol(val, unsafe {
        buf.offset(bsz as isize).offset_from(val) as libc::c_long as size_t
    });
    if eol.is_null() {
        /* no end of line */
        return res;
    }
    while unsafe {
        val < eol && (*val as libc::c_int == ' ' as i32 || *val as libc::c_int == '\t' as i32)
    } {
        val = unsafe { val.offset(1) }
    }
    /* overread URL designators */
    uri = xmemmem(
        val,
        unsafe { eol.offset_from(val) as libc::c_long as size_t },
        b"://\x00" as *const u8 as *const libc::c_char,
        3 as libc::c_uint as size_t,
    );
    if uri.is_null() {
        /* not touching that! */
        return res;
    }
    /* spaces inside uri are not allowed, CRLF should follow */
    p = val;
    while p < eol {
        if unsafe {
            *(*__ctype_b_loc()).offset(*p as libc::c_uchar as libc::c_int as isize) as libc::c_int
                & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
                != 0
        } {
            return res;
        }
        unsafe { p = p.offset(1) }
    }
    /* there must be at least space for ftp */
    if uri < unsafe { val.offset(3 as libc::c_uint as isize) } {
        return res;
    }
    /* move uri to point to after :// */
    uri = unsafe { uri.offset(3 as libc::c_uint as isize) };
    /* now then, inspect the URI */
    if !(memcmp_safe(
        val as *const libc::c_void,
        b"file\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
        4 as libc::c_uint as libc::c_ulong,
    ) == 0 as libc::c_int)
    {
        if memcmp_safe(
            val as *const libc::c_void,
            b"http\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
            4 as libc::c_uint as libc::c_ulong,
        ) == 0 as libc::c_int
            || memcmp_safe(
                val as *const libc::c_void,
                b"ftp\x00" as *const u8 as *const libc::c_char as *const libc::c_void,
                3 as libc::c_uint as libc::c_ulong,
            ) == 0 as libc::c_int
        {
            /* overread domain, and the first / */
            while uri < eol && {
                unsafe {
                    let fresh7 = uri;
                    uri = uri.offset(1);
                    (*fresh7 as libc::c_int) != '/' as i32
                }
            } {}
        } else {
            /* not sure what to do? best to bugger off */
            return res;
        }
    }
    res.str_0 = uri;
    res.len = unsafe { eol.offset_from(uri) as libc::c_long as size_t };
    return res;
}
extern "C" fn _warc_rdlen(mut buf: *const libc::c_char, mut bsz: size_t) -> ssize_t {
    static mut _key: [libc::c_char; 18] = unsafe {
        *::std::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"\r\nContent-Length:\x00")
    };
    let mut val: *const libc::c_char = 0 as *const libc::c_char;
    let mut eol: *const libc::c_char = 0 as *const libc::c_char;
    let mut on: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: libc::c_long = 0;
    val = xmemmem(
        buf,
        bsz,
        unsafe { _key.as_ptr() },
        (::std::mem::size_of::<[libc::c_char; 18]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_uint as libc::c_ulong),
    );
    if val.is_null() {
        /* no bother */
        return -(1 as libc::c_int) as ssize_t;
    }
    val = unsafe {
        val.offset(
            (::std::mem::size_of::<[libc::c_char; 18]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_uint as libc::c_ulong) as isize,
        )
    };
    eol = _warc_find_eol(val, unsafe {
        buf.offset(bsz as isize).offset_from(val) as libc::c_long as size_t
    });
    if eol.is_null() {
        /* no end of line */
        return -(1 as libc::c_int) as ssize_t;
    }
    /* skip leading whitespace */
    unsafe {
        while val < eol && (*val as libc::c_int == ' ' as i32 || *val as libc::c_int == '\t' as i32)
        {
            val = val.offset(1)
        }
    }
    /* there must be at least one digit */
    if unsafe {
        *(*__ctype_b_loc()).offset(*val as libc::c_uchar as libc::c_int as isize) as libc::c_int
            & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int
            == 0
    } {
        return -(1 as libc::c_int) as ssize_t;
    }
    unsafe { *__errno_location_safe() = 0 as libc::c_int };
    len = strtol_safe(val, &mut on, 10 as libc::c_int);
    if unsafe { *__errno_location_safe() != 0 as libc::c_int } || on != eol as *mut libc::c_char {
        /* line must end here */
        return -(1 as libc::c_int) as ssize_t;
    }
    return len as size_t as ssize_t;
}
extern "C" fn _warc_rdrtm(mut buf: *const libc::c_char, mut bsz: size_t) -> time_t {
    static mut _key: [libc::c_char; 13] =
        unsafe { *::std::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"\r\nWARC-Date:\x00") };
    let mut val: *const libc::c_char = 0 as *const libc::c_char;
    let mut eol: *const libc::c_char = 0 as *const libc::c_char;
    let mut on: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut res: time_t = 0;
    val = xmemmem(
        buf,
        bsz,
        unsafe { _key.as_ptr() },
        (::std::mem::size_of::<[libc::c_char; 13]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_uint as libc::c_ulong),
    );
    if val.is_null() {
        /* no bother */
        return -(1 as libc::c_int) as time_t;
    }
    val = unsafe {
        val.offset(
            (::std::mem::size_of::<[libc::c_char; 13]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_uint as libc::c_ulong) as isize,
        )
    };
    eol = _warc_find_eol(val, unsafe {
        buf.offset(bsz as isize).offset_from(val) as libc::c_long as size_t
    });
    if eol.is_null() {
        /* no end of line */
        return -(1 as libc::c_int) as time_t;
    }
    /* xstrpisotime() kindly overreads whitespace for us, so use that */
    res = xstrpisotime(val, &mut on);
    if on != eol as *mut libc::c_char {
        /* line must end here */
        return -(1 as libc::c_int) as time_t;
    }
    return res;
}
extern "C" fn _warc_rdmtm(mut buf: *const libc::c_char, mut bsz: size_t) -> time_t {
    static mut _key: [libc::c_char; 17] = unsafe {
        *::std::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"\r\nLast-Modified:\x00")
    };
    let mut val: *const libc::c_char = 0 as *const libc::c_char;
    let mut eol: *const libc::c_char = 0 as *const libc::c_char;
    let mut on: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut res: time_t = 0;
    val = xmemmem(
        buf,
        bsz,
        unsafe { _key.as_ptr() },
        (::std::mem::size_of::<[libc::c_char; 17]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_uint as libc::c_ulong),
    );
    if val.is_null() {
        /* no bother */
        return -(1 as libc::c_int) as time_t;
    }
    val = unsafe {
        val.offset(
            (::std::mem::size_of::<[libc::c_char; 17]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_uint as libc::c_ulong) as isize,
        )
    };
    eol = _warc_find_eol(val, unsafe {
        buf.offset(bsz as isize).offset_from(val) as libc::c_long as size_t
    });
    if eol.is_null() {
        /* no end of line */
        return -(1 as libc::c_int) as time_t;
    }
    /* xstrpisotime() kindly overreads whitespace for us, so use that */
    res = xstrpisotime(val, &mut on);
    if on != eol as *mut libc::c_char {
        /* line must end here */
        return -(1 as libc::c_int) as time_t;
    }
    return res;
}
extern "C" fn _warc_find_eoh(mut buf: *const libc::c_char, mut bsz: size_t) -> *const libc::c_char {
    static mut _marker: [libc::c_char; 5] =
        unsafe { *::std::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"\r\n\r\n\x00") };
    let mut hit: *const libc::c_char = xmemmem(
        buf,
        bsz,
        unsafe { _marker.as_ptr() },
        (::std::mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_uint as libc::c_ulong),
    );
    if !hit.is_null() {
        hit = unsafe {
            hit.offset(
                (::std::mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_uint as libc::c_ulong) as isize,
            )
        }
    }
    return hit;
}
extern "C" fn _warc_find_eol(mut buf: *const libc::c_char, mut bsz: size_t) -> *const libc::c_char {
    static mut _marker: [libc::c_char; 3] =
        unsafe { *::std::mem::transmute::<&[u8; 3], &[libc::c_char; 3]>(b"\r\n\x00") };
    let mut hit: *const libc::c_char = xmemmem(
        buf,
        bsz,
        unsafe { _marker.as_ptr() },
        (::std::mem::size_of::<[libc::c_char; 3]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_uint as libc::c_ulong),
    );
    return hit;
}
/* archive_read_support_format_warc.c ends here */
