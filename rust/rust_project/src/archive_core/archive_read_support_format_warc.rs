use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;
use std::mem::size_of;
use std::mem::transmute;

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
pub extern "C" fn archive_read_support_format_warc(_a: *mut archive) -> i32 {
    let a: *mut archive_read = _a as *mut archive_read;
    let w: *mut warc_s;
    let r: i32;

    let safe_a = unsafe { &mut *a };
    let magic_test: i32 = __archive_check_magic_safe(
        _a,
        ARCHIVE_WARC_DEFINED_PARAM.archive_read_magic,
        ARCHIVE_WARC_DEFINED_PARAM.archive_state_new,
        b"archive_read_support_format_warc\x00" as *const u8 as *const i8,
    );
    if magic_test == ARCHIVE_WARC_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
    }
    w = calloc_safe(1, size_of::<warc_s>() as u64) as *mut warc_s;
    if w.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_WARC_DEFINED_PARAM.enomem,
            b"Can\'t allocate warc data\x00" as *const u8 as *const i8
        );
        return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
    }
    r = __archive_read_register_format_safe(
        a,
        w as *mut (),
        b"warc\x00" as *const u8 as *const i8,
        Some(_warc_bid),
        None,
        Some(_warc_rdhdr),
        Some(_warc_read),
        Some(_warc_skip),
        None,
        Some(_warc_cleanup),
        None,
        None,
    );
    if r != ARCHIVE_WARC_DEFINED_PARAM.archive_ok {
        free_safe(w as *mut ());
        return r;
    }
    return 0;
}

extern "C" fn _warc_cleanup(a: *mut archive_read) -> i32 {
    let w: *mut warc_s = unsafe { (*(*a).format).data as *mut warc_s };
    let safe_w = unsafe { &mut *w };
    let safe_a = unsafe { &mut *a };
    if safe_w.pool.len > 0 {
        free_safe(safe_w.pool.str_0 as *mut ());
    }
    archive_string_free_safe(&mut safe_w.sver);
    free_safe(w as *mut ());
    unsafe { (*safe_a.format).data = 0 as *mut() };
    return ARCHIVE_WARC_DEFINED_PARAM.archive_ok;
}
extern "C" fn _warc_bid(mut a: *mut archive_read, best_bid: i32) -> i32 {
    let mut hdr: *const i8;
    let mut nrd: ssize_t = 0;
    let mut ver: u32;
    /* UNUSED */
    /* check first line of file, it should be a record already */
    hdr =
        __archive_read_ahead_safe(a, 12, &mut nrd) as *const i8;
    if hdr.is_null() {
        /* no idea what to do */
        return -1;
    } else if nrd < 12 {
        /* nah, not for us, our magic cookie is at least 12 bytes */
        return -1;
    }
    /* otherwise snarf the record's version number */
    ver = _warc_rdver(hdr, nrd as size_t);
    if ver < 1200 || ver > 10000 {
        /* we only support WARC 0.12 to 1.0 */
        return -1;
    }
    /* otherwise be confident */
    return 64;
}
extern "C" fn _warc_rdhdr(a: *mut archive_read, entry: *mut archive_entry) -> i32 {
    let w: *mut warc_s = unsafe { (*(*a).format).data as *mut warc_s };
    let mut ver: u32;
    let mut buf: *const i8;
    let mut nrd: ssize_t = 0;
    let mut eoh: *const i8;
    /* for the file name, saves some strndup()'ing */
    let mut fnam: warc_string_t = warc_string_t {len: 0, str_0: 0 as *const i8};
    /* warc record type, not that we really use it a lot */
    let mut ftyp: warc_type_t;
    /* content-length+error monad */
    let mut cntlen: ssize_t;
    /* record time is the WARC-Date time we reinterpret it as ctime */
    let mut rtime: time_t;
    /* mtime is the Last-Modified time which will be the entry's mtime */
    let mut mtime: time_t;
    let safe_a = unsafe { &mut *a };
    let safe_w = unsafe { &mut *w };
    loop {
        /* just use read_ahead() they keep track of unconsumed
         * bits and bobs for us; no need to put an extra shift in
         * and reproduce that functionality here */
        buf = __archive_read_ahead_safe(a, ARCHIVE_WARC_DEFINED_PARAM.hdr_probe_len as u64, &mut nrd)
            as *const i8;
        if nrd < 0 {
            /* no good */
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_WARC_DEFINED_PARAM.archive_errno_misc,
                b"Bad record header\x00" as *const u8 as *const i8
            );
            return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
        } else if buf.is_null() {
            /* there should be room for at least WARC/bla\r\n
                * must be EOF therefore */
            return ARCHIVE_WARC_DEFINED_PARAM.archive_eof;
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
                b"Bad record header\x00" as *const u8 as *const i8
            );
            return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
        }
        ver = _warc_rdver(buf, (eoh as u64) - (buf as u64));
        /* we currently support WARC 0.12 to 1.0 */
        if ver == 0 {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_WARC_DEFINED_PARAM.archive_errno_misc,
                b"Invalid record version\x00" as *const u8 as *const i8
            );
            return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
        } else if ver < 1200 || ver > 10000 {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_WARC_DEFINED_PARAM.archive_errno_misc,
                b"Unsupported record version: %u.%u\x00" as *const u8 as *const i8,
                ver / 10000, (ver % 10000) / 100);
            return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
        }
        cntlen = _warc_rdlen(buf, (eoh as u64) - (buf as u64));
        if cntlen < 0 {
            /* nightmare!  the specs say content-length is mandatory
             * so I don't feel overly bad stopping the reader here */
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_WARC_DEFINED_PARAM.einval,
                b"Bad content length\x00" as *const u8 as *const i8
            );
            return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
        }
        rtime = _warc_rdrtm(buf, (eoh as u64) - (buf as u64));
        if rtime == -1 as time_t{
            /* record time is mandatory as per WARC/1.0,
             * so just barf here, fast and loud */
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_WARC_DEFINED_PARAM.einval,
                b"Bad record time\x00" as *const u8 as *const i8
            );
            return ARCHIVE_WARC_DEFINED_PARAM.archive_fatal;
        }
        /* let the world know we're a WARC archive */
        safe_a.archive.archive_format = ARCHIVE_WARC_DEFINED_PARAM.archive_format_warc;
        if ver != safe_w.pver {
            /* stringify this entry's version */
            unsafe {archive_string_sprintf(
                    &mut safe_w.sver as *mut archive_string,
                    b"WARC/%u.%u\x00" as *const u8 as *const i8,
                    ver / 10000, (ver % 10000) / 100)};
            /* remember the version */
            safe_w.pver = ver
        }
        /* start off with the type */
        ftyp = _warc_rdtyp(buf, (eoh as u64) - (buf as u64));
        /* and let future calls know about the content */
        safe_w.cntlen = cntlen as size_t; /* Avoid compiling error on some platform. */
        safe_w.cntoff = 0;
        mtime = 0;
        match ftyp {
            WT_RSRC | WT_RSP => {
                /* only try and read the filename in the cases that are
                 * guaranteed to have one */
                fnam = _warc_rduri(buf, (eoh as u64) - (buf as u64));
                /* check the last character in the URI to avoid creating
                 * directory endpoints as files, see Todo above */
                if fnam.len == 0 || unsafe {*fnam.str_0.offset((fnam.len - 1) as isize)} == '/' as i8 {
                    /* break here for now */
                    fnam.len = 0;
                    fnam.str_0 = 0 as *const i8;
                }
                /* bang to our string pool, so we save a
                * malloc()+free() roundtrip */
                if fnam.len + 1 > safe_w.pool.len {
                    safe_w.pool.len = ((fnam.len + 64) / 64) * 64;
                    safe_w.pool.str_0 = realloc_safe(safe_w.pool.str_0 as *mut (), safe_w.pool.len) as *mut i8
                }
                memcpy_safe(
                    safe_w.pool.str_0 as *mut (),
                    fnam.str_0 as *const (),
                    fnam.len,
                );
                unsafe {
                    *safe_w.pool.str_0.offset(fnam.len as isize) = '\u{0}' as i8
                };
                /* let no one else know about the pool, it's a secret, shhh */
                fnam.str_0 = safe_w.pool.str_0;

                /* snarf mtime or deduce from rtime
                * this is a custom header added by our writer, it's quite
                * hard to believe anyone else would go through with it
                * (apart from being part of some http responses of course) */
                mtime = _warc_rdmtm(buf, (eoh as u64) - (buf as u64));
                if mtime == -1 {
                    mtime = rtime
                }
            }
            WT_NONE | WT_INFO | WT_META | WT_REQ | WT_RVIS | WT_CONV | WT_CONT | LAST_WT | _ => {
                fnam.len = 0;
                fnam.str_0 = 0 as *const i8;
            }
        }
        /* now eat some of those delicious buffer bits */
        __archive_read_consume_safe(a, unsafe { eoh.offset_from(buf) as i64 });
        match ftyp {
            WT_RSRC | WT_RSP => {
                if fnam.len > 0 {
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
    archive_entry_set_perm_safe(entry, 0o644);
    /* rtime is the new ctime, mtime stays mtime */
    archive_entry_set_ctime_safe(entry, rtime, 0);
    archive_entry_set_mtime_safe(entry, mtime, 0);
    return ARCHIVE_WARC_DEFINED_PARAM.archive_ok;
}

extern "C" fn _warc_read(
    a: *mut archive_read,
    buf: *mut *const (),
    bsz: *mut size_t,
    off: *mut int64_t,
) -> i32 {
    let w: *mut warc_s = unsafe { (*(*a).format).data as *mut warc_s };
    let rab: *const i8;
    let mut nrd: ssize_t = 0;
    let safe_off = unsafe { &mut *off };
    let safe_w = unsafe { &mut *w };
    let safe_bsz = unsafe { &mut *bsz };
    let safe_buf = unsafe { &mut *buf };
    if !(safe_w.cntoff >= safe_w.cntlen) {
        if safe_w.unconsumed != 0 {
            __archive_read_consume_safe(a, safe_w.unconsumed as int64_t);
            safe_w.unconsumed = 0;
        }
        rab = __archive_read_ahead_safe(a, 1, &mut nrd) as *const i8;
        if nrd < 0 {
            unsafe { *bsz = 0 };
            /* big catastrophe */
            return nrd as i32;
        } else if !(nrd == 0) {
            if nrd as size_t > safe_w.cntlen - safe_w.cntoff {
                /* clamp to content-length */
                nrd = (safe_w.cntlen - safe_w.cntoff) as ssize_t;
            }
            *safe_off = safe_w.cntoff as int64_t;
            *safe_bsz = nrd as size_t;
            *safe_buf = rab as *const ();
            safe_w.cntoff = safe_w.cntoff - nrd as u64;
            safe_w.unconsumed = nrd as size_t;
            return ARCHIVE_WARC_DEFINED_PARAM.archive_ok;
        }
    }
    /* it's our lucky day, no work, we can leave early */
    *safe_buf = 0 as *const (); /*for \r\n\r\n separator*/
    *safe_bsz = 0;
    *safe_off = (safe_w.cntoff + 4) as i64;
    safe_w.unconsumed = 0;
    return ARCHIVE_WARC_DEFINED_PARAM.archive_eof;
}

extern "C" fn _warc_skip(a: *mut archive_read) -> i32 {
    let w: *mut warc_s = unsafe { (*(*a).format).data as *mut warc_s };
    let safe_w = unsafe { &mut *w };
    __archive_read_consume_safe(a, (safe_w.cntlen + 4) as int64_t);
    safe_w.cntlen = 0;
    safe_w.cntoff = 0;
    return ARCHIVE_WARC_DEFINED_PARAM.archive_ok;
}

/* private routines */
extern "C" fn deconst(c: *const ()) -> *mut () {
    return c as uintptr_t as *mut ();
}

extern "C" fn xmemmem(
    mut hay: *const i8,
    haysize: size_t,
    needle: *const i8,
    needlesize: size_t,
) -> *mut i8 {
    let eoh: *const i8 = unsafe { hay.offset(haysize as isize) };
    let eon: *const i8 = unsafe { needle.offset(needlesize as isize) };
    let mut hp: *const i8;
    let mut np: *const i8;
    let mut cand: *const i8;
    let mut hsum: u32;
    let mut nsum: u32;
    let mut eqp: u32;

    /* trivial checks first
     * a 0-sized needle is defined to be found anywhere in haystack
     * then run strchr() to find a candidate in HAYSTACK (i.e. a portion
     * that happens to begin with *NEEDLE) */
    if needlesize == 0 {
        return deconst(hay as *const ()) as *mut i8;
    } else {
        hay = memchr_safe(
            hay as *const (),
            unsafe { *needle as i32 },
            haysize,
        ) as *const i8;
        if hay.is_null() {
            /* trivial */
            return 0 as *mut i8;
        }
    }

    /* First characters of haystack and needle are the same now. Both are
     * guaranteed to be at least one character long.  Now computes the sum
     * of characters values of needle together with the sum of the first
     * needle_len characters of haystack. */
    hp = unsafe { hay.offset(1) };
    np = unsafe { needle.offset(1) };
    hsum = unsafe { *hay as u32 };
    nsum = unsafe { *hay as u32 };
    eqp = 1;
    while hp < eoh && np < eon {
        hsum ^= unsafe { *hp as u32 };
        nsum ^= unsafe { *np as u32 };
        eqp &= unsafe { (*hp as i32 == *np as i32) as u32 };
        unsafe { hp = hp.offset(1);}
        unsafe { np = np.offset(1);}
    }

    /* HP now references the (NEEDLESIZE + 1)-th character. */
    if np < eon {
        /* haystack is smaller than needle, :O */
        return 0 as *mut i8;
    } else if eqp != 0 {
        /* found a match */
        return deconst(hay as *const ()) as *mut i8;
    }

    /* now loop through the rest of haystack,
     * updating the sum iteratively */
    cand = hay;
    while hp < eoh {
        hsum ^= unsafe { *cand as u32 };
        cand = unsafe { cand.offset(1) };
        hsum ^= unsafe { *hp as u32 };
        /* Since the sum of the characters is already known to be
         * equal at that point, it is enough to check just NEEDLESIZE - 1
         * characters for equality,
         * also CAND is by design < HP, so no need for range checks */
        if hsum == nsum
            && memcmp_safe(cand as *const (), needle as *const (), needlesize - 1) == 0
        {
            return deconst(cand as *const ()) as *mut i8;
        }
        hp = unsafe { hp.offset(1) }
    }
    return 0 as *mut i8;
}

extern "C" fn strtoi_lim(
    str: *const i8,
    ep: *mut *const i8,
    mut llim: i32,
    mut ulim: i32,
) -> i32 {
    let mut res: i32 = 0;
    let mut sp: *const i8;
    /* we keep track of the number of digits via rulim */
    let mut rulim: i32;

    sp = str;
    rulim = if ulim > 10 { ulim } else { 10 };
    while res * 10 <= ulim && rulim != 0
        && unsafe{*sp} as i32 >= '0' as i32
        && unsafe{*sp} as i32 <= '9' as i32
    {
        res *= 10;
        unsafe {
            res += *sp as i32 - '0' as i32;
            sp = sp.offset(1)
        };
        rulim /= 10
    }
    if sp == str {
        res = -1
    } else if res < llim || res > ulim {
        res = -2
    }
    unsafe { *ep = sp };
    return res;
}

extern "C" fn time_from_tm(t: *mut tm) -> time_t {
    /* Use platform timegm() if available. */
    #[cfg(HAVE_TIMEGM)]
    return timegm_safe(t);
    #[cfg_attr(HAVE__MKGMTIME64, cfg(not(HAVE_TIMEGM)))]
    return _mkgmtime_safe(t);
    /* Else use direct calculation using POSIX assumptions. */
    /* First, fix up tm_yday based on the year/month/day. */
    if mktime_safe(t) == -1 as time_t {
        return -1 as time_t;
    }
    let safe_t = unsafe { &mut *t };
    /* Then we can compute timegm() from first principles. */
    return (safe_t.tm_sec
        + safe_t.tm_min * 60
        + safe_t.tm_hour * 3600
        + safe_t.tm_yday * 86400
        + (safe_t.tm_year - 70) * 31536000
        + (safe_t.tm_year - 69) / 4 * 86400 
        - (safe_t.tm_year - 1) / 100 * 86400
        + (safe_t.tm_year + 299) / 400 * 86400)
        as time_t;
}

extern "C" fn xstrpisotime(
    mut s: *const i8,
    endptr: *mut *mut i8,
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
        tm_zone: 0 as *const i8,
    };
    let mut res: time_t = -1;
    /* make sure tm is clean */
    memset_safe(
        &mut tm as *mut tm as *mut (),
        0 as i32,
        size_of::<tm>() as u64,
    );
    /* as a courtesy to our callers, and since this is a non-standard
     * routine, we skip leading whitespace */
    while unsafe { *s as i32 == ' ' as i32 || *s as i32 == '\t' as i32 } {
        unsafe { s = s.offset(1) }
    }

    let mut out: bool = false;
    loop {
        /* read year */
        tm.tm_year = strtoi_lim(s, &mut s, 1583, 4095);
        if tm.tm_year < 0 || {
            unsafe {
                let fresh1 = s;
                s = s.offset(1);
                (*fresh1 as i32) != '-' as i32
            }
        } {
            out = true;
            break;
        }
        /* read month */
        tm.tm_mon = strtoi_lim(s, &mut s, 1, 12);
        if tm.tm_mon < 0 || {
            unsafe {
                let fresh2 = s;
                s = s.offset(1);
                (*fresh2 as i32) != '-' as i32
            }
        } {
            out = true;
            break;
        }
        /* read day-of-month */
        tm.tm_mday = strtoi_lim(s, &mut s, 1 as i32, 31 as i32);
        if tm.tm_mday < 0 as i32 || {
            unsafe {
                let fresh3 = s;
                s = s.offset(1);
                (*fresh3 as i32) != 'T' as i32
            }
        } {
            out = true;
            break;
        }
        /* read hour */
        tm.tm_hour = strtoi_lim(s, &mut s, 0 as i32, 23 as i32);
        if tm.tm_hour < 0 as i32 || {
            unsafe {
                let fresh4 = s;
                s = s.offset(1);
                (*fresh4 as i32) != ':' as i32
            }
        } {
            out = true;
            break;
        }
        /* read minute */
        tm.tm_min = strtoi_lim(s, &mut s, 0 as i32, 59 as i32);
        if tm.tm_min < 0 as i32 || {
            unsafe {
                let fresh5 = s;
                s = s.offset(1);
                (*fresh5 as i32) != ':' as i32
            }
        } {
            out = true;
            break;
        }
        /* read second */
        tm.tm_sec = strtoi_lim(s, &mut s, 0 as i32, 60 as i32);
        if tm.tm_sec < 0 as i32 || {
            unsafe {
                let fresh6 = s;
                s = s.offset(1);
                (*fresh6 as i32) != 'Z' as i32
            }
        } {
            out = true;
            break;
        }
        break;
    }
    
    if out == false {
        /* massage TM to fulfill some of POSIX' constraints */
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;
        /* now convert our custom tm struct to a unix stamp using UTC */
        res = time_from_tm(&mut tm);
    } 
    if !endptr.is_null() {
        unsafe { *endptr = deconst(s as *const ()) as *mut i8 }
    }
    return res;
}

/* private routines */
extern "C" fn _warc_rdver(mut buf: *const i8, mut bsz: size_t) -> u32 {
    static magic: [i8; 6] =
        unsafe { *transmute::<&[u8; 6], &[i8; 6]>(b"WARC/\x00") };
    let c: *const i8;
    let mut ver: u32 = 0;
    let mut end: u32 = 0;
    if bsz < 12 as u64
        || memcmp_safe(
            buf as *const (),
            unsafe { magic.as_ptr() as *const () },
            size_of::<[i8; 6]>() as u64 - 1,
        ) != 0
    {
        /* buffer too small or invalid magic */
        return ver;
    }
    /* looks good so far, read the version number for a laugh */
    buf = unsafe {
        buf.offset(
            (size_of::<[i8; 6]>() as u64 - 1) as isize,
        )
    };
    if unsafe {
        *(*__ctype_b_loc()).offset(
            *buf.offset(0) as isize
        ) as i32
            & _ISdigit as i32
            != 0
            && *buf.offset(1) == '.' as i8
            && *(*__ctype_b_loc()).offset(
                *buf.offset(2) as isize
            ) as i32
                & _ISdigit as i32
                != 0
    } {
        /* we support a maximum of 2 digits in the minor version */
        if unsafe {
            *(*__ctype_b_loc()).offset(
                *buf.offset(3) as isize
            ) as i32
                & _ISdigit as i32
                != 0
        } {
            end = 1
        }
        /* set up major version */
        ver = unsafe {
            ((*buf.offset(0) - '0' as i8) as u32) * 10000
        };
        /* set up minor version */
        if end == 1 {
            ver = ver.wrapping_add(
                (unsafe { *buf.offset(2) - '0' as i8 }
                    as u32) * 1000,
            );
            ver = ver.wrapping_add(
                (unsafe { *buf.offset(3) - '0' as i8 }
                    as u32) * 100,
            )
        } else {
            ver = ver.wrapping_add(
                (unsafe { *buf.offset(2) - '0' as i8 }
                    as u32) * 100,
            )
        }
        /*
         * WARC below version 0.12 has a space-separated header
         * WARC 0.12 and above terminates the version with a CRLF
         */
        c = unsafe { buf.offset(3).offset(end as isize) };
        if ver >= 1200 {
            if memcmp_safe(
                c as *const (),
                b"\r\n\x00" as *const u8 as *const i8 as *const (),
                2,
            ) != 0
            {
                ver = 0
            }
        } else if unsafe { *c != ' ' as i8 && *c != '\t' as i8 } {
            ver = 0
        }
    }
    return ver;
}
extern "C" fn _warc_rdtyp(mut buf: *const i8, mut bsz: size_t) -> u32 {
    static _key: [i8; 13] =
        unsafe { *transmute::<&[u8; 13], &[i8; 13]>(b"\r\nWARC-Type:\x00") };
    let mut val: *const i8;
    let eol: *const i8;
    val = xmemmem(
        buf,
        bsz,
        unsafe { _key.as_ptr() },
        size_of::<[i8; 13]>() as u64 - 1,
    );
    if val.is_null() {
        /* ver < 1200U */
        /* no bother */
        return WT_NONE;
    }
    val = unsafe {
        val.offset(
            (size_of::<[i8; 13]>() as u64 - 1) as isize,
        )
    };
    eol = _warc_find_eol(val, unsafe {
        buf.offset(bsz as isize).offset_from(val) as size_t
    });
    if eol.is_null() {
        /* no end of line */
        return WT_NONE;
    }
    /* overread whitespace */
    while unsafe {
        val < eol && (*val == ' ' as i8 || *val == '\t' as i8)
    } {
        unsafe { val = val.offset(1) }
    }
    if unsafe { val.offset(8) } == eol {
        if memcmp_safe(
            val as *const (),
            b"resource\x00" as *const u8 as *const i8 as *const (),
            8,
        ) == 0
        {
            return WT_RSRC;
        } else {
            if memcmp_safe(
                val as *const (),
                b"response\x00" as *const u8 as *const i8 as *const (),
                8,
            ) == 0
            {
                return WT_RSP;
            }
        }
    }
    return WT_NONE;
}
extern "C" fn _warc_rduri(mut buf: *const i8, mut bsz: size_t) -> warc_string_t {
    static _key: [i8; 19] = unsafe {
        *transmute::<&[u8; 19], &[i8; 19]>(b"\r\nWARC-Target-URI:\x00")
    };
    let mut val: *const i8;
    let mut uri: *const i8;
    let eol: *const i8;
    let mut p: *const i8;
    let mut res = warc_string_t {  
            len: 0,
            str_0: 0 as *const i8,
    };
    val = xmemmem(
        buf,
        bsz,
        unsafe { _key.as_ptr() },
        size_of::<[i8; 19]>() as u64 - 1,
    );
    if val.is_null() {
        /* no bother */
        return res;
    }
    /* overread whitespace */
    val = unsafe {
        val.offset(
            (size_of::<[i8; 19]>() as u64 - 1) as isize,
        )
    };
    eol = _warc_find_eol(val, unsafe {
        buf.offset(bsz as isize).offset_from(val) as size_t
    });
    if eol.is_null() {
        /* no end of line */
        return res;
    }
    while unsafe {
        val < eol && (*val == ' ' as i8 || *val == '\t' as i8)
    } {
        val = unsafe { val.offset(1) }
    }
    /* overread URL designators */
    uri = xmemmem(
        val,
        unsafe { eol.offset_from(val) as size_t },
        b"://\x00" as *const u8 as *const i8,
        3,
    );
    if uri.is_null() {
        /* not touching that! */
        return res;
    }
    /* spaces inside uri are not allowed, CRLF should follow */
    p = val;
    while p < eol {
        if unsafe {
            *(*__ctype_b_loc()).offset(*p as isize) as i32
                & _ISspace as i32
                != 0
        } {
            return res;
        }
        unsafe { p = p.offset(1) }
    }
    /* there must be at least space for ftp */
    if uri < unsafe { val.offset(3) } {
        return res;
    }
    /* move uri to point to after :// */
    uri = unsafe { uri.offset(3) };
    /* now then, inspect the URI */
    if !(memcmp_safe(
        val as *const (),
        b"file\x00" as *const u8 as *const i8 as *const (),
        4,
    ) == 0)
    {
        if memcmp_safe(
            val as *const (),
            b"http\x00" as *const u8 as *const i8 as *const (),
            4,
        ) == 0
            || memcmp_safe(
                val as *const (),
                b"ftp\x00" as *const u8 as *const i8 as *const (),
                3,
            ) == 0
        {
            /* overread domain, and the first / */
            while uri < eol && {
                unsafe { 
                    let before_uri = uri;
                    uri = uri.offset(1); 
                    *before_uri != '/' as i8
                }
            } {}
        } else {
            /* not sure what to do? best to bugger off */
            return res;
        }
    }
    res.str_0 = uri;
    res.len = unsafe { eol.offset_from(uri) as size_t };
    return res;
}
extern "C" fn _warc_rdlen(mut buf: *const i8, mut bsz: size_t) -> ssize_t {
    static _key: [i8; 18] = unsafe {
        *transmute::<&[u8; 18], &[i8; 18]>(b"\r\nContent-Length:\x00")
    };
    let mut val: *const i8;
    let eol: *const i8;
    let mut on: *mut i8 = 0 as *mut i8;
    let mut len: i64;
    val = xmemmem(
        buf,
        bsz,
        unsafe { _key.as_ptr() },
        (size_of::<[i8; 18]>() as u64) - 1,
    );
    if val.is_null() {
        /* no bother */
        return -1;
    }
    val = unsafe {
        val.offset(
            (size_of::<[i8; 18]>() as u64 - 1) as isize,
        )
    };
    eol = _warc_find_eol(val, unsafe {
        buf.offset(bsz as isize).offset_from(val) as size_t
    });
    if eol.is_null() {
        /* no end of line */
        return -1;
    }
    /* skip leading whitespace */
    unsafe {
        while val < eol && (*val == ' ' as i8 || *val == '\t' as i8)
        {
            val = val.offset(1)
        }
    }
    /* there must be at least one digit */
    if unsafe {
        *(*__ctype_b_loc()).offset(*val as isize) as i32
            & _ISdigit as i32
            == 0
    } {
        return -1;
    }
    unsafe { *__errno_location_safe() = 0};
    len = strtol_safe(val, &mut on, 10);
    if unsafe { *__errno_location_safe() != 0 } || on != eol as *mut i8 {
        /* line must end here */
        return -1;
    }
    return len as ssize_t;
}
extern "C" fn _warc_rdrtm(mut buf: *const i8, mut bsz: size_t) -> time_t {
    static _key: [i8; 13] =
        unsafe { *transmute::<&[u8; 13], &[i8; 13]>(b"\r\nWARC-Date:\x00") };
    let mut val: *const i8;
    let eol: *const i8;
    let mut on: *mut i8 = 0 as *mut i8;
    let res: time_t;
    val = xmemmem(
        buf,
        bsz,
        unsafe { _key.as_ptr() },
        size_of::<[i8; 13]>() as u64 - 1,
    );
    if val.is_null() {
        /* no bother */
        return -1;
    }
    val = unsafe {
        val.offset(
            (size_of::<[i8; 13]>() as u64 - 1) as isize,
        )
    };
    eol = _warc_find_eol(val, unsafe {
        buf.offset(bsz as isize).offset_from(val) as size_t
    });
    if eol.is_null() {
        /* no end of line */
        return -1;
    }
    /* xstrpisotime() kindly overreads whitespace for us, so use that */
    res = xstrpisotime(val, &mut on);
    if on != eol as *mut i8 {
        /* line must end here */
        return -1;
    }
    return res;
}
extern "C" fn _warc_rdmtm(mut buf: *const i8, mut bsz: size_t) -> time_t {
    static _key: [i8; 17] = unsafe {
        *transmute::<&[u8; 17], &[i8; 17]>(b"\r\nLast-Modified:\x00")
    };
    let mut val: *const i8;
    let eol: *const i8;
    let mut on: *mut i8 = 0 as *mut i8;
    let res: time_t;
    val = xmemmem(
        buf,
        bsz,
        unsafe { _key.as_ptr() },
        size_of::<[i8; 17]>() as u64 - 1,
    );
    if val.is_null() {
        /* no bother */
        return -1;
    }
    val = unsafe {
        val.offset(
            (size_of::<[i8; 17]>() as u64 - 1) as isize,
        )
    };
    eol = _warc_find_eol(val, unsafe {
        buf.offset(bsz as isize).offset_from(val) as size_t
    });
    if eol.is_null() {
        /* no end of line */
        return -1;
    }
    /* xstrpisotime() kindly overreads whitespace for us, so use that */
    res = xstrpisotime(val, &mut on);
    if on != eol as *mut i8 {
        /* line must end here */
        return -1;
    }
    return res;
}
extern "C" fn _warc_find_eoh(mut buf: *const i8, mut bsz: size_t) -> *const i8 {
    static _marker: [i8; 5] = 
        unsafe { *transmute::<&[u8; 5], &[i8; 5]>(b"\r\n\r\n\x00") };
    let mut hit: *const i8 = xmemmem(
        buf,
        bsz,
        unsafe { _marker.as_ptr() },
        size_of::<[i8; 5]>() as u64 - 1,
    );
    if !hit.is_null() {
        hit = unsafe {
            hit.offset(
                (size_of::<[i8; 5]>() as u64 - 1) as isize,
            )
        }
    }
    return hit;
}
extern "C" fn _warc_find_eol(mut buf: *const i8, mut bsz: size_t) -> *const i8 {
    static _marker: [i8; 3] = 
        unsafe { *transmute::<&[u8; 3], &[i8; 3]>(b"\r\n\x00") };
    let hit: *const i8 = xmemmem(
        buf,
        bsz,
        unsafe { _marker.as_ptr() },
        size_of::<[i8; 3]>() as u64 - 1,
    );
    return hit;
}
/* archive_read_support_format_warc.c ends here */
