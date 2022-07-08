use rust_ffi::ffi_alias::alias_set::*;

#[inline]
pub fn archive_be16dec(mut pp: *const libc::c_void) -> uint16_t {
    let mut p: *const libc::c_uchar = pp as *const libc::c_uchar;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p1: libc::c_uint = unsafe { *p.offset(1 as libc::c_int as isize) } as libc::c_uint;
    let mut p0: libc::c_uint = unsafe { *p.offset(0 as libc::c_int as isize) } as libc::c_uint;
    return (p0 << 8 as libc::c_int | p1) as uint16_t;
}

#[inline]
pub fn archive_le16dec(mut pp: *const libc::c_void) -> uint16_t {
    let mut p: *const libc::c_uchar = pp as *const libc::c_uchar;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p1: libc::c_uint = unsafe { *p.offset(1 as libc::c_int as isize) } as libc::c_uint;
    let mut p0: libc::c_uint = unsafe { *p.offset(0 as libc::c_int as isize) } as libc::c_uint;
    return (p1 << 8 as libc::c_int | p0) as uint16_t;
}

#[inline]
pub fn archive_be32dec(mut pp: *const libc::c_void) -> uint32_t {
    let mut p: *const libc::c_uchar = pp as *const libc::c_uchar;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p3: libc::c_uint = unsafe { *p.offset(3 as libc::c_int as isize) } as libc::c_uint;
    let mut p2: libc::c_uint = unsafe { *p.offset(2 as libc::c_int as isize) } as libc::c_uint;
    let mut p1: libc::c_uint = unsafe { *p.offset(1 as libc::c_int as isize) } as libc::c_uint;
    let mut p0: libc::c_uint = unsafe { *p.offset(0 as libc::c_int as isize) } as libc::c_uint;
    return p0 << 24 as libc::c_int | p1 << 16 as libc::c_int | p2 << 8 as libc::c_int | p3;
}

#[inline]
pub fn archive_le32dec(mut pp: *const libc::c_void) -> uint32_t {
    let mut p: *const libc::c_uchar = pp as *const libc::c_uchar;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p3: libc::c_uint = unsafe { *p.offset(3 as libc::c_int as isize) } as libc::c_uint;
    let mut p2: libc::c_uint = unsafe { *p.offset(2 as libc::c_int as isize) } as libc::c_uint;
    let mut p1: libc::c_uint = unsafe { *p.offset(1 as libc::c_int as isize) } as libc::c_uint;
    let mut p0: libc::c_uint = unsafe { *p.offset(0 as libc::c_int as isize) } as libc::c_uint;
    return p3 << 24 as libc::c_int | p2 << 16 as libc::c_int | p1 << 8 as libc::c_int | p0;
}

#[inline]
pub fn archive_le64dec(mut pp: *const libc::c_void) -> uint64_t {
    let mut p: *const libc::c_uchar = pp as *const libc::c_uchar;
    return (archive_le32dec(unsafe { p.offset(4 as libc::c_int as isize) } as *const libc::c_void)
        as uint64_t)
        << 32 as libc::c_int
        | archive_le32dec(p as *const libc::c_void) as libc::c_ulong;
}

#[inline]
pub extern "C" fn archive_be64dec(mut pp: *const libc::c_void) -> uint64_t {
    let mut p: *const libc::c_uchar = pp as *const libc::c_uchar;
    return (archive_be32dec(p as *const libc::c_void) as uint64_t) << 32 as libc::c_int
        | archive_be32dec(unsafe { p.offset(4 as libc::c_int as isize) as *const libc::c_void })
            as libc::c_ulong;
}

#[inline]
pub extern "C" fn archive_le16enc(mut pp: *mut libc::c_void, mut u: uint16_t) {
    let mut p: *mut libc::c_uchar = pp as *mut libc::c_uchar;
    unsafe {
        *p.offset(0 as libc::c_int as isize) =
            (u as libc::c_int & 0xff as libc::c_int) as libc::c_uchar;
        *p.offset(1 as libc::c_int as isize) =
            (u as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int) as libc::c_uchar;
    }
}

#[inline]
pub extern "C" fn archive_le32enc(mut pp: *mut libc::c_void, mut u: uint32_t) {
    let mut p: *mut libc::c_uchar = pp as *mut libc::c_uchar;
    unsafe {
        *p.offset(0 as libc::c_int as isize) =
            (u & 0xff as libc::c_int as libc::c_uint) as libc::c_uchar;
        *p.offset(1 as libc::c_int as isize) =
            (u >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as libc::c_uchar;
        *p.offset(2 as libc::c_int as isize) =
            (u >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as libc::c_uchar;
        *p.offset(3 as libc::c_int as isize) =
            (u >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as libc::c_uchar;
    }
}

#[inline]
pub extern "C" fn archive_be16enc(mut pp: *mut libc::c_void, mut u: uint16_t) {
    let mut p: *mut libc::c_uchar = pp as *mut libc::c_uchar;
    unsafe{
    *p.offset(0 as libc::c_int as isize) =
        (u as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int) as libc::c_uchar;
    *p.offset(1 as libc::c_int as isize) =
        (u as libc::c_int & 0xff as libc::c_int) as libc::c_uchar;
    }
}
