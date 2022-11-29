use rust_ffi::ffi_alias::alias_set::*;

#[inline]
pub fn archive_be16dec(pp: *const ()) -> uint16_t {
    let mut p: *const u8 = pp as *const u8;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p1: u32 = unsafe { *p.offset(1) } as u32;
    let mut p0: u32 = unsafe { *p.offset(0) } as u32;
    return (p0 << 8 | p1) as uint16_t;
}

#[inline]
pub fn archive_le16dec(pp: *const ()) -> uint16_t {
    let mut p: *const u8 = pp as *const u8;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p1: u32 = unsafe { *p.offset(1) } as u32;
    let mut p0: u32 = unsafe { *p.offset(0) } as u32;
    return (p1 << 8 | p0) as uint16_t;
}

#[inline]
pub fn archive_be32dec(mut pp: *const ()) -> uint32_t {
    let mut p: *const u8 = pp as *const u8;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p3: u32 = unsafe { *p.offset(3) } as u32;
    let mut p2: u32 = unsafe { *p.offset(2) } as u32;
    let mut p1: u32 = unsafe { *p.offset(1) } as u32;
    let mut p0: u32 = unsafe { *p.offset(0) } as u32;
    return p0 << 24 | p1 << 16 | p2 << 8 | p3;
}

#[inline]
pub fn archive_le32dec(pp: *const ()) -> uint32_t {
    let p: *const u8 = pp as *const u8;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p3: u32 = unsafe { *p.offset(3) } as u32;
    let mut p2: u32 = unsafe { *p.offset(2) } as u32;
    let mut p1: u32 = unsafe { *p.offset(1) } as u32;
    let mut p0: u32 = unsafe { *p.offset(0) } as u32;
    return p3 << 24 | p2 << 16 | p1 << 8 | p0;
}

#[inline]
pub fn archive_le64dec(pp: *const ()) -> uint64_t {
    let p: *const u8 = pp as *const u8;
    return (archive_le32dec(unsafe { p.offset(4) } as *const ()) as uint64_t) << 32
        | archive_le32dec(p as *const ()) as u64;
}

#[inline]
pub fn archive_be64dec(pp: *const ()) -> uint64_t {
    let p: *const u8 = pp as *const u8;
    return (archive_be32dec(p as *const ()) as uint64_t) << 32
        | archive_be32dec(unsafe { p.offset(4) as *const () }) as u64;
}

#[inline]
pub fn archive_le16enc(pp: *mut (), u: uint16_t) {
    let p: *mut u8 = pp as *mut u8;
    unsafe {
        *p.offset(0) = (u as i32 & 0xff) as u8;
        *p.offset(1) = (u as i32 >> 8 & 0xff) as u8;
    }
}

#[inline]
pub fn archive_le32enc(pp: *mut (), u: uint32_t) {
    let p: *mut u8 = pp as *mut u8;
    unsafe {
        *p.offset(0) = (u & 0xff) as u8;
        *p.offset(1) = (u >> 8 & 0xff) as u8;
        *p.offset(2) = (u >> 16 & 0xff) as u8;
        *p.offset(3) = (u >> 24 & 0xff) as u8;
    }
}

#[inline]
pub fn archive_be16enc(pp: *mut (), u: uint16_t) {
    let p: *mut u8 = pp as *mut u8;
    unsafe {
        *p.offset(0) = (u as i32 >> 8 & 0xff) as u8;
        *p.offset(1) = (u as i32 & 0xff) as u8;
    }
}
