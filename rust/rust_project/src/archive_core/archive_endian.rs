use rust_ffi::ffi_alias::alias_set::*;
use std::mem::size_of;

#[inline]
pub fn archive_be16dec(mut pp: *const ()) -> uint16_t {
    let mut p: *const u8 = pp as *const u8;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p1: u32 = unsafe { *p.offset(1 as i32 as isize) } as u32;
    let mut p0: u32 = unsafe { *p.offset(0 as i32 as isize) } as u32;
    return (p0 << 8 as i32 | p1) as uint16_t;
}

#[inline]
pub fn archive_le16dec(mut pp: *const ()) -> uint16_t {
    let mut p: *const u8 = pp as *const u8;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p1: u32 = unsafe { *p.offset(1 as i32 as isize) } as u32;
    let mut p0: u32 = unsafe { *p.offset(0 as i32 as isize) } as u32;
    return (p1 << 8 as i32 | p0) as uint16_t;
}

#[inline]
pub fn archive_be32dec(mut pp: *const ()) -> uint32_t {
    let mut p: *const u8 = pp as *const u8;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p3: u32 = unsafe { *p.offset(3 as i32 as isize) } as u32;
    let mut p2: u32 = unsafe { *p.offset(2 as i32 as isize) } as u32;
    let mut p1: u32 = unsafe { *p.offset(1 as i32 as isize) } as u32;
    let mut p0: u32 = unsafe { *p.offset(0 as i32 as isize) } as u32;
    return p0 << 24 as i32 | p1 << 16 as i32 | p2 << 8 as i32 | p3;
}

#[inline]
pub fn archive_le32dec(mut pp: *const ()) -> uint32_t {
    let mut p: *const u8 = pp as *const u8;
    /* Store into unsigned temporaries before left shifting, to avoid
    promotion to signed int and then left shifting into the sign bit,
    which is undefined behaviour. */
    let mut p3: u32 = unsafe { *p.offset(3 as i32 as isize) } as u32;
    let mut p2: u32 = unsafe { *p.offset(2 as i32 as isize) } as u32;
    let mut p1: u32 = unsafe { *p.offset(1 as i32 as isize) } as u32;
    let mut p0: u32 = unsafe { *p.offset(0 as i32 as isize) } as u32;
    return p3 << 24 as i32 | p2 << 16 as i32 | p1 << 8 as i32 | p0;
}

#[inline]
pub fn archive_le64dec(mut pp: *const ()) -> uint64_t {
    let mut p: *const u8 = pp as *const u8;
    return (archive_le32dec(unsafe { p.offset(4 as i32 as isize) } as *const ()) as uint64_t)
        << 32 as i32
        | archive_le32dec(p as *const ()) as u64;
}

#[inline]
pub extern "C" fn archive_be64dec(mut pp: *const ()) -> uint64_t {
    let mut p: *const u8 = pp as *const u8;
    return (archive_be32dec(p as *const ()) as uint64_t) << 32 as i32
        | archive_be32dec(unsafe { p.offset(4 as i32 as isize) as *const () }) as u64;
}

#[inline]
pub extern "C" fn archive_le16enc(mut pp: *mut (), mut u: uint16_t) {
    let mut p: *mut u8 = pp as *mut u8;
    unsafe {
        *p.offset(0 as i32 as isize) = (u as i32 & 0xff as i32) as u8;
        *p.offset(1 as i32 as isize) = (u as i32 >> 8 as i32 & 0xff as i32) as u8;
    }
}

#[inline]
pub extern "C" fn archive_le32enc(mut pp: *mut (), mut u: uint32_t) {
    let mut p: *mut u8 = pp as *mut u8;
    unsafe {
        *p.offset(0 as i32 as isize) = (u & 0xff as i32 as u32) as u8;
        *p.offset(1 as i32 as isize) = (u >> 8 as i32 & 0xff as i32 as u32) as u8;
        *p.offset(2 as i32 as isize) = (u >> 16 as i32 & 0xff as i32 as u32) as u8;
        *p.offset(3 as i32 as isize) = (u >> 24 as i32 & 0xff as i32 as u32) as u8;
    }
}

#[inline]
pub extern "C" fn archive_be16enc(mut pp: *mut (), mut u: uint16_t) {
    let mut p: *mut u8 = pp as *mut u8;
    unsafe {
        *p.offset(0 as i32 as isize) = (u as i32 >> 8 as i32 & 0xff as i32) as u8;
        *p.offset(1 as i32 as isize) = (u as i32 & 0xff as i32) as u8;
    }
}
