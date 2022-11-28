use archive_core::archive_endian::*;
use rust_ffi::archive_set_error_safe;
use rust_ffi::archive_string_sprintf_safe;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;
use std::mem::size_of;
/* Real RAR5 magic number is:
 *
 * 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00
 * "Rar!→•☺·\x00"
 *
 * Retrieved with `rar5_signature()` by XOR'ing it with 0xA1, because I don't
 * want to put this magic sequence in each binary that uses libarchive, so
 * applications that scan through the file for this marker won't trigger on
 * this "false" one.
 *
 * The array itself is decrypted in `rar5_init` function. */
static mut rar5_signature_xor: [u8; 8] = [
    243 as i32 as u8,
    192 as i32 as u8,
    211 as i32 as u8,
    128 as i32 as u8,
    187 as i32 as u8,
    166 as i32 as u8,
    160 as i32 as u8,
    161 as i32 as u8,
];
static mut g_unpack_window_size: size_t = 0x20000 as i32 as size_t;
/* Clears the contents of this circular deque. */
fn cdeque_clear(mut d: *mut cdeque) {
    let safe_d = unsafe { &mut *d };
    safe_d.size = 0;
    safe_d.beg_pos = 0;
    safe_d.end_pos = 0;
}
/* Creates a new circular deque object. Capacity must be power of 2: 8, 16, 32,
 * 64, 256, etc. When the user will add another item above current capacity,
 * the circular deque will overwrite the oldest entry. */
fn cdeque_init(d: *mut cdeque, max_capacity_power_of_2: i32) -> i32 {
    if d.is_null() || max_capacity_power_of_2 == 0 {
        return CDE_PARAM as i32;
    }
    let safe_d = unsafe { &mut *d };
    safe_d.cap_mask = (max_capacity_power_of_2 - 1) as uint16_t;
    safe_d.arr = 0 as *mut size_t;
    if max_capacity_power_of_2 & safe_d.cap_mask as i32 != 0 as i32 {
        return CDE_PARAM as i32;
    }
    cdeque_clear(d);
    safe_d.arr = unsafe {
        malloc_safe((size_of::<*mut ()>() as u64).wrapping_mul(max_capacity_power_of_2 as u64))
    } as *mut size_t;
    return if !safe_d.arr.is_null() {
        CDE_OK as i32
    } else {
        CDE_ALLOC as i32
    };
}
/* Return the current size (not capacity) of circular deque `d`. */
fn cdeque_size(mut d: *mut cdeque) -> size_t {
    let safe_d = unsafe { &mut *d };
    return safe_d.size as size_t;
}
/* Returns the first element of current circular deque. Note that this function
 * doesn't perform any bounds checking. If you need bounds checking, use
 * `cdeque_front()` function instead. */
fn cdeque_front_fast(d: *mut cdeque, value: *mut *mut ()) {
    let safe_d = unsafe { &mut *d };
    let safe_value = unsafe { &mut *value };
    unsafe { *safe_value = *(*d).arr.offset(safe_d.beg_pos as isize) as *mut () };
}
/* Returns the first element of current circular deque. This function
 * performs bounds checking. */
fn cdeque_front(d: *mut cdeque, mut value: *mut *mut ()) -> i32 {
    let safe_d = unsafe { &mut *d };
    if safe_d.size > 0 {
        cdeque_front_fast(d, value);
        return CDE_OK as i32;
    } else {
        return CDE_OUT_OF_BOUNDS as i32;
    };
}
/* Pushes a new element into the end of this circular deque object. If current
 * size will exceed capacity, the oldest element will be overwritten. */
fn cdeque_push_back(d: *mut cdeque, item: *mut ()) -> i32 {
    if d.is_null() {
        return CDE_PARAM as i32;
    }
    let safe_d = unsafe { &mut *d };
    if safe_d.size == safe_d.cap_mask + 1 {
        return CDE_OUT_OF_BOUNDS as i32;
    }
    unsafe { *(*d).arr.offset((*d).end_pos as isize) = item as size_t };
    safe_d.end_pos = (safe_d.end_pos + 1 & safe_d.cap_mask);
    safe_d.size = safe_d.size + 1;
    return CDE_OK as i32;
}
/* Pops a front element of this circular deque object and returns its value.
 * This function doesn't perform any bounds checking. */
fn cdeque_pop_front_fast(d: *mut cdeque, value: *mut *mut ()) {
    let safe_d = unsafe { &mut *d };
    let safe_value = unsafe { &mut *value };
    unsafe { *safe_value = *(*d).arr.offset(safe_d.beg_pos as isize) as *mut () };
    safe_d.beg_pos = (safe_d.beg_pos + 1 & safe_d.cap_mask);
    safe_d.size = safe_d.size - 1;
}
/* Pops a front element of this circular deque object and returns its value.
 * This function performs bounds checking. */
fn cdeque_pop_front(d: *mut cdeque, value: *mut *mut ()) -> i32 {
    let safe_d = unsafe { &mut *d };
    if d.is_null() || value.is_null() {
        return CDE_PARAM as i32;
    }
    if safe_d.size as i32 == 0 {
        return CDE_OUT_OF_BOUNDS as i32;
    }
    cdeque_pop_front_fast(d, value);
    return CDE_OK as i32;
}
/* Convenience function to cast filter_info** to void **. */
fn cdeque_filter_p(f: *mut *mut filter_info) -> *mut *mut () {
    return f as *mut *mut ();
}
/* Convenience function to cast filter_info* to void *. */
fn cdeque_filter(mut f: *mut filter_info) -> *mut () {
    return f as size_t as *mut *mut () as *mut ();
}
/* Destroys this circular deque object. Deallocates the memory of the
 * collection buffer, but doesn't deallocate the memory of any pointer passed
 * to this deque as a value. */
fn cdeque_free(d: *mut cdeque) {
    if d.is_null() {
        return;
    }
    let safe_d = unsafe { &mut *d };
    if safe_d.arr.is_null() {
        return;
    }
    unsafe {
        free_safe(safe_d.arr as *mut ());
    }
    safe_d.arr = 0 as *mut size_t;
    safe_d.beg_pos = -(1 as i32) as uint16_t;
    safe_d.end_pos = -(1 as i32) as uint16_t;
    safe_d.cap_mask = 0;
}

#[inline]
fn bf_bit_size(hdr: *const compressed_block_header) -> uint8_t {
    return unsafe { ((*hdr).block_flags_u8 & 7) as uint8_t };
}

#[inline]
fn bf_byte_count(hdr: *const compressed_block_header) -> uint8_t {
    return unsafe { ((*hdr).block_flags_u8 >> 3 & 7) as uint8_t };
}

#[inline]
fn bf_is_table_present(hdr: *const compressed_block_header) -> uint8_t {
    return unsafe { ((*hdr).block_flags_u8 >> 7 & 1) as uint8_t };
}

#[inline]
fn get_context(a: *mut archive_read) -> *mut rar5 {
    return unsafe { (*(*a).format).data as *mut rar5 };
}
/* Convenience functions used by filter implementations. */
fn circular_memcpy(
    mut dst: *mut uint8_t,
    mut window: *mut uint8_t,
    mask: uint64_t,
    mut start: int64_t,
    mut end: int64_t,
) {
    if start as u64 & mask > end as u64 & mask {
        let mut len1: ssize_t = (mask + 1 - (start as u64 & mask)) as ssize_t;
        let mut len2: ssize_t = (end as u64 & mask) as ssize_t;
        unsafe {
            memcpy_safe(
                dst as *mut (),
                &mut *window.offset((start as u64 & mask) as isize) as *mut uint8_t as *const (),
                len1 as u64,
            );
            memcpy_safe(
                dst.offset(len1 as isize) as *mut (),
                window as *const (),
                len2 as u64,
            );
        }
    } else {
        unsafe {
            memcpy_safe(
                dst as *mut (),
                unsafe {
                    &mut *window.offset((start as u64 & mask) as isize) as *mut uint8_t as *const ()
                },
                (end - start) as size_t,
            );
        }
    };
}

fn read_filter_data(rar: *mut rar5, offset: uint32_t) -> uint32_t {
    let mut linear_buf: [uint8_t; 4] = [0; 4];
    let safe_rar = unsafe { &mut *rar };
    circular_memcpy(
        linear_buf.as_mut_ptr(),
        safe_rar.cstate.window_buf,
        safe_rar.cstate.window_mask,
        offset as int64_t,
        (offset + 4) as int64_t,
    );
    return archive_le32dec(linear_buf.as_mut_ptr() as *const ());
}

fn write_filter_data(rar: *mut rar5, offset: uint32_t, value: uint32_t) {
    archive_le32enc(
        unsafe {
            &mut *(*rar).cstate.filtered_buf.offset(offset as isize) as *mut uint8_t as *mut ()
        },
        value,
    );
}
/* Allocates a new filter descriptor and adds it to the filter array. */
fn add_new_filter(rar: *mut rar5) -> *mut filter_info {
    let safe_rar = unsafe { &mut *rar };
    let mut f: *mut filter_info =
        unsafe { calloc_safe(1, size_of::<filter_info>() as u64) as *mut filter_info };
    if f.is_null() {
        return 0 as *mut filter_info;
    }
    cdeque_push_back(&mut safe_rar.cstate.filters, cdeque_filter(f));
    return f;
}

fn run_delta_filter(rar: *mut rar5, flt: *mut filter_info) -> i32 {
    let mut i: i32;
    let mut dest_pos: ssize_t = 0;
    let mut src_pos: ssize_t = 0;
    let safe_flt = unsafe { &mut *flt };
    let safe_rar = unsafe { &mut *rar };
    i = 0;
    while i < safe_flt.channels {
        let mut prev_byte: uint8_t = 0;
        dest_pos = i as ssize_t;
        while dest_pos < safe_flt.block_length {
            let mut byte: uint8_t = 0;
            unsafe {
                byte = *(*rar).cstate.window_buf.offset(
                    ((safe_rar.cstate.solid_offset + safe_flt.block_start + src_pos) as u64
                        & safe_rar.cstate.window_mask) as isize,
                )
            };
            prev_byte = (prev_byte - byte);
            unsafe { *(*rar).cstate.filtered_buf.offset(dest_pos as isize) = prev_byte };
            src_pos += 1;
            dest_pos += safe_flt.channels as i64
        }
        i += 1
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn run_e8e9_filter(rar: *mut rar5, flt: *mut filter_info, extended: i32) -> i32 {
    let file_size: uint32_t = 0x1000000;
    let mut i: ssize_t;
    let safe_rar = unsafe { &mut *rar };
    let safe_flt = unsafe { &mut *flt };
    circular_memcpy(
        safe_rar.cstate.filtered_buf,
        safe_rar.cstate.window_buf,
        safe_rar.cstate.window_mask,
        safe_rar.cstate.solid_offset + safe_flt.block_start,
        safe_rar.cstate.solid_offset + safe_flt.block_start + safe_flt.block_length,
    );
    i = 0;
    while i < safe_flt.block_length - 4 {
        let fresh0 = i;
        i = i + 1;
        let mut b: uint8_t = unsafe {
            *(*rar).cstate.window_buf.offset(
                ((safe_rar.cstate.solid_offset + safe_flt.block_start + fresh0) as u64
                    & safe_rar.cstate.window_mask) as isize,
            )
        };
        /*
         * 0xE8 = x86's call <relative_addr_uint32> (function call)
         * 0xE9 = x86's jmp <relative_addr_uint32> (unconditional jump)
         */
        if b == 0xe8 || extended != 0 && b == 0xe9 {
            let mut addr: uint32_t;
            let mut offset: uint32_t = ((i + safe_flt.block_start) % file_size as i64) as uint32_t;
            addr = read_filter_data(
                rar,
                ((safe_rar.cstate.solid_offset + safe_flt.block_start + i) as uint32_t as u64
                    & safe_rar.cstate.window_mask) as uint32_t,
            );
            if addr & 0x80000000 != 0 {
                if addr.wrapping_add(offset) & 0x80000000 == 0 as i32 as u32 {
                    write_filter_data(rar, i as uint32_t, addr.wrapping_add(file_size));
                }
            } else if addr.wrapping_sub(file_size) & 0x80000000 != 0 {
                let mut naddr: uint32_t = addr - offset;
                write_filter_data(rar, i as uint32_t, naddr);
            }
            i += 4
        }
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn run_arm_filter(rar: *mut rar5, flt: *mut filter_info) -> i32 {
    let mut i: ssize_t = 0;
    let mut offset: uint32_t;
    let safe_rar = unsafe { &mut *rar };
    let safe_flt = unsafe { &mut *flt };
    circular_memcpy(
        safe_rar.cstate.filtered_buf,
        safe_rar.cstate.window_buf,
        safe_rar.cstate.window_mask,
        safe_rar.cstate.solid_offset + safe_flt.block_start,
        safe_rar.cstate.solid_offset + safe_flt.block_start + safe_flt.block_length,
    );
    i = 0;
    while i < safe_flt.block_length - 3 {
        let mut b: *mut uint8_t = unsafe {
            &mut *(*rar).cstate.window_buf.offset(
                ((safe_rar.cstate.solid_offset + safe_flt.block_start + i + 3 as i32 as i64) as u64
                    & (*rar).cstate.window_mask) as isize,
            ) as *mut uint8_t
        };
        let safe_b = unsafe { &mut *b };
        if *safe_b == 0xeb {
            /* 0xEB = ARM's BL (branch + link) instruction. */
            offset = read_filter_data(
                rar,
                ((safe_rar.cstate.solid_offset + safe_flt.block_start + i) as u64
                    & safe_rar.cstate.window_mask) as uint32_t,
            ) & 0xffffff;
            offset = (offset as u32)
                .wrapping_sub(((i + safe_flt.block_start) / 4 as i32 as i64) as uint32_t)
                as uint32_t as uint32_t;
            offset = offset & 0xffffff | 0xeb000000;
            write_filter_data(rar, i as uint32_t, offset);
        }
        i += 4
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn run_filter(a: *mut archive_read, flt: *mut filter_info) -> i32 {
    let mut ret: i32;
    let mut rar: *mut rar5 = get_context(a);
    let safe_rar = unsafe { &mut *rar };
    let safe_flt = unsafe { &mut *flt };
    unsafe { free_safe(safe_rar.cstate.filtered_buf as *mut ()) };
    safe_rar.cstate.filtered_buf =
        unsafe { malloc_safe(safe_flt.block_length as u64) } as *mut uint8_t;
    if safe_rar.cstate.filtered_buf.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.enomem,
            b"Can\'t allocate memory for filter data.\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    match safe_flt.type_0 as u32 {
        FILTER_DELTA => ret = run_delta_filter(rar, flt),
        FILTER_E8 | FILTER_E8E9 => {
            /* fallthrough */
            ret = run_e8e9_filter(rar, flt, (safe_flt.type_0 == FILTER_E8E9 as i32) as i32)
        }
        FILTER_ARM => ret = run_arm_filter(rar, flt),
        _ => {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                b"Unsupported filter type: 0x%x\x00" as *const u8,
                (*flt).type_0
            );
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
    }
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        /* Filter has failed. */
        return ret;
    }
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
        != unsafe {
            push_data_ready(
                a,
                rar,
                safe_rar.cstate.filtered_buf,
                safe_flt.block_length as size_t,
                safe_rar.cstate.last_write_ptr,
            )
        }
    {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Stack overflow when submitting unpacked data\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    safe_rar.cstate.last_write_ptr += safe_flt.block_length;
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}
/* The `push_data` function submits the selected data range to the user.
 * Next call of `use_data` will use the pointer, size and offset arguments
 * that are specified here. These arguments are pushed to the FIFO stack here,
 * and popped from the stack by the `use_data` function. */
fn push_data(
    a: *mut archive_read,
    rar: *mut rar5,
    buf: *const uint8_t,
    mut idx_begin: int64_t,
    mut idx_end: int64_t,
) {
    let safe_rar = unsafe { &mut *rar };
    let wmask: uint64_t = safe_rar.cstate.window_mask;
    let solid_write_ptr: ssize_t =
        ((safe_rar.cstate.solid_offset + safe_rar.cstate.last_write_ptr) as u64 & wmask) as ssize_t;
    idx_begin += safe_rar.cstate.solid_offset;
    idx_end += safe_rar.cstate.solid_offset;
    /* Check if our unpacked data is wrapped inside the window circular
     * buffer.  If it's not wrapped, it can be copied out by using
     * a single memcpy, but when it's wrapped, we need to copy the first
     * part with one memcpy, and the second part with another memcpy. */
    if idx_begin as u64 & wmask > idx_end as u64 & wmask {
        /* The data is wrapped (begin offset sis bigger than end
         * offset). */
        let frag1_size: ssize_t =
            (safe_rar.cstate.window_size as u64).wrapping_sub(idx_begin as u64 & wmask) as ssize_t;
        let frag2_size: ssize_t = (idx_end as u64 & wmask) as ssize_t;
        /* Copy the first part of the buffer first. */
        push_data_ready(
            a,
            rar,
            unsafe { buf.offset(solid_write_ptr as isize) },
            frag1_size as size_t,
            safe_rar.cstate.last_write_ptr,
        );
        /* Copy the second part of the buffer. */

        push_data_ready(
            a,
            rar,
            buf,
            frag2_size as size_t,
            safe_rar.cstate.last_write_ptr + frag1_size,
        );
        safe_rar.cstate.last_write_ptr += frag1_size + frag2_size
    } else {
        /* Data is not wrapped, so we can just use one call to copy the
         * data. */
        push_data_ready(
            a,
            rar,
            unsafe { buf.offset(solid_write_ptr as isize) },
            (idx_end - idx_begin) as u64 & wmask,
            safe_rar.cstate.last_write_ptr,
        );
        safe_rar.cstate.last_write_ptr += idx_end - idx_begin
    };
}

/* Convenience function that submits the data to the user. It uses the
 * unpack window buffer as a source location. */
fn push_window_data(a: *mut archive_read, rar: *mut rar5, idx_begin: int64_t, idx_end: int64_t) {
    let safe_rar = unsafe { &mut *rar };
    push_data(a, rar, safe_rar.cstate.window_buf, idx_begin, idx_end);
}

fn apply_filters(mut a: *mut archive_read) -> i32 {
    let mut flt: *mut filter_info = 0 as *mut filter_info;
    let mut rar: *mut rar5 = get_context(a);
    let mut ret: i32 = 0;
    unsafe { (*rar).cstate.set_all_filters_applied(0) };
    /* Get the first filter that can be applied to our data. The data
     * needs to be fully unpacked before the filter can be run. */
    if CDE_OK as i32
        == cdeque_front(
            &mut unsafe { (*rar).cstate.filters },
            cdeque_filter_p(&mut flt),
        )
    {
        unsafe {
            /* Check if our unpacked data fully covers this filter's
             * range. */
            if (*rar).cstate.write_ptr > (*flt).block_start
                && (*rar).cstate.write_ptr >= (*flt).block_start + (*flt).block_length
            {
                /* Check if we have some data pending to be written
                 * right before the filter's start offset. */
                if (*rar).cstate.last_write_ptr == (*flt).block_start {
                    /* Run the filter specified by descriptor
                     * `flt`. */
                    ret = run_filter(a, flt);
                    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
                        /* Filter failure, return error. */
                        return ret;
                    }
                    /* Filter descriptor won't be needed anymore
                     * after it's used, * so remove it from the
                     * filter list and free its memory. */
                    cdeque_pop_front(&mut (*rar).cstate.filters, cdeque_filter_p(&mut flt));
                    free_safe(flt as *mut ());
                } else {
                    /* We can't run filters yet, dump the memory
                     * right before the filter. */
                    push_window_data(a, rar, (*rar).cstate.last_write_ptr, (*flt).block_start);
                }
                /* Return 'filter applied or not needed' state to the
                 * caller. */
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_retry;
            }
        }
    }
    unsafe { (*rar).cstate.set_all_filters_applied(1) };
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn dist_cache_push(rar: *mut rar5, value: i32) {
    let safe_rar = unsafe { &mut *rar };
    let mut q: *mut i32 = safe_rar.cstate.dist_cache.as_mut_ptr();
    unsafe {
        *q.offset(3) = *q.offset(2);
        *q.offset(2) = *q.offset(1);
        *q.offset(1) = *q.offset(0);
        *q.offset(0) = value;
    }
}

fn dist_cache_touch(rar: *mut rar5, idx: i32) -> i32 {
    let safe_rar = unsafe { &mut *rar };
    let mut q: *mut i32 = safe_rar.cstate.dist_cache.as_mut_ptr();
    let mut i: i32 = 0;
    let mut dist: i32 = unsafe { *q.offset(idx as isize) };
    i = idx;
    while i > 0 as i32 {
        unsafe { *q.offset(i as isize) = *q.offset((i - 1 as i32) as isize) };
        i -= 1
    }
    unsafe { *q.offset(0) = dist };
    return dist;
}

fn free_filters(rar: *mut rar5) {
    let safe_rar = unsafe { &mut *rar };
    let d: *mut cdeque = &mut safe_rar.cstate.filters;
    /* Free any remaining filters. All filters should be naturally
     * consumed by the unpacking function, so remaining filters after
     * unpacking normally mean that unpacking wasn't successful.
     * But still of course we shouldn't leak memory in such case. */
    /* cdeque_size() is a fast operation, so we can use it as a loop
     * expression. */
    while cdeque_size(d) > 0 {
        let mut f: *mut filter_info = 0 as *mut filter_info;
        /* Pop_front will also decrease the collection's size. */
        if CDE_OK as i32 == cdeque_pop_front(d, cdeque_filter_p(&mut f)) {
            unsafe { free_safe(f as *mut ()) };
        }
    }
    cdeque_clear(d);
    /* Also clear out the variables needed for sanity checking. */
    safe_rar.cstate.last_block_start = 0;
    safe_rar.cstate.last_block_length = 0;
}

fn reset_file_context(mut rar: *mut rar5) {
    let safe_rar = unsafe { &mut *rar };
    unsafe {
        memset_safe(
            &mut safe_rar.file as *mut file_header as *mut (),
            0,
            size_of::<file_header>() as u64,
        );
        blake2sp_init_safe(&mut safe_rar.file.b2state, 32);
    }
    if safe_rar.main.solid() != 0 {
        safe_rar.cstate.solid_offset += safe_rar.cstate.write_ptr
    } else {
        safe_rar.cstate.solid_offset = 0
    }
    safe_rar.cstate.write_ptr = 0;
    safe_rar.cstate.last_write_ptr = 0;
    safe_rar.cstate.last_unstore_ptr = 0;
    safe_rar.file.redir_type = REDIR_TYPE_NONE as i32 as uint64_t;
    safe_rar.file.redir_flags = 0;
    free_filters(rar);
}

#[inline]
fn get_archive_read(a: *mut archive, ar: *mut *mut archive_read) -> i32 {
    unsafe { *ar = a as *mut archive_read };
    let mut magic_test: i32 = unsafe {
        __archive_check_magic_safe(
            a,
            0xdeb0c5,
            1,
            b"archive_read_support_format_rar5\x00" as *const u8,
        )
    };
    if magic_test == ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn read_ahead(a: *mut archive_read, how_many: size_t, ptr: *mut *const uint8_t) -> i32 {
    let mut avail: ssize_t = -1;
    if ptr.is_null() {
        return 0;
    }
    let safe_ptr = unsafe { &mut *ptr };
    *safe_ptr = unsafe { __archive_read_ahead_safe(a, how_many, &mut avail) as *const uint8_t };
    if safe_ptr.is_null() {
        return 0;
    }
    return 1;
}

fn consume(mut a: *mut archive_read, mut how_many: int64_t) -> i32 {
    let mut ret: i32 = 0;
    ret = if how_many == unsafe { __archive_read_consume_safe(a, how_many) } {
        ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
    } else {
        ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal
    };
    return ret;
}
/* *
 * Read a RAR5 variable sized numeric value. This value will be stored in
 * `pvalue`. The `pvalue_len` argument points to a variable that will receive
 * the byte count that was consumed in order to decode the `pvalue` value, plus
 * one.
 *
 * pvalue_len is optional and can be NULL.
 *
 * NOTE: if `pvalue_len` is NOT NULL, the caller needs to manually consume
 * the number of bytes that `pvalue_len` value contains. If the `pvalue_len`
 * is NULL, this consuming operation is done automatically.
 *
 * Returns 1 if *pvalue was successfully read.
 * Returns 0 if there was an error. In this case, *pvalue contains an
 *           invalid value.
 */
fn read_var(a: *mut archive_read, pvalue: *mut uint64_t, pvalue_len: *mut uint64_t) -> i32 {
    let mut result: uint64_t = 0;
    let mut shift: size_t;
    let mut i: size_t;
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let mut b: uint8_t;
    let safe_pvalue = unsafe { &mut *pvalue };
    let safe_pvalue_len = unsafe { &mut *pvalue_len };
    /* We will read maximum of 8 bytes. We don't have to handle the
     * situation to read the RAR5 variable-sized value stored at the end of
     * the file, because such situation will never happen. */
    if read_ahead(a, 8, &mut p) == 0 {
        return 0;
    }
    shift = 0;
    i = 0;
    while i < 8 {
        unsafe { b = *p.offset(i as isize) };
        /* Strip the MSB from the input byte and add the resulting
         * number to the `result`. */
        result = (result as u64).wrapping_add((b as u64 & 0x7f as i32 as uint64_t) << shift)
            as uint64_t as uint64_t;
        /* MSB set to 1 means we need to continue decoding process.
         * MSB set to 0 means we're done.
         *
         * This conditional checks for the second case. */
        if b & 0x80 == 0 {
            if !pvalue.is_null() {
                *safe_pvalue = result
            }
            /* If the caller has passed the `pvalue_len` pointer,
             * store the number of consumed bytes in it and do NOT
             * consume those bytes, since the caller has all the
             * information it needs to perform */
            if !pvalue_len.is_null() {
                *safe_pvalue_len = i + 1
            } else if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
                != consume(a, (1 as i32 as u64).wrapping_add(i) as int64_t)
            {
                return 0;
            }
            /* If the caller did not provide the
             * `pvalue_len` pointer, it will not have the
             * possibility to advance the file pointer,
             * because it will not know how many bytes it
             * needs to consume. This is why we handle
             * such situation here automatically. */
            /* End of decoding process, return success. */
            return 1;
        }
        i = i + 1;
        shift = (shift as u64).wrapping_add(7 as i32 as u64) as size_t as size_t
    }
    /* The decoded value takes the maximum number of 8 bytes.
     * It's a maximum number of bytes, so end decoding process here
     * even if the first bit of last byte is 1. */
    if !pvalue.is_null() {
        *safe_pvalue = result
    }
    if !pvalue_len.is_null() {
        *safe_pvalue_len = 9
    } else if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, 9 as i32 as int64_t) {
        return 0;
    }
    return 1;
}

fn read_var_sized(a: *mut archive_read, pvalue: *mut size_t, pvalue_len: *mut size_t) -> i32 {
    let mut v: uint64_t = 0;
    let mut v_size: uint64_t = 0;
    let safe_pvalue_len = unsafe { &mut *pvalue_len };
    let safe_pvalue = unsafe { &mut *pvalue };
    let ret: i32 = if !pvalue_len.is_null() {
        read_var(a, &mut v, &mut v_size)
    } else {
        read_var(a, &mut v, 0 as *mut uint64_t)
    };
    if ret == 1 && !pvalue.is_null() {
        *safe_pvalue = v
    }
    if !pvalue_len.is_null() {
        /* Possible data truncation should be safe. */
        *safe_pvalue_len = v_size
    }
    return ret;
}

fn read_bits_32(rar: *mut rar5, p: *const uint8_t, value: *mut uint32_t) -> i32 {
    let safe_rar = unsafe { &mut *rar };
    let safe_value = unsafe { &mut *value };
    let mut bits: uint32_t =
        unsafe { (*p.offset(safe_rar.bits.in_addr as isize) as uint32_t) << 24 as i32 };
    unsafe {
        bits |=
            ((*p.offset((safe_rar.bits.in_addr + 1 as i32) as isize) as i32) << 16 as i32) as u32;
        bits |=
            ((*p.offset((safe_rar.bits.in_addr + 2 as i32) as isize) as i32) << 8 as i32) as u32;
        bits |= *p.offset((safe_rar.bits.in_addr + 3 as i32) as isize) as u32;
        bits <<= safe_rar.bits.bit_addr as i32;
        bits |= (*p.offset((safe_rar.bits.in_addr + 4 as i32) as isize) as i32
            >> 8 as i32 - safe_rar.bits.bit_addr as i32) as u32;
    }
    *safe_value = bits;
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn read_bits_16(rar: *mut rar5, p: *const uint8_t, value: *mut uint16_t) -> i32 {
    let safe_rar = unsafe { &mut *rar };
    let safe_value = unsafe { &mut *value };
    let mut bits: i32 =
        unsafe { (*p.offset(safe_rar.bits.in_addr as isize) as uint32_t as i32) << 16 as i32 };
    unsafe {
        bits |= (*p.offset((safe_rar.bits.in_addr + 1 as i32) as isize) as i32) << 8 as i32;
        bits |= *p.offset((safe_rar.bits.in_addr + 2 as i32) as isize) as i32;
        bits >>= 8 as i32 - safe_rar.bits.bit_addr as i32;
    }
    *safe_value = (bits & 0xffff as i32) as uint16_t;
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn skip_bits(rar: *mut rar5, bits: i32) {
    let safe_rar = unsafe { &mut *rar };
    let new_bits: i32 = safe_rar.bits.bit_addr as i32 + bits;
    safe_rar.bits.in_addr += new_bits >> 3 as i32;
    safe_rar.bits.bit_addr = (new_bits & 7 as i32) as int8_t;
}
/* n = up to 16 */
fn read_consume_bits(rar: *mut rar5, p: *const uint8_t, n: i32, value: *mut i32) -> i32 {
    let mut v: uint16_t = 0;
    let mut ret: i32 = 0;
    let mut num: i32 = 0;
    let safe_value = unsafe { &mut *value };
    if n == 0 || n > 16 {
        /* This is a programmer error and should never happen
         * in runtime. */
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    ret = read_bits_16(rar, p, &mut v);
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        return ret;
    }
    num = v as i32;
    num >>= 16 as i32 - n;
    skip_bits(rar, n);
    if !value.is_null() {
        *safe_value = num
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn read_u32(a: *mut archive_read, pvalue: *mut uint32_t) -> i32 {
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let safe_pvalue = unsafe { &mut *pvalue };
    if read_ahead(a, 4, &mut p) == 0 {
        return 0;
    }
    *safe_pvalue = archive_le32dec(p as *const ());
    return if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok == consume(a, 4 as i32 as int64_t) {
        1
    } else {
        0
    };
}

fn read_u64(a: *mut archive_read, pvalue: *mut uint64_t) -> i32 {
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let safe_pvalue = unsafe { &mut *pvalue };
    if read_ahead(a, 8 as i32 as size_t, &mut p) == 0 {
        return 0;
    }
    *safe_pvalue = archive_le64dec(p as *const ());
    return if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok == consume(a, 8 as i32 as int64_t) {
        1
    } else {
        0
    };
}

fn bid_standard(a: *mut archive_read) -> i32 {
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let mut signature: [u8; 8] = [0; 8];
    rar5_signature(signature.as_mut_ptr());
    if read_ahead(a, size_of::<[u8; 8]>() as u64, &mut p) == 0 {
        return -1;
    }
    if unsafe {
        memcmp_safe(
            signature.as_mut_ptr() as *const (),
            p as *const (),
            size_of::<[u8; 8]>() as u64,
        )
    } == 0
    {
        return 30;
    }
    return -1;
}

fn rar5_bid(a: *mut archive_read, best_bid: i32) -> i32 {
    let mut my_bid: i32;
    if best_bid > 30 {
        return -1;
    }
    my_bid = bid_standard(a);
    if my_bid > -1 {
        return my_bid;
    }
    return -1;
}

fn rar5_options(a: *mut archive_read, key: *const u8, val: *const u8) -> i32 {
    /* No options supported in this version. Return the ARCHIVE_WARN code
     * to signal the options supervisor that the unpacker didn't handle
     * setting this option. */
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_warn;
}

fn init_header(a: *mut archive_read) {
    let safe_a = unsafe { &mut *a };
    safe_a.archive.archive_format = ARCHIVE_RAR5_DEFINED_PARAM.archive_format_rar_v5;
    safe_a.archive.archive_format_name = b"RAR5\x00" as *const u8;
}

fn init_window_mask(mut rar: *mut rar5) {
    let safe_rar = unsafe { &mut *rar };
    if safe_rar.cstate.window_size != 0 {
        safe_rar.cstate.window_mask = (safe_rar.cstate.window_size - 1 as i32 as i64) as size_t
    } else {
        safe_rar.cstate.window_mask = 0
    };
}

fn process_main_locator_extra_block(a: *mut archive_read, rar: *mut rar5) -> i32 {
    let mut locator_flags: uint64_t = 0;
    let safe_rar = unsafe { &mut *rar };
    if read_var(a, &mut locator_flags, 0 as *mut uint64_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if locator_flags & QLIST as i32 as u64 != 0 {
        if read_var(a, &mut safe_rar.qlist_offset, 0 as *mut uint64_t) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        /* qlist is not used */
    }
    if locator_flags & RECOVERY as i32 as u64 != 0 {
        if read_var(a, &mut safe_rar.rr_offset, 0 as *mut uint64_t) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        /* rr is not used */
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn parse_file_extra_hash(
    mut a: *mut archive_read,
    mut rar: *mut rar5,
    mut extra_data_size: *mut ssize_t,
) -> i32 {
    let mut hash_type: size_t = 0 as i32 as size_t;
    let mut value_len: size_t = 0;
    let safe_extra_data_size = unsafe { &mut *extra_data_size };
    let safe_rar = unsafe { &mut *rar };
    if read_var_sized(a, &mut hash_type, &mut value_len) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    *safe_extra_data_size =
        (*safe_extra_data_size as u64).wrapping_sub(value_len) as ssize_t as ssize_t;
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, value_len as int64_t) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    /* The file uses BLAKE2sp checksum algorithm instead of plain old
     * CRC32. */
    if hash_type == BLAKE2sp as i32 as u64 {
        let mut p: *const uint8_t = 0 as *const uint8_t;
        let hash_size: i32 = size_of::<[uint8_t; 32]>() as u64 as i32;
        if read_ahead(a, hash_size as size_t, &mut p) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        safe_rar.file.has_blake2 = 1;
        unsafe {
            memcpy_safe(
                &mut safe_rar.file.blake2sp as *mut [uint8_t; 32] as *mut (),
                p as *const (),
                hash_size as u64,
            );
        }
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, hash_size as int64_t) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        *safe_extra_data_size -= hash_size as i64
    } else {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Unsupported hash type (0x%x)\x00" as *const u8,
            hash_type as i32
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn time_win_to_unix(win_time: uint64_t) -> uint64_t {
    let ns_in_sec: size_t = 10000000;
    let sec_to_unix: uint64_t = 11644473600;
    return win_time.wrapping_div(ns_in_sec).wrapping_sub(sec_to_unix);
}

fn parse_htime_item(
    a: *mut archive_read,
    unix_time: u8,
    where_0: *mut uint64_t,
    extra_data_size: *mut ssize_t,
) -> i32 {
    let safe_extra_data_size = unsafe { &mut *extra_data_size };
    let safe_where_0 = unsafe { &mut *where_0 };
    if unix_time != 0 {
        let mut time_val: uint32_t = 0;
        if read_u32(a, &mut time_val) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        *safe_extra_data_size -= 4;
        *safe_where_0 = time_val as uint64_t
    } else {
        let mut windows_time: uint64_t = 0;
        if read_u64(a, &mut windows_time) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        *safe_where_0 = time_win_to_unix(windows_time);
        *safe_extra_data_size -= 8
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn parse_file_extra_version(
    a: *mut archive_read,
    e: *mut archive_entry,
    extra_data_size: *mut ssize_t,
) -> i32 {
    let mut flags: size_t = 0;
    let mut version: size_t = 0;
    let mut value_len: size_t = 0;
    let safe_extra_data_size = unsafe { &mut *extra_data_size };
    let mut version_string: archive_string = archive_string {
        s: 0 as *mut u8,
        length: 0,
        buffer_length: 0,
    };
    let mut name_utf8_string: archive_string = archive_string {
        s: 0 as *mut u8,
        length: 0,
        buffer_length: 0,
    };
    let mut cur_filename: *const u8 = 0 as *const u8;
    /* Flags are ignored. */
    if read_var_sized(a, &mut flags, &mut value_len) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    *safe_extra_data_size =
        (*safe_extra_data_size as u64).wrapping_sub(value_len) as ssize_t as ssize_t;
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, value_len as int64_t) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if read_var_sized(a, &mut version, &mut value_len) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    *safe_extra_data_size =
        (*safe_extra_data_size as u64).wrapping_sub(value_len) as ssize_t as ssize_t;
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, value_len as int64_t) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    /* extra_data_size should be zero here. */
    cur_filename = unsafe { archive_entry_pathname_utf8_safe(e) };
    if cur_filename.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_programmer,
            b"Version entry without file name\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    version_string.s = 0 as *mut u8;
    version_string.length = 0;
    version_string.buffer_length = 0;
    name_utf8_string.s = 0 as *mut u8;
    name_utf8_string.length = 0;
    name_utf8_string.buffer_length = 0;
    /* Prepare a ;123 suffix for the filename, where '123' is the version
     * value of this file. */
    archive_string_sprintf_safe!(
        &mut version_string as *mut archive_string,
        b";%zu\x00" as *const u8,
        version
    );
    /* Build the new filename. */
    unsafe {
        archive_strcat_safe(&mut name_utf8_string, cur_filename as *const ());
        archive_strcat_safe(&mut name_utf8_string, version_string.s as *const ());
        /* Apply the new filename into this file's context. */
        archive_entry_update_pathname_utf8_safe(e, name_utf8_string.s);
        /* Free buffers. */
        archive_string_free_safe(&mut version_string);
        archive_string_free_safe(&mut name_utf8_string);
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn parse_file_extra_htime(
    a: *mut archive_read,
    e: *mut archive_entry,
    rar: *mut rar5,
    extra_data_size: *mut ssize_t,
) -> i32 {
    let mut unix_time: u8 = 0;
    let mut flags: size_t = 0;
    let mut value_len: size_t = 0;
    let safe_extra_data_size = unsafe { &mut *extra_data_size };
    let safe_rar = unsafe { &mut *rar };
    if read_var_sized(a, &mut flags, &mut value_len) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    *safe_extra_data_size =
        (*safe_extra_data_size as u64).wrapping_sub(value_len) as ssize_t as ssize_t;
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, value_len as int64_t) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    unix_time = (flags & IS_UNIX as i32 as u64) as u8;
    if flags & HAS_MTIME as i32 as u64 != 0 {
        parse_htime_item(a, unix_time, &mut safe_rar.file.e_mtime, extra_data_size);
        unsafe {
            archive_entry_set_mtime_safe(e, safe_rar.file.e_mtime as time_t, 0 as i32 as i64)
        };
    }
    if flags & HAS_CTIME as i32 as u64 != 0 {
        parse_htime_item(a, unix_time, &mut safe_rar.file.e_ctime, extra_data_size);
        unsafe {
            archive_entry_set_ctime_safe(e, safe_rar.file.e_ctime as time_t, 0 as i32 as i64)
        };
    }
    if flags & HAS_ATIME as i32 as u64 != 0 {
        parse_htime_item(a, unix_time, &mut safe_rar.file.e_atime, extra_data_size);
        unsafe {
            archive_entry_set_atime_safe(e, safe_rar.file.e_atime as time_t, 0 as i32 as i64)
        };
    }
    if flags & HAS_UNIX_NS as i32 as u64 != 0 {
        if read_u32(a, &mut safe_rar.file.e_unix_ns) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        *safe_extra_data_size -= 4
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn parse_file_extra_redir(
    a: *mut archive_read,
    e: *mut archive_entry,
    rar: *mut rar5,
    extra_data_size: *mut ssize_t,
) -> i32 {
    let mut value_size: uint64_t = 0 as i32 as uint64_t;
    let mut target_size: size_t = 0 as i32 as size_t;
    let mut target_utf8_buf: [u8; 8192] = [0; 8192];
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let safe_rar = unsafe { &mut *rar };
    let safe_extra_data_size = unsafe { &mut *extra_data_size };
    if read_var(a, &mut safe_rar.file.redir_type, &mut value_size) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, value_size as int64_t) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    *safe_extra_data_size =
        (*safe_extra_data_size as u64).wrapping_sub(value_size) as ssize_t as ssize_t;
    if read_var(a, &mut safe_rar.file.redir_flags, &mut value_size) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, value_size as int64_t) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    *safe_extra_data_size =
        (*safe_extra_data_size as u64).wrapping_sub(value_size) as ssize_t as ssize_t;
    if read_var_sized(a, &mut target_size, 0 as *mut size_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    *safe_extra_data_size =
        (*safe_extra_data_size as u64).wrapping_sub(target_size + 1) as ssize_t as ssize_t;
    if read_ahead(a, target_size, &mut p) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if target_size > (ARCHIVE_RAR5_DEFINED_PARAM.max_name_in_chars - 1 as i32) as u64 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Link target is too long\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    if target_size == 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"No link target specified\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    unsafe {
        memcpy_safe(
            target_utf8_buf.as_mut_ptr() as *mut (),
            p as *const (),
            target_size,
        )
    };
    target_utf8_buf[target_size as usize] = 0 as i32 as u8;
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, target_size as int64_t) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    match safe_rar.file.redir_type as u32 {
        REDIR_TYPE_UNIXSYMLINK | REDIR_TYPE_WINSYMLINK => {
            unsafe {
                archive_entry_set_filetype_safe(e, ARCHIVE_RAR5_DEFINED_PARAM.ae_iflnk as mode_t);
                archive_entry_update_symlink_utf8_safe(e, target_utf8_buf.as_mut_ptr());
            }
            if safe_rar.file.redir_flags & ARCHIVE_RAR5_DEFINED_PARAM.redir_symlink_is_dir as u64
                != 0
            {
                unsafe {
                    archive_entry_set_symlink_type_safe(
                        e,
                        ARCHIVE_RAR5_DEFINED_PARAM.ae_symlink_type_directory,
                    )
                };
            } else {
                unsafe {
                    archive_entry_set_symlink_type_safe(
                        e,
                        ARCHIVE_RAR5_DEFINED_PARAM.ae_symlink_type_file,
                    )
                };
            }
        }
        REDIR_TYPE_HARDLINK => unsafe {
            archive_entry_set_filetype_safe(e, ARCHIVE_RAR5_DEFINED_PARAM.ae_ifreg as mode_t);
            archive_entry_update_hardlink_utf8_safe(e, target_utf8_buf.as_mut_ptr());
        },
        _ => {}
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn parse_file_extra_owner(
    a: *mut archive_read,
    e: *mut archive_entry,
    extra_data_size: *mut ssize_t,
) -> i32 {
    let mut flags: uint64_t = 0;
    let mut value_size: uint64_t = 0;
    let mut id: uint64_t = 0;
    let mut name_len: size_t = 0;
    let mut name_size: size_t = 0;
    let mut namebuf: [u8; 256] = [0; 256];
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let safe_extra_data_size = unsafe { &mut *extra_data_size };
    if read_var(a, &mut flags, &mut value_size) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, value_size as int64_t) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    *safe_extra_data_size = (*safe_extra_data_size as u64 - value_size) as ssize_t;
    if flags & ARCHIVE_RAR5_DEFINED_PARAM.owner_user_name as u64 != 0 as i32 as u64 {
        if read_var_sized(a, &mut name_size, 0 as *mut size_t) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        *safe_extra_data_size = (*safe_extra_data_size as u64 - (name_size + 1)) as ssize_t;
        if read_ahead(a, name_size, &mut p) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        if name_size >= ARCHIVE_RAR5_DEFINED_PARAM.owner_maxnamelen as size_t {
            name_len = (ARCHIVE_RAR5_DEFINED_PARAM.owner_maxnamelen - 1) as size_t
        } else {
            name_len = name_size
        }
        unsafe { memcpy_safe(namebuf.as_mut_ptr() as *mut (), p as *const (), name_len) };
        namebuf[name_len as usize] = 0;
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, name_size as int64_t) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        unsafe { archive_entry_set_uname_safe(e, namebuf.as_mut_ptr()) };
    }
    if flags & ARCHIVE_RAR5_DEFINED_PARAM.owner_group_name as u64 != 0 {
        if read_var_sized(a, &mut name_size, 0 as *mut size_t) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        *safe_extra_data_size =
            (*safe_extra_data_size as u64).wrapping_sub(name_size + 1) as ssize_t;
        if read_ahead(a, name_size, &mut p) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        if name_size >= ARCHIVE_RAR5_DEFINED_PARAM.owner_maxnamelen as u64 {
            name_len = (ARCHIVE_RAR5_DEFINED_PARAM.owner_maxnamelen - 1 as i32) as size_t
        } else {
            name_len = name_size
        }
        unsafe { memcpy_safe(namebuf.as_mut_ptr() as *mut (), p as *const (), name_len) };
        namebuf[name_len as usize] = 0;
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, name_size as int64_t) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        unsafe { archive_entry_set_gname_safe(e, namebuf.as_mut_ptr()) };
    }
    if flags & ARCHIVE_RAR5_DEFINED_PARAM.owner_user_uid as u64 != 0 as i32 as u64 {
        if read_var(a, &mut id, &mut value_size) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, value_size as int64_t) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        *safe_extra_data_size =
            (*safe_extra_data_size as u64).wrapping_sub(value_size) as ssize_t as ssize_t;
        unsafe { archive_entry_set_uid_safe(e, id as la_int64_t) };
    }
    if flags & ARCHIVE_RAR5_DEFINED_PARAM.owner_group_gid as u64 != 0 as i32 as u64 {
        if read_var(a, &mut id, &mut value_size) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, value_size as int64_t) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        *safe_extra_data_size =
            (*safe_extra_data_size as u64).wrapping_sub(value_size) as ssize_t as ssize_t;
        unsafe { archive_entry_set_gid_safe(e, id as la_int64_t) };
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn process_head_file_extra(
    a: *mut archive_read,
    e: *mut archive_entry,
    rar: *mut rar5,
    mut extra_data_size: ssize_t,
) -> i32 {
    let mut extra_field_size: size_t = 0;
    let mut extra_field_id: size_t = 0;
    let mut ret: i32 = ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    let mut var_size: size_t = 0;
    while extra_data_size > 0 {
        if read_var_sized(a, &mut extra_field_size, &mut var_size) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        unsafe {
            extra_data_size = (extra_data_size as u64).wrapping_sub(var_size) as ssize_t as ssize_t
        };
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, var_size as int64_t) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        if read_var_sized(a, &mut extra_field_id, &mut var_size) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        unsafe {
            extra_data_size = (extra_data_size as u64).wrapping_sub(var_size) as ssize_t as ssize_t
        };
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, var_size as int64_t) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        match extra_field_id as u32 {
            EX_HASH => {
                ret = parse_file_extra_hash(a, rar, &mut extra_data_size);
            }
            EX_HTIME => {
                ret = parse_file_extra_htime(a, e, rar, &mut extra_data_size);
            }
            EX_REDIR => {
                ret = parse_file_extra_redir(a, e, rar, &mut extra_data_size);
            }
            EX_UOWNER => {
                ret = parse_file_extra_owner(a, e, &mut extra_data_size);
            }
            EX_VERSION => {
                ret = parse_file_extra_version(a, e, &mut extra_data_size);
            }
            EX_CRYPT => {
                /* fallthrough */
                return consume(a, extra_data_size);
            }
            EX_SUBDATA | _ => {
                return consume(a, extra_data_size);
            }
        }
    }
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        /* Attribute not implemented. */
        return ret;
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn process_head_file(
    a: *mut archive_read,
    rar: *mut rar5,
    entry: *mut archive_entry,
    block_flags: size_t,
) -> i32 {
    let mut extra_data_size: ssize_t = 0;
    let mut data_size: size_t = 0;
    let mut file_flags: size_t = 0;
    let mut file_attr: size_t = 0;
    let mut compression_info: size_t = 0;
    let mut host_os: size_t = 0;
    let mut name_size: size_t = 0;
    let mut unpacked_size: uint64_t = 0;
    let mut window_size: uint64_t = 0;
    let mut mtime: uint32_t = 0;
    let mut crc: uint32_t = 0;
    let mut c_method: i32 = 0;
    let mut c_version: i32 = 0;
    let mut name_utf8_buf: [u8; 8192] = [0; 8192];
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let safe_rar = unsafe { &mut *rar };
    unsafe { archive_entry_clear_safe(entry) };
    /* Do not reset file context if we're switching archives. */
    if safe_rar.cstate.switch_multivolume() == 0 {
        reset_file_context(rar);
    }
    if block_flags & HFL_EXTRA_DATA as u64 != 0 {
        let mut edata_size: size_t = 0;
        if read_var_sized(a, &mut edata_size, 0 as *mut size_t) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        /* Intentional type cast from unsigned to signed. */
        extra_data_size = edata_size as ssize_t
    }
    if block_flags & HFL_DATA as i32 as u64 != 0 {
        if read_var_sized(a, &mut data_size, 0 as *mut size_t) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        safe_rar.file.bytes_remaining = data_size as ssize_t
    } else {
        safe_rar.file.bytes_remaining = 0;
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"no data found in file/service block\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    if read_var_sized(a, &mut file_flags, 0 as *mut size_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if read_var(a, &mut unpacked_size, 0 as *mut uint64_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if file_flags & UNKNOWN_UNPACKED_SIZE as i32 as u64 != 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_programmer,
            b"Files with unknown unpacked size are not supported\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    safe_rar
        .file
        .set_dir((file_flags & DIRECTORY as i32 as u64 > 0 as i32 as u64) as i32 as uint8_t);
    if read_var_sized(a, &mut file_attr, 0 as *mut size_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if file_flags & UTIME as i32 as u64 != 0 {
        if read_u32(a, &mut mtime) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
    }
    if file_flags & CRC32 as i32 as u64 != 0 {
        if read_u32(a, &mut crc) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
    }
    if read_var_sized(a, &mut compression_info, 0 as *mut size_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    c_method = (compression_info >> 7 as i32) as i32 & 0x7 as i32;
    c_version = (compression_info & 0x3f as i32 as u64) as i32;
    /* RAR5 seems to limit the dictionary size to 64MB. */
    window_size = if safe_rar.file.dir() as i32 > 0 as i32 {
        0 as i32 as u64
    } else {
        unsafe { (g_unpack_window_size) << (compression_info >> 10 as i32 & 15 as i32 as u64) }
    };
    safe_rar.cstate.method = c_method;
    safe_rar.cstate.version = c_version + 50 as i32;
    safe_rar
        .file
        .set_solid((compression_info & SOLID as i32 as u64 > 0 as i32 as u64) as i32 as uint8_t);
    /* Archives which declare solid files without initializing the window
     * buffer first are invalid. */
    if safe_rar.file.solid() as i32 > 0 as i32 && safe_rar.cstate.window_buf.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Declared solid file, but no window buffer initialized yet.\x00" as *const u8
                as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    /* Check if window_size is a sane value. Also, if the file is not
     * declared as a directory, disallow window_size == 0. */
    if window_size > (64 * 1024 * 1024)
        || safe_rar.file.dir() as i32 == 0 as i32 && window_size == 0 as i32 as u64
    {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Declared dictionary size is not supported.\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    if safe_rar.file.solid() as i32 > 0 {
        /* Re-check if current window size is the same as previous
         * window size (for solid files only). */
        if safe_rar.file.solid_window_size > 0
            && safe_rar.file.solid_window_size != window_size as ssize_t
        {
            archive_set_error_safe!(&mut (*a).archive as *mut archive,
                              ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                              b"Window size for this solid file doesn\'t match the window size used in previous solid file. \x00"
                                  as *const u8);
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
    }
    /* If we're currently switching volumes, ignore the new definition of
     * window_size. */
    if safe_rar.cstate.switch_multivolume() as i32 == 0 {
        /* Values up to 64M should fit into ssize_t on every
         * architecture. */
        safe_rar.cstate.window_size = window_size as ssize_t
    }
    if safe_rar.file.solid() as i32 > 0 as i32 && safe_rar.file.solid_window_size == 0 as i32 as i64
    {
        /* Solid files have to have the same window_size across
        whole archive. Remember the window_size parameter
        for first solid file found. */
        safe_rar.file.solid_window_size = safe_rar.cstate.window_size
    }
    init_window_mask(rar);
    safe_rar.file.set_service(0);
    if read_var_sized(a, &mut host_os, 0 as *mut size_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if host_os == HOST_WINDOWS as i32 as u64 {
        /* Host OS is Windows */
        let mut mode: mode_t = 0;
        if file_attr & ATTR_DIRECTORY as i32 as u64 != 0 {
            if file_attr & ATTR_READONLY as i32 as u64 != 0 {
                mode = 0o555 | ARCHIVE_RAR5_DEFINED_PARAM.ae_ifdir as mode_t
            } else {
                mode = 0o755 | ARCHIVE_RAR5_DEFINED_PARAM.ae_ifdir as mode_t
            }
        } else if file_attr & ATTR_READONLY as i32 as u64 != 0 {
            mode = 0o444 | ARCHIVE_RAR5_DEFINED_PARAM.ae_ifreg as mode_t
        } else {
            mode = 0o644 | ARCHIVE_RAR5_DEFINED_PARAM.ae_ifreg as mode_t
        }

        unsafe { archive_entry_set_mode_safe(entry, mode) };
        if file_attr & (ATTR_READONLY as i32 | ATTR_HIDDEN as i32 | ATTR_SYSTEM as i32) as u64 != 0
        {
            let mut fflags_text: *mut u8 = 0 as *mut u8;
            let mut ptr: *mut u8 = 0 as *mut u8;
            /* allocate for "rdonly,hidden,system," */
            fflags_text = unsafe {
                malloc_safe((22 as i32 as u64).wrapping_mul(size_of::<u8>() as u64)) as *mut u8
            };
            if !fflags_text.is_null() {
                ptr = fflags_text;
                if file_attr & ATTR_READONLY as i32 as u64 != 0 {
                    unsafe { strcpy_safe(ptr, b"rdonly,\x00" as *const u8) };
                    unsafe { ptr = ptr.offset(7) }
                }
                if file_attr & ATTR_HIDDEN as i32 as u64 != 0 {
                    unsafe { strcpy_safe(ptr, b"hidden,\x00" as *const u8) };
                    unsafe { ptr = ptr.offset(7) }
                }
                if file_attr & ATTR_SYSTEM as i32 as u64 != 0 {
                    unsafe { strcpy_safe(ptr, b"system,\x00" as *const u8) };
                    unsafe { ptr = ptr.offset(7) }
                }
                if ptr > fflags_text {
                    /* Delete trailing comma */
                    unsafe { *ptr.offset(-(1)) = '\u{0}' as i32 as u8 };
                    unsafe { archive_entry_copy_fflags_text_safe(entry, fflags_text) };
                }
                unsafe { free_safe(fflags_text as *mut ()) };
            }
        }
    } else if host_os == HOST_UNIX as i32 as u64 {
        /* Host OS is Unix */
        unsafe { archive_entry_set_mode_safe(entry, file_attr as mode_t) };
    } else {
        /* Unknown host OS */
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Unsupported Host OS: 0x%x\x00" as *const u8,
            host_os as i32
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    if read_var_sized(a, &mut name_size, 0 as *mut size_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if read_ahead(a, name_size, &mut p) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if name_size > (ARCHIVE_RAR5_DEFINED_PARAM.max_name_in_chars - 1 as i32) as u64 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Filename is too long\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    if name_size == 0 as i32 as u64 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"No filename specified\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    unsafe {
        memcpy_safe(
            name_utf8_buf.as_mut_ptr() as *mut (),
            p as *const (),
            name_size,
        )
    };
    name_utf8_buf[name_size as usize] = 0 as i32 as u8;
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, name_size as int64_t) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    unsafe { archive_entry_update_pathname_utf8_safe(entry, name_utf8_buf.as_mut_ptr()) };
    if extra_data_size > 0 {
        let mut ret: i32 = process_head_file_extra(a, entry, rar, extra_data_size);
        /*
         * TODO: rewrite or remove useless sanity check
         *       as extra_data_size is not passed as a pointer
         *
        if(extra_data_size < 0) {
            archive_set_error(&a->archive, ARCHIVE_ERRNO_PROGRAMMER,
                "File extra data size is not zero");
            return ARCHIVE_FATAL;
        }
         */
        if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
            return ret;
        }
    }
    if file_flags & UNKNOWN_UNPACKED_SIZE as i32 as u64 == 0 {
        safe_rar.file.unpacked_size = unpacked_size as ssize_t;
        if safe_rar.file.redir_type == REDIR_TYPE_NONE as i32 as u64 {
            unsafe { archive_entry_set_size_safe(entry, unpacked_size as la_int64_t) };
        }
    }
    if file_flags & UTIME as i32 as u64 != 0 {
        unsafe { archive_entry_set_mtime_safe(entry, mtime as time_t, 0 as i32 as i64) };
    }
    if file_flags & CRC32 as i32 as u64 != 0 {
        safe_rar.file.stored_crc32 = crc
    }
    if safe_rar.cstate.switch_multivolume() == 0 {
        /* Do not reinitialize unpacking state if we're switching
         * archives. */
        safe_rar.cstate.set_block_parsing_finished(1);
        safe_rar.cstate.set_all_filters_applied(1);
        safe_rar.cstate.set_initialized(0)
    }
    if safe_rar.generic.split_before() as i32 > 0 {
        /* If now we're standing on a header that has a 'split before'
         * mark, it means we're standing on a 'continuation' file
         * header. Signal the caller that if it wants to move to
         * another file, it must call rar5_read_header() function
         * again. */
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_retry;
    } else {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
    };
}

fn process_head_service(
    a: *mut archive_read,
    rar: *mut rar5,
    entry: *mut archive_entry,
    block_flags: size_t,
) -> i32 {
    /* Process this SERVICE block the same way as FILE blocks. */
    let mut ret: i32 = process_head_file(a, rar, entry, block_flags);
    let safe_rar = unsafe { &mut *rar };
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        return ret;
    }
    safe_rar.file.set_service(1);
    /* But skip the data part automatically. It's no use for the user
     * anyway.  It contains only service data, not even needed to
     * properly unpack the file. */
    ret = rar5_read_data_skip(a);
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        return ret;
    }
    /* After skipping, try parsing another block automatically. */
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_retry;
}

fn process_head_main(
    a: *mut archive_read,
    rar: *mut rar5,
    entry: *mut archive_entry,
    block_flags: size_t,
) -> i32 {
    let mut ret: i32 = 0;
    let mut extra_data_size: size_t = 0;
    let mut extra_field_size: size_t = 0;
    let mut extra_field_id: size_t = 0;
    let mut archive_flags: size_t = 0;
    let safe_rar = unsafe { &mut *rar };
    if block_flags & HFL_EXTRA_DATA as i32 as u64 != 0 {
        if read_var_sized(a, &mut extra_data_size, 0 as *mut size_t) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
    } else {
        extra_data_size = 0
    }
    if read_var_sized(a, &mut archive_flags, 0 as *mut size_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    safe_rar
        .main
        .set_volume((archive_flags & VOLUME as i32 as u64 > 0 as i32 as u64) as i32 as uint8_t);
    safe_rar
        .main
        .set_solid((archive_flags & SOLID_0 as i32 as u64 > 0 as i32 as u64) as i32 as uint8_t);
    if archive_flags & VOLUME_NUMBER as i32 as u64 != 0 {
        let mut v: size_t = 0;
        if read_var_sized(a, &mut v, 0 as *mut size_t) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        if v > ARCHIVE_RAR5_DEFINED_PARAM.uint_max as u64 {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                b"Invalid volume number\x00" as *const u8
            );
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
        safe_rar.main.vol_no = v as u32
    } else {
        safe_rar.main.vol_no = 0
    }
    if safe_rar.vol.expected_vol_no > 0 as i32 as u32
        && safe_rar.main.vol_no != safe_rar.vol.expected_vol_no
    {
        /* Returning EOF instead of FATAL because of strange
         * libarchive behavior. When opening multiple files via
         * archive_read_open_filenames(), after reading up the whole
         * last file, the __archive_read_ahead function wraps up to
         * the first archive instead of returning EOF. */
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if extra_data_size == 0 as i32 as u64 {
        /* Early return. */
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
    }
    if read_var_sized(a, &mut extra_field_size, 0 as *mut size_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if read_var_sized(a, &mut extra_field_id, 0 as *mut size_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if extra_field_size == 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid extra field size\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    match extra_field_id as u32 {
        LOCATOR => {
            ret = process_main_locator_extra_block(a, rar);
            if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
                /* Error while parsing main locator extra
                 * block. */
                return ret;
            }
        }
        _ => {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                b"Unsupported extra type (0x%x)\x00" as *const u8,
                extra_field_id as i32
            );
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn skip_unprocessed_bytes(mut a: *mut archive_read) -> i32 {
    let mut rar: *mut rar5 = get_context(a);
    let mut ret: i32 = 0;
    let safe_rar = unsafe { &mut *rar };
    if safe_rar.file.bytes_remaining != 0 {
        /* Use different skipping method in block merging mode than in
         * normal mode. If merge mode is active, rar5_read_data_skip
         * can't be used, because it could allow recursive use of
         * merge_block() * function, and this function doesn't support
         * recursive use. */
        if safe_rar.merge_mode != 0 {
            /* Discard whole merged block. This is valid in solid
             * mode as well, because the code will discard blocks
             * only if those blocks are safe to discard (i.e.
             * they're not FILE blocks).  */
            ret = consume(a, safe_rar.file.bytes_remaining);
            if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
                return ret;
            }
            safe_rar.file.bytes_remaining = 0
        } else {
            /* If we're not in merge mode, use safe skipping code.
             * This will ensure we'll handle solid archives
             * properly. */
            ret = rar5_read_data_skip(a);
            if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
                return ret;
            }
        }
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}
/* Base block processing function. A 'base block' is a RARv5 header block
 * that tells the reader what kind of data is stored inside the block.
 *
 * From the birds-eye view a RAR file looks file this:
 *
 * <magic><base_block_1><base_block_2>...<base_block_n>
 *
 * There are a few types of base blocks. Those types are specified inside
 * the 'switch' statement in this function. For example purposes, I'll write
 * how a standard RARv5 file could look like here:
 *
 * <magic><MAIN><FILE><FILE><FILE><SERVICE><ENDARC>
 *
 * The structure above could describe an archive file with 3 files in it,
 * one service "QuickOpen" block (that is ignored by this parser), and an
 * end of file base block marker.
 *
 * If the file is stored in multiple archive files ("multiarchive"), it might
 * look like this:
 *
 * .part01.rar: <magic><MAIN><FILE><ENDARC>
 * .part02.rar: <magic><MAIN><FILE><ENDARC>
 * .part03.rar: <magic><MAIN><FILE><ENDARC>
 *
 * This example could describe 3 RAR files that contain ONE archived file.
 * Or it could describe 3 RAR files that contain 3 different files. Or 3
 * RAR files than contain 2 files. It all depends what metadata is stored in
 * the headers of <FILE> blocks.
 *
 * Each <FILE> block contains info about its size, the name of the file it's
 * storing inside, and whether this FILE block is a continuation block of
 * previous archive ('split before'), and is this FILE block should be
 * continued in another archive ('split after'). By parsing the 'split before'
 * and 'split after' flags, we're able to tell if multiple <FILE> base blocks
 * are describing one file, or multiple files (with the same filename, for
 * example).
 *
 * One thing to note is that if we're parsing the first <FILE> block, and
 * we see 'split after' flag, then we need to jump over to another <FILE>
 * block to be able to decompress rest of the data. To do this, we need
 * to skip the <ENDARC> block, then switch to another file, then skip the
 * <magic> block, <MAIN> block, and then we're standing on the proper
 * <FILE> block.
 */
fn process_base_block(a: *mut archive_read, entry: *mut archive_entry) -> i32 {
    let SMALLEST_RAR5_BLOCK_SIZE: size_t = 3;
    let mut rar: *mut rar5 = get_context(a);
    let mut hdr_crc: uint32_t = 0;
    let mut computed_crc: uint32_t = 0;
    let mut raw_hdr_size: size_t = 0;
    let mut hdr_size_len: size_t = 0;
    let mut hdr_size: size_t = 0;
    let mut header_id: size_t = 0;
    let mut header_flags: size_t = 0;
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let mut ret: i32 = 0;
    let safe_rar = unsafe { &mut *rar };
    /* Skip any unprocessed data for this file. */
    ret = skip_unprocessed_bytes(a);
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        return ret;
    }
    /* Read the expected CRC32 checksum. */
    if read_u32(a, &mut hdr_crc) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    /* Read header size. */
    if read_var_sized(a, &mut raw_hdr_size, &mut hdr_size_len) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    hdr_size = raw_hdr_size + hdr_size_len;
    /* Sanity check, maximum header size for RAR5 is 2MB. */
    if hdr_size > (2 * 1024 * 1024) as u64 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Base block header is too large\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    /* Additional sanity checks to weed out invalid files. */
    if raw_hdr_size == 0 || hdr_size_len == 0 || hdr_size < SMALLEST_RAR5_BLOCK_SIZE {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Too small block encountered (%zu bytes)\x00" as *const u8,
            raw_hdr_size
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    /* Read the whole header data into memory, maximum memory use here is
     * 2MB. */
    if read_ahead(a, hdr_size, &mut p) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    /* Verify the CRC32 of the header data. */
    computed_crc = unsafe { crc32_safe(0, p, hdr_size as i32 as uInt) as uint32_t };
    if computed_crc != hdr_crc {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Header CRC error\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    /* If the checksum is OK, we proceed with parsing. */
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, hdr_size_len as int64_t) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if read_var_sized(a, &mut header_id, 0 as *mut size_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if read_var_sized(a, &mut header_flags, 0 as *mut size_t) == 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    safe_rar.generic.set_split_after(
        (header_flags & HFL_SPLIT_AFTER as i32 as u64 > 0 as i32 as u64) as i32 as uint8_t,
    );
    safe_rar.generic.set_split_before(
        (header_flags & HFL_SPLIT_BEFORE as i32 as u64 > 0 as i32 as u64) as i32 as uint8_t,
    );
    safe_rar.generic.size = hdr_size as i32;
    safe_rar.generic.last_header_id = header_id as i32;
    safe_rar.main.set_endarc(0);
    /* Those are possible header ids in RARv5. */
    match header_id as u32 {
        HEAD_MAIN => {
            ret = process_head_main(a, rar, entry, header_flags);
            /* Main header doesn't have any files in it, so it's
             * pointless to return to the caller. Retry to next
             * header, which should be HEAD_FILE/HEAD_SERVICE. */
            if ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_retry;
            }
            return ret;
        }
        HEAD_SERVICE => {
            ret = process_head_service(a, rar, entry, header_flags);
            return ret;
        }
        HEAD_FILE => {
            ret = process_head_file(a, rar, entry, header_flags);
            return ret;
        }
        HEAD_CRYPT => {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                b"Encryption is not supported\x00" as *const u8
            );
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
        HEAD_ENDARC => {
            safe_rar.main.set_endarc(1);
            /* After encountering an end of file marker, we need
             * to take into consideration if this archive is
             * continued in another file (i.e. is it part01.rar:
             * is there a part02.rar?) */
            if safe_rar.main.volume() != 0 {
                /* In case there is part02.rar, position the
                 * read pointer in a proper place, so we can
                 * resume parsing. */
                ret = scan_for_signature(a);
                if ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal {
                    return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
                } else {
                    if safe_rar.vol.expected_vol_no == ARCHIVE_RAR5_DEFINED_PARAM.uint_max as u32 {
                        archive_set_error_safe!(
                            &mut (*a).archive as *mut archive,
                            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                            b"Header error\x00" as *const u8
                        );
                        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
                    }
                    safe_rar.vol.expected_vol_no = safe_rar.main.vol_no + 1;
                    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
                }
            } else {
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
            }
        }
        HEAD_MARK => {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        _ => {
            if header_flags & HFL_SKIP_IF_UNKNOWN as i32 as u64 == 0 as i32 as u64 {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                    b"Header type error\x00" as *const u8
                );
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
            } else {
                /* If the block is marked as 'skip if unknown',
                 * do as the flag says: skip the block
                 * instead on failing on it. */
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_retry;
            }
        }
    };
}

fn skip_base_block(mut a: *mut archive_read) -> i32 {
    let mut ret: i32 = 0;
    let mut rar: *mut rar5 = get_context(a);
    let safe_rar = unsafe { &mut *rar };
    /* Create a new local archive_entry structure that will be operated on
     * by header reader; operations on this archive_entry will be discarded.
     */
    let mut entry: *mut archive_entry = unsafe { archive_entry_new_safe() };
    ret = process_base_block(a, entry);
    /* Discard operations on this archive_entry structure. */
    unsafe { archive_entry_free_safe(entry) };
    if ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal {
        return ret;
    }
    if safe_rar.generic.last_header_id == 2 && safe_rar.generic.split_before() > 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
    }
    if ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_retry;
    } else {
        return ret;
    };
}

fn rar5_read_header(a: *mut archive_read, entry: *mut archive_entry) -> i32 {
    let mut rar: *mut rar5 = get_context(a);
    let mut ret: i32 = 0;
    let safe_rar = unsafe { &mut *rar };
    if safe_rar.header_initialized == 0 {
        init_header(a);
        safe_rar.header_initialized = 1
    }
    if safe_rar.skipped_magic == 0 {
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
            != consume(a, size_of::<[u8; 8]>() as u64 as int64_t)
        {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        safe_rar.skipped_magic = 1
    }
    loop {
        ret = process_base_block(a, entry);
        if !(ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_retry
            || safe_rar.main.endarc() as i32 > 0 && ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_ok)
        {
            break;
        }
    }
    return ret;
}

fn init_unpack(mut rar: *mut rar5) {
    let safe_rar = unsafe { &mut *rar };
    safe_rar.file.calculated_crc32 = 0 as i32 as uint32_t;
    init_window_mask(rar);
    unsafe {
        free_safe(safe_rar.cstate.window_buf as *mut ());
        free_safe(safe_rar.cstate.filtered_buf as *mut ());
    }
    if safe_rar.cstate.window_size > 0 {
        safe_rar.cstate.window_buf =
            unsafe { calloc_safe(1, safe_rar.cstate.window_size as u64) as *mut uint8_t };
        safe_rar.cstate.filtered_buf =
            unsafe { calloc_safe(1, safe_rar.cstate.window_size as u64) as *mut uint8_t }
    } else {
        safe_rar.cstate.window_buf = 0 as *mut uint8_t;
        safe_rar.cstate.filtered_buf = 0 as *mut uint8_t
    }
    safe_rar.cstate.write_ptr = 0;
    safe_rar.cstate.last_write_ptr = 0;
    unsafe {
        memset_safe(
            &mut safe_rar.cstate.bd as *mut decode_table as *mut (),
            0,
            size_of::<decode_table>() as u64,
        );
        memset_safe(
            &mut safe_rar.cstate.ld as *mut decode_table as *mut (),
            0,
            size_of::<decode_table>() as u64,
        );
        memset_safe(
            &mut safe_rar.cstate.dd as *mut decode_table as *mut (),
            0,
            size_of::<decode_table>() as u64,
        );
        memset_safe(
            &mut safe_rar.cstate.ldd as *mut decode_table as *mut (),
            0,
            size_of::<decode_table>() as u64,
        );
        memset_safe(
            &mut safe_rar.cstate.rd as *mut decode_table as *mut (),
            0,
            size_of::<decode_table>() as u64,
        );
    }
}

fn update_crc(rar: *mut rar5, p: *const uint8_t, to_read: size_t) {
    let mut verify_crc: i32 = 0;
    let safe_rar = unsafe { &mut *rar };
    if safe_rar.skip_mode != 0 {
        match () {
            #[cfg(CHECK_CRC_ON_SOLID_SKIP)]
            _ => {
                verify_crc = 1 as i32;
            }
            #[cfg(not(CHECK_CRC_ON_SOLID_SKIP))]
            _ => verify_crc = 0,
        }
    } else {
        verify_crc = 1
    }
    if verify_crc != 0 {
        /* Don't update CRC32 if the file doesn't have the
         * `stored_crc32` info filled in. */
        if safe_rar.file.stored_crc32 > 0 {
            safe_rar.file.calculated_crc32 = unsafe {
                crc32_safe(safe_rar.file.calculated_crc32 as uLong, p, to_read as uInt) as uint32_t
            }
        }
        /* Check if the file uses an optional BLAKE2sp checksum
         * algorithm. */
        if safe_rar.file.has_blake2 > 0 {
            /* Return value of the `update` function is always 0,
             * so we can explicitly ignore it here. */
            unsafe {
                blake2sp_update_safe(&mut safe_rar.file.b2state, p, to_read);
            }
        }
    };
}

fn create_decode_tables(
    mut bit_length: *mut uint8_t,
    mut table: *mut decode_table,
    mut size: i32,
) -> i32 {
    let mut code: i32 = 0;
    let mut upper_limit: i32 = 0 as i32;
    let mut i: i32 = 0;
    let mut lc: [i32; 16] = [0; 16];
    let mut decode_pos_clone: [uint32_t; 16] = [0; 16];
    let mut cur_len: ssize_t = 0;
    let mut quick_data_size: ssize_t = 0;
    let safe_table = unsafe { &mut *table };
    unsafe {
        memset_safe(
            &mut lc as *mut [i32; 16] as *mut (),
            0,
            size_of::<[i32; 16]>() as u64,
        );
        memset_safe(
            safe_table.decode_num.as_mut_ptr() as *mut (),
            0,
            size_of::<[uint16_t; 306]>() as u64,
        );
    }
    safe_table.size = size as uint32_t;
    safe_table.quick_bits = if size == ARCHIVE_RAR5_DEFINED_PARAM.huff_nc {
        10
    } else {
        7
    } as uint32_t;
    i = 0;
    while i < size {
        unsafe { lc[(*bit_length.offset(i as isize) as i32 & 15 as i32) as usize] += 1 };
        i += 1
    }
    lc[0] = 0;
    safe_table.decode_pos[0] = 0;
    safe_table.decode_len[0] = 0;
    i = 1;
    while i < 16 {
        upper_limit += lc[i as usize];
        safe_table.decode_len[i as usize] = upper_limit << 16 as i32 - i;
        safe_table.decode_pos[i as usize] = safe_table.decode_pos[(i - 1 as i32) as usize]
            .wrapping_add(lc[(i - 1) as usize] as u32);
        upper_limit <<= 1;
        i += 1
    }
    unsafe {
        memcpy_safe(
            decode_pos_clone.as_mut_ptr() as *mut (),
            safe_table.decode_pos.as_mut_ptr() as *const (),
            size_of::<[uint32_t; 16]>() as u64,
        );
    }
    i = 0;
    while i < size {
        let mut clen: uint8_t = unsafe { (*bit_length.offset(i as isize) & 15) as uint8_t };
        if clen as i32 > 0 {
            let mut last_pos: i32 = decode_pos_clone[clen as usize] as i32;
            safe_table.decode_num[last_pos as usize] = i as uint16_t;
            decode_pos_clone[clen as usize] = decode_pos_clone[clen as usize] + 1
        }
        i += 1
    }
    quick_data_size = (1) << safe_table.quick_bits;
    cur_len = 1;
    code = 0;
    while (code as i64) < quick_data_size {
        let mut bit_field: i32 = code << (16) - safe_table.quick_bits;
        let mut dist: i32 = 0;
        let mut pos: i32 = 0;
        while cur_len
            < (size_of::<[int32_t; 16]>() as u64).wrapping_div(size_of::<int32_t>() as u64)
                as ssize_t
            && bit_field >= safe_table.decode_len[cur_len as usize]
        {
            cur_len += 1
        }
        safe_table.quick_len[code as usize] = cur_len as uint8_t;
        dist = bit_field - safe_table.decode_len[(cur_len - 1) as usize];
        dist >>= 16 as i32 as i64 - cur_len;
        pos = safe_table.decode_pos[(cur_len & 15 as i32 as i64) as usize].wrapping_add(dist as u32)
            as i32;
        if cur_len
            < (size_of::<[uint32_t; 16]>() as u64).wrapping_div(size_of::<uint32_t>() as u64)
                as ssize_t
            && pos < size
        {
            safe_table.quick_num[code as usize] = safe_table.decode_num[pos as usize]
        } else {
            safe_table.quick_num[code as usize] = 0
        }
        code += 1
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn decode_number(
    a: *mut archive_read,
    table: *mut decode_table,
    p: *const uint8_t,
    num: *mut uint16_t,
) -> i32 {
    let mut i: i32 = 0;
    let mut bits: i32 = 0;
    let mut dist: i32 = 0;
    let mut bitfield: uint16_t = 0;
    let mut pos: uint32_t = 0;
    let mut rar: *mut rar5 = get_context(a);
    let safe_table = unsafe { &mut *table };
    let safe_num = unsafe { &mut *num };
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != read_bits_16(rar, p, &mut bitfield) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    bitfield = (bitfield as i32 & 0xfffe as i32) as uint16_t;
    if (bitfield as i32) < safe_table.decode_len[safe_table.quick_bits as usize] {
        let mut code: i32 =
            bitfield as i32 >> (16 as i32 as u32).wrapping_sub(safe_table.quick_bits);
        skip_bits(rar, safe_table.quick_len[code as usize] as i32);
        *safe_num = safe_table.quick_num[code as usize];
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
    }
    bits = 15;
    i = safe_table.quick_bits.wrapping_add(1 as i32 as u32) as i32;
    while i < 15 {
        if (bitfield as i32) < safe_table.decode_len[i as usize] {
            bits = i;
            break;
        } else {
            i += 1
        }
    }
    skip_bits(rar, bits);
    dist = bitfield as i32 - safe_table.decode_len[(bits - 1 as i32) as usize];
    dist >>= 16 - bits;
    pos = safe_table.decode_pos[bits as usize].wrapping_add(dist as u32);
    if pos >= safe_table.size {
        pos = 0
    }
    *safe_num = safe_table.decode_num[pos as usize];
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}
/* Reads and parses Huffman tables from the beginning of the block. */
fn parse_tables(a: *mut archive_read, rar: *mut rar5, p: *const uint8_t) -> i32 {
    let mut ret: i32 = 0;
    let mut value: i32 = 0;
    let mut i: i32 = 0;
    let mut w: i32 = 0;
    let mut idx: i32 = 0 as i32;
    let mut bit_length: [uint8_t; 20] = [0; 20];
    let mut table: [uint8_t; 430] = [0; 430];
    let mut nibble_mask: uint8_t = 0xf0;
    let mut nibble_shift: uint8_t = 4;
    let safe_rar = unsafe { &mut *rar };
    /* The data for table generation is compressed using a simple RLE-like
     * algorithm when storing zeroes, so we need to unpack it first. */
    w = 0;
    i = 0;
    while w < ARCHIVE_RAR5_DEFINED_PARAM.huff_bc {
        if i as i64 >= safe_rar.cstate.cur_block_size {
            /* Truncated data, can't continue. */
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                b"Truncated data in huffman tables\x00" as *const u8
            );
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
        value =
            unsafe { (*p.offset(i as isize) as i32 & nibble_mask as i32) >> nibble_shift as i32 };
        if nibble_mask as i32 == 0xf as i32 {
            i += 1
        }
        nibble_mask = (nibble_mask as i32 ^ 0xff as i32) as uint8_t;
        nibble_shift = (nibble_shift as i32 ^ 4 as i32) as uint8_t;
        /* Values smaller than 15 is data, so we write it directly.
         * Value 15 is a flag telling us that we need to unpack more
         * bytes. */
        if value == ESCAPE as i32 {
            value = unsafe {
                (*p.offset(i as isize) as i32 & nibble_mask as i32) >> nibble_shift as i32
            };
            if nibble_mask as i32 == 0xf as i32 {
                i += 1
            }
            nibble_mask = (nibble_mask as i32 ^ 0xff as i32) as uint8_t;
            nibble_shift = (nibble_shift as i32 ^ 4 as i32) as uint8_t;
            if value == 0 as i32 {
                /* We sometimes need to write the actual value
                 * of 15, so this case handles that. */
                let fresh1 = w;
                w = w + 1;
                bit_length[fresh1 as usize] = ESCAPE as i32 as uint8_t
            } else {
                let mut k: i32 = 0;
                /* Fill zeroes. */
                k = 0 as i32;
                while k < value + 2 as i32 && w < ARCHIVE_RAR5_DEFINED_PARAM.huff_bc {
                    let fresh2 = w;
                    w = w + 1;
                    bit_length[fresh2 as usize] = 0 as i32 as uint8_t;
                    k += 1
                }
            }
        } else {
            let fresh3 = w;
            w = w + 1;
            bit_length[fresh3 as usize] = value as uint8_t
        }
    }
    safe_rar.bits.in_addr = i;
    safe_rar.bits.bit_addr = (nibble_shift as i32 ^ 4 as i32) as int8_t;
    ret = create_decode_tables(
        bit_length.as_mut_ptr(),
        &mut safe_rar.cstate.bd,
        ARCHIVE_RAR5_DEFINED_PARAM.huff_bc,
    );
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Decoding huffman tables failed\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    i = 0;
    while i < ARCHIVE_RAR5_DEFINED_PARAM.huff_table_size {
        let mut num: uint16_t = 0;
        if (safe_rar.bits.in_addr + 6 as i32) as i64 >= safe_rar.cstate.cur_block_size {
            /* Truncated data, can't continue. */
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                b"Truncated data in huffman tables (#2)\x00" as *const u8
            );
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
        ret = decode_number(a, &mut safe_rar.cstate.bd, p, &mut num);
        if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                b"Decoding huffman tables failed\x00" as *const u8
            );
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
        if (num as i32) < 16 {
            /* 0..15: store directly */
            table[i as usize] = num as uint8_t;
            i += 1
        } else if (num as i32) < 18 {
            /* 16..17: repeat previous code */
            let mut n: uint16_t = 0;
            if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != read_bits_16(rar, p, &mut n) {
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
            }
            if num as i32 == 16 {
                n = (n as i32 >> 13) as uint16_t;
                n = (n + 3) as uint16_t;
                skip_bits(rar, 3 as i32);
            } else {
                n = (n >> 9) as uint16_t;
                n = (n + 11) as uint16_t;
                skip_bits(rar, 7 as i32);
            }
            if i > 0 {
                loop {
                    let fresh4 = n;
                    n = n - 1;
                    if !(fresh4 as i32 > 0 as i32 && i < ARCHIVE_RAR5_DEFINED_PARAM.huff_table_size)
                    {
                        break;
                    }
                    table[i as usize] = table[(i - 1 as i32) as usize];
                    i += 1
                }
            } else {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                    b"Unexpected error when decoding huffman tables\x00" as *const u8
                );
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
            }
        } else {
            /* other codes: fill with zeroes `n` times */
            let mut n_0: uint16_t = 0;
            if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != read_bits_16(rar, p, &mut n_0) {
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
            }
            if num == 18 {
                n_0 = (n_0 >> 13) as uint16_t;
                n_0 = (n_0 + 3) as uint16_t;
                skip_bits(rar, 3);
            } else {
                n_0 = (n_0 >> 9) as uint16_t;
                n_0 = (n_0 + 11) as uint16_t;
                skip_bits(rar, 7);
            }
            loop {
                let fresh5 = n_0;
                n_0 = n_0 - 1;
                if !(fresh5 as i32 > 0 as i32 && i < ARCHIVE_RAR5_DEFINED_PARAM.huff_table_size) {
                    break;
                }
                let fresh6 = i;
                i = i + 1;
                table[fresh6 as usize] = 0 as i32 as uint8_t
            }
        }
    }
    ret = create_decode_tables(
        unsafe { &mut *table.as_mut_ptr().offset(idx as isize) },
        &mut safe_rar.cstate.ld,
        ARCHIVE_RAR5_DEFINED_PARAM.huff_nc,
    );
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Failed to create literal table\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    idx += ARCHIVE_RAR5_DEFINED_PARAM.huff_nc;
    ret = create_decode_tables(
        unsafe { &mut *table.as_mut_ptr().offset(idx as isize) },
        &mut safe_rar.cstate.dd,
        ARCHIVE_RAR5_DEFINED_PARAM.huff_dc,
    );
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Failed to create distance table\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    idx += ARCHIVE_RAR5_DEFINED_PARAM.huff_dc;
    ret = create_decode_tables(
        unsafe { &mut *table.as_mut_ptr().offset(idx as isize) },
        &mut safe_rar.cstate.ldd,
        ARCHIVE_RAR5_DEFINED_PARAM.huff_ldc,
    );
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Failed to create lower bits of distances table\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    idx += ARCHIVE_RAR5_DEFINED_PARAM.huff_ldc;
    ret = create_decode_tables(
        unsafe { &mut *table.as_mut_ptr().offset(idx as isize) },
        &mut safe_rar.cstate.rd,
        ARCHIVE_RAR5_DEFINED_PARAM.huff_rc,
    );
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Failed to create repeating distances table\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

/* Parses the block header, verifies its CRC byte, and saves the header
 * fields inside the `hdr` pointer. */
fn parse_block_header(
    a: *mut archive_read,
    p: *const uint8_t,
    block_size: *mut ssize_t,
    hdr: *mut compressed_block_header,
) -> i32 {
    let mut calculated_cksum: uint8_t = 0;
    let safe_block_size = unsafe { &mut *block_size };
    let safe_hdr = unsafe { &mut *hdr };
    unsafe {
        memcpy_safe(
            hdr as *mut (),
            p as *const (),
            size_of::<compressed_block_header>() as u64,
        )
    };
    if bf_byte_count(hdr) > 2 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Unsupported block header size (was %d, max is 2)\x00" as *const u8,
            bf_byte_count(hdr) as i32
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    /* This should probably use bit reader interface in order to be more
     * future-proof. */
    *safe_block_size = 0;
    match bf_byte_count(hdr) as i32 {
        0 => {
            /* 1-byte block size */
            *safe_block_size = unsafe { *(&*p.offset(2) as *const uint8_t) as ssize_t }
        }
        1 => {
            /* 2-byte block size */
            *safe_block_size =
                unsafe { archive_le16dec(&*p.offset(2) as *const uint8_t as *const ()) as ssize_t }
        }
        2 => {
            /* 3-byte block size */
            *safe_block_size =
                unsafe { archive_le32dec(&*p.offset(2) as *const uint8_t as *const ()) as ssize_t };
            *safe_block_size &= 0xffffff
        }
        _ => {
            /* Other block sizes are not supported. This case is not
             * reached, because we have an 'if' guard before the switch
             * that makes sure of it. */
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
    }
    /* Verify the block header checksum. 0x5A is a magic value and is
     * always * constant. */
    calculated_cksum = (0x5a as i32
        ^ safe_hdr.block_flags_u8 as i32
        ^ *safe_block_size as uint8_t as i32
        ^ (*safe_block_size >> 8 as i32) as uint8_t as i32
        ^ (*safe_block_size >> 16 as i32) as uint8_t as i32) as uint8_t;
    if calculated_cksum != safe_hdr.block_cksum {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Block checksum error: got 0x%x, expected 0x%x\x00" as *const u8,
            (*hdr).block_cksum as i32,
            calculated_cksum as i32
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}
/* Convenience function used during filter processing. */
fn parse_filter_data(rar: *mut rar5, p: *const uint8_t, filter_data: *mut uint32_t) -> i32 {
    let mut i: i32 = 0;
    let mut bytes: i32 = 0;
    let mut data: uint32_t = 0;
    let safe_filter_data = unsafe { &mut *filter_data };
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != read_consume_bits(rar, p, 2 as i32, &mut bytes) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    bytes += 1;
    i = 0;
    while i < bytes {
        let mut byte: uint16_t = 0;
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != read_bits_16(rar, p, &mut byte) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        /* Cast to uint32_t will ensure the shift operation will not
         * produce undefined result. */
        data = (data as u32).wrapping_add((byte as uint32_t >> 8 as i32) << i * 8 as i32)
            as uint32_t as uint32_t;
        skip_bits(rar, 8 as i32);
        i += 1
    }
    *safe_filter_data = data;
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}
/* Function is used during sanity checking. */
fn is_valid_filter_block_start(rar: *mut rar5, start: uint32_t) -> i32 {
    let safe_rar = unsafe { &mut *rar };
    let block_start: int64_t = start as ssize_t + safe_rar.cstate.write_ptr;
    let last_bs: int64_t = safe_rar.cstate.last_block_start;
    let last_bl: ssize_t = safe_rar.cstate.last_block_length;
    if last_bs == 0 || last_bl == 0 {
        /* We didn't have any filters yet, so accept this offset. */
        return 1;
    }
    if block_start >= last_bs + last_bl {
        /* Current offset is bigger than last block's end offset, so
         * accept current offset. */
        return 1;
    }
    /* Any other case is not a normal situation and we should fail. */
    return 0;
}
/* The function will create a new filter, read its parameters from the input
 * stream and add it to the filter collection. */
fn parse_filter(ar: *mut archive_read, p: *const uint8_t) -> i32 {
    let mut block_start: uint32_t = 0;
    let mut block_length: uint32_t = 0;
    let mut filter_type: uint16_t = 0;
    let mut filt: *mut filter_info = 0 as *mut filter_info;
    let mut rar: *mut rar5 = get_context(ar);
    let safe_rar = unsafe { &mut *rar };
    /* Read the parameters from the input stream. */
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != parse_filter_data(rar, p, &mut block_start) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != parse_filter_data(rar, p, &mut block_length) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != read_bits_16(rar, p, &mut filter_type) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    filter_type = (filter_type >> 13) as uint16_t;
    skip_bits(rar, 3);
    /* Perform some sanity checks on this filter parameters. Note that we
     * allow only DELTA, E8/E9 and ARM filters here, because rest of
     * filters are not used in RARv5. */
    if block_length < 4
        || block_length > 0x400000
        || filter_type as i32 > FILTER_ARM as i32
        || is_valid_filter_block_start(rar, block_start) == 0
    {
        archive_set_error_safe!(
            &mut (*ar).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid filter encountered\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    /* Allocate a new filter. */
    filt = add_new_filter(rar);
    if filt.is_null() {
        archive_set_error_safe!(
            &mut (*ar).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.enomem,
            b"Can\'t allocate memory for a filter descriptor.\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    unsafe {
        (*filt).type_0 = filter_type as i32;
        (*filt).block_start = safe_rar.cstate.write_ptr + block_start as i64;
        (*filt).block_length = block_length as ssize_t;
        safe_rar.cstate.last_block_start = (*filt).block_start;
        safe_rar.cstate.last_block_length = (*filt).block_length;
    }
    /* Read some more data in case this is a DELTA filter. Other filter
     * types don't require any additional data over what was already
     * read. */
    if filter_type as i32 == FILTER_DELTA as i32 {
        let mut channels: i32 = 0;
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
            != read_consume_bits(rar, p, 5 as i32, &mut channels)
        {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        unsafe { (*filt).channels = channels + 1 }
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn decode_code_length(rar: *mut rar5, p: *const uint8_t, code: uint16_t) -> i32 {
    let mut lbits: i32 = 0;
    let mut length: i32 = 2 as i32;
    if (code) < 8 {
        lbits = 0;
        length += code as i32
    } else {
        lbits = code as i32 / 4 as i32 - 1 as i32;
        length += (4 as i32 | code as i32 & 3 as i32) << lbits
    }
    if lbits > 0 {
        let mut add: i32 = 0;
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != read_consume_bits(rar, p, lbits, &mut add) {
            return -1;
        }
        length += add
    }
    return length;
}

fn copy_string(a: *mut archive_read, len: i32, dist: i32) -> i32 {
    let mut rar: *mut rar5 = get_context(a);
    let safe_rar = unsafe { &mut *rar };
    let cmask: uint64_t = safe_rar.cstate.window_mask;
    let write_ptr: uint64_t =
        (safe_rar.cstate.write_ptr + safe_rar.cstate.solid_offset) as uint64_t;
    let mut i: i32 = 0;
    if safe_rar.cstate.window_buf.is_null() {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    /* The unpacker spends most of the time in this function. It would be
     * a good idea to introduce some optimizations here.
     *
     * Just remember that this loop treats buffers that overlap differently
     * than buffers that do not overlap. This is why a simple memcpy(3)
     * call will not be enough. */
    i = 0;
    while i < len {
        let write_idx: ssize_t = (write_ptr.wrapping_add(i as u64) & cmask) as ssize_t;
        let read_idx: ssize_t =
            (write_ptr.wrapping_add(i as u64).wrapping_sub(dist as u64) & cmask) as ssize_t;
        unsafe {
            *(*rar).cstate.window_buf.offset(write_idx as isize) =
                *(*rar).cstate.window_buf.offset(read_idx as isize)
        };
        i += 1
    }
    safe_rar.cstate.write_ptr += len as i64;
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn do_uncompress_block(a: *mut archive_read, p: *const uint8_t) -> i32 {
    let mut rar: *mut rar5 = get_context(a);
    let mut num: uint16_t = 0;
    let mut ret: i32 = 0;
    let safe_rar = unsafe { &mut *rar };
    let cmask: uint64_t = safe_rar.cstate.window_mask;
    let mut hdr: *const compressed_block_header = &mut safe_rar.last_block_hdr;
    let bit_size: uint8_t = (1 + bf_bit_size(hdr) as i32) as uint8_t;
    while !(safe_rar.cstate.write_ptr - safe_rar.cstate.last_write_ptr
        > safe_rar.cstate.window_size >> 1)
    {
        if safe_rar.bits.in_addr as i64 > safe_rar.cstate.cur_block_size - 1 as i32 as i64
            || safe_rar.bits.in_addr as i64 == safe_rar.cstate.cur_block_size - 1 as i32 as i64
                && safe_rar.bits.bit_addr as i32 >= bit_size as i32
        {
            /* If the program counter is here, it means the
             * function has finished processing the block. */
            safe_rar.cstate.set_block_parsing_finished(1);
            break;
        } else {
            /* Decode the next literal. */
            if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
                != decode_number(a, &mut safe_rar.cstate.ld, p, &mut num)
            {
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
            }
            /* Num holds a decompression literal, or 'command code'.
             *
             * - Values lower than 256 are just bytes. Those codes
             *   can be stored in the output buffer directly.
             *
             * - Code 256 defines a new filter, which is later used to
             *   ransform the data block accordingly to the filter type.
             *   The data block needs to be fully uncompressed first.
             *
             * - Code bigger than 257 and smaller than 262 define
             *   a repetition pattern that should be copied from
             *   an already uncompressed chunk of data.
             */
            if num < 256 {
                /* Directly store the byte. */
                let fresh7 = safe_rar.cstate.write_ptr;
                safe_rar.cstate.write_ptr = safe_rar.cstate.write_ptr + 1;
                let mut write_idx: int64_t = safe_rar.cstate.solid_offset + fresh7;
                unsafe {
                    *(*rar)
                        .cstate
                        .window_buf
                        .offset((write_idx as u64 & cmask) as isize) = num as uint8_t
                }
            } else if num >= 262 {
                let mut dist_slot: uint16_t = 0;
                let mut len: i32 = decode_code_length(rar, p, (num as i32 - 262) as uint16_t);
                let mut dbits: i32 = 0;
                let mut dist: i32 = 1;
                if len == -1 {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_programmer,
                        b"Failed to decode the code length\x00" as *const u8
                    );
                    return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
                }
                if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
                    != decode_number(a, &mut safe_rar.cstate.dd, p, &mut dist_slot)
                {
                    archive_set_error_safe!(
                        &mut (*a).archive as *mut archive,
                        ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_programmer,
                        b"Failed to decode the distance slot\x00" as *const u8
                    );
                    return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
                }
                if (dist_slot) < 4 {
                    dbits = 0;
                    dist += dist_slot as i32
                } else {
                    dbits = dist_slot as i32 / 2 as i32 - 1 as i32;
                    /* Cast to uint32_t will make sure the shift
                     * left operation won't produce undefined
                     * result. Then, the uint32_t type will
                     * be implicitly casted to int. */
                    dist = (dist as u32).wrapping_add(
                        ((2 as i32 | dist_slot as i32 & 1 as i32) as uint32_t) << dbits,
                    ) as i32 as i32
                }
                if dbits > 0 {
                    if dbits >= 4 {
                        let mut add: uint32_t = 0;
                        let mut low_dist: uint16_t = 0;
                        if dbits > 4 {
                            if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
                                != read_bits_32(rar, p, &mut add)
                            {
                                /* Return EOF if we
                                 * can't read more
                                 * data. */
                                return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
                            }
                            skip_bits(rar, dbits - 4);
                            add = add >> 36 - dbits << 4;
                            dist = (dist as u32).wrapping_add(add) as i32 as i32
                        }
                        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
                            != decode_number(a, &mut safe_rar.cstate.ldd, p, &mut low_dist)
                        {
                            archive_set_error_safe!(
                                &mut (*a).archive as *mut archive,
                                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_programmer,
                                b"Failed to decode the distance slot\x00" as *const u8
                            );
                            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
                        }
                        if dist >= ARCHIVE_RAR5_DEFINED_PARAM.int_max - low_dist as i32 - 1 as i32 {
                            /* This only happens in
                             * invalid archives. */
                            archive_set_error_safe!(
                                &mut (*a).archive as *mut archive,
                                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                                b"Distance pointer overflow\x00" as *const u8
                            );
                            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
                        }
                        dist += low_dist as i32
                    } else {
                        /* dbits is one of [0,1,2,3] */
                        let mut add_0: i32 = 0;
                        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
                            != read_consume_bits(rar, p, dbits, &mut add_0)
                        {
                            /* Return EOF if we can't read
                             * more data. */
                            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
                        }
                        dist += add_0
                    }
                }
                if dist > 0x100 {
                    len += 1;
                    if dist > 0x2000 {
                        len += 1;
                        if dist > 0x40000 {
                            len += 1
                        }
                    }
                }
                dist_cache_push(rar, dist);
                safe_rar.cstate.last_len = len;
                if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != copy_string(a, len, dist) {
                    return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
                }
            } else if num == 256 {
                /* Create a filter. */
                ret = parse_filter(a, p);
                if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
                    return ret;
                }
            } else if num == 257 {
                if safe_rar.cstate.last_len != 0 {
                    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
                        != copy_string(a, safe_rar.cstate.last_len, safe_rar.cstate.dist_cache[0])
                    {
                        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
                    }
                }
            } else {
                /* num < 262 */
                let idx: i32 = num as i32 - 258;
                let dist_0: i32 = dist_cache_touch(rar, idx);
                let mut len_slot: uint16_t = 0;
                let mut len_0: i32 = 0;
                if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok
                    != decode_number(a, &mut safe_rar.cstate.rd, p, &mut len_slot)
                {
                    return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
                }
                len_0 = decode_code_length(rar, p, len_slot);
                safe_rar.cstate.last_len = len_0;
                if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != copy_string(a, len_0, dist_0) {
                    return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
                }
            }
        }
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

/* Binary search for the RARv5 signature. */
fn scan_for_signature(mut a: *mut archive_read) -> i32 {
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let chunk_size: i32 = 512;
    let mut i: ssize_t = 0;
    let mut signature: [u8; 8] = [0; 8];
    /* If we're here, it means we're on an 'unknown territory' data.
     * There's no indication what kind of data we're reading here.
     * It could be some text comment, any kind of binary data,
     * digital sign, dragons, etc.
     *
     * We want to find a valid RARv5 magic header inside this unknown
     * data. */
    /* Is it possible in libarchive to just skip everything until the
     * end of the file? If so, it would be a better approach than the
     * current implementation of this function. */
    rar5_signature(signature.as_mut_ptr());
    loop {
        if read_ahead(a, chunk_size as size_t, &mut p) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        i = 0;
        while i < (chunk_size - size_of::<[u8; 8]>() as u64 as i32) as i64 {
            if unsafe {
                memcmp_safe(
                    unsafe { &*p.offset(i as isize) as *const uint8_t as *const () },
                    signature.as_mut_ptr() as *const (),
                    size_of::<[u8; 8]>() as u64,
                )
            } == 0
            {
                /* Consume the number of bytes we've used to
                 * search for the signature, as well as the
                 * number of bytes used by the signature
                 * itself. After this we should be standing
                 * on a valid base block header. */
                consume(
                    a,
                    (i as u64).wrapping_add(size_of::<[u8; 8]>() as u64) as int64_t,
                );
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
            }
            i += 1
        }
        consume(a, chunk_size as int64_t);
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
}
/* This function will switch the multivolume archive file to another file,
 * i.e. from part03 to part 04. */
fn advance_multivolume(a: *mut archive_read) -> i32 {
    let mut lret: i32 = 0;
    let mut rar: *mut rar5 = get_context(a);
    let safe_rar = unsafe { &mut *rar };
    loop
    /* A small state machine that will skip unnecessary data, needed to
     * switch from one multivolume to another. Such skipping is needed if
     * we want to be an stream-oriented (instead of file-oriented)
     * unpacker.
     *
     * The state machine starts with `rar->main.endarc` == 0. It also
     * assumes that current stream pointer points to some base block
     * header.
     *
     * The `endarc` field is being set when the base block parsing
     * function encounters the 'end of archive' marker.
     */
    {
        if safe_rar.main.endarc() == 1 {
            let mut looping: i32 = 1;
            safe_rar.main.set_endarc(0);
            while looping != 0 {
                lret = skip_base_block(a);
                if lret == ARCHIVE_RAR5_DEFINED_PARAM.archive_retry {
                } else if lret == ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
                    /* Break loop. */
                    looping = 0
                } else {
                    /* Forward any errors to the
                     * caller. */
                    return lret;
                }
            }
            break;
        } else {
            /* Skip current base block. In order to properly skip
             * it, we really need to simply parse it and discard
             * the results. */
            lret = skip_base_block(a);
            if lret == ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal
                || lret == ARCHIVE_RAR5_DEFINED_PARAM.archive_failed
            {
                return lret;
            }
            /* The `skip_base_block` function tells us if we
             * should continue with skipping, or we should stop
             * skipping. We're trying to skip everything up to
             * a base FILE block. */
            if !(lret != ARCHIVE_RAR5_DEFINED_PARAM.archive_retry) {
                continue;
            }
            /* If there was an error during skipping, or we
             * have just skipped a FILE base block... */
            if !(safe_rar.main.endarc() == 0) {
                continue;
            }
            return lret;
        }
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}
/* Merges the partial block from the first multivolume archive file, and
 * partial block from the second multivolume archive file. The result is
 * a chunk of memory containing the whole block, and the stream pointer
 * is advanced to the next block in the second multivolume archive file. */
fn merge_block(a: *mut archive_read, block_size: ssize_t, p: *mut *const uint8_t) -> i32 {
    let mut rar: *mut rar5 = get_context(a);
    let mut cur_block_size: ssize_t = 0;
    let mut partial_offset: ssize_t = 0;
    let mut lp: *const uint8_t = 0 as *const uint8_t;
    let mut ret: i32 = 0;
    let safe_rar = unsafe { &mut *rar };
    let safe_p = unsafe { &mut *p };
    if safe_rar.merge_mode != 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_programmer,
            b"Recursive merge is not allowed\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    /* Set a flag that we're in the switching mode. */
    safe_rar.cstate.set_switch_multivolume(1);
    /* Reallocate the memory which will hold the whole block. */
    if !safe_rar.vol.push_buf.is_null() {
        unsafe { free_safe(safe_rar.vol.push_buf as *mut ()) };
    }
    /* Increasing the allocation block by 8 is due to bit reading functions,
     * which are using additional 2 or 4 bytes. Allocating the block size
     * by exact value would make bit reader perform reads from invalid
     * memory block when reading the last byte from the buffer. */
    safe_rar.vol.push_buf = unsafe { malloc_safe((block_size + 8) as u64) as *mut uint8_t };
    if safe_rar.vol.push_buf.is_null() {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.enomem,
            b"Can\'t allocate memory for a merge block buffer.\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    /* Valgrind complains if the extension block for bit reader is not
     * initialized, so initialize it. */
    unsafe {
        memset_safe(
            unsafe {
                &mut *(*rar).vol.push_buf.offset(block_size as isize) as *mut uint8_t as *mut ()
            },
            0,
            8,
        )
    };
    loop
    /* A single block can span across multiple multivolume archive files,
     * so we use a loop here. This loop will consume enough multivolume
     * archive files until the whole block is read. */
    /* Get the size of current block chunk in this multivolume
     * archive file and read it. */
    {
        cur_block_size = if safe_rar.file.bytes_remaining > block_size - partial_offset {
            (block_size) - partial_offset
        } else {
            safe_rar.file.bytes_remaining
        };
        if cur_block_size == 0 {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                b"Encountered block size == 0 during block merge\x00" as *const u8
            );
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
        if read_ahead(a, cur_block_size as size_t, &mut lp) == 0 {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        /* Sanity check; there should never be a situation where this
         * function reads more data than the block's size. */
        if partial_offset + cur_block_size > block_size {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_programmer,
                b"Consumed too much data when merging blocks.\x00" as *const u8
            );
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
        /* Merge previous block chunk with current block chunk,
         * or create first block chunk if this is our first
         * iteration. */
        unsafe {
            memcpy_safe(
                unsafe {
                    &mut *(*rar).vol.push_buf.offset(partial_offset as isize) as *mut uint8_t
                        as *mut ()
                },
                lp as *const (),
                cur_block_size as u64,
            )
        };
        /* Advance the stream read pointer by this block chunk size. */
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, cur_block_size) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        /* Update the pointers. `partial_offset` contains information
         * about the sum of merged block chunks. */
        partial_offset += cur_block_size;
        safe_rar.file.bytes_remaining -= cur_block_size;
        /* If `partial_offset` is the same as `block_size`, this means
         * we've merged all block chunks and we have a valid full
         * block. */
        if partial_offset == block_size {
            break;
        }
        /* If we don't have any bytes to read, this means we should
         * switch to another multivolume archive file. */
        if safe_rar.file.bytes_remaining == 0 {
            safe_rar.merge_mode += 1;
            ret = advance_multivolume(a);
            safe_rar.merge_mode -= 1;
            if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
                return ret;
            }
        }
    }
    *safe_p = safe_rar.vol.push_buf;
    /* If we're here, we can resume unpacking by processing the block
     * pointed to by the `*p` memory pointer. */
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn process_block(a: *mut archive_read) -> i32 {
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let mut rar: *mut rar5 = get_context(a);
    let mut ret: i32 = 0;
    let safe_rar = unsafe { &mut *rar };
    /* If we don't have any data to be processed, this most probably means
     * we need to switch to the next volume. */
    if safe_rar.main.volume() as i32 != 0 && safe_rar.file.bytes_remaining == 0 as i32 as i64 {
        ret = advance_multivolume(a);
        if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
            return ret;
        }
    }
    if safe_rar.cstate.block_parsing_finished() != 0 {
        let mut block_size: ssize_t = 0;
        let mut to_skip: ssize_t = 0;
        let mut cur_block_size: ssize_t = 0;
        /* The header size won't be bigger than 6 bytes. */
        if read_ahead(a, 6, &mut p) == 0 {
            /* Failed to prefetch data block header. */
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        /*
         * Read block_size by parsing block header. Validate the header
         * by calculating CRC byte stored inside the header. Size of
         * the header is not constant (block size can be stored either
         * in 1 or 2 bytes), that's why block size is left out from the
         * `compressed_block_header` structure and returned by
         * `parse_block_header` as the second argument. */
        ret = parse_block_header(a, p, &mut block_size, &mut safe_rar.last_block_hdr);
        if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
            return ret;
        }
        /* Skip block header. Next data is huffman tables,
         * if present. */
        to_skip = (size_of::<compressed_block_header>() as u64)
            .wrapping_add(bf_byte_count(&mut safe_rar.last_block_hdr) as u64)
            .wrapping_add(1) as ssize_t;
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, to_skip) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
        }
        safe_rar.file.bytes_remaining -= to_skip;
        /* The block size gives information about the whole block size,
         * but the block could be stored in split form when using
         * multi-volume archives. In this case, the block size will be
         * bigger than the actual data stored in this file. Remaining
         * part of the data will be in another file. */
        cur_block_size = if safe_rar.file.bytes_remaining > block_size {
            block_size
        } else {
            safe_rar.file.bytes_remaining
        };
        if block_size > safe_rar.file.bytes_remaining {
            /* If current blocks' size is bigger than our data
             * size, this means we have a multivolume archive.
             * In this case, skip all base headers until the end
             * of the file, proceed to next "partXXX.rar" volume,
             * find its signature, skip all headers up to the first
             * FILE base header, and continue from there.
             *
             * Note that `merge_block` will update the `rar`
             * context structure quite extensively. */
            ret = merge_block(a, block_size, &mut p);
            if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
                return ret;
            }
            cur_block_size = block_size
            /* Current stream pointer should be now directly
             * *after* the block that spanned through multiple
             * archive files. `p` pointer should have the data of
             * the *whole* block (merged from partial blocks
             * stored in multiple archives files). */
        } else {
            safe_rar.cstate.set_switch_multivolume(0);
            /* Read the whole block size into memory. This can take
             * up to  8 megabytes of memory in theoretical cases.
             * Might be worth to optimize this and use a standard
             * chunk of 4kb's. */
            if read_ahead(a, (4 + cur_block_size) as size_t, &mut p) == 0 {
                /* Failed to prefetch block data. */
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
            }
        }
        safe_rar.cstate.block_buf = p;
        safe_rar.cstate.cur_block_size = cur_block_size;
        safe_rar.cstate.set_block_parsing_finished(0);
        safe_rar.bits.in_addr = 0;
        safe_rar.bits.bit_addr = 0;
        if bf_is_table_present(&mut safe_rar.last_block_hdr) != 0 {
            /* Load Huffman tables. */
            ret = parse_tables(a, rar, p);
            if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
                /* Error during decompression of Huffman
                 * tables. */
                return ret;
            }
        }
    } else {
        /* Block parsing not finished, reuse previous memory buffer. */
        p = safe_rar.cstate.block_buf
    }
    /* Uncompress the block, or a part of it, depending on how many bytes
     * will be generated by uncompressing the block.
     *
     * In case too many bytes will be generated, calling this function
     * again will resume the uncompression operation. */
    ret = do_uncompress_block(a, p);
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        return ret;
    }
    if safe_rar.cstate.block_parsing_finished() != 0
        && safe_rar.cstate.switch_multivolume() == 0
        && safe_rar.cstate.cur_block_size > 0
    {
        /* If we're processing a normal block, consume the whole
         * block. We can do this because we've already read the whole
         * block to memory. */
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, safe_rar.cstate.cur_block_size) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
        safe_rar.file.bytes_remaining -= safe_rar.cstate.cur_block_size
    } else if safe_rar.cstate.switch_multivolume() != 0 {
        /* Don't consume the block if we're doing multivolume
         * processing. The volume switching function will consume
         * the proper count of bytes instead. */
        safe_rar.cstate.set_switch_multivolume(0)
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}
/* Pops the `buf`, `size` and `offset` from the "data ready" stack.
 *
 * Returns ARCHIVE_OK when those arguments can be used, ARCHIVE_RETRY
 * when there is no data on the stack. */
fn use_data(rar: *mut rar5, buf: *mut *const (), size: *mut size_t, offset: *mut int64_t) -> i32 {
    let mut i: i32 = 0;
    let safe_buf = unsafe { &mut *buf };
    let safe_size = unsafe { &mut *size };
    let safe_offset = unsafe { &mut *offset };
    i = 0;
    while (i as i64)
        < (size_of::<[data_ready; 2]>() as u64).wrapping_div(size_of::<data_ready>() as u64)
            as ssize_t
    {
        let mut d: *mut data_ready = unsafe {
            &mut *(*rar).cstate.dready.as_mut_ptr().offset(i as isize) as *mut data_ready
        };
        let safe_d = unsafe { &mut *d };
        if safe_d.used != 0 {
            if !buf.is_null() {
                *safe_buf = safe_d.buf as *const ()
            }
            if !size.is_null() {
                *safe_size = safe_d.size
            }
            if !offset.is_null() {
                *safe_offset = safe_d.offset
            }
            safe_d.used = 0;
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
        }
        i += 1
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_retry;
}
/* Pushes the `buf`, `size` and `offset` arguments to the rar->cstate.dready
 * FIFO stack. Those values will be popped from this stack by the `use_data`
 * function. */
fn push_data_ready(
    mut a: *mut archive_read,
    mut rar: *mut rar5,
    mut buf: *const uint8_t,
    mut size: size_t,
    mut offset: int64_t,
) -> i32 {
    let mut i: i32 = 0;
    let safe_rar = unsafe { &mut *rar };
    /* Don't push if we're in skip mode. This is needed because solid
     * streams need full processing even if we're skipping data. After
     * fully processing the stream, we need to discard the generated bytes,
     * because we're interested only in the side effect: building up the
     * internal window circular buffer. This window buffer will be used
     * later during unpacking of requested data. */
    if safe_rar.skip_mode != 0 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
    }
    /* Sanity check. */
    if offset != safe_rar.file.last_offset + safe_rar.file.last_size {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_programmer,
            b"Sanity check error: output stream is not continuous\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    i = 0;
    while (i as i64)
        < (size_of::<[data_ready; 2]>() as u64).wrapping_div(size_of::<data_ready>() as u64)
            as ssize_t
    {
        let mut d: *mut data_ready = unsafe {
            &mut *(*rar).cstate.dready.as_mut_ptr().offset(i as isize) as *mut data_ready
        };
        let safe_d = unsafe { &mut *d };
        if safe_d.used == 0 {
            safe_d.used = 1;
            safe_d.buf = buf;
            safe_d.size = size;
            safe_d.offset = offset;
            /* These fields are used only in sanity checking. */
            safe_rar.file.last_offset = offset;
            safe_rar.file.last_size = size as int64_t;
            /* Calculate the checksum of this new block before
             * submitting data to libarchive's engine. */
            update_crc(rar, safe_d.buf, safe_d.size);
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
        }
        i += 1
    }
    /* Program counter will reach this code if the `rar->cstate.data_ready`
     * stack will be filled up so that no new entries will be allowed. The
     * code shouldn't allow such situation to occur. So we treat this case
     * as an internal error. */
    archive_set_error_safe!(
        &mut (*a).archive as *mut archive,
        ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_programmer,
        b"Error: premature end of data_ready stack\x00" as *const u8
    );
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
}
/* This function uncompresses the data that is stored in the <FILE> base
 * block.
 *
 * The FILE base block looks like this:
 *
 * <header><huffman tables><block_1><block_2>...<block_n>
 *
 * The <header> is a block header, that is parsed in parse_block_header().
 * It's a "compressed_block_header" structure, containing metadata needed
 * to know when we should stop looking for more <block_n> blocks.
 *
 * <huffman tables> contain data needed to set up the huffman tables, needed
 * for the actual decompression.
 *
 * Each <block_n> consists of series of literals:
 *
 * <literal><literal><literal>...<literal>
 *
 * Those literals generate the uncompression data. They operate on a circular
 * buffer, sometimes writing raw data into it, sometimes referencing
 * some previous data inside this buffer, and sometimes declaring a filter
 * that will need to be executed on the data stored in the circular buffer.
 * It all depends on the literal that is used.
 *
 * Sometimes blocks produce output data, sometimes they don't. For example, for
 * some huge files that use lots of filters, sometimes a block is filled with
 * only filter declaration literals. Such blocks won't produce any data in the
 * circular buffer.
 *
 * Sometimes blocks will produce 4 bytes of data, and sometimes 1 megabyte,
 * because a literal can reference previously decompressed data. For example,
 * there can be a literal that says: 'append a byte 0xFE here', and after
 * it another literal can say 'append 1 megabyte of data from circular buffer
 * offset 0x12345'. This is how RAR format handles compressing repeated
 * patterns.
 *
 * The RAR compressor creates those literals and the actual efficiency of
 * compression depends on what those literals are. The literals can also
 * be seen as a kind of a non-turing-complete virtual machine that simply
 * tells the decompressor what it should do.
 * */
fn do_uncompress_file(mut a: *mut archive_read) -> i32 {
    let mut rar: *mut rar5 = get_context(a);
    let mut ret: i32 = 0;
    let mut max_end_pos: int64_t = 0;
    let safe_rar = unsafe { &mut *rar };
    if safe_rar.cstate.initialized() == 0 {
        /* Don't perform full context reinitialization if we're
         * processing a solid archive. */
        if safe_rar.main.solid() == 0 || safe_rar.cstate.window_buf.is_null() {
            init_unpack(rar);
        }
        safe_rar.cstate.set_initialized(1)
    }
    if safe_rar.cstate.all_filters_applied() == 1 {
        loop
        /* We use while(1) here, but standard case allows for just 1
         * iteration. The loop will iterate if process_block() didn't
         * generate any data at all. This can happen if the block
         * contains only filter definitions (this is common in big
         * files). */
        {
            ret = process_block(a);
            if ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_eof
                || ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal
            {
                return ret;
            }
            if !(safe_rar.cstate.last_write_ptr == safe_rar.cstate.write_ptr) {
                break;
            }
        }
    }
    /* Try to run filters. If filters won't be applied, it means that
     * insufficient data was generated. */
    ret = apply_filters(a);
    if ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_retry {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
    } else {
        if ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
    }
    /* If apply_filters() will return ARCHIVE_OK, we can continue here. */
    if cdeque_size(&mut safe_rar.cstate.filters) > 0 {
        /* Check if we can write something before hitting first
         * filter. */
        let mut flt: *mut filter_info = 0 as *mut filter_info;
        /* Get the block_start offset from the first filter. */
        if CDE_OK as i32 != cdeque_front(&mut safe_rar.cstate.filters, cdeque_filter_p(&mut flt)) {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_programmer,
                b"Can\'t read first filter\x00" as *const u8
            );
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
        max_end_pos = if unsafe { (*flt).block_start > safe_rar.cstate.write_ptr } {
            safe_rar.cstate.write_ptr
        } else {
            unsafe { (*flt).block_start }
        }
    } else {
        /* There are no filters defined, or all filters were applied.
         * This means we can just store the data without any
         * postprocessing. */
        max_end_pos = safe_rar.cstate.write_ptr
    }
    if max_end_pos == safe_rar.cstate.last_write_ptr {
        /* We can't write anything yet. The block uncompression
         * function did not generate enough data, and no filter can be
         * applied. At the same time we don't have any data that can be
         *  stored without filter postprocessing. This means we need to
         *  wait for more data to be generated, so we can apply the
         * filters.
         *
         * Signal the caller that we need more data to be able to do
         * anything.
         */
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_retry;
    } else {
        /* We can write the data before hitting the first filter.
         * So let's do it. The push_window_data() function will
         * effectively return the selected data block to the user
         * application. */
        push_window_data(a, rar, safe_rar.cstate.last_write_ptr, max_end_pos);
        safe_rar.cstate.last_write_ptr = max_end_pos
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn uncompress_file(a: *mut archive_read) -> i32 {
    let mut ret: i32 = 0;
    loop {
        /* Sometimes the uncompression function will return a
         * 'retry' signal. If this will happen, we have to retry
         * the function. */
        ret = do_uncompress_file(a);
        if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_retry {
            return ret;
        }
    }
}

fn do_unstore_file(
    a: *mut archive_read,
    rar: *mut rar5,
    buf: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let mut to_read: size_t = 0;
    let mut p: *const uint8_t = 0 as *const uint8_t;
    let safe_rar = unsafe { &mut *rar };
    let safe_buf = unsafe { &mut *buf };
    let safe_size = unsafe { &mut *size };
    let safe_offset = unsafe { &mut *offset };
    if safe_rar.file.bytes_remaining == 0
        && safe_rar.main.volume() > 0
        && safe_rar.generic.split_after() > 0
    {
        let mut ret: i32 = 0;
        safe_rar.cstate.set_switch_multivolume(1);
        ret = advance_multivolume(a);
        safe_rar.cstate.set_switch_multivolume(0);
        if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
            /* Failed to advance to next multivolume archive
             * file. */
            return ret;
        }
    }
    to_read = if safe_rar.file.bytes_remaining > (64 * 1024) as i64 {
        (64 * 1024)
    } else {
        safe_rar.file.bytes_remaining
    } as size_t;
    if to_read == 0 as i32 as u64 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if read_ahead(a, to_read, &mut p) == 0 {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"I/O error when unstoring file\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, to_read as int64_t) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    if !buf.is_null() {
        *safe_buf = p as *const ()
    }
    if !size.is_null() {
        *safe_size = to_read
    }
    if !offset.is_null() {
        *safe_offset = safe_rar.cstate.last_unstore_ptr
    }
    safe_rar.file.bytes_remaining =
        (safe_rar.file.bytes_remaining as u64).wrapping_sub(to_read) as ssize_t as ssize_t;
    safe_rar.cstate.last_unstore_ptr =
        (safe_rar.cstate.last_unstore_ptr as u64).wrapping_add(to_read) as int64_t as int64_t;
    update_crc(rar, p, to_read);
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn do_unpack(
    a: *mut archive_read,
    rar: *mut rar5,
    buf: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let safe_rar = unsafe { &mut *rar };
    if safe_rar.file.service() > 0 {
        return do_unstore_file(a, rar, buf, size, offset);
    } else {
        match safe_rar.cstate.method as u32 {
            STORE => {
                return do_unstore_file(a, rar, buf, size, offset);
            }
            FASTEST => { /* fallthrough */ }
            FAST => {}
            GOOD => { /* fallthrough */ }
            NORMAL | BEST => {}
            _ => {
                archive_set_error_safe!(
                    &mut (*a).archive as *mut archive,
                    ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                    b"Compression method not supported: 0x%x\x00" as *const u8,
                    (*rar).cstate.method
                );
                return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
            }
        }
        /* fallthrough */
        return uncompress_file(a);
    };
}

fn verify_checksums(a: *mut archive_read) -> i32 {
    let mut verify_crc: i32 = 0;
    let mut rar: *mut rar5 = get_context(a);
    let safe_rar = unsafe { &mut *rar };
    /* Check checksums only when actually unpacking the data. There's no
     * need to calculate checksum when we're skipping data in solid archives
     * (skipping in solid archives is the same thing as unpacking compressed
     * data and discarding the result). */
    if safe_rar.skip_mode == 0 {
        /* Always check checksums if we're not in skip mode */
        verify_crc = 1
    } else {
        /* We can override the logic above with a compile-time option
         * NO_CRC_ON_SOLID_SKIP. This option is used during debugging,
         * and it will check checksums of unpacked data even when
         * we're skipping it. */
        /* Normal case */
        match () {
            #[cfg(CHECK_CRC_ON_SOLID_SKIP)]
            _ => {
                verify_crc = 1 as i32;
            }
            #[cfg(not(CHECK_CRC_ON_SOLID_SKIP))]
            _ => verify_crc = 0,
        }
    }
    if verify_crc != 0 {
        /* During unpacking, on each unpacked block we're calling the
         * update_crc() function. Since we are here, the unpacking
         * process is already over and we can check if calculated
         * checksum (CRC32 or BLAKE2sp) is the same as what is stored
         * in the archive. */
        if safe_rar.file.stored_crc32 > 0 {
            /* Check CRC32 only when the file contains a CRC32
             * value for this file. */
            if safe_rar.file.calculated_crc32 != safe_rar.file.stored_crc32 {
                /* Checksums do not match; the unpacked file
                 * is corrupted. */

                match () {
                    #[cfg(not(CHECK_CRC_ON_SOLID_SKIP))]
                    _ => {
                        archive_set_error_safe!(
                            &mut (*a).archive as *mut archive,
                            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                            b"Checksum error: CRC32\x00" as *const u8
                        );
                        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
                    }
                    #[cfg(CHECK_CRC_ON_SOLID_SKIP)]
                    _ => {}
                }
            }
        }
        if safe_rar.file.has_blake2 > 0 {
            /* BLAKE2sp is an optional checksum algorithm that is
             * added to RARv5 archives when using the `-htb` switch
             *  during creation of archive.
             *
             * We now finalize the hash calculation by calling the
             * `final` function. This will generate the final hash
             * value we can use to compare it with the BLAKE2sp
             * checksum that is stored in the archive.
             *
             * The return value of this `final` function is not
             * very helpful, as it guards only against improper use.
             * This is why we're explicitly ignoring it. */
            let mut b2_buf: [uint8_t; 32] = [0; 32];
            unsafe {
                blake2sp_final_safe(&mut safe_rar.file.b2state, b2_buf.as_mut_ptr(), 32);
            }
            if unsafe {
                memcmp_safe(
                    &mut safe_rar.file.blake2sp as *mut [uint8_t; 32] as *const (),
                    b2_buf.as_mut_ptr() as *const (),
                    32,
                )
            } != 0
            {
                match () {
                    #[cfg(not(DONT_FAIL_ON_CRC_ERROR))]
                    _ => {
                        archive_set_error_safe!(
                            &mut (*a).archive as *mut archive,
                            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
                            b"Checksum error: BLAKE2\x00" as *const u8
                        );
                        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
                    }
                    #[cfg(DONT_FAIL_ON_CRC_ERROR)]
                    _ => {}
                }
            }
        }
    }
    /* Finalization for this file has been successfully completed. */
    return 0;
}

fn verify_global_checksums(mut a: *mut archive_read) -> i32 {
    return verify_checksums(a);
}
/* Forward function declarations. */
/*
 * Decryption function for the magic signature pattern. Check the comment near
 * the `rar5_signature_xor` symbol to read the rationale behind this.
 */
fn rar5_signature(buf: *mut u8) {
    let mut i: size_t = 0;
    i = 0;
    while i < size_of::<[u8; 8]>() as u64 {
        unsafe {
            *buf.offset(i as isize) = (rar5_signature_xor[i as usize] as i32 ^ 0xa1 as i32) as u8
        };
        i = i + 1
    }
}

fn rar5_read_data(
    a: *mut archive_read,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let mut ret: i32 = 0;
    let mut rar: *mut rar5 = get_context(a);
    let safe_rar = unsafe { &mut *rar };
    let safe_size = unsafe { &mut *size };
    if !size.is_null() {
        *safe_size = 0
    }
    if safe_rar.file.dir() > 0 {
        /* Don't process any data if this file entry was declared
         * as a directory. This is needed, because entries marked as
         * directory doesn't have any dictionary buffer allocated, so
         * it's impossible to perform any decompression. */
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_file_format,
            b"Can\'t decompress an entry marked as a directory\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_failed;
    }
    if safe_rar.skip_mode == 0 && safe_rar.cstate.last_write_ptr > safe_rar.file.unpacked_size {
        archive_set_error_safe!(
            &mut (*a).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.archive_errno_programmer,
            b"Unpacker has written too many bytes\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    ret = use_data(rar, buff, size, offset);
    if ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        return ret;
    }
    if safe_rar.file.eof() == 1 {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_eof;
    }
    ret = do_unpack(a, rar, buff, size, offset);
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        return ret;
    }
    if safe_rar.file.bytes_remaining == 0
        && safe_rar.cstate.last_write_ptr == safe_rar.file.unpacked_size
    {
        /* If all bytes of current file were processed, run
         * finalization.
         *
         * Finalization will check checksum against proper values. If
         * some of the checksums will not match, we'll return an error
         * value in the last `archive_read_data` call to signal an error
         * to the user. */
        safe_rar.file.set_eof(1);
        return verify_global_checksums(a);
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn rar5_read_data_skip(a: *mut archive_read) -> i32 {
    let mut rar: *mut rar5 = get_context(a);
    let safe_rar = unsafe { &mut *rar };
    if safe_rar.main.solid() != 0 {
        /* In solid archives, instead of skipping the data, we need to
         * extract it, and dispose the result. The side effect of this
         * operation will be setting up the initial window buffer state
         * needed to be able to extract the selected file. */
        let mut ret: i32 = 0;
        /* Make sure to process all blocks in the compressed stream. */
        while safe_rar.file.bytes_remaining > 0 {
            /* Setting the "skip mode" will allow us to skip
             * checksum checks during data skipping. Checking the
             * checksum of skipped data isn't really necessary and
             * it's only slowing things down.
             *
             * This is incremented instead of setting to 1 because
             * this data skipping function can be called
             * recursively. */
            safe_rar.skip_mode += 1;
            /* We're disposing 1 block of data, so we use triple
             * NULLs in arguments. */
            ret = rar5_read_data(a, 0 as *mut *const (), 0 as *mut size_t, 0 as *mut int64_t);
            /* Turn off "skip mode". */
            safe_rar.skip_mode -= 1;
            if ret < 0 || ret == ARCHIVE_RAR5_DEFINED_PARAM.archive_eof {
                /* Propagate any potential error conditions
                 * to the caller. */
                return ret;
            }
        }
    } else {
        /* In standard archives, we can just jump over the compressed
         * stream. Each file in non-solid archives starts from an empty
         * window buffer. */
        if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != consume(a, safe_rar.file.bytes_remaining) {
            return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
        }
        safe_rar.file.bytes_remaining = 0
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn rar5_seek_data(a: *mut archive_read, offset: int64_t, whence: i32) -> int64_t {
    /* We're a streaming unpacker, and we don't support seeking. */
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal as int64_t;
}

fn rar5_cleanup(mut a: *mut archive_read) -> i32 {
    let mut rar: *mut rar5 = get_context(a);
    let safe_rar = unsafe { &mut *rar };
    unsafe {
        free_safe(safe_rar.cstate.window_buf as *mut ());
        free_safe(safe_rar.cstate.filtered_buf as *mut ());
        free_safe(safe_rar.vol.push_buf as *mut ());
    }
    free_filters(rar);
    cdeque_free(&mut safe_rar.cstate.filters);
    unsafe {
        free_safe(rar as *mut ());
    }
    unsafe { (*(*a).format).data = 0 as *mut () };
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

fn rar5_capabilities(a: *mut archive_read) -> i32 {
    return 0;
}

fn rar5_has_encrypted_entries(mut _a: *mut archive_read) -> i32 {
    /* Unsupported for now. */
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_read_format_encryption_unsupported;
}

fn rar5_init(rar: *mut rar5) -> i32 {
    let safe_rar = unsafe { &mut *rar };
    unsafe {
        memset_safe(rar as *mut (), 0, size_of::<rar5>() as u64);
    }
    if CDE_OK as i32 != cdeque_init(&mut safe_rar.cstate.filters, 8192 as i32) {
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    return ARCHIVE_RAR5_DEFINED_PARAM.archive_ok;
}

#[no_mangle]
pub fn archive_read_support_format_rar5(mut _a: *mut archive) -> i32 {
    let mut ar: *mut archive_read = 0 as *mut archive_read;
    let mut ret: i32 = 0;
    let mut rar: *mut rar5 = 0 as *mut rar5;
    ret = get_archive_read(_a, &mut ar);
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != ret {
        return ret;
    }
    rar = unsafe { malloc_safe(size_of::<rar5>() as u64) as *mut rar5 };
    if rar.is_null() {
        archive_set_error_safe!(
            &mut (*ar).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.enomem,
            b"Can\'t allocate rar5 data\x00" as *const u8
        );
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    if ARCHIVE_RAR5_DEFINED_PARAM.archive_ok != rar5_init(rar) {
        archive_set_error_safe!(
            &mut (*ar).archive as *mut archive,
            ARCHIVE_RAR5_DEFINED_PARAM.enomem,
            b"Can\'t allocate rar5 filter buffer\x00" as *const u8
        );
        unsafe { free_safe(rar as *mut ()) };
        return ARCHIVE_RAR5_DEFINED_PARAM.archive_fatal;
    }
    ret = unsafe {
        __archive_read_register_format_safe(
            ar,
            rar as *mut (),
            b"rar5\x00" as *const u8,
            Some(rar5_bid as unsafe fn(_: *mut archive_read, _: i32) -> i32),
            Some(
                rar5_options as unsafe fn(_: *mut archive_read, _: *const u8, _: *const u8) -> i32,
            ),
            Some(rar5_read_header as unsafe fn(_: *mut archive_read, _: *mut archive_entry) -> i32),
            Some(
                rar5_read_data
                    as unsafe fn(
                        _: *mut archive_read,
                        _: *mut *const (),
                        _: *mut size_t,
                        _: *mut int64_t,
                    ) -> i32,
            ),
            Some(rar5_read_data_skip as unsafe fn(_: *mut archive_read) -> i32),
            Some(rar5_seek_data as unsafe fn(_: *mut archive_read, _: int64_t, _: i32) -> int64_t),
            Some(rar5_cleanup as unsafe fn(_: *mut archive_read) -> i32),
            Some(rar5_capabilities as unsafe fn(_: *mut archive_read) -> i32),
            Some(rar5_has_encrypted_entries as unsafe fn(_: *mut archive_read) -> i32),
        )
    };
    if ret != ARCHIVE_RAR5_DEFINED_PARAM.archive_ok {
        rar5_cleanup(ar);
    }
    return ret;
}

#[no_mangle]
pub fn archive_test_rar5_empty_function(_a: *mut archive) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut res1: i32 = rar5_capabilities(a);
    let mut res2: i32 = rar5_has_encrypted_entries(a);
    let mut res3: i32 = rar5_seek_data(a, 0, 0) as i32;
    return res1 + res2 + res3;
}

#[no_mangle]
pub fn archive_test_circular_memcpy(
    dst: *mut uint8_t,
    window: *mut uint8_t,
    mask: uint64_t,
    start: int64_t,
    end: int64_t,
) {
    circular_memcpy(dst, window, mask, start, end);
}

#[no_mangle]
pub fn archive_test_rar5_read_data(
    _a: *mut archive,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
    flag: i32,
) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut rar5: *mut rar5 = 0 as *mut rar5;
    rar5 = unsafe { calloc_safe(1 as i32 as u64, size_of::<rar5>() as u64) } as *mut rar5;
    unsafe {
        if flag as i32 != 0 as i32 {
            (*rar5).skip_mode = 0;
            (*rar5).cstate.last_write_ptr = 1;
            (*rar5).file.unpacked_size = 0;
        };
        (*(*a).format).data = rar5 as *mut ();
    }
    return rar5_read_data(a, buff, size, offset);
}

#[no_mangle]
pub fn archive_test_do_unpack(
    _a: *mut archive,
    buff: *mut *const (),
    size: *mut size_t,
    offset: *mut int64_t,
) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut rar5: *mut rar5 = 0 as *mut rar5;
    rar5 = unsafe { calloc_safe(1, size_of::<rar5>() as u64) } as *mut rar5;
    unsafe { (*rar5).cstate.method = 6 };
    return do_unpack(a, rar5, buff, size, offset);
}

#[no_mangle]
pub fn archive_test_run_filter(mut _a: *mut archive, mut flag: i32) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut rar5: *mut rar5 = 0 as *mut rar5;
    rar5 = unsafe { calloc_safe(1 as i32 as u64, size_of::<rar5>() as u64) } as *mut rar5;
    let mut flt: *mut filter_info = 0 as *mut filter_info;
    flt = unsafe { calloc_safe(1 as i32 as u64, size_of::<filter_info>() as u64) }
        as *mut filter_info;
    unsafe { (*(*a).format).data = rar5 as *mut () };
    return run_filter(a, flt);
}

#[no_mangle]
pub fn archive_test_push_data(
    mut _a: *mut archive,
    mut buf: *const uint8_t,
    mut idx_begin: int64_t,
    mut idx_end: int64_t,
) {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut rar5: *mut rar5 = 0 as *mut rar5;
    rar5 = unsafe { calloc_safe(1 as i32 as u64, size_of::<rar5>() as u64) } as *mut rar5;
    unsafe {
        (*rar5).cstate.window_mask = 1;
        (*rar5).cstate.solid_offset = 0;
        (*rar5).cstate.last_write_ptr = 0;
        (*rar5).cstate.solid_offset = 0;
        (*rar5).cstate.window_size = 1;
    }
    return push_data(a, rar5, buf, idx_begin, idx_end);
}

#[no_mangle]
pub fn archive_test_process_head_file(
    mut _a: *mut archive,
    mut e: *mut archive_entry,
    mut block_flags: size_t,
) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut rar5: *mut rar5 = 0 as *mut rar5;
    rar5 = unsafe { calloc_safe(1 as i32 as u64, size_of::<rar5>() as u64) } as *mut rar5;
    return process_head_file(a, rar5, e, block_flags);
}

#[no_mangle]
pub fn archive_test_parse_htime_item(
    mut _a: *mut archive,
    mut unix_time: u8,
    mut where_0: *mut uint64_t,
    mut extra_data_size: *mut ssize_t,
) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut archive_read_filter: *mut archive_read_filter = 0 as *mut archive_read_filter;
    archive_read_filter =
        unsafe { calloc_safe(1 as i32 as u64, size_of::<archive_read_filter>() as u64) }
            as *mut archive_read_filter;
    unsafe { (*archive_read_filter).fatal = 'a' as u8 };
    return parse_htime_item(a, unix_time, where_0, extra_data_size);
}

#[no_mangle]
pub fn archive_test_init_unpack() {
    let mut rar5: *mut rar5 = 0 as *mut rar5;
    rar5 = unsafe { calloc_safe(1 as i32 as u64, size_of::<rar5>() as u64) } as *mut rar5;
    unsafe { (*rar5).cstate.window_size = 0 };
    init_unpack(rar5);
}

#[no_mangle]
pub fn archive_test_do_unstore_file(
    mut _a: *mut archive,
    mut buf: *mut *const (),
    mut size: *mut size_t,
    mut offset: *mut int64_t,
    mut bytes_remaining: i32,
) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut rar5: *mut rar5 = 0 as *mut rar5;
    rar5 = unsafe { calloc_safe(1 as i32 as u64, size_of::<rar5>() as u64) } as *mut rar5;
    unsafe { (*rar5).file.bytes_remaining = bytes_remaining as ssize_t };
    return do_unstore_file(a, rar5, buf, size, offset);
}

#[no_mangle]
pub fn archive_test_merge_block(
    mut _a: *mut archive,
    mut block_size: ssize_t,
    mut p: *mut *const uint8_t,
    mut merge_mode: i32,
) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut rar5: *mut rar5 = 0 as *mut rar5;
    rar5 = unsafe { calloc_safe(1 as i32 as u64, size_of::<rar5>() as u64) } as *mut rar5;
    unsafe {
        (*rar5).merge_mode = merge_mode;
        (*(*a).format).data = rar5 as *mut ();
    }
    return merge_block(a, block_size, p);
}

#[no_mangle]
pub fn archive_test_parse_tables(mut _a: *mut archive, mut p: *const uint8_t) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut rar5: *mut rar5 = 0 as *mut rar5;
    rar5 = unsafe { calloc_safe(1 as i32 as u64, size_of::<rar5>() as u64) } as *mut rar5;
    unsafe { (*rar5).cstate.cur_block_size = 0 };
    return parse_tables(a, rar5, p);
}

#[no_mangle]
pub fn archive_test_parse_block_header(
    mut _a: *mut archive,
    mut p: *const uint8_t,
    mut block_size: *mut ssize_t,
) -> i32 {
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut hdr: *mut compressed_block_header = 0 as *mut compressed_block_header;
    hdr = unsafe { calloc_safe(1 as i32 as u64, size_of::<compressed_block_header>() as u64) }
        as *mut compressed_block_header;
    unsafe { (*hdr).block_flags_u8 = 56 };
    return parse_block_header(a, p, block_size, hdr);
}
