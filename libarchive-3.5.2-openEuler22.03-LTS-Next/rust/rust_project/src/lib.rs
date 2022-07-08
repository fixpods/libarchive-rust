#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut
)]

#[macro_use]
extern crate lazy_static;
extern crate libz_sys;
extern crate rust_ffi;
extern crate c2rust_bitfields;

mod archive_core;
