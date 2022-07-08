#![allow(
    dead_code,
    mutable_transmutes,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments,
    unused_mut,
    deref_nullptr
)]

#[macro_use]
extern crate lazy_static;
extern crate c2rust_bitfields;

pub mod ffi_alias;
pub mod ffi_defined_param;
pub mod ffi_method;
pub mod ffi_struct;
