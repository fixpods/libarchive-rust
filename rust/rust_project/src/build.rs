fn main() {
    let mut rust_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    rust_path.pop();
    rust_path.pop();
    rust_path.push("libarchive");
    let archive_path: String = String::from(rust_path.to_string_lossy());
    println!("cargo:rustc-link-lib=static=archive_static");
    println!("cargo:rustc-link-search=native={}", archive_path);
    rust_ffi::ffi_defined_param::defined_param_set::defined_param_set();
}
