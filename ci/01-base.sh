#!/bin/bash

cmake -DSTEP="build"
make

cd rust/

#开始检查
cargo fmt --all -- --check -v
cargo clean

#cargo clippy --all-targets --all-features --tests --benches -- -D warnings
# cargo clippy --all-targets --all-features --tests --benches -- -v
cargo clean

cargo check
cargo clean

cargo build --release -v
cd ../
cmake -DSTEP="link"
make
ctest -E "libarchive_test_write_filter_lzma|libarchive_test_write_filter_xz|libarchive_test_write_format_xar|bsdtar_test_option_H_upper|bsdtar_test_option_L_upper|bsdtar_test_option_n|bsdtar_test_option_U_upper"


#cargo rustc -- -D warnings
# bin=$(sed -n '/[[bin]]/ {n;p}' Cargo.toml | sed 's/\"//g' | sed 's/name = //g')
# for bin_name in $bin
# do
# echo $bin_name
# cargo rustc --bin $bin_name -- -D warnings -v
# done

# cargo build --release -v

#RUST_BACKTRACE=1 cargo test --all -v -- --nocapture --test-threads=1
# RUST_BACKTRACE=1 cargo test --all -- --nocapture

# cargo doc --all --no-deps
