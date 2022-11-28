use ffi_alias::alias_set::*;
use ffi_struct::struct_transfer::*;

extern "C" {

    fn get_u_composition_table() -> *mut unicode_composition_table;

    fn get_u_decomposable_blocks() -> *mut u8;

    fn get_ccc_val() -> *mut u8;

    fn get_ccc_val_index() -> *mut u8;

    fn get_ccc_index() -> *mut u8;

    fn get_u_decomposition_table() -> *mut unicode_decomposition_table;

    pub fn archive_clear_error(_: *mut archive);

    pub fn archive_string_ensure(_: *mut archive_string, _: size_t) -> *mut archive_string;

    pub fn archive_string_conversion_set_opt(_: *mut archive_string_conv, _: i32);

    pub fn archive_acl_from_text_l(
        _: *mut archive_acl,
        _: *const u8,
        _: i32,
        _: *mut archive_string_conv,
    ) -> i32;

    pub fn archive_entry_size(_: *mut archive_entry) -> la_int64_t;

    pub fn archive_entry_copy_gname(_: *mut archive_entry, _: *const u8);

    pub fn archive_entry_set_ino(_: *mut archive_entry, _: la_int64_t);

    pub fn archive_entry_copy_link(_: *mut archive_entry, _: *const u8);

    pub fn archive_entry_set_rdevmajor(_: *mut archive_entry, _: dev_t);

    pub fn archive_entry_set_rdevminor(_: *mut archive_entry, _: dev_t);

    pub fn archive_entry_copy_uname(_: *mut archive_entry, _: *const u8);

    pub fn archive_entry_copy_mac_metadata(_: *mut archive_entry, _: *const (), _: size_t);

    pub fn archive_entry_acl(_: *mut archive_entry) -> *mut archive_acl;

    pub fn archive_entry_sparse_add_entry(_: *mut archive_entry, _: la_int64_t, _: la_int64_t);

    pub fn _archive_entry_copy_link_l(
        _: *mut archive_entry,
        _: *const u8,
        _: size_t,
        _: *mut archive_string_conv,
    ) -> i32;
    pub fn xmlCleanupParser();

    pub fn xmlTextReaderSetErrorHandler(
        reader: xmlTextReaderPtr,
        f: xmlTextReaderErrorFunc,
        arg: *mut (),
    );

    pub fn xmlReaderForIO(
        ioread: xmlInputReadCallback,
        ioclose: xmlInputCloseCallback,
        ioctx: *mut (),
        URL: *const u8,
        encoding: *const u8,
        options: i32,
    ) -> xmlTextReaderPtr;

    pub fn xmlFreeTextReader(reader: xmlTextReaderPtr);

    pub fn xmlTextReaderRead(reader: xmlTextReaderPtr) -> i32;

    pub fn xmlTextReaderIsEmptyElement(reader: xmlTextReaderPtr) -> i32;

    pub fn xmlTextReaderNodeType(reader: xmlTextReaderPtr) -> i32;

    pub fn xmlTextReaderConstLocalName(reader: xmlTextReaderPtr) -> *const xmlChar;

    pub fn xmlTextReaderConstValue(reader: xmlTextReaderPtr) -> *const xmlChar;

    pub fn xmlTextReaderMoveToFirstAttribute(reader: xmlTextReaderPtr) -> i32;

    pub fn xmlTextReaderMoveToNextAttribute(reader: xmlTextReaderPtr) -> i32;

    pub fn inflateEnd(strm: z_streamp) -> i32;

    pub fn inflateInit_(strm: z_streamp, version: *const u8, stream_size: i32) -> i32;

    static __archive_digest: archive_digest;

    pub fn archive_entry_set_devmajor(_: *mut archive_entry, _: dev_t);

    pub fn archive_entry_set_devminor(_: *mut archive_entry, _: dev_t);
    /* Returns pointer to start of first invalid token, or NULL if none. */
    /* Note that all recognized tokens are processed, regardless. */

    fn archive_entry_set_ino64(_: *mut archive_entry, _: la_int64_t);

    pub fn strtol(_: *const u8, _: *mut *mut u8, _: i32) -> i64;

    pub fn __ctype_b_loc() -> *mut *const u16;

    pub fn malloc(size: u64) -> *mut ();

    pub fn memcpy(str1: *mut (), str2: *const (), n: u64) -> *mut ();

    pub fn memset(str: *mut (), c: i32, n: u64) -> *mut ();

    pub fn memcmp(str1: *const (), str2: *const (), n: u64) -> i32;

    pub fn calloc(nitems: u64, size: u64) -> *mut ();

    pub fn free(ptr: *mut ());

    pub fn strcmp(str1: *const u8, str2: *const u8) -> i32;

    pub fn strlen(str: *const u8) -> u64;

    pub fn sprintf(str: *mut u8, format: *const u8, more_params: ...) -> i32;

    pub fn mktime(timeptr: *mut tm) -> time_t;

    pub fn wcschr(str: *const wchar_t, c: wchar_t) -> *mut wchar_t;

    pub fn wcslen(str: *const wchar_t) -> u64;

    pub fn archive_set_error(a: *mut archive, error_number: i32, fmt: *const u8, more_params: ...);

    pub fn archive_entry_filetype(entry: *mut archive_entry) -> mode_t;

    pub fn archive_entry_pathname(entry: *mut archive_entry) -> *const u8;

    pub fn archive_entry_pathname_w(entry: *mut archive_entry) -> *const wchar_t;

    pub fn archive_entry_symlink(entry: *mut archive_entry) -> *const u8;

    pub fn archive_entry_symlink_w(entry: *mut archive_entry) -> *const wchar_t;

    pub fn archive_entry_set_atime(entry: *mut archive_entry, t: time_t, ns: i64);

    pub fn archive_entry_unset_atime(entry: *mut archive_entry);

    pub fn archive_entry_set_birthtime(entry: *mut archive_entry, t: time_t, ns: i64);

    pub fn archive_entry_unset_birthtime(entry: *mut archive_entry);

    pub fn archive_entry_set_ctime(entry: *mut archive_entry, t: time_t, ns: i64);

    pub fn archive_entry_unset_ctime(entry: *mut archive_entry);

    pub fn archive_entry_set_gid(entry: *mut archive_entry, g: la_int64_t);

    pub fn archive_entry_set_gname(entry: *mut archive_entry, g: *const u8);

    pub fn archive_entry_set_mode(entry: *mut archive_entry, m: mode_t);

    pub fn archive_entry_set_mtime(entry: *mut archive_entry, t: time_t, ns: i64);

    pub fn archive_entry_copy_pathname_w(entry: *mut archive_entry, name: *const wchar_t);

    pub fn archive_entry_set_size(entry: *mut archive_entry, s: la_int64_t);

    pub fn archive_entry_unset_size(entry: *mut archive_entry);

    pub fn archive_entry_set_symlink(entry: *mut archive_entry, linkname: *const u8);

    pub fn archive_entry_copy_symlink_w(entry: *mut archive_entry, linkname: *const wchar_t);

    pub fn archive_entry_set_uid(entry: *mut archive_entry, u: la_int64_t);

    pub fn archive_entry_set_uname(entry: *mut archive_entry, name: *const u8);

    pub fn archive_entry_set_filetype(entry: *mut archive_entry, _type: u32);

    pub fn archive_entry_set_pathname(entry: *mut archive_entry, name: *const u8);

    pub fn archive_entry_set_perm(entry: *mut archive_entry, p: mode_t);

    pub fn archive_entry_set_hardlink(entry: *mut archive_entry, target: *const u8);

    pub fn archive_entry_set_nlink(entry: *mut archive_entry, nlink: u32);

    pub fn archive_entry_set_rdev(entry: *mut archive_entry, m: dev_t);

    pub fn archive_entry_copy_symlink(entry: *mut archive_entry, linkname: *const u8);

    pub fn _archive_entry_copy_hardlink_l(
        entry: *mut archive_entry,
        target: *const u8,
        len: size_t,
        sc: *mut archive_string_conv,
    ) -> i32;

    pub fn _archive_entry_copy_pathname_l(
        entry: *mut archive_entry,
        name: *const u8,
        len: size_t,
        sc: *mut archive_string_conv,
    ) -> i32;

    pub fn archive_wstring_free(_as: *mut archive_wstring);

    pub fn archive_string_free(_as: *mut archive_string);

    pub fn archive_wstrncat(
        _as: *mut archive_wstring,
        p: *const wchar_t,
        n: size_t,
    ) -> *mut archive_wstring;

    pub fn archive_wstring_concat(dest: *mut archive_wstring, src: *mut archive_wstring);

    pub fn archive_string_conversion_charset_name(sc: *mut archive_string_conv) -> *const u8;

    pub fn archive_array_append(
        _as: *mut archive_string,
        p: *const u8,
        s: size_t,
    ) -> *mut archive_string;

    pub fn archive_strcat(_as: *mut archive_string, p: *const ()) -> *mut archive_string;

    pub fn archive_string_concat(dest: *mut archive_string, src: *mut archive_string);

    pub fn archive_string_sprintf(_as: *mut archive_string, fmt: *const u8, more_params: ...);

    pub fn archive_string_conversion_from_charset(
        a: *mut archive,
        charset: *const u8,
        best_effort: i32,
    ) -> *mut archive_string_conv;

    pub fn archive_strncat(
        _as: *mut archive_string,
        _p: *const (),
        n: size_t,
    ) -> *mut archive_string;

    pub fn archive_mstring_clean(aes: *mut archive_mstring);

    pub fn archive_mstring_get_wcs(
        a: *mut archive,
        aes: *mut archive_mstring,
        wp: *mut *const wchar_t,
    ) -> i32;

    pub fn archive_mstring_copy_mbs_len_l(
        aes: *mut archive_mstring,
        mbs: *const u8,
        len: size_t,
        sc: *mut archive_string_conv,
    ) -> i32;

    pub fn __archive_check_magic(
        a: *mut archive,
        magic: u32,
        state: u32,
        function: *const u8,
    ) -> i32;

    pub fn __archive_read_register_format(
        a: *mut archive_read,
        format_data: *mut (),
        name: *const u8,
        bid: Option<unsafe fn(a: *mut archive_read, best_bid: i32) -> i32>,
        options: Option<unsafe fn(a: *mut archive_read, key: *const u8, val: *const u8) -> i32>,
        read_header: Option<unsafe fn(a: *mut archive_read, entry: *mut archive_entry) -> i32>,
        read_data: Option<
            unsafe fn(
                a: *mut archive_read,
                buff: *mut *const (),
                size: *mut size_t,
                offset: *mut int64_t,
            ) -> i32,
        >,
        read_data_skip: Option<unsafe fn(a: *mut archive_read) -> i32>,
        seek_data: Option<unsafe fn(a: *mut archive_read, offset: int64_t, whence: i32) -> int64_t>,
        cleanup: Option<unsafe fn(a: *mut archive_read) -> i32>,
        format_capabilities: Option<unsafe fn(a: *mut archive_read) -> i32>,
        has_encrypted_entries: Option<unsafe fn(a: *mut archive_read) -> i32>,
    ) -> i32;

    pub fn __archive_read_ahead(
        a: *mut archive_read,
        min: size_t,
        avail: *mut ssize_t,
    ) -> *const ();

    pub fn __archive_read_header(a: *mut archive_read, entry: *mut archive_entry) -> i32;

    pub fn __archive_read_consume(a: *mut archive_read, request: int64_t) -> int64_t;

    pub fn __archive_read_seek(a: *mut archive_read, offset: int64_t, whence: i32) -> int64_t;

    pub fn __errno_location() -> *mut i32;

    pub fn localtime_r(__timer: *const time_t, __tp: *mut tm) -> *mut tm;

    pub fn crc32(crc: uLong, buf: *const Bytef, len: uInt) -> uLong;

    pub fn archive_entry_set_is_data_encrypted(_: *mut archive_entry, is_encrypted: u8);

    pub fn archive_entry_set_is_metadata_encrypted(_: *mut archive_entry, is_encrypted: u8);

    pub fn _archive_entry_copy_symlink_l(
        _: *mut archive_entry,
        _: *const u8,
        _: size_t,
        _: *mut archive_string_conv,
    ) -> i32;

    pub fn realloc(_: *mut (), _: u64) -> *mut ();

    pub static __archive_ppmd7_functions: IPpmd7;

    pub fn __archive_reset_read_data(_: *mut archive);

    pub fn strchr(_: *const u8, _: i32) -> *mut u8;

    pub fn printf(_: *const u8, _: ...) -> i32;

    pub fn archive_entry_clear(_: *mut archive_entry) -> *mut archive_entry;

    pub fn archive_entry_free(_: *mut archive_entry);

    pub fn archive_entry_new() -> *mut archive_entry;

    pub fn archive_entry_pathname_utf8(_: *mut archive_entry) -> *const u8;

    pub fn archive_entry_copy_fflags_text(_: *mut archive_entry, _: *const u8) -> *const u8;

    pub fn archive_entry_update_hardlink_utf8(_: *mut archive_entry, _: *const u8) -> i32;

    pub fn archive_entry_update_pathname_utf8(_: *mut archive_entry, _: *const u8) -> i32;

    pub fn archive_entry_set_symlink_type(_: *mut archive_entry, _: i32);

    pub fn archive_entry_update_symlink_utf8(_: *mut archive_entry, _: *const u8) -> i32;

    pub fn strcpy(_: *mut u8, _: *const u8) -> *mut u8;

    pub fn blake2sp_init(S: *mut blake2sp_state, outlen: size_t) -> i32;

    pub fn blake2sp_update(S: *mut blake2sp_state, in_0: *const uint8_t, inlen: size_t) -> i32;

    pub fn blake2sp_final(S: *mut blake2sp_state, out: *mut uint8_t, outlen: size_t) -> i32;

    pub fn wcscpy(__dest: *mut wchar_t, __src: *const wchar_t) -> *mut wchar_t;

    pub fn wmemcmp(_: *const wchar_t, _: *const wchar_t, _: u64) -> i32;

    pub fn inflateInit2_(
        strm: z_streamp,
        windowBits: i32,
        version: *const u8,
        stream_size: i32,
    ) -> i32;

    pub fn archive_mstring_copy_wcs_len(
        _: *mut archive_mstring,
        wcs: *const wchar_t,
        _: size_t,
    ) -> i32;

    pub fn archive_mstring_copy_mbs(_: *mut archive_mstring, mbs: *const u8) -> i32;

    pub fn archive_mstring_get_mbs_l(
        _: *mut archive,
        _: *mut archive_mstring,
        _: *mut *const u8,
        _: *mut size_t,
        _: *mut archive_string_conv,
    ) -> i32;

    pub fn archive_mstring_get_mbs(
        _: *mut archive,
        _: *mut archive_mstring,
        _: *mut *const u8,
    ) -> i32;

    pub fn archive_mstring_copy(dest: *mut archive_mstring, src: *mut archive_mstring);

    pub fn __archive_errx(retvalue: i32, msg: &str) -> !;

    pub fn iconv_open(__tocode: *const u8, __fromcode: *const u8) -> iconv_t;

    pub fn iconv(
        __cd: iconv_t,
        __inbuf: *mut *mut u8,
        __inbytesleft: *mut size_t,
        __outbuf: *mut *mut u8,
        __outbytesleft: *mut size_t,
    ) -> size_t;

    pub fn iconv_close(__cd: iconv_t) -> i32;

    pub fn nl_langinfo(__item: nl_item) -> *mut u8;

    pub fn __ctype_get_mb_cur_max() -> size_t;

    pub fn memchr(_: *const (), _: i32, _: u64) -> *mut ();

    pub fn memmove(_: *mut (), _: *const (), _: u64) -> *mut ();

    pub fn strdup(_: *const u8) -> *mut u8;

    pub fn wmemmove(__s1: *mut wchar_t, __s2: *const wchar_t, __n: size_t) -> *mut wchar_t;

    pub fn mbrtowc(__pwc: *mut wchar_t, __s: *const u8, __n: size_t, __p: *mut mbstate_t)
        -> size_t;

    pub fn wcrtomb(__s: *mut u8, __wc: wchar_t, __ps: *mut mbstate_t) -> size_t;

    pub fn _archive_entry_copy_uname_l(
        _: *mut archive_entry,
        _: *const u8,
        _: size_t,
        _: *mut archive_string_conv,
    ) -> i32;

    pub fn archive_entry_set_dev(_: *mut archive_entry, _: dev_t);

    pub fn archive_entry_xattr_add_entry(
        _: *mut archive_entry,
        _: *const u8,
        _: *const (),
        _: size_t,
    );

    pub fn _archive_entry_copy_gname_l(
        _: *mut archive_entry,
        _: *const u8,
        _: size_t,
        _: *mut archive_string_conv,
    ) -> i32;

    pub fn archive_entry_copy_pathname(_: *mut archive_entry, _: *const u8);

    pub fn strncpy(_: *mut u8, _: *const u8, _: u64) -> *mut u8;

    pub fn strncmp(_: *const u8, _: *const u8, _: u64) -> i32;

    pub fn archive_strappend_char(_: *mut archive_string, _: u8) -> *mut archive_string;

    pub fn inflateSetDictionary(strm: z_streamp, dictionary: *const Bytef, dictLength: uInt)
        -> i32;

    pub fn archive_wstring_ensure(_: *mut archive_wstring, _: size_t) -> *mut archive_wstring;

    pub fn fstat(__fd: i32, __buf: *mut stat) -> i32;

    pub fn lstat(__file: *const u8, __buf: *mut stat) -> i32;

    pub fn open(__file: *const u8, __oflag: i32, _: ...) -> i32;

    pub fn strcspn(_: *const u8, _: *const u8) -> u64;

    pub fn strnlen(__string: *const u8, __maxlen: size_t) -> size_t;

    pub fn close(__fd: i32) -> i32;

    pub fn read(__fd: i32, __buf: *mut (), __nbytes: size_t) -> ssize_t;

    pub fn archive_entry_linkresolver_new() -> *mut archive_entry_linkresolver;

    pub fn archive_entry_linkresolver_set_strategy(_: *mut archive_entry_linkresolver, _: i32);

    pub fn archive_entry_linkresolver_free(_: *mut archive_entry_linkresolver);

    pub fn archive_entry_linkify(
        _: *mut archive_entry_linkresolver,
        _: *mut *mut archive_entry,
        _: *mut *mut archive_entry,
    );

    pub fn archive_entry_set_digest(
        entry: *mut archive_entry,
        type_0: i32,
        digest: *const u8,
    ) -> i32;

    pub fn __archive_ensure_cloexec_flag(fd: i32);

    pub fn __archive_rb_tree_init(_: *mut archive_rb_tree, _: *const archive_rb_tree_ops);

    pub fn __archive_rb_tree_insert_node(_: *mut archive_rb_tree, _: *mut archive_rb_node) -> i32;

    pub fn __archive_rb_tree_find_node(
        _: *mut archive_rb_tree,
        _: *const (),
    ) -> *mut archive_rb_node;

    pub fn pack_find(_: *const u8) -> Option<pack_t>;

    pub fn strspn(_: *const u8, _: *const u8) -> u64;

    pub fn archive_entry_dev(_: *mut archive_entry) -> dev_t;

    pub fn archive_entry_ino64(_: *mut archive_entry) -> la_int64_t;

    pub fn archive_entry_mode(_: *mut archive_entry) -> mode_t;

    pub fn archive_entry_nlink(_: *mut archive_entry) -> u32;

    pub fn archive_entry_copy_hardlink(_: *mut archive_entry, _: *const u8);

    pub fn BZ2_bzDecompressInit(strm: *mut bz_stream, verbosity: i32, small: i32) -> i32;

    pub fn BZ2_bzDecompress(strm: *mut bz_stream) -> i32;

    pub fn BZ2_bzDecompressEnd(strm: *mut bz_stream) -> i32;

    pub fn lzma_stream_decoder(
        strm: *mut lzma_stream,
        memlimit: uint64_t,
        flags: uint32_t,
    ) -> lzma_ret;

    pub fn lzma_alone_decoder(strm: *mut lzma_stream, memlimit: uint64_t) -> lzma_ret;

    pub fn lzma_code(strm: *mut lzma_stream, action: lzma_action) -> lzma_ret;

    pub fn lzma_end(strm: *mut lzma_stream);

    pub fn archive_filter_bytes(_: *mut archive, _: i32) -> la_int64_t;

    pub fn strrchr(_: *const u8, _: i32) -> *mut u8;

    pub fn archive_wstrcat(_: *mut archive_wstring, _: *const wchar_t) -> *mut archive_wstring;

    pub fn archive_wstrappend_wchar(_: *mut archive_wstring, _: wchar_t) -> *mut archive_wstring;

    pub fn __archive_rb_tree_remove_node(_: *mut archive_rb_tree, _: *mut archive_rb_node);

    pub fn __archive_rb_tree_iterate(
        _: *mut archive_rb_tree,
        _: *mut archive_rb_node,
        _: u32,
    ) -> *mut archive_rb_node;

    pub fn __archive_read_reset_passphrase(a: *mut archive_read);

    pub fn __archive_read_next_passphrase(a: *mut archive_read) -> *const u8;

    pub fn lzma_properties_decode(
        filter: *mut lzma_filter,
        allocator: *const lzma_allocator,
        props: *const uint8_t,
        props_size: size_t,
    ) -> lzma_ret;

    pub fn lzma_raw_decoder(strm: *mut lzma_stream, filters: *const lzma_filter) -> lzma_ret;

    pub fn inflateReset(strm: z_streamp) -> i32;

    pub fn inflate(strm: z_streamp, flush: i32) -> i32;

    pub fn isprint(c: i32) -> i32;

    pub static __archive_hmac: archive_hmac;

    pub static __archive_ppmd8_functions: IPpmd8;

    pub static __archive_cryptor: archive_cryptor;
}

pub unsafe fn malloc_safe(size: u64) -> *mut () {
    return unsafe { malloc(size) };
}

pub unsafe fn memcpy_safe(str1: *mut (), str2: *const (), n: u64) -> *mut () {
    return unsafe { memcpy(str1, str2, n) };
}

pub unsafe fn memset_safe(str: *mut (), c: i32, n: u64) -> *mut () {
    return unsafe { memset(str, c, n) };
}

pub unsafe fn memcmp_safe(str1: *const (), str2: *const (), n: u64) -> i32 {
    return unsafe { memcmp(str1, str2, n) };
}

pub unsafe fn calloc_safe(nitems: u64, size: u64) -> *mut () {
    return unsafe { calloc(nitems, size) };
}

pub unsafe fn free_safe(ptr: *mut ()) {
    unsafe { free(ptr) };
}

pub unsafe fn strcmp_safe(str1: *const u8, str2: *const u8) -> i32 {
    return unsafe { strcmp(str1, str2) };
}

pub unsafe fn strlen_safe(str: *const u8) -> u64 {
    return unsafe { strlen(str) };
}

#[macro_export]
macro_rules! sprintf_safe {
    () => {};
    ($str:expr, $format:expr$(, $more_params:expr)*) => {{
        unsafe { sprintf($str, $format$(, $more_params)*) }
    }};
}

pub unsafe fn mktime_safe(timeptr: *mut tm) -> time_t {
    return unsafe { mktime(timeptr) };
}

pub unsafe fn wcschr_safe(str: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    return unsafe { wcschr(str, c) };
}

pub unsafe fn wcslen_safe(str: *const wchar_t) -> u64 {
    return unsafe { wcslen(str) };
}

#[macro_export]
macro_rules! archive_set_error_safe {
    () => {};
    ($a:expr, $error_number:expr, $fmt:expr$(, $more_params:expr)*) => {{
        unsafe { archive_set_error($a, $error_number, $fmt$(, $more_params)*) }
    }};
}

pub unsafe fn archive_entry_filetype_safe(entry: *mut archive_entry) -> mode_t {
    return unsafe { archive_entry_filetype(entry) };
}

pub unsafe fn archive_entry_pathname_safe(entry: *mut archive_entry) -> *const u8 {
    return unsafe { archive_entry_pathname(entry) };
}

pub unsafe fn archive_entry_pathname_w_safe(entry: *mut archive_entry) -> *const wchar_t {
    return unsafe { archive_entry_pathname_w(entry) };
}

pub unsafe fn archive_entry_symlink_safe(entry: *mut archive_entry) -> *const u8 {
    return unsafe { archive_entry_symlink(entry) };
}

pub unsafe fn archive_entry_symlink_w_safe(entry: *mut archive_entry) -> *const wchar_t {
    return unsafe { archive_entry_symlink_w(entry) };
}

pub unsafe fn archive_entry_set_atime_safe(entry: *mut archive_entry, t: time_t, ns: i64) {
    archive_entry_set_atime(entry, t, ns);
}

pub unsafe fn archive_entry_unset_atime_safe(entry: *mut archive_entry) {
    archive_entry_unset_atime(entry);
}

pub unsafe fn archive_entry_set_birthtime_safe(entry: *mut archive_entry, t: time_t, ns: i64) {
    archive_entry_set_birthtime(entry, t, ns);
}

pub unsafe fn archive_entry_unset_birthtime_safe(entry: *mut archive_entry) {
    archive_entry_unset_birthtime(entry);
}

pub unsafe fn archive_entry_set_ctime_safe(entry: *mut archive_entry, t: time_t, ns: i64) {
    archive_entry_set_ctime(entry, t, ns);
}

pub unsafe fn archive_entry_unset_ctime_safe(entry: *mut archive_entry) {
    archive_entry_unset_ctime(entry);
}

pub unsafe fn archive_entry_set_gid_safe(entry: *mut archive_entry, g: la_int64_t) {
    archive_entry_set_gid(entry, g);
}

pub unsafe fn archive_entry_set_gname_safe(entry: *mut archive_entry, g: *const u8) {
    archive_entry_set_gname(entry, g);
}

pub unsafe fn archive_entry_set_mode_safe(entry: *mut archive_entry, m: mode_t) {
    archive_entry_set_mode(entry, m);
}

pub unsafe fn archive_entry_set_mtime_safe(entry: *mut archive_entry, t: time_t, ns: i64) {
    archive_entry_set_mtime(entry, t, ns);
}

pub unsafe fn archive_entry_copy_pathname_w_safe(entry: *mut archive_entry, name: *const wchar_t) {
    archive_entry_copy_pathname_w(entry, name);
}

pub unsafe fn archive_entry_set_size_safe(entry: *mut archive_entry, s: la_int64_t) {
    archive_entry_set_size(entry, s);
}

pub unsafe fn archive_entry_unset_size_safe(entry: *mut archive_entry) {
    archive_entry_unset_size(entry);
}

pub unsafe fn archive_entry_set_symlink_safe(entry: *mut archive_entry, linkname: *const u8) {
    archive_entry_set_symlink(entry, linkname);
}

pub unsafe fn archive_entry_copy_symlink_w_safe(
    entry: *mut archive_entry,
    linkname: *const wchar_t,
) {
    archive_entry_copy_symlink_w(entry, linkname);
}

pub unsafe fn archive_entry_set_uid_safe(entry: *mut archive_entry, u: la_int64_t) {
    archive_entry_set_uid(entry, u);
}

pub unsafe fn archive_entry_set_uname_safe(entry: *mut archive_entry, name: *const u8) {
    archive_entry_set_uname(entry, name);
}

pub unsafe fn archive_entry_set_filetype_safe(entry: *mut archive_entry, _type: u32) {
    archive_entry_set_filetype(entry, _type);
}

pub unsafe fn archive_entry_set_pathname_safe(entry: *mut archive_entry, name: *const u8) {
    archive_entry_set_pathname(entry, name);
}

pub unsafe fn archive_entry_set_perm_safe(entry: *mut archive_entry, p: mode_t) {
    archive_entry_set_perm(entry, p);
}

pub unsafe fn archive_entry_set_hardlink_safe(entry: *mut archive_entry, target: *const u8) {
    archive_entry_set_hardlink(entry, target);
}

pub unsafe fn archive_entry_set_nlink_safe(entry: *mut archive_entry, nlink: u32) {
    archive_entry_set_nlink(entry, nlink);
}

pub unsafe fn archive_entry_set_rdev_safe(entry: *mut archive_entry, m: dev_t) {
    archive_entry_set_rdev(entry, m);
}

pub unsafe fn archive_entry_copy_symlink_safe(entry: *mut archive_entry, linkname: *const u8) {
    unsafe { archive_entry_copy_symlink(entry, linkname) }
}

pub unsafe fn _archive_entry_copy_hardlink_l_safe(
    entry: *mut archive_entry,
    target: *const u8,
    len: size_t,
    sc: *mut archive_string_conv,
) -> i32 {
    return unsafe { _archive_entry_copy_hardlink_l(entry, target, len, sc) };
}

pub unsafe fn archive_wstring_free_safe(_as: *mut archive_wstring) {
    unsafe { archive_wstring_free(_as) };
}

pub unsafe fn archive_string_free_safe(_as: *mut archive_string) {
    unsafe { archive_string_free(_as) };
}

pub unsafe fn archive_wstrncat_safe(
    _as: *mut archive_wstring,
    p: *const wchar_t,
    n: size_t,
) -> *mut archive_wstring {
    return unsafe { archive_wstrncat(_as, p, n) };
}

pub unsafe fn archive_wstring_concat_safe(dest: *mut archive_wstring, src: *mut archive_wstring) {
    unsafe { archive_wstring_concat(dest, src) };
}

pub unsafe fn archive_string_conversion_charset_name_safe(
    sc: *mut archive_string_conv,
) -> *const u8 {
    return unsafe { archive_string_conversion_charset_name(sc) };
}

pub unsafe fn archive_array_append_safe(
    _as: *mut archive_string,
    p: *const u8,
    s: size_t,
) -> *mut archive_string {
    return unsafe { archive_array_append(_as, p, s) };
}

pub unsafe fn archive_strcat_safe(_as: *mut archive_string, p: *const ()) -> *mut archive_string {
    return unsafe { archive_strcat(_as, p) };
}

pub unsafe fn archive_string_concat_safe(dest: *mut archive_string, src: *mut archive_string) {
    unsafe { archive_string_concat(dest, src) };
}

#[macro_export]
macro_rules! archive_string_sprintf_safe {
    () => {};
    ($_as:expr, $fmt:expr$(, $more_params:expr)*) => {{
        unsafe { archive_string_sprintf($_as, $fmt$(, $more_params)*) }
    }};
}

pub unsafe fn archive_string_conversion_from_charset_safe(
    a: *mut archive,
    charset: *const u8,
    best_effort: i32,
) -> *mut archive_string_conv {
    return unsafe { archive_string_conversion_from_charset(a, charset, best_effort) };
}

pub unsafe fn archive_strncat_safe(
    _as: *mut archive_string,
    _p: *const (),
    n: size_t,
) -> *mut archive_string {
    return unsafe { archive_strncat(_as, _p, n) };
}

pub unsafe fn archive_mstring_clean_safe(aes: *mut archive_mstring) {
    archive_mstring_clean(aes);
}

pub unsafe fn archive_mstring_get_wcs_safe(
    a: *mut archive,
    aes: *mut archive_mstring,
    wp: *mut *const wchar_t,
) -> i32 {
    return unsafe { archive_mstring_get_wcs(a, aes, wp) };
}

pub unsafe fn archive_mstring_copy_mbs_len_l_safe(
    aes: *mut archive_mstring,
    mbs: *const u8,
    len: size_t,
    sc: *mut archive_string_conv,
) -> i32 {
    return unsafe { archive_mstring_copy_mbs_len_l(aes, mbs, len, sc) };
}

pub unsafe fn __archive_check_magic_safe(
    a: *mut archive,
    magic: u32,
    state: u32,
    function: *const u8,
) -> i32 {
    return unsafe { __archive_check_magic(a, magic, state, function) };
}

pub unsafe fn __archive_read_register_format_safe(
    a: *mut archive_read,
    format_data: *mut (),
    name: *const u8,
    bid: Option<unsafe fn(a: *mut archive_read, best_bid: i32) -> i32>,
    options: Option<unsafe fn(a: *mut archive_read, key: *const u8, val: *const u8) -> i32>,
    read_header: Option<unsafe fn(a: *mut archive_read, entry: *mut archive_entry) -> i32>,
    read_data: Option<
        unsafe fn(
            a: *mut archive_read,
            buff: *mut *const (),
            size: *mut size_t,
            offset: *mut int64_t,
        ) -> i32,
    >,
    read_data_skip: Option<unsafe fn(a: *mut archive_read) -> i32>,
    seek_data: Option<unsafe fn(a: *mut archive_read, offset: int64_t, whence: i32) -> int64_t>,
    cleanup: Option<unsafe fn(a: *mut archive_read) -> i32>,
    format_capabilities: Option<unsafe fn(a: *mut archive_read) -> i32>,
    has_encrypted_entries: Option<unsafe fn(a: *mut archive_read) -> i32>,
) -> i32 {
    return unsafe {
        __archive_read_register_format(
            a,
            format_data,
            name,
            bid,
            options,
            read_header,
            read_data,
            read_data_skip,
            seek_data,
            cleanup,
            format_capabilities,
            has_encrypted_entries,
        )
    };
}

pub unsafe fn __archive_read_ahead_safe(
    a: *mut archive_read,
    min: size_t,
    avail: *mut ssize_t,
) -> *const () {
    return unsafe { __archive_read_ahead(a, min, avail) };
}

pub unsafe fn __archive_read_header_safe(a: *mut archive_read, entry: *mut archive_entry) -> i32 {
    return unsafe { __archive_read_header(a, entry) };
}

pub unsafe fn __archive_read_consume_safe(a: *mut archive_read, request: int64_t) -> int64_t {
    return unsafe { __archive_read_consume(a, request) };
}

pub unsafe fn __archive_read_seek_safe(
    a: *mut archive_read,
    offset: int64_t,
    whence: i32,
) -> int64_t {
    return unsafe { __archive_read_seek(a, offset, whence) };
}

pub unsafe fn __errno_location_safe() -> *mut i32 {
    return unsafe { __errno_location() };
}

pub unsafe fn _archive_entry_copy_pathname_l_safe(
    param1: *mut archive_entry,
    param2: *const u8,
    param3: size_t,
    param4: *mut archive_string_conv,
) -> i32 {
    return unsafe { _archive_entry_copy_pathname_l(param1, param2, param3, param4) };
}

pub unsafe fn crc32_safe(crc: uLong, buf: *const Bytef, len: uInt) -> uLong {
    return unsafe { crc32(crc, buf, len) };
}

pub unsafe fn inflateInit2__safe(
    strm: z_streamp,
    windowBits: i32,
    version: *const u8,
    stream_size: i32,
) -> i32 {
    return unsafe { inflateInit2_(strm, windowBits, version, stream_size) };
}

pub unsafe fn BZ2_bzDecompressInit_safe(strm: *mut bz_stream, verbosity: i32, small: i32) -> i32 {
    return unsafe { BZ2_bzDecompressInit(strm, verbosity, small) };
}

pub unsafe fn BZ2_bzDecompress_safe(strm: *mut bz_stream) -> i32 {
    return unsafe { BZ2_bzDecompress(strm) };
}

pub unsafe fn BZ2_bzDecompressEnd_safe(strm: *mut bz_stream) -> i32 {
    return unsafe { BZ2_bzDecompressEnd(strm) };
}

pub unsafe fn lzma_stream_decoder_safe(
    strm: *mut lzma_stream,
    memlimit: uint64_t,
    flags: uint32_t,
) -> lzma_ret {
    return unsafe { lzma_stream_decoder(strm, memlimit, flags) };
}

pub unsafe fn lzma_alone_decoder_safe(strm: *mut lzma_stream, memlimit: uint64_t) -> lzma_ret {
    return unsafe { lzma_alone_decoder(strm, memlimit) };
}

pub unsafe fn lzma_code_safe(strm: *mut lzma_stream, action: lzma_action) -> lzma_ret {
    return unsafe { lzma_code(strm, action) };
}

pub unsafe fn lzma_end_safe(strm: *mut lzma_stream) {
    lzma_end(strm);
}

pub unsafe fn archive_filter_bytes_safe(param1: *mut archive, param2: i32) -> la_int64_t {
    return unsafe { archive_filter_bytes(param1, param2) };
}

pub unsafe fn archive_entry_copy_mac_metadata_safe(
    param1: *mut archive_entry,
    param2: *const (),
    param3: size_t,
) {
    archive_entry_copy_mac_metadata(param1, param2, param3);
}

pub unsafe fn _archive_entry_copy_symlink_l_safe(
    param1: *mut archive_entry,
    param2: *const u8,
    param3: size_t,
    param4: *mut archive_string_conv,
) -> i32 {
    return unsafe { _archive_entry_copy_symlink_l(param1, param2, param3, param4) };
}

pub unsafe fn memchr_safe(param1: *const (), param2: i32, param3: u64) -> *mut () {
    return unsafe { memchr(param1, param2, param3) };
}

pub unsafe fn strncmp_safe(param1: *const u8, param2: *const u8, param3: u64) -> i32 {
    return unsafe { strncmp(param1, param2, param3) };
}

pub unsafe fn strrchr_safe(param1: *const u8, param2: i32) -> *mut u8 {
    return unsafe { strrchr(param1, param2) };
}

pub unsafe fn archive_wstrcat_safe(
    param1: *mut archive_wstring,
    param2: *const wchar_t,
) -> *mut archive_wstring {
    return unsafe { archive_wstrcat(param1, param2) };
}

pub unsafe fn archive_strappend_char_safe(
    param1: *mut archive_string,
    param2: u8,
) -> *mut archive_string {
    return unsafe { archive_strappend_char(param1, param2) };
}

pub unsafe fn archive_wstrappend_wchar_safe(
    param1: *mut archive_wstring,
    param2: wchar_t,
) -> *mut archive_wstring {
    return unsafe { archive_wstrappend_wchar(param1, param2) };
}

pub unsafe fn __archive_rb_tree_init_safe(
    param1: *mut archive_rb_tree,
    param2: *const archive_rb_tree_ops,
) {
    __archive_rb_tree_init(param1, param2);
}

pub unsafe fn __archive_rb_tree_insert_node_safe(
    param1: *mut archive_rb_tree,
    param2: *mut archive_rb_node,
) -> i32 {
    return unsafe { __archive_rb_tree_insert_node(param1, param2) };
}

pub unsafe fn __archive_rb_tree_find_node_safe(
    param1: *mut archive_rb_tree,
    param2: *const (),
) -> *mut archive_rb_node {
    return unsafe { __archive_rb_tree_find_node(param1, param2) };
}

pub unsafe fn __archive_rb_tree_remove_node_safe(
    param1: *mut archive_rb_tree,
    param2: *mut archive_rb_node,
) {
    __archive_rb_tree_remove_node(param1, param2);
}

pub unsafe fn __archive_rb_tree_iterate_safe(
    param1: *mut archive_rb_tree,
    param2: *mut archive_rb_node,
    param3: u32,
) -> *mut archive_rb_node {
    return unsafe { __archive_rb_tree_iterate(param1, param2, param3) };
}

pub unsafe fn __archive_read_reset_passphrase_safe(a: *mut archive_read) {
    __archive_read_reset_passphrase(a);
}

pub unsafe fn __archive_read_next_passphrase_safe(a: *mut archive_read) -> *const u8 {
    return unsafe { __archive_read_next_passphrase(a) };
}

pub unsafe fn archive_entry_set_is_metadata_encrypted_safe(
    _a: *mut archive_entry,
    is_encrypted: u8,
) {
    return unsafe { archive_entry_set_is_metadata_encrypted(_a, is_encrypted) };
}

pub unsafe fn archive_entry_set_is_data_encrypted_safe(_a: *mut archive_entry, is_encrypted: u8) {
    return unsafe { archive_entry_set_is_data_encrypted(_a, is_encrypted) };
}

pub unsafe fn __archive_reset_read_data_safe(_a: *mut archive) {
    return unsafe { __archive_reset_read_data(_a) };
}

pub unsafe fn realloc_safe(_a: *mut (), _b: u64) -> *mut () {
    return unsafe { realloc(_a, _b) };
}

pub unsafe fn strchr_safe(_a: *const u8, _b: i32) -> *mut u8 {
    return unsafe { strchr(_a, _b) };
}

pub unsafe fn localtime_r_safe(__timer: *const time_t, __tp: *mut tm) -> *mut tm {
    return unsafe { localtime_r(__timer, __tp) };
}

pub unsafe fn blake2sp_init_safe(S: *mut blake2sp_state, outlen: size_t) -> i32 {
    return unsafe { blake2sp_init(S, outlen) };
}

pub unsafe fn archive_entry_pathname_utf8_safe(_a: *mut archive_entry) -> *const u8 {
    return unsafe { archive_entry_pathname_utf8(_a) };
}

pub unsafe fn archive_entry_update_pathname_utf8_safe(
    _a: *mut archive_entry,
    _b: *const u8,
) -> i32 {
    return unsafe { archive_entry_update_pathname_utf8(_a, _b) };
}

pub unsafe fn archive_entry_update_symlink_utf8_safe(_a: *mut archive_entry, _b: *const u8) -> i32 {
    return unsafe { archive_entry_update_symlink_utf8(_a, _b) };
}

pub unsafe fn archive_entry_set_symlink_type_safe(_a: *mut archive_entry, _b: i32) {
    return unsafe { archive_entry_set_symlink_type(_a, _b) };
}

pub unsafe fn archive_entry_update_hardlink_utf8_safe(
    _a: *mut archive_entry,
    _b: *const u8,
) -> i32 {
    return unsafe { archive_entry_update_hardlink_utf8(_a, _b) };
}

pub unsafe fn archive_entry_clear_safe(_a: *mut archive_entry) -> *mut archive_entry {
    return unsafe { archive_entry_clear(_a) };
}

pub unsafe fn archive_entry_copy_fflags_text_safe(
    _a: *mut archive_entry,
    _b: *const u8,
) -> *const u8 {
    return unsafe { archive_entry_copy_fflags_text(_a, _b) };
}

pub unsafe fn archive_entry_new_safe() -> *mut archive_entry {
    return unsafe { archive_entry_new() };
}

pub unsafe fn archive_entry_free_safe(_a: *mut archive_entry) {
    return unsafe { archive_entry_free(_a) };
}

pub unsafe fn blake2sp_update_safe(
    S: *mut blake2sp_state,
    in_0: *const uint8_t,
    inlen: size_t,
) -> i32 {
    return unsafe { blake2sp_update(S, in_0, inlen) };
}

pub unsafe fn blake2sp_final_safe(
    S: *mut blake2sp_state,
    out: *mut uint8_t,
    outlen: size_t,
) -> i32 {
    return unsafe { blake2sp_final(S, out, outlen) };
}
pub unsafe fn wcscpy_safe(__dest: *mut wchar_t, __src: *const wchar_t) -> *mut wchar_t {
    return unsafe { wcscpy(__dest, __src) };
}

pub unsafe fn wmemcmp_safe(_const1: *const wchar_t, _const2: *const wchar_t, _const3: u64) -> i32 {
    return unsafe { wmemcmp(_const1, _const2, _const3) };
}

pub unsafe fn strcpy_safe(_var1: *mut u8, _var2: *const u8) -> *mut u8 {
    return unsafe { strcpy(_var1, _var2) };
}

pub unsafe fn archive_mstring_copy_wcs_len_safe(
    _var1: *mut archive_mstring,
    wcs: *const wchar_t,
    _var2: size_t,
) -> i32 {
    return unsafe { archive_mstring_copy_wcs_len(_var1, wcs, _var2) };
}

pub unsafe fn archive_mstring_copy_mbs_safe(_var1: *mut archive_mstring, mbs: *const u8) -> i32 {
    return unsafe { archive_mstring_copy_mbs(_var1, mbs) };
}

pub unsafe fn archive_mstring_get_mbs_l_safe(
    _var1: *mut archive,
    _var2: *mut archive_mstring,
    _var3: *mut *const u8,
    _var4: *mut size_t,
    _var5: *mut archive_string_conv,
) -> i32 {
    return unsafe { archive_mstring_get_mbs_l(_var1, _var2, _var3, _var4, _var5) };
}

pub unsafe fn archive_mstring_get_mbs_safe(
    _var1: *mut archive,
    _var2: *mut archive_mstring,
    _var3: *mut *const u8,
) -> i32 {
    return unsafe { archive_mstring_get_mbs(_var1, _var2, _var3) };
}

pub unsafe fn archive_mstring_copy_safe(dest: *mut archive_mstring, src: *mut archive_mstring) {
    return unsafe { archive_mstring_copy(dest, src) };
}

pub unsafe fn __archive_errx_safe(retvalue: i32, msg: &str) -> ! {
    return unsafe { __archive_errx(retvalue, msg) };
}

pub unsafe fn iconv_open_safe(__tocode: *const u8, __fromcode: *const u8) -> iconv_t {
    return unsafe { iconv_open(__tocode, __fromcode) };
}

pub unsafe fn iconv_safe(
    __cd: iconv_t,
    __inbuf: *mut *mut u8,
    __inbytesleft: *mut size_t,
    __outbuf: *mut *mut u8,
    __outbytesleft: *mut size_t,
) -> size_t {
    return unsafe { iconv(__cd, __inbuf, __inbytesleft, __outbuf, __outbytesleft) };
}

pub unsafe fn iconv_close_safe(__cd: iconv_t) -> i32 {
    return unsafe { iconv_close(__cd) };
}

pub unsafe fn nl_langinfo_safe(__item: nl_item) -> *mut u8 {
    return unsafe { nl_langinfo(__item) };
}

pub unsafe fn __ctype_get_mb_cur_max_safe() -> size_t {
    return unsafe { __ctype_get_mb_cur_max() };
}

pub unsafe fn memmove_safe(_var1: *mut (), _var2: *const (), _var3: u64) -> *mut () {
    return unsafe { memmove(_var1, _var2, _var3) };
}

pub unsafe fn strncpy_safe(_a: *mut u8, _b: *const u8, _c: u64) -> *mut u8 {
    return unsafe { strncpy(_a, _b, _c) };
}

pub unsafe fn archive_entry_copy_pathname_safe(_a: *mut archive_entry, _pn: *const u8) {
    return unsafe { archive_entry_copy_pathname(_a, _pn) };
}

pub unsafe fn _archive_entry_copy_uname_l_safe(
    _a: *mut archive_entry,
    _b: *const u8,
    _c: size_t,
    _d: *mut archive_string_conv,
) -> i32 {
    return unsafe { _archive_entry_copy_uname_l(_a, _b, _c, _d) };
}

pub unsafe fn _archive_entry_copy_gname_l_safe(
    _a: *mut archive_entry,
    _b: *const u8,
    _c: size_t,
    _d: *mut archive_string_conv,
) -> i32 {
    return unsafe { _archive_entry_copy_gname_l(_a, _b, _c, _d) };
}
pub unsafe fn archive_entry_xattr_add_entry_safe(
    _a: *mut archive_entry,
    _b: *const u8,
    _c: *const (),
    _d: size_t,
) {
    return unsafe { archive_entry_xattr_add_entry(_a, _b, _c, _d) };
}

pub unsafe fn archive_entry_set_dev_safe(_a: *mut archive_entry, _b: dev_t) {
    return unsafe { archive_entry_set_dev(_a, _b) };
}

pub unsafe fn strtol_safe(_a: *const u8, _b: *mut *mut u8, _c: i32) -> i64 {
    return unsafe { strtol(_a, _b, _c) };
}

pub unsafe fn __ctype_b_loc_safe() -> *mut *const u16 {
    return unsafe { __ctype_b_loc() };
}

pub unsafe fn archive_string_sprintf_safe(_a: *mut archive_string, _b: *const u8) {
    return unsafe { archive_string_sprintf(_a, _b) };
}

pub unsafe fn xmlCleanupParser_safe() {
    return unsafe { xmlCleanupParser() };
}

pub unsafe fn xmlTextReaderSetErrorHandler_safe(
    reader: xmlTextReaderPtr,
    f: xmlTextReaderErrorFunc,
    arg: *mut (),
) {
    return unsafe { xmlTextReaderSetErrorHandler(reader, f, arg) };
}

pub unsafe fn xmlReaderForIO_safe(
    ioread: xmlInputReadCallback,
    ioclose: xmlInputCloseCallback,
    ioctx: *mut (),
    URL: *const u8,
    encoding: *const u8,
    options: i32,
) -> xmlTextReaderPtr {
    return unsafe { xmlReaderForIO(ioread, ioclose, ioctx, URL, encoding, options) };
}

pub unsafe fn xmlFreeTextReader_safe(reader: xmlTextReaderPtr) {
    return unsafe { xmlFreeTextReader(reader) };
}

pub unsafe fn xmlTextReaderRead_safe(reader: xmlTextReaderPtr) -> i32 {
    return unsafe { xmlTextReaderRead(reader) };
}

pub unsafe fn xmlTextReaderIsEmptyElement_safe(reader: xmlTextReaderPtr) -> i32 {
    return unsafe { xmlTextReaderIsEmptyElement(reader) };
}

pub unsafe fn xmlTextReaderNodeType_safe(reader: xmlTextReaderPtr) -> i32 {
    return unsafe { xmlTextReaderNodeType(reader) };
}

pub unsafe fn xmlTextReaderConstLocalName_safe(reader: xmlTextReaderPtr) -> *const xmlChar {
    return unsafe { xmlTextReaderConstLocalName(reader) };
}

pub unsafe fn xmlTextReaderConstValue_safe(reader: xmlTextReaderPtr) -> *const xmlChar {
    return unsafe { xmlTextReaderConstValue(reader) };
}

pub unsafe fn xmlTextReaderMoveToFirstAttribute_safe(reader: xmlTextReaderPtr) -> i32 {
    return unsafe { xmlTextReaderMoveToFirstAttribute(reader) };
}

pub unsafe fn xmlTextReaderMoveToNextAttribute_safe(reader: xmlTextReaderPtr) -> i32 {
    return unsafe { xmlTextReaderMoveToNextAttribute(reader) };
}

pub unsafe fn inflateInit__safe(strm: z_streamp, version: *const u8, stream_size: i32) -> i32 {
    return unsafe { inflateInit_(strm, version, stream_size) };
}

pub unsafe fn archive_entry_set_devmajor_safe(_a: *mut archive_entry, _b: dev_t) {
    return unsafe { archive_entry_set_devmajor(_a, _b) };
}

pub unsafe fn archive_entry_set_devminor_safe(_a: *mut archive_entry, _b: dev_t) {
    return unsafe { archive_entry_set_devminor(_a, _b) };
}

pub unsafe fn archive_entry_set_ino64_safe(_a: *mut archive_entry, _b: la_int64_t) {
    return unsafe { archive_entry_set_ino64(_a, _b) };
}

pub unsafe fn archive_clear_error_safe(_a: *mut archive) {
    return unsafe { archive_clear_error(_a) };
}

pub unsafe fn archive_string_ensure_safe(
    _a: *mut archive_string,
    _s: size_t,
) -> *mut archive_string {
    return unsafe { archive_string_ensure(_a, _s) };
}

pub unsafe fn archive_string_conversion_set_opt_safe(_a: *mut archive_string_conv, _opt: i32) {
    return unsafe { archive_string_conversion_set_opt(_a, _opt) };
}

pub unsafe fn archive_acl_from_text_l_safe(
    _a: *mut archive_acl,
    _b: *const u8,
    _c: i32,
    _d: *mut archive_string_conv,
) -> i32 {
    return unsafe { archive_acl_from_text_l(_a, _b, _c, _d) };
}

pub unsafe fn archive_entry_size_safe(_a: *mut archive_entry) -> la_int64_t {
    return unsafe { archive_entry_size(_a) };
}

pub unsafe fn archive_entry_copy_gname_safe(_a: *mut archive_entry, _b: *const u8) {
    return unsafe { archive_entry_copy_gname(_a, _b) };
}

pub unsafe fn archive_entry_set_ino_safe(_a: *mut archive_entry, _b: la_int64_t) {
    return unsafe { archive_entry_set_ino(_a, _b) };
}

pub unsafe fn archive_entry_copy_link_safe(_a: *mut archive_entry, _b: *const u8) {
    return unsafe { archive_entry_copy_link(_a, _b) };
}

pub unsafe fn archive_entry_set_rdevmajor_safe(_a: *mut archive_entry, _b: dev_t) {
    return unsafe { archive_entry_set_rdevmajor(_a, _b) };
}

pub unsafe fn archive_entry_set_rdevminor_safe(_a: *mut archive_entry, _b: dev_t) {
    return unsafe { archive_entry_set_rdevminor(_a, _b) };
}

pub unsafe fn archive_entry_copy_uname_safe(_a: *mut archive_entry, _b: *const u8) {
    return unsafe { archive_entry_copy_uname(_a, _b) };
}

pub unsafe fn archive_entry_acl_safe(_a: *mut archive_entry) -> *mut archive_acl {
    return unsafe { archive_entry_acl(_a) };
}

pub unsafe fn archive_entry_sparse_add_entry_safe(
    _a: *mut archive_entry,
    _b: la_int64_t,
    _c: la_int64_t,
) {
    return unsafe { archive_entry_sparse_add_entry(_a, _b, _c) };
}

pub unsafe fn _archive_entry_copy_link_l_safe(
    _a: *mut archive_entry,
    _b: *const u8,
    _c: size_t,
    _d: *mut archive_string_conv,
) -> i32 {
    return unsafe { _archive_entry_copy_link_l(_a, _b, _c, _d) };
}

pub unsafe fn strdup_safe(_var1: *const u8) -> *mut u8 {
    return unsafe { strdup(_var1) };
}

pub unsafe fn wmemmove_safe(__s1: *mut wchar_t, __s2: *const wchar_t, __n: size_t) -> *mut wchar_t {
    return unsafe { wmemmove(__s1, __s2, __n) };
}

pub unsafe fn inflateSetDictionary_safe(
    strm: z_streamp,
    dictionary: *const Bytef,
    dictLength: uInt,
) -> i32 {
    return unsafe { inflateSetDictionary(strm, dictionary, dictLength) };
}

pub unsafe fn archive_wstring_ensure_safe(
    _a1: *mut archive_wstring,
    _a2: size_t,
) -> *mut archive_wstring {
    return unsafe { archive_wstring_ensure(_a1, _a2) };
}

pub unsafe fn fstat_safe(__fd: i32, __buf: *mut stat) -> i32 {
    return unsafe { fstat(__fd, __buf) };
}

pub unsafe fn lstat_safe(__file: *const u8, __buf: *mut stat) -> i32 {
    return unsafe { lstat(__file, __buf) };
}

pub unsafe fn open_safe(__file: *const u8, __oflag: i32) -> i32 {
    return unsafe { open(__file, __oflag) };
}

pub unsafe fn strcspn_safe(_a1: *const u8, _a2: *const u8) -> u64 {
    return unsafe { strcspn(_a1, _a2) };
}

pub unsafe fn strnlen_safe(__string: *const u8, __maxlen: size_t) -> size_t {
    return unsafe { strnlen(__string, __maxlen) };
}

pub unsafe fn close_safe(__fd: i32) -> i32 {
    return unsafe { close(__fd) };
}

pub unsafe fn read_safe(__fd: i32, __buf: *mut (), __nbytes: size_t) -> ssize_t {
    return unsafe { read(__fd, __buf, __nbytes) };
}

pub unsafe fn archive_entry_linkresolver_new_safe() -> *mut archive_entry_linkresolver {
    return unsafe { archive_entry_linkresolver_new() };
}

pub unsafe fn archive_entry_linkresolver_set_strategy_safe(
    _a1: *mut archive_entry_linkresolver,
    _a2: i32,
) {
    return unsafe { archive_entry_linkresolver_set_strategy(_a1, _a2) };
}

pub unsafe fn archive_entry_linkresolver_free_safe(_a: *mut archive_entry_linkresolver) {
    return unsafe { archive_entry_linkresolver_free(_a) };
}

pub unsafe fn archive_entry_linkify_safe(
    _a1: *mut archive_entry_linkresolver,
    _a2: *mut *mut archive_entry,
    _a3: *mut *mut archive_entry,
) {
    return unsafe { archive_entry_linkify(_a1, _a2, _a3) };
}

pub unsafe fn archive_entry_set_digest_safe(
    entry: *mut archive_entry,
    type_0: i32,
    digest: *const u8,
) -> i32 {
    return unsafe { archive_entry_set_digest(entry, type_0, digest) };
}

pub unsafe fn __archive_ensure_cloexec_flag_safe(fd: i32) {
    return unsafe { __archive_ensure_cloexec_flag(fd) };
}

pub unsafe fn pack_find_safe(_a1: *const u8) -> Option<pack_t> {
    return unsafe { pack_find(_a1) };
}

pub unsafe fn archive_entry_dev_safe(an: *mut archive_entry) -> dev_t {
    return unsafe { archive_entry_dev(an) };
}

pub unsafe fn archive_entry_ino64_safe(an: *mut archive_entry) -> la_int64_t {
    return unsafe { archive_entry_ino64(an) };
}

pub unsafe fn archive_entry_nlink_safe(an: *mut archive_entry) -> u32 {
    return unsafe { archive_entry_nlink(an) };
}

pub unsafe fn archive_entry_copy_hardlink_safe(an: *mut archive_entry, a2: *const u8) {
    return unsafe { archive_entry_copy_hardlink(an, a2) };
}

pub unsafe fn lzma_properties_decode_safe(
    filter: *mut lzma_filter,
    allocator: *const lzma_allocator,
    props: *const uint8_t,
    props_size: size_t,
) -> lzma_ret {
    return unsafe { lzma_properties_decode(filter, allocator, props, props_size) };
}

pub unsafe fn lzma_raw_decoder_safe(
    strm: *mut lzma_stream,
    filters: *const lzma_filter,
) -> lzma_ret {
    return unsafe { lzma_raw_decoder(strm, filters) };
}

pub unsafe fn inflateReset_safe(strm: z_streamp) -> i32 {
    return unsafe { inflateReset(strm) };
}

pub unsafe fn inflate_safe(strm: z_streamp, flush: i32) -> i32 {
    return unsafe { inflate(strm, flush) };
}

pub unsafe fn inflateEnd_safe(strm: z_streamp) -> i32 {
    return unsafe { inflateEnd(strm) };
}

lazy_static! {
    pub static ref u_composition_table: [unicode_composition_table; 931] = unsafe {
        let mut res: [unicode_composition_table; 931] = [unicode_composition_table {
            cp1: 0x0 as uint32_t,
            cp2: 0x0 as uint32_t,
            nfc: 0x0 as uint32_t,
        }; 931];
        let ptr: *mut unicode_composition_table = get_u_composition_table();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
    pub static ref u_decomposable_blocks: [u8; 467] = unsafe {
        let mut res: [u8; 467] = [0; 467];
        let ptr: *mut u8 = get_u_decomposable_blocks();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
    pub static ref ccc_val: [u8; 16 * 115] = unsafe {
        let mut res: [u8; 16 * 115] = [0; 16 * 115];
        let ptr: *mut u8 = get_ccc_val();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
    pub static ref ccc_val_index: [u8; 16 * 39] = unsafe {
        let mut res: [u8; 16 * 39] = [0; 16 * 39];
        let ptr: *mut u8 = get_ccc_val_index();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
    pub static ref ccc_index: [u8; 467] = unsafe {
        let mut res: [u8; 467] = [0; 467];
        let ptr: *mut u8 = get_ccc_index();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
    pub static ref u_decomposition_table: [unicode_decomposition_table; 931] = unsafe {
        let mut res: [unicode_decomposition_table; 931] = [unicode_decomposition_table {
            nfc: 0x0 as uint32_t,
            cp1: 0x0 as uint32_t,
            cp2: 0x0 as uint32_t,
        }; 931];
        let ptr: *mut unicode_decomposition_table = get_u_decomposition_table();
        for i in 0..res.len() {
            res[i] = *ptr.offset(i as isize);
        }
        free(ptr as *mut ());
        return res;
    };
}
