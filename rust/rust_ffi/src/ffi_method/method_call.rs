use ffi_alias::alias_set::*;
use ffi_struct::struct_transfer::*;

extern "C" {

    pub fn archive_clear_error(_: *mut archive);

    pub fn archive_string_ensure(_: *mut archive_string, _: size_t) -> *mut archive_string;

    pub fn archive_string_conversion_set_opt(_: *mut archive_string_conv, _: libc::c_int);

    pub fn archive_acl_from_text_l(
        _: *mut archive_acl,
        _: *const libc::c_char,
        _: libc::c_int,
        _: *mut archive_string_conv,
    ) -> libc::c_int;

    pub fn archive_entry_size(_: *mut archive_entry) -> la_int64_t;

    pub fn archive_entry_copy_gname(_: *mut archive_entry, _: *const libc::c_char);

    pub fn archive_entry_set_ino(_: *mut archive_entry, _: la_int64_t);

    pub fn archive_entry_copy_link(_: *mut archive_entry, _: *const libc::c_char);

    pub fn archive_entry_set_rdevmajor(_: *mut archive_entry, _: dev_t);

    pub fn archive_entry_set_rdevminor(_: *mut archive_entry, _: dev_t);

    pub fn archive_entry_copy_uname(_: *mut archive_entry, _: *const libc::c_char);

    pub fn archive_entry_copy_mac_metadata(
        _: *mut archive_entry,
        _: *const libc::c_void,
        _: size_t,
    );

    pub fn archive_entry_acl(_: *mut archive_entry) -> *mut archive_acl;

    pub fn archive_entry_sparse_add_entry(_: *mut archive_entry, _: la_int64_t, _: la_int64_t);

    pub fn _archive_entry_copy_link_l(
        _: *mut archive_entry,
        _: *const libc::c_char,
        _: size_t,
        _: *mut archive_string_conv,
    ) -> libc::c_int;
    pub fn xmlCleanupParser();

    pub fn xmlTextReaderSetErrorHandler(
        reader: xmlTextReaderPtr,
        f: xmlTextReaderErrorFunc,
        arg: *mut libc::c_void,
    );

    pub fn xmlReaderForIO(
        ioread: xmlInputReadCallback,
        ioclose: xmlInputCloseCallback,
        ioctx: *mut libc::c_void,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlTextReaderPtr;

    pub fn xmlFreeTextReader(reader: xmlTextReaderPtr);

    pub fn xmlTextReaderRead(reader: xmlTextReaderPtr) -> libc::c_int;

    pub fn xmlTextReaderIsEmptyElement(reader: xmlTextReaderPtr) -> libc::c_int;

    pub fn xmlTextReaderNodeType(reader: xmlTextReaderPtr) -> libc::c_int;

    pub fn xmlTextReaderConstLocalName(reader: xmlTextReaderPtr) -> *const xmlChar;

    pub fn xmlTextReaderConstValue(reader: xmlTextReaderPtr) -> *const xmlChar;

    pub fn xmlTextReaderMoveToFirstAttribute(reader: xmlTextReaderPtr) -> libc::c_int;

    pub fn xmlTextReaderMoveToNextAttribute(reader: xmlTextReaderPtr) -> libc::c_int;

    pub fn inflateEnd(strm: z_streamp) -> libc::c_int;

    pub fn inflateInit_(
        strm: z_streamp,
        version: *const libc::c_char,
        stream_size: libc::c_int,
    ) -> libc::c_int;

    static __archive_digest: archive_digest;

    pub fn archive_entry_set_devmajor(_: *mut archive_entry, _: dev_t);

    pub fn archive_entry_set_devminor(_: *mut archive_entry, _: dev_t);
    /* Returns pointer to start of first invalid token, or NULL if none. */
    /* Note that all recognized tokens are processed, regardless. */

    fn archive_entry_set_ino64(_: *mut archive_entry, _: la_int64_t);

    pub fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;

    pub fn __ctype_b_loc() -> *mut *const libc::c_ushort;

    pub fn malloc(size: libc::c_ulong) -> *mut libc::c_void;

    pub fn memcpy(
        str1: *mut libc::c_void,
        str2: *const libc::c_void,
        n: libc::c_ulong,
    ) -> *mut libc::c_void;

    pub fn memset(str: *mut libc::c_void, c: libc::c_int, n: libc::c_ulong) -> *mut libc::c_void;

    pub fn memcmp(
        str1: *const libc::c_void,
        str2: *const libc::c_void,
        n: libc::c_ulong,
    ) -> libc::c_int;

    pub fn calloc(nitems: libc::c_ulong, size: libc::c_ulong) -> *mut libc::c_void;

    pub fn free(ptr: *mut libc::c_void);

    pub fn strcmp(str1: *const libc::c_char, str2: *const libc::c_char) -> libc::c_int;

    pub fn strlen(str: *const libc::c_char) -> libc::c_ulong;

    pub fn sprintf(
        str: *mut libc::c_char,
        format: *const libc::c_char,
        more_params: ...
    ) -> libc::c_int;

    pub fn mktime(timeptr: *mut tm) -> time_t;

    pub fn wcschr(str: *const wchar_t, c: wchar_t) -> *mut wchar_t;

    pub fn wcslen(str: *const wchar_t) -> libc::c_ulong;

    pub fn archive_set_error(
        a: *mut archive,
        error_number: libc::c_int,
        fmt: *const libc::c_char,
        more_params: ...
    );

    pub fn archive_entry_filetype(entry: *mut archive_entry) -> mode_t;

    pub fn archive_entry_pathname(entry: *mut archive_entry) -> *const libc::c_char;

    pub fn archive_entry_pathname_w(entry: *mut archive_entry) -> *const wchar_t;

    pub fn archive_entry_symlink(entry: *mut archive_entry) -> *const libc::c_char;

    pub fn archive_entry_symlink_w(entry: *mut archive_entry) -> *const wchar_t;

    pub fn archive_entry_set_atime(entry: *mut archive_entry, t: time_t, ns: libc::c_long);

    pub fn archive_entry_unset_atime(entry: *mut archive_entry);

    pub fn archive_entry_set_birthtime(entry: *mut archive_entry, t: time_t, ns: libc::c_long);

    pub fn archive_entry_unset_birthtime(entry: *mut archive_entry);

    pub fn archive_entry_set_ctime(entry: *mut archive_entry, t: time_t, ns: libc::c_long);

    pub fn archive_entry_unset_ctime(entry: *mut archive_entry);

    pub fn archive_entry_set_gid(entry: *mut archive_entry, g: la_int64_t);

    pub fn archive_entry_set_gname(entry: *mut archive_entry, g: *const libc::c_char);

    pub fn archive_entry_set_mode(entry: *mut archive_entry, m: mode_t);

    pub fn archive_entry_set_mtime(entry: *mut archive_entry, t: time_t, ns: libc::c_long);

    pub fn archive_entry_copy_pathname_w(entry: *mut archive_entry, name: *const wchar_t);

    pub fn archive_entry_set_size(entry: *mut archive_entry, s: la_int64_t);

    pub fn archive_entry_unset_size(entry: *mut archive_entry);

    pub fn archive_entry_set_symlink(entry: *mut archive_entry, linkname: *const libc::c_char);

    pub fn archive_entry_copy_symlink_w(entry: *mut archive_entry, linkname: *const wchar_t);

    pub fn archive_entry_set_uid(entry: *mut archive_entry, u: la_int64_t);

    pub fn archive_entry_set_uname(entry: *mut archive_entry, name: *const libc::c_char);

    pub fn archive_entry_set_filetype(entry: *mut archive_entry, _type: libc::c_uint);

    pub fn archive_entry_set_pathname(entry: *mut archive_entry, name: *const libc::c_char);

    pub fn archive_entry_set_perm(entry: *mut archive_entry, p: mode_t);

    pub fn archive_entry_set_hardlink(entry: *mut archive_entry, target: *const libc::c_char);

    pub fn archive_entry_set_nlink(entry: *mut archive_entry, nlink: libc::c_uint);

    pub fn archive_entry_set_rdev(entry: *mut archive_entry, m: dev_t);

    pub fn archive_entry_copy_symlink(entry: *mut archive_entry, linkname: *const libc::c_char);

    pub fn _archive_entry_copy_hardlink_l(
        entry: *mut archive_entry,
        target: *const libc::c_char,
        len: size_t,
        sc: *mut archive_string_conv,
    ) -> libc::c_int;

    pub fn _archive_entry_copy_pathname_l(
        entry: *mut archive_entry,
        name: *const libc::c_char,
        len: size_t,
        sc: *mut archive_string_conv,
    ) -> libc::c_int;

    pub fn archive_wstring_free(_as: *mut archive_wstring);

    pub fn archive_string_free(_as: *mut archive_string);

    pub fn archive_wstrncat(
        _as: *mut archive_wstring,
        p: *const wchar_t,
        n: size_t,
    ) -> *mut archive_wstring;

    pub fn archive_wstring_concat(dest: *mut archive_wstring, src: *mut archive_wstring);

    pub fn archive_string_conversion_charset_name(
        sc: *mut archive_string_conv,
    ) -> *const libc::c_char;

    pub fn archive_array_append(
        _as: *mut archive_string,
        p: *const libc::c_char,
        s: size_t,
    ) -> *mut archive_string;

    pub fn archive_strcat(_as: *mut archive_string, p: *const libc::c_void) -> *mut archive_string;

    pub fn archive_string_concat(dest: *mut archive_string, src: *mut archive_string);

    pub fn archive_string_sprintf(
        _as: *mut archive_string,
        fmt: *const libc::c_char,
        more_params: ...
    );

    pub fn archive_string_conversion_from_charset(
        a: *mut archive,
        charset: *const libc::c_char,
        best_effort: libc::c_int,
    ) -> *mut archive_string_conv;

    pub fn archive_strncat(
        _as: *mut archive_string,
        _p: *const libc::c_void,
        n: size_t,
    ) -> *mut archive_string;

    pub fn archive_mstring_clean(aes: *mut archive_mstring);

    pub fn archive_mstring_get_wcs(
        a: *mut archive,
        aes: *mut archive_mstring,
        wp: *mut *const wchar_t,
    ) -> libc::c_int;

    pub fn archive_mstring_copy_mbs_len_l(
        aes: *mut archive_mstring,
        mbs: *const libc::c_char,
        len: size_t,
        sc: *mut archive_string_conv,
    ) -> libc::c_int;

    pub fn __archive_check_magic(
        a: *mut archive,
        magic: libc::c_uint,
        state: libc::c_uint,
        function: *const libc::c_char,
    ) -> libc::c_int;

    pub fn __archive_read_register_format(
        a: *mut archive_read,
        format_data: *mut libc::c_void,
        name: *const libc::c_char,
        bid: Option<extern "C" fn(a: *mut archive_read, best_bid: libc::c_int) -> libc::c_int>,
        options: Option<
            extern "C" fn(
                a: *mut archive_read,
                key: *const libc::c_char,
                val: *const libc::c_char,
            ) -> libc::c_int,
        >,
        read_header: Option<
            extern "C" fn(a: *mut archive_read, entry: *mut archive_entry) -> libc::c_int,
        >,
        read_data: Option<
            extern "C" fn(
                a: *mut archive_read,
                buff: *mut *const libc::c_void,
                size: *mut size_t,
                offset: *mut int64_t,
            ) -> libc::c_int,
        >,
        read_data_skip: Option<extern "C" fn(a: *mut archive_read) -> libc::c_int>,
        seek_data: Option<
            extern "C" fn(a: *mut archive_read, offset: int64_t, whence: libc::c_int) -> int64_t,
        >,
        cleanup: Option<extern "C" fn(a: *mut archive_read) -> libc::c_int>,
        format_capabilities: Option<extern "C" fn(a: *mut archive_read) -> libc::c_int>,
        has_encrypted_entries: Option<extern "C" fn(a: *mut archive_read) -> libc::c_int>,
    ) -> libc::c_int;

    pub fn __archive_read_ahead(
        a: *mut archive_read,
        min: size_t,
        avail: *mut ssize_t,
    ) -> *const libc::c_void;

    pub fn __archive_read_header(a: *mut archive_read, entry: *mut archive_entry) -> libc::c_int;

    pub fn __archive_read_consume(a: *mut archive_read, request: int64_t) -> int64_t;

    pub fn __archive_read_seek(
        a: *mut archive_read,
        offset: int64_t,
        whence: libc::c_int,
    ) -> int64_t;

    pub fn __errno_location() -> *mut libc::c_int;

    pub fn localtime_r(__timer: *const time_t, __tp: *mut tm) -> *mut tm;

    pub fn crc32(crc: uLong, buf: *const Bytef, len: uInt) -> uLong;

    pub fn archive_entry_set_is_data_encrypted(_: *mut archive_entry, is_encrypted: libc::c_char);
    pub fn archive_entry_set_is_metadata_encrypted(
        _: *mut archive_entry,
        is_encrypted: libc::c_char,
    );

    pub fn _archive_entry_copy_symlink_l(
        _: *mut archive_entry,
        _: *const libc::c_char,
        _: size_t,
        _: *mut archive_string_conv,
    ) -> libc::c_int;

    pub fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;

    pub static __archive_ppmd7_functions: IPpmd7;

    pub fn __archive_reset_read_data(_: *mut archive);

    pub fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;

    pub fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;

    pub fn archive_entry_clear(_: *mut archive_entry) -> *mut archive_entry;

    pub fn archive_entry_free(_: *mut archive_entry);

    pub fn archive_entry_new() -> *mut archive_entry;

    pub fn archive_entry_pathname_utf8(_: *mut archive_entry) -> *const libc::c_char;

    pub fn archive_entry_copy_fflags_text(
        _: *mut archive_entry,
        _: *const libc::c_char,
    ) -> *const libc::c_char;

    pub fn archive_entry_update_hardlink_utf8(
        _: *mut archive_entry,
        _: *const libc::c_char,
    ) -> libc::c_int;

    pub fn archive_entry_update_pathname_utf8(
        _: *mut archive_entry,
        _: *const libc::c_char,
    ) -> libc::c_int;

    pub fn archive_entry_set_symlink_type(_: *mut archive_entry, _: libc::c_int);

    pub fn archive_entry_update_symlink_utf8(
        _: *mut archive_entry,
        _: *const libc::c_char,
    ) -> libc::c_int;

    pub fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;

    pub fn blake2sp_init(S: *mut blake2sp_state, outlen: size_t) -> libc::c_int;

    pub fn blake2sp_update(
        S: *mut blake2sp_state,
        in_0: *const uint8_t,
        inlen: size_t,
    ) -> libc::c_int;

    pub fn blake2sp_final(S: *mut blake2sp_state, out: *mut uint8_t, outlen: size_t)
        -> libc::c_int;

    pub fn wcscpy(__dest: *mut wchar_t, __src: *const wchar_t) -> *mut wchar_t;

    pub fn wmemcmp(_: *const wchar_t, _: *const wchar_t, _: libc::c_ulong) -> libc::c_int;

    pub fn inflateInit2_(
        strm: z_streamp,
        windowBits: libc::c_int,
        version: *const libc::c_char,
        stream_size: libc::c_int,
    ) -> libc::c_int;

    pub fn archive_mstring_copy_wcs_len(
        _: *mut archive_mstring,
        wcs: *const wchar_t,
        _: size_t,
    ) -> libc::c_int;

    pub fn archive_mstring_copy_mbs(
        _: *mut archive_mstring,
        mbs: *const libc::c_char,
    ) -> libc::c_int;

    pub fn archive_mstring_get_mbs_l(
        _: *mut archive,
        _: *mut archive_mstring,
        _: *mut *const libc::c_char,
        _: *mut size_t,
        _: *mut archive_string_conv,
    ) -> libc::c_int;

    pub fn archive_mstring_get_mbs(
        _: *mut archive,
        _: *mut archive_mstring,
        _: *mut *const libc::c_char,
    ) -> libc::c_int;

    pub fn archive_mstring_copy(dest: *mut archive_mstring, src: *mut archive_mstring);

    pub fn __archive_errx(retvalue: libc::c_int, msg: *const libc::c_char) -> !;

    pub fn iconv_open(__tocode: *const libc::c_char, __fromcode: *const libc::c_char) -> iconv_t;

    pub fn iconv(
        __cd: iconv_t,
        __inbuf: *mut *mut libc::c_char,
        __inbytesleft: *mut size_t,
        __outbuf: *mut *mut libc::c_char,
        __outbytesleft: *mut size_t,
    ) -> size_t;

    pub fn iconv_close(__cd: iconv_t) -> libc::c_int;

    pub fn nl_langinfo(__item: nl_item) -> *mut libc::c_char;

    pub fn __ctype_get_mb_cur_max() -> size_t;

    pub fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;

    pub fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;

    pub fn strdup(_: *const libc::c_char) -> *mut libc::c_char;

    pub fn wmemmove(__s1: *mut wchar_t, __s2: *const wchar_t, __n: size_t) -> *mut wchar_t;

    pub fn mbrtowc(
        __pwc: *mut wchar_t,
        __s: *const libc::c_char,
        __n: size_t,
        __p: *mut mbstate_t,
    ) -> size_t;

    pub fn wcrtomb(__s: *mut libc::c_char, __wc: wchar_t, __ps: *mut mbstate_t) -> size_t;

    pub fn _archive_entry_copy_uname_l(
        _: *mut archive_entry,
        _: *const libc::c_char,
        _: size_t,
        _: *mut archive_string_conv,
    ) -> libc::c_int;

    pub fn archive_entry_set_dev(_: *mut archive_entry, _: dev_t);

    pub fn archive_entry_xattr_add_entry(
        _: *mut archive_entry,
        _: *const libc::c_char,
        _: *const libc::c_void,
        _: size_t,
    );

    pub fn _archive_entry_copy_gname_l(
        _: *mut archive_entry,
        _: *const libc::c_char,
        _: size_t,
        _: *mut archive_string_conv,
    ) -> libc::c_int;

    pub fn archive_entry_copy_pathname(_: *mut archive_entry, _: *const libc::c_char);

    pub fn strncpy(
        _: *mut libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> *mut libc::c_char;

    pub fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong)
        -> libc::c_int;

    pub fn archive_strappend_char(_: *mut archive_string, _: libc::c_char) -> *mut archive_string;

    pub fn inflateSetDictionary(
        strm: z_streamp,
        dictionary: *const Bytef,
        dictLength: uInt,
    ) -> libc::c_int;

    pub fn archive_wstring_ensure(_: *mut archive_wstring, _: size_t) -> *mut archive_wstring;

    pub fn fstat(__fd: libc::c_int, __buf: *mut stat) -> libc::c_int;

    pub fn lstat(__file: *const libc::c_char, __buf: *mut stat) -> libc::c_int;

    pub fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;

    pub fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;

    pub fn strnlen(__string: *const libc::c_char, __maxlen: size_t) -> size_t;

    pub fn close(__fd: libc::c_int) -> libc::c_int;

    pub fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;

    pub fn archive_entry_linkresolver_new() -> *mut archive_entry_linkresolver;

    pub fn archive_entry_linkresolver_set_strategy(
        _: *mut archive_entry_linkresolver,
        _: libc::c_int,
    );

    pub fn archive_entry_linkresolver_free(_: *mut archive_entry_linkresolver);

    pub fn archive_entry_linkify(
        _: *mut archive_entry_linkresolver,
        _: *mut *mut archive_entry,
        _: *mut *mut archive_entry,
    );

    pub fn archive_entry_set_digest(
        entry: *mut archive_entry,
        type_0: libc::c_int,
        digest: *const libc::c_uchar,
    ) -> libc::c_int;

    pub fn __archive_ensure_cloexec_flag(fd: libc::c_int);

    pub fn __archive_rb_tree_init(_: *mut archive_rb_tree, _: *const archive_rb_tree_ops);

    pub fn __archive_rb_tree_insert_node(
        _: *mut archive_rb_tree,
        _: *mut archive_rb_node,
    ) -> libc::c_int;

    pub fn __archive_rb_tree_find_node(
        _: *mut archive_rb_tree,
        _: *const libc::c_void,
    ) -> *mut archive_rb_node;

    pub fn pack_find(_: *const libc::c_char) -> Option<pack_t>;

    pub fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;

    pub fn archive_entry_dev(_: *mut archive_entry) -> dev_t;

    pub fn archive_entry_ino64(_: *mut archive_entry) -> la_int64_t;

    pub fn archive_entry_mode(_: *mut archive_entry) -> mode_t;

    pub fn archive_entry_nlink(_: *mut archive_entry) -> libc::c_uint;

    pub fn archive_entry_copy_hardlink(_: *mut archive_entry, _: *const libc::c_char);

    pub fn BZ2_bzDecompressInit(
        strm: *mut bz_stream,
        verbosity: libc::c_int,
        small: libc::c_int,
    ) -> libc::c_int;

    pub fn BZ2_bzDecompress(strm: *mut bz_stream) -> libc::c_int;

    pub fn BZ2_bzDecompressEnd(strm: *mut bz_stream) -> libc::c_int;

    pub fn lzma_stream_decoder(
        strm: *mut lzma_stream,
        memlimit: uint64_t,
        flags: uint32_t,
    ) -> lzma_ret;

    pub fn lzma_alone_decoder(strm: *mut lzma_stream, memlimit: uint64_t) -> lzma_ret;

    pub fn lzma_code(strm: *mut lzma_stream, action: lzma_action) -> lzma_ret;

    pub fn lzma_end(strm: *mut lzma_stream);

    pub fn archive_filter_bytes(_: *mut archive, _: libc::c_int) -> la_int64_t;

    pub fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;

    pub fn archive_wstrcat(_: *mut archive_wstring, _: *const wchar_t) -> *mut archive_wstring;

    pub fn archive_wstrappend_wchar(_: *mut archive_wstring, _: wchar_t) -> *mut archive_wstring;

    pub fn __archive_rb_tree_remove_node(_: *mut archive_rb_tree, _: *mut archive_rb_node);

    pub fn __archive_rb_tree_iterate(
        _: *mut archive_rb_tree,
        _: *mut archive_rb_node,
        _: libc::c_uint,
    ) -> *mut archive_rb_node;

    pub fn __archive_read_reset_passphrase(a: *mut archive_read);

    pub fn __archive_read_next_passphrase(a: *mut archive_read) -> *const libc::c_char;

    pub fn lzma_properties_decode(
        filter: *mut lzma_filter,
        allocator: *const lzma_allocator,
        props: *const uint8_t,
        props_size: size_t,
    ) -> lzma_ret;

    pub fn lzma_raw_decoder(strm: *mut lzma_stream, filters: *const lzma_filter) -> lzma_ret;

    pub fn inflateReset(strm: z_streamp) -> libc::c_int;

    pub fn inflate(strm: z_streamp, flush: libc::c_int) -> libc::c_int;

    pub fn isprint(c: libc::c_int) -> libc::c_int;

    pub static __archive_hmac: archive_hmac;

    pub static __archive_ppmd8_functions: IPpmd8;

    pub static __archive_cryptor: archive_cryptor;
}

pub fn malloc_safe(size: libc::c_ulong) -> *mut libc::c_void {
    return unsafe { malloc(size) };
}

pub fn memcpy_safe(
    str1: *mut libc::c_void,
    str2: *const libc::c_void,
    n: libc::c_ulong,
) -> *mut libc::c_void {
    return unsafe { memcpy(str1, str2, n) };
}

pub fn memset_safe(str: *mut libc::c_void, c: libc::c_int, n: libc::c_ulong) -> *mut libc::c_void {
    return unsafe { memset(str, c, n) };
}

pub fn memcmp_safe(
    str1: *const libc::c_void,
    str2: *const libc::c_void,
    n: libc::c_ulong,
) -> libc::c_int {
    return unsafe { memcmp(str1, str2, n) };
}

pub fn calloc_safe(nitems: libc::c_ulong, size: libc::c_ulong) -> *mut libc::c_void {
    return unsafe { calloc(nitems, size) };
}

pub fn free_safe(ptr: *mut libc::c_void) {
    unsafe { free(ptr) };
}

pub fn strcmp_safe(str1: *const libc::c_char, str2: *const libc::c_char) -> libc::c_int {
    return unsafe { strcmp(str1, str2) };
}

pub fn strlen_safe(str: *const libc::c_char) -> libc::c_ulong {
    return unsafe { strlen(str) };
}

#[macro_export]
macro_rules! sprintf_safe {
    () => {};
    ($str:expr, $format:expr$(, $more_params:expr)*) => {{
        unsafe { sprintf($str, $format$(, $more_params)*) }
    }};
}

pub fn mktime_safe(timeptr: *mut tm) -> time_t {
    return unsafe { mktime(timeptr) };
}

pub fn wcschr_safe(str: *const wchar_t, c: wchar_t) -> *mut wchar_t {
    return unsafe { wcschr(str, c) };
}

pub fn wcslen_safe(str: *const wchar_t) -> libc::c_ulong {
    return unsafe { wcslen(str) };
}

#[macro_export]
macro_rules! archive_set_error_safe {
    () => {};
    ($a:expr, $error_number:expr, $fmt:expr$(, $more_params:expr)*) => {{
        unsafe { archive_set_error($a, $error_number, $fmt$(, $more_params)*) }
    }};
}

pub fn archive_entry_filetype_safe(entry: *mut archive_entry) -> mode_t {
    return unsafe { archive_entry_filetype(entry) };
}

pub fn archive_entry_pathname_safe(entry: *mut archive_entry) -> *const libc::c_char {
    return unsafe { archive_entry_pathname(entry) };
}

pub fn archive_entry_pathname_w_safe(entry: *mut archive_entry) -> *const wchar_t {
    return unsafe { archive_entry_pathname_w(entry) };
}

pub fn archive_entry_symlink_safe(entry: *mut archive_entry) -> *const libc::c_char {
    return unsafe { archive_entry_symlink(entry) };
}

pub fn archive_entry_symlink_w_safe(entry: *mut archive_entry) -> *const wchar_t {
    return unsafe { archive_entry_symlink_w(entry) };
}

pub fn archive_entry_set_atime_safe(entry: *mut archive_entry, t: time_t, ns: libc::c_long) {
    unsafe {
        archive_entry_set_atime(entry, t, ns);
    }
}

pub fn archive_entry_unset_atime_safe(entry: *mut archive_entry) {
    unsafe {
        archive_entry_unset_atime(entry);
    }
}

pub fn archive_entry_set_birthtime_safe(entry: *mut archive_entry, t: time_t, ns: libc::c_long) {
    unsafe {
        archive_entry_set_birthtime(entry, t, ns);
    }
}

pub fn archive_entry_unset_birthtime_safe(entry: *mut archive_entry) {
    unsafe {
        archive_entry_unset_birthtime(entry);
    }
}

pub fn archive_entry_set_ctime_safe(entry: *mut archive_entry, t: time_t, ns: libc::c_long) {
    unsafe {
        archive_entry_set_ctime(entry, t, ns);
    }
}

pub fn archive_entry_unset_ctime_safe(entry: *mut archive_entry) {
    unsafe {
        archive_entry_unset_ctime(entry);
    }
}

pub fn archive_entry_set_gid_safe(entry: *mut archive_entry, g: la_int64_t) {
    unsafe {
        archive_entry_set_gid(entry, g);
    }
}

pub fn archive_entry_set_gname_safe(entry: *mut archive_entry, g: *const libc::c_char) {
    unsafe {
        archive_entry_set_gname(entry, g);
    }
}

pub fn archive_entry_set_mode_safe(entry: *mut archive_entry, m: mode_t) {
    unsafe {
        archive_entry_set_mode(entry, m);
    }
}

pub fn archive_entry_set_mtime_safe(entry: *mut archive_entry, t: time_t, ns: libc::c_long) {
    unsafe {
        archive_entry_set_mtime(entry, t, ns);
    }
}

pub fn archive_entry_copy_pathname_w_safe(entry: *mut archive_entry, name: *const wchar_t) {
    unsafe {
        archive_entry_copy_pathname_w(entry, name);
    }
}

pub fn archive_entry_set_size_safe(entry: *mut archive_entry, s: la_int64_t) {
    unsafe {
        archive_entry_set_size(entry, s);
    }
}

pub fn archive_entry_unset_size_safe(entry: *mut archive_entry) {
    unsafe {
        archive_entry_unset_size(entry);
    }
}

pub fn archive_entry_set_symlink_safe(entry: *mut archive_entry, linkname: *const libc::c_char) {
    unsafe {
        archive_entry_set_symlink(entry, linkname);
    }
}

pub fn archive_entry_copy_symlink_w_safe(entry: *mut archive_entry, linkname: *const wchar_t) {
    unsafe {
        archive_entry_copy_symlink_w(entry, linkname);
    }
}

pub fn archive_entry_set_uid_safe(entry: *mut archive_entry, u: la_int64_t) {
    unsafe {
        archive_entry_set_uid(entry, u);
    }
}

pub fn archive_entry_set_uname_safe(entry: *mut archive_entry, name: *const libc::c_char) {
    unsafe {
        archive_entry_set_uname(entry, name);
    }
}

pub fn archive_entry_set_filetype_safe(entry: *mut archive_entry, _type: libc::c_uint) {
    unsafe {
        archive_entry_set_filetype(entry, _type);
    }
}

pub fn archive_entry_set_pathname_safe(entry: *mut archive_entry, name: *const libc::c_char) {
    unsafe {
        archive_entry_set_pathname(entry, name);
    }
}

pub fn archive_entry_set_perm_safe(entry: *mut archive_entry, p: mode_t) {
    unsafe {
        archive_entry_set_perm(entry, p);
    }
}

pub fn archive_entry_set_hardlink_safe(entry: *mut archive_entry, target: *const libc::c_char) {
    unsafe {
        archive_entry_set_hardlink(entry, target);
    }
}

pub fn archive_entry_set_nlink_safe(entry: *mut archive_entry, nlink: libc::c_uint) {
    unsafe {
        archive_entry_set_nlink(entry, nlink);
    }
}

pub fn archive_entry_set_rdev_safe(entry: *mut archive_entry, m: dev_t) {
    unsafe {
        archive_entry_set_rdev(entry, m);
    }
}

pub fn archive_entry_copy_symlink_safe(entry: *mut archive_entry, linkname: *const libc::c_char) {
    unsafe { archive_entry_copy_symlink(entry, linkname) }
}

pub fn _archive_entry_copy_hardlink_l_safe(
    entry: *mut archive_entry,
    target: *const libc::c_char,
    len: size_t,
    sc: *mut archive_string_conv,
) -> libc::c_int {
    return unsafe { _archive_entry_copy_hardlink_l(entry, target, len, sc) };
}

pub fn archive_wstring_free_safe(_as: *mut archive_wstring) {
    unsafe { archive_wstring_free(_as) };
}

pub fn archive_string_free_safe(_as: *mut archive_string) {
    unsafe { archive_string_free(_as) };
}

pub fn archive_wstrncat_safe(
    _as: *mut archive_wstring,
    p: *const wchar_t,
    n: size_t,
) -> *mut archive_wstring {
    return unsafe { archive_wstrncat(_as, p, n) };
}

pub fn archive_wstring_concat_safe(dest: *mut archive_wstring, src: *mut archive_wstring) {
    unsafe { archive_wstring_concat(dest, src) };
}

pub fn archive_string_conversion_charset_name_safe(
    sc: *mut archive_string_conv,
) -> *const libc::c_char {
    return unsafe { archive_string_conversion_charset_name(sc) };
}

pub fn archive_array_append_safe(
    _as: *mut archive_string,
    p: *const libc::c_char,
    s: size_t,
) -> *mut archive_string {
    return unsafe { archive_array_append(_as, p, s) };
}

pub fn archive_strcat_safe(
    _as: *mut archive_string,
    p: *const libc::c_void,
) -> *mut archive_string {
    return unsafe { archive_strcat(_as, p) };
}

pub fn archive_string_concat_safe(dest: *mut archive_string, src: *mut archive_string) {
    unsafe { archive_string_concat(dest, src) };
}

#[macro_export]
macro_rules! archive_string_sprintf_safe {
    () => {};
    ($_as:expr, $fmt:expr$(, $more_params:expr)*) => {{
        unsafe { archive_string_sprintf($_as, $fmt$(, $more_params)*) }
    }};
}

pub fn archive_string_conversion_from_charset_safe(
    a: *mut archive,
    charset: *const libc::c_char,
    best_effort: libc::c_int,
) -> *mut archive_string_conv {
    return unsafe { archive_string_conversion_from_charset(a, charset, best_effort) };
}

pub fn archive_strncat_safe(
    _as: *mut archive_string,
    _p: *const libc::c_void,
    n: size_t,
) -> *mut archive_string {
    return unsafe { archive_strncat(_as, _p, n) };
}

pub fn archive_mstring_clean_safe(aes: *mut archive_mstring) {
    unsafe {
        archive_mstring_clean(aes);
    }
}

pub fn archive_mstring_get_wcs_safe(
    a: *mut archive,
    aes: *mut archive_mstring,
    wp: *mut *const wchar_t,
) -> libc::c_int {
    return unsafe { archive_mstring_get_wcs(a, aes, wp) };
}

pub fn archive_mstring_copy_mbs_len_l_safe(
    aes: *mut archive_mstring,
    mbs: *const libc::c_char,
    len: size_t,
    sc: *mut archive_string_conv,
) -> libc::c_int {
    return unsafe { archive_mstring_copy_mbs_len_l(aes, mbs, len, sc) };
}

pub fn __archive_check_magic_safe(
    a: *mut archive,
    magic: libc::c_uint,
    state: libc::c_uint,
    function: *const libc::c_char,
) -> libc::c_int {
    return unsafe { __archive_check_magic(a, magic, state, function) };
}

pub fn __archive_read_register_format_safe(
    a: *mut archive_read,
    format_data: *mut libc::c_void,
    name: *const libc::c_char,
    bid: Option<extern "C" fn(a: *mut archive_read, best_bid: libc::c_int) -> libc::c_int>,
    options: Option<
        extern "C" fn(
            a: *mut archive_read,
            key: *const libc::c_char,
            val: *const libc::c_char,
        ) -> libc::c_int,
    >,
    read_header: Option<
        extern "C" fn(a: *mut archive_read, entry: *mut archive_entry) -> libc::c_int,
    >,
    read_data: Option<
        extern "C" fn(
            a: *mut archive_read,
            buff: *mut *const libc::c_void,
            size: *mut size_t,
            offset: *mut int64_t,
        ) -> libc::c_int,
    >,
    read_data_skip: Option<extern "C" fn(a: *mut archive_read) -> libc::c_int>,
    seek_data: Option<
        extern "C" fn(a: *mut archive_read, offset: int64_t, whence: libc::c_int) -> int64_t,
    >,
    cleanup: Option<extern "C" fn(a: *mut archive_read) -> libc::c_int>,
    format_capabilities: Option<extern "C" fn(a: *mut archive_read) -> libc::c_int>,
    has_encrypted_entries: Option<extern "C" fn(a: *mut archive_read) -> libc::c_int>,
) -> libc::c_int {
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

pub fn __archive_read_ahead_safe(
    a: *mut archive_read,
    min: size_t,
    avail: *mut ssize_t,
) -> *const libc::c_void {
    return unsafe { __archive_read_ahead(a, min, avail) };
}

pub fn __archive_read_header_safe(a: *mut archive_read, entry: *mut archive_entry) -> libc::c_int {
    return unsafe { __archive_read_header(a, entry) };
}

pub fn __archive_read_consume_safe(a: *mut archive_read, request: int64_t) -> int64_t {
    return unsafe { __archive_read_consume(a, request) };
}

pub fn __archive_read_seek_safe(
    a: *mut archive_read,
    offset: int64_t,
    whence: libc::c_int,
) -> int64_t {
    return unsafe { __archive_read_seek(a, offset, whence) };
}

pub fn __errno_location_safe() -> *mut libc::c_int {
    return unsafe { __errno_location() };
}

pub fn _archive_entry_copy_pathname_l_safe(
    param1: *mut archive_entry,
    param2: *const libc::c_char,
    param3: size_t,
    param4: *mut archive_string_conv,
) -> libc::c_int {
    return unsafe { _archive_entry_copy_pathname_l(param1, param2, param3, param4) };
}

pub fn crc32_safe(crc: uLong, buf: *const Bytef, len: uInt) -> uLong {
    return unsafe { crc32(crc, buf, len) };
}

pub fn inflateInit2__safe(
    strm: z_streamp,
    windowBits: libc::c_int,
    version: *const libc::c_char,
    stream_size: libc::c_int,
) -> libc::c_int {
    return unsafe { inflateInit2_(strm, windowBits, version, stream_size) };
}

pub fn BZ2_bzDecompressInit_safe(
    strm: *mut bz_stream,
    verbosity: libc::c_int,
    small: libc::c_int,
) -> libc::c_int {
    return unsafe { BZ2_bzDecompressInit(strm, verbosity, small) };
}

pub fn BZ2_bzDecompress_safe(strm: *mut bz_stream) -> libc::c_int {
    return unsafe { BZ2_bzDecompress(strm) };
}

pub fn BZ2_bzDecompressEnd_safe(strm: *mut bz_stream) -> libc::c_int {
    return unsafe { BZ2_bzDecompressEnd(strm) };
}

pub fn lzma_stream_decoder_safe(
    strm: *mut lzma_stream,
    memlimit: uint64_t,
    flags: uint32_t,
) -> lzma_ret {
    return unsafe { lzma_stream_decoder(strm, memlimit, flags) };
}

pub fn lzma_alone_decoder_safe(strm: *mut lzma_stream, memlimit: uint64_t) -> lzma_ret {
    return unsafe { lzma_alone_decoder(strm, memlimit) };
}

pub fn lzma_code_safe(strm: *mut lzma_stream, action: lzma_action) -> lzma_ret {
    return unsafe { lzma_code(strm, action) };
}

pub fn lzma_end_safe(strm: *mut lzma_stream) {
    unsafe {
        lzma_end(strm);
    }
}

pub fn archive_filter_bytes_safe(param1: *mut archive, param2: libc::c_int) -> la_int64_t {
    return unsafe { archive_filter_bytes(param1, param2) };
}

pub fn archive_entry_copy_mac_metadata_safe(
    param1: *mut archive_entry,
    param2: *const libc::c_void,
    param3: size_t,
) {
    unsafe {
        archive_entry_copy_mac_metadata(param1, param2, param3);
    }
}

pub fn _archive_entry_copy_symlink_l_safe(
    param1: *mut archive_entry,
    param2: *const libc::c_char,
    param3: size_t,
    param4: *mut archive_string_conv,
) -> libc::c_int {
    return unsafe { _archive_entry_copy_symlink_l(param1, param2, param3, param4) };
}

pub fn memchr_safe(
    param1: *const libc::c_void,
    param2: libc::c_int,
    param3: libc::c_ulong,
) -> *mut libc::c_void {
    return unsafe { memchr(param1, param2, param3) };
}

pub fn strncmp_safe(
    param1: *const libc::c_char,
    param2: *const libc::c_char,
    param3: libc::c_ulong,
) -> libc::c_int {
    return unsafe { strncmp(param1, param2, param3) };
}

pub fn strrchr_safe(param1: *const libc::c_char, param2: libc::c_int) -> *mut libc::c_char {
    return unsafe { strrchr(param1, param2) };
}

pub fn archive_wstrcat_safe(
    param1: *mut archive_wstring,
    param2: *const wchar_t,
) -> *mut archive_wstring {
    return unsafe { archive_wstrcat(param1, param2) };
}

pub fn archive_strappend_char_safe(
    param1: *mut archive_string,
    param2: libc::c_char,
) -> *mut archive_string {
    return unsafe { archive_strappend_char(param1, param2) };
}

pub fn archive_wstrappend_wchar_safe(
    param1: *mut archive_wstring,
    param2: wchar_t,
) -> *mut archive_wstring {
    return unsafe { archive_wstrappend_wchar(param1, param2) };
}

pub fn __archive_rb_tree_init_safe(
    param1: *mut archive_rb_tree,
    param2: *const archive_rb_tree_ops,
) {
    unsafe {
        __archive_rb_tree_init(param1, param2);
    }
}

pub fn __archive_rb_tree_insert_node_safe(
    param1: *mut archive_rb_tree,
    param2: *mut archive_rb_node,
) -> libc::c_int {
    return unsafe { __archive_rb_tree_insert_node(param1, param2) };
}

pub fn __archive_rb_tree_find_node_safe(
    param1: *mut archive_rb_tree,
    param2: *const libc::c_void,
) -> *mut archive_rb_node {
    return unsafe { __archive_rb_tree_find_node(param1, param2) };
}

pub fn __archive_rb_tree_remove_node_safe(
    param1: *mut archive_rb_tree,
    param2: *mut archive_rb_node,
) {
    unsafe {
        __archive_rb_tree_remove_node(param1, param2);
    }
}

pub fn __archive_rb_tree_iterate_safe(
    param1: *mut archive_rb_tree,
    param2: *mut archive_rb_node,
    param3: libc::c_uint,
) -> *mut archive_rb_node {
    return unsafe { __archive_rb_tree_iterate(param1, param2, param3) };
}

pub fn __archive_read_reset_passphrase_safe(a: *mut archive_read) {
    unsafe {
        __archive_read_reset_passphrase(a);
    }
}

pub fn __archive_read_next_passphrase_safe(a: *mut archive_read) -> *const libc::c_char {
    return unsafe { __archive_read_next_passphrase(a) };
}

pub fn archive_entry_set_is_metadata_encrypted_safe(
    _a: *mut archive_entry,
    is_encrypted: libc::c_char,
) {
    return unsafe { archive_entry_set_is_metadata_encrypted(_a, is_encrypted) };
}

pub fn archive_entry_set_is_data_encrypted_safe(
    _a: *mut archive_entry,
    is_encrypted: libc::c_char,
) {
    return unsafe { archive_entry_set_is_data_encrypted(_a, is_encrypted) };
}

pub fn __archive_reset_read_data_safe(_a: *mut archive) {
    return unsafe { __archive_reset_read_data(_a) };
}

pub fn realloc_safe(_a: *mut libc::c_void, _b: libc::c_ulong) -> *mut libc::c_void {
    return unsafe { realloc(_a, _b) };
}

pub fn strchr_safe(_a: *const libc::c_char, _b: libc::c_int) -> *mut libc::c_char {
    return unsafe { strchr(_a, _b) };
}

pub fn localtime_r_safe(__timer: *const time_t, __tp: *mut tm) -> *mut tm {
    return unsafe { localtime_r(__timer, __tp) };
}

pub fn blake2sp_init_safe(S: *mut blake2sp_state, outlen: size_t) -> libc::c_int {
    return unsafe { blake2sp_init(S, outlen) };
}

pub fn archive_entry_pathname_utf8_safe(_a: *mut archive_entry) -> *const libc::c_char {
    return unsafe { archive_entry_pathname_utf8(_a) };
}

pub fn archive_entry_update_pathname_utf8_safe(
    _a: *mut archive_entry,
    _b: *const libc::c_char,
) -> libc::c_int {
    return unsafe { archive_entry_update_pathname_utf8(_a, _b) };
}

pub fn archive_entry_update_symlink_utf8_safe(
    _a: *mut archive_entry,
    _b: *const libc::c_char,
) -> libc::c_int {
    return unsafe { archive_entry_update_symlink_utf8(_a, _b) };
}

pub fn archive_entry_set_symlink_type_safe(_a: *mut archive_entry, _b: libc::c_int) {
    return unsafe { archive_entry_set_symlink_type(_a, _b) };
}

pub fn archive_entry_update_hardlink_utf8_safe(
    _a: *mut archive_entry,
    _b: *const libc::c_char,
) -> libc::c_int {
    return unsafe { archive_entry_update_hardlink_utf8(_a, _b) };
}

pub fn archive_entry_clear_safe(_a: *mut archive_entry) -> *mut archive_entry {
    return unsafe { archive_entry_clear(_a) };
}

pub fn archive_entry_copy_fflags_text_safe(
    _a: *mut archive_entry,
    _b: *const libc::c_char,
) -> *const libc::c_char {
    return unsafe { archive_entry_copy_fflags_text(_a, _b) };
}

pub fn archive_entry_new_safe() -> *mut archive_entry {
    return unsafe { archive_entry_new() };
}

pub fn archive_entry_free_safe(_a: *mut archive_entry) {
    return unsafe { archive_entry_free(_a) };
}

pub fn blake2sp_update_safe(
    S: *mut blake2sp_state,
    in_0: *const uint8_t,
    inlen: size_t,
) -> libc::c_int {
    return unsafe { blake2sp_update(S, in_0, inlen) };
}

pub fn blake2sp_final_safe(
    S: *mut blake2sp_state,
    out: *mut uint8_t,
    outlen: size_t,
) -> libc::c_int {
    return unsafe { blake2sp_final(S, out, outlen) };
}
pub fn wcscpy_safe(__dest: *mut wchar_t, __src: *const wchar_t) -> *mut wchar_t {
    return unsafe { wcscpy(__dest, __src) };
}

pub fn wmemcmp_safe(
    _const1: *const wchar_t,
    _const2: *const wchar_t,
    _const3: libc::c_ulong,
) -> libc::c_int {
    return unsafe { wmemcmp(_const1, _const2, _const3) };
}

pub fn strcpy_safe(_var1: *mut libc::c_char, _var2: *const libc::c_char) -> *mut libc::c_char {
    return unsafe { strcpy(_var1, _var2) };
}

pub fn archive_mstring_copy_wcs_len_safe(
    _var1: *mut archive_mstring,
    wcs: *const wchar_t,
    _var2: size_t,
) -> libc::c_int {
    return unsafe { archive_mstring_copy_wcs_len(_var1, wcs, _var2) };
}

pub fn archive_mstring_copy_mbs_safe(
    _var1: *mut archive_mstring,
    mbs: *const libc::c_char,
) -> libc::c_int {
    return unsafe { archive_mstring_copy_mbs(_var1, mbs) };
}

pub fn archive_mstring_get_mbs_l_safe(
    _var1: *mut archive,
    _var2: *mut archive_mstring,
    _var3: *mut *const libc::c_char,
    _var4: *mut size_t,
    _var5: *mut archive_string_conv,
) -> libc::c_int {
    return unsafe { archive_mstring_get_mbs_l(_var1, _var2, _var3, _var4, _var5) };
}

pub fn archive_mstring_get_mbs_safe(
    _var1: *mut archive,
    _var2: *mut archive_mstring,
    _var3: *mut *const libc::c_char,
) -> libc::c_int {
    return unsafe { archive_mstring_get_mbs(_var1, _var2, _var3) };
}

pub fn archive_mstring_copy_safe(dest: *mut archive_mstring, src: *mut archive_mstring) {
    return unsafe { archive_mstring_copy(dest, src) };
}

pub fn __archive_errx_safe(retvalue: libc::c_int, msg: *const libc::c_char) -> ! {
    return unsafe { __archive_errx(retvalue, msg) };
}

pub fn iconv_open_safe(__tocode: *const libc::c_char, __fromcode: *const libc::c_char) -> iconv_t {
    return unsafe { iconv_open(__tocode, __fromcode) };
}

pub fn iconv_safe(
    __cd: iconv_t,
    __inbuf: *mut *mut libc::c_char,
    __inbytesleft: *mut size_t,
    __outbuf: *mut *mut libc::c_char,
    __outbytesleft: *mut size_t,
) -> size_t {
    return unsafe { iconv(__cd, __inbuf, __inbytesleft, __outbuf, __outbytesleft) };
}

pub fn iconv_close_safe(__cd: iconv_t) -> libc::c_int {
    return unsafe { iconv_close(__cd) };
}

pub fn nl_langinfo_safe(__item: nl_item) -> *mut libc::c_char {
    return unsafe { nl_langinfo(__item) };
}

pub fn __ctype_get_mb_cur_max_safe() -> size_t {
    return unsafe { __ctype_get_mb_cur_max() };
}

pub fn memmove_safe(
    _var1: *mut libc::c_void,
    _var2: *const libc::c_void,
    _var3: libc::c_ulong,
) -> *mut libc::c_void {
    return unsafe { memmove(_var1, _var2, _var3) };
}

pub fn strncpy_safe(
    _a: *mut libc::c_char,
    _b: *const libc::c_char,
    _c: libc::c_ulong,
) -> *mut libc::c_char {
    return unsafe { strncpy(_a, _b, _c) };
}

pub fn archive_entry_copy_pathname_safe(_a: *mut archive_entry, _pn: *const libc::c_char) {
    return unsafe { archive_entry_copy_pathname(_a, _pn) };
}

pub fn _archive_entry_copy_uname_l_safe(
    _a: *mut archive_entry,
    _b: *const libc::c_char,
    _c: size_t,
    _d: *mut archive_string_conv,
) -> libc::c_int {
    return unsafe { _archive_entry_copy_uname_l(_a, _b, _c, _d) };
}

pub fn _archive_entry_copy_gname_l_safe(
    _a: *mut archive_entry,
    _b: *const libc::c_char,
    _c: size_t,
    _d: *mut archive_string_conv,
) -> libc::c_int {
    return unsafe { _archive_entry_copy_gname_l(_a, _b, _c, _d) };
}
pub fn archive_entry_xattr_add_entry_safe(
    _a: *mut archive_entry,
    _b: *const libc::c_char,
    _c: *const libc::c_void,
    _d: size_t,
) {
    return unsafe { archive_entry_xattr_add_entry(_a, _b, _c, _d) };
}

pub fn archive_entry_set_dev_safe(_a: *mut archive_entry, _b: dev_t) {
    return unsafe { archive_entry_set_dev(_a, _b) };
}

pub fn strtol_safe(
    _a: *const libc::c_char,
    _b: *mut *mut libc::c_char,
    _c: libc::c_int,
) -> libc::c_long {
    return unsafe { strtol(_a, _b, _c) };
}

pub fn __ctype_b_loc_safe() -> *mut *const libc::c_ushort {
    return unsafe { __ctype_b_loc() };
}

pub fn archive_string_sprintf_safe(_a: *mut archive_string, _b: *const libc::c_char) {
    return unsafe { archive_string_sprintf(_a, _b) };
}

pub fn xmlCleanupParser_safe() {
    return unsafe { xmlCleanupParser() };
}

pub fn xmlTextReaderSetErrorHandler_safe(
    reader: xmlTextReaderPtr,
    f: xmlTextReaderErrorFunc,
    arg: *mut libc::c_void,
) {
    return unsafe { xmlTextReaderSetErrorHandler(reader, f, arg) };
}

pub fn xmlReaderForIO_safe(
    ioread: xmlInputReadCallback,
    ioclose: xmlInputCloseCallback,
    ioctx: *mut libc::c_void,
    URL: *const libc::c_char,
    encoding: *const libc::c_char,
    options: libc::c_int,
) -> xmlTextReaderPtr {
    return unsafe { xmlReaderForIO(ioread, ioclose, ioctx, URL, encoding, options) };
}

pub fn xmlFreeTextReader_safe(reader: xmlTextReaderPtr) {
    return unsafe { xmlFreeTextReader(reader) };
}

pub fn xmlTextReaderRead_safe(reader: xmlTextReaderPtr) -> libc::c_int {
    return unsafe { xmlTextReaderRead(reader) };
}

pub fn xmlTextReaderIsEmptyElement_safe(reader: xmlTextReaderPtr) -> libc::c_int {
    return unsafe { xmlTextReaderIsEmptyElement(reader) };
}

pub fn xmlTextReaderNodeType_safe(reader: xmlTextReaderPtr) -> libc::c_int {
    return unsafe { xmlTextReaderNodeType(reader) };
}

pub fn xmlTextReaderConstLocalName_safe(reader: xmlTextReaderPtr) -> *const xmlChar {
    return unsafe { xmlTextReaderConstLocalName(reader) };
}

pub fn xmlTextReaderConstValue_safe(reader: xmlTextReaderPtr) -> *const xmlChar {
    return unsafe { xmlTextReaderConstValue(reader) };
}

pub fn xmlTextReaderMoveToFirstAttribute_safe(reader: xmlTextReaderPtr) -> libc::c_int {
    return unsafe { xmlTextReaderMoveToFirstAttribute(reader) };
}

pub fn xmlTextReaderMoveToNextAttribute_safe(reader: xmlTextReaderPtr) -> libc::c_int {
    return unsafe { xmlTextReaderMoveToNextAttribute(reader) };
}

pub fn inflateInit__safe(
    strm: z_streamp,
    version: *const libc::c_char,
    stream_size: libc::c_int,
) -> libc::c_int {
    return unsafe { inflateInit_(strm, version, stream_size) };
}

pub fn archive_entry_set_devmajor_safe(_a: *mut archive_entry, _b: dev_t) {
    return unsafe { archive_entry_set_devmajor(_a, _b) };
}

pub fn archive_entry_set_devminor_safe(_a: *mut archive_entry, _b: dev_t) {
    return unsafe { archive_entry_set_devminor(_a, _b) };
}

pub fn archive_entry_set_ino64_safe(_a: *mut archive_entry, _b: la_int64_t) {
    return unsafe { archive_entry_set_ino64(_a, _b) };
}

pub fn archive_clear_error_safe(_a: *mut archive) {
    return unsafe { archive_clear_error(_a) };
}

pub fn archive_string_ensure_safe(_a: *mut archive_string, _s: size_t) -> *mut archive_string {
    return unsafe { archive_string_ensure(_a, _s) };
}

pub fn archive_string_conversion_set_opt_safe(_a: *mut archive_string_conv, _opt: libc::c_int) {
    return unsafe { archive_string_conversion_set_opt(_a, _opt) };
}

pub fn archive_acl_from_text_l_safe(
    _a: *mut archive_acl,
    _b: *const libc::c_char,
    _c: libc::c_int,
    _d: *mut archive_string_conv,
) -> libc::c_int {
    return unsafe { archive_acl_from_text_l(_a, _b, _c, _d) };
}

pub fn archive_entry_size_safe(_a: *mut archive_entry) -> la_int64_t {
    return unsafe { archive_entry_size(_a) };
}

pub fn archive_entry_copy_gname_safe(_a: *mut archive_entry, _b: *const libc::c_char) {
    return unsafe { archive_entry_copy_gname(_a, _b) };
}

pub fn archive_entry_set_ino_safe(_a: *mut archive_entry, _b: la_int64_t) {
    return unsafe { archive_entry_set_ino(_a, _b) };
}

pub fn archive_entry_copy_link_safe(_a: *mut archive_entry, _b: *const libc::c_char) {
    return unsafe { archive_entry_copy_link(_a, _b) };
}

pub fn archive_entry_set_rdevmajor_safe(_a: *mut archive_entry, _b: dev_t) {
    return unsafe { archive_entry_set_rdevmajor(_a, _b) };
}

pub fn archive_entry_set_rdevminor_safe(_a: *mut archive_entry, _b: dev_t) {
    return unsafe { archive_entry_set_rdevminor(_a, _b) };
}

pub fn archive_entry_copy_uname_safe(_a: *mut archive_entry, _b: *const libc::c_char) {
    return unsafe { archive_entry_copy_uname(_a, _b) };
}

pub fn archive_entry_acl_safe(_a: *mut archive_entry) -> *mut archive_acl {
    return unsafe { archive_entry_acl(_a) };
}

pub fn archive_entry_sparse_add_entry_safe(_a: *mut archive_entry, _b: la_int64_t, _c: la_int64_t) {
    return unsafe { archive_entry_sparse_add_entry(_a, _b, _c) };
}

pub fn _archive_entry_copy_link_l_safe(
    _a: *mut archive_entry,
    _b: *const libc::c_char,
    _c: size_t,
    _d: *mut archive_string_conv,
) -> libc::c_int {
    return unsafe { _archive_entry_copy_link_l(_a, _b, _c, _d) };
}

pub fn strdup_safe(_var1: *const libc::c_char) -> *mut libc::c_char {
    return unsafe { strdup(_var1) };
}

pub fn wmemmove_safe(__s1: *mut wchar_t, __s2: *const wchar_t, __n: size_t) -> *mut wchar_t {
    return unsafe { wmemmove(__s1, __s2, __n) };
}

pub fn inflateSetDictionary_safe(
    strm: z_streamp,
    dictionary: *const Bytef,
    dictLength: uInt,
) -> libc::c_int {
    return unsafe { inflateSetDictionary(strm, dictionary, dictLength) };
}

pub fn archive_wstring_ensure_safe(_a1: *mut archive_wstring, _a2: size_t) -> *mut archive_wstring {
    return unsafe { archive_wstring_ensure(_a1, _a2) };
}

pub fn fstat_safe(__fd: libc::c_int, __buf: *mut stat) -> libc::c_int {
    return unsafe { fstat(__fd, __buf) };
}

pub fn lstat_safe(__file: *const libc::c_char, __buf: *mut stat) -> libc::c_int {
    return unsafe { lstat(__file, __buf) };
}

pub fn open_safe(__file: *const libc::c_char, __oflag: libc::c_int) -> libc::c_int {
    return unsafe { open(__file, __oflag) };
}

pub fn strcspn_safe(_a1: *const libc::c_char, _a2: *const libc::c_char) -> libc::c_ulong {
    return unsafe { strcspn(_a1, _a2) };
}

pub fn strnlen_safe(__string: *const libc::c_char, __maxlen: size_t) -> size_t {
    return unsafe { strnlen(__string, __maxlen) };
}

pub fn close_safe(__fd: libc::c_int) -> libc::c_int {
    return unsafe { close(__fd) };
}

pub fn read_safe(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t {
    return unsafe { read(__fd, __buf, __nbytes) };
}

pub fn archive_entry_linkresolver_new_safe() -> *mut archive_entry_linkresolver {
    return unsafe { archive_entry_linkresolver_new() };
}

pub fn archive_entry_linkresolver_set_strategy_safe(
    _a1: *mut archive_entry_linkresolver,
    _a2: libc::c_int,
) {
    return unsafe { archive_entry_linkresolver_set_strategy(_a1, _a2) };
}

pub fn archive_entry_linkresolver_free_safe(_a: *mut archive_entry_linkresolver) {
    return unsafe { archive_entry_linkresolver_free(_a) };
}

pub fn archive_entry_linkify_safe(
    _a1: *mut archive_entry_linkresolver,
    _a2: *mut *mut archive_entry,
    _a3: *mut *mut archive_entry,
) {
    return unsafe { archive_entry_linkify(_a1, _a2, _a3) };
}

pub fn archive_entry_set_digest_safe(
    entry: *mut archive_entry,
    type_0: libc::c_int,
    digest: *const libc::c_uchar,
) -> libc::c_int {
    return unsafe { archive_entry_set_digest(entry, type_0, digest) };
}

pub fn __archive_ensure_cloexec_flag_safe(fd: libc::c_int) {
    return unsafe { __archive_ensure_cloexec_flag(fd) };
}

pub fn pack_find_safe(_a1: *const libc::c_char) -> Option<pack_t> {
    return unsafe { pack_find(_a1) };
}

pub fn archive_entry_dev_safe(an: *mut archive_entry) -> dev_t {
    return unsafe { archive_entry_dev(an) };
}

pub fn archive_entry_ino64_safe(an: *mut archive_entry) -> la_int64_t {
    return unsafe { archive_entry_ino64(an) };
}

pub fn archive_entry_nlink_safe(an: *mut archive_entry) -> libc::c_uint {
    return unsafe { archive_entry_nlink(an) };
}

pub fn archive_entry_copy_hardlink_safe(an: *mut archive_entry, a2: *const libc::c_char) {
    return unsafe { archive_entry_copy_hardlink(an, a2) };
}

pub fn lzma_properties_decode_safe(
    filter: *mut lzma_filter,
    allocator: *const lzma_allocator,
    props: *const uint8_t,
    props_size: size_t,
) -> lzma_ret {
    return unsafe { lzma_properties_decode(filter, allocator, props, props_size) };
}

pub fn lzma_raw_decoder_safe(strm: *mut lzma_stream, filters: *const lzma_filter) -> lzma_ret {
    return unsafe { lzma_raw_decoder(strm, filters) };
}

pub fn inflateReset_safe(strm: z_streamp) -> libc::c_int {
    return unsafe { inflateReset(strm) };
}

pub fn inflate_safe(strm: z_streamp, flush: libc::c_int) -> libc::c_int {
    return unsafe { inflate(strm, flush) };
}

pub fn inflateEnd_safe(strm: z_streamp) -> libc::c_int {
    return unsafe { inflateEnd(strm) };
}
