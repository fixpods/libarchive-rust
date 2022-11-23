use archive_core::archive_endian::*;
use rust_ffi::archive_set_error_safe;
use rust_ffi::ffi_alias::alias_set::*;
use rust_ffi::ffi_defined_param::defined_param_get::*;
use rust_ffi::ffi_method::method_call::*;
use rust_ffi::ffi_struct::struct_transfer::*;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct xar {
    pub offset: uint64_t,
    pub total: int64_t,
    pub h_base: uint64_t,
    pub end_of_file: i32,
    pub outbuff: *mut u8,
    pub xmlsts: xmlstatus,
    pub xmlsts_unknown: xmlstatus,
    pub unknowntags: *mut unknown_tag,
    pub base64text: i32,
    pub toc_remaining: uint64_t,
    pub toc_total: uint64_t,
    pub toc_chksum_offset: uint64_t,
    pub toc_chksum_size: uint64_t,
    pub rd_encoding: enctype,
    pub stream: z_stream,
    pub stream_valid: i32,
    #[cfg(HAVE_BZLIB_H)]
    pub bzstream: bz_stream,
    #[cfg(HAVE_BZLIB_H)]
    pub bzstream_valid: i32,
    #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
    pub lzstream: lzma_stream,
    #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
    pub lzstream_valid: i32,
    pub a_sumwrk: chksumwork,
    pub e_sumwrk: chksumwork,
    pub file: *mut xar_file,
    pub xattr: *mut xattr,
    pub file_queue: heap_queue,
    pub hdlink_orgs: *mut xar_file,
    pub hdlink_list: *mut hdlink,
    pub entry_init: i32,
    pub entry_total: uint64_t,
    pub entry_remaining: uint64_t,
    pub entry_unconsumed: size_t,
    pub entry_size: uint64_t,
    pub entry_encoding: enctype,
    pub entry_a_sum: chksumval,
    pub entry_e_sum: chksumval,
    pub sconv: *mut archive_string_conv,
}

#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
pub struct XML_ParserStruct;

#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
pub type XML_Parser = *mut XML_ParserStruct;
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
pub type XML_Status = u32;
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
pub const XML_STATUS_SUSPENDED: XML_Status = 2;
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
pub const XML_STATUS_OK: XML_Status = 1;
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
pub const XML_STATUS_ERROR: XML_Status = 0;
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
pub type XML_StartElementHandler =
    Option<unsafe fn(_: *mut (), _: *const XML_Char, _: *mut *const XML_Char) -> ()>;
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
pub type XML_EndElementHandler = Option<unsafe fn(_: *mut (), _: *const XML_Char) -> ()>;
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
pub type XML_CharacterDataHandler = Option<unsafe fn(_: *mut (), _: *const XML_Char, _: i32) -> ()>;

#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct expat_userData {
    pub state: i32,
    pub archive: *mut archive_read,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct chksumwork {
    pub alg: i32,
    #[cfg(ARCHIVE_HAS_MD5)]
    pub md5ctx: archive_md5_ctx,
    #[cfg(ARCHIVE_HAS_SHA1)]
    pub sha1ctx: archive_sha1_ctx,
}

extern "C" {
    static __archive_digest: archive_digest;
    #[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
    fn XML_ParserCreate(encoding: *const XML_Char) -> XML_Parser;

    #[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
    fn XML_SetElementHandler(
        parser: XML_Parser,
        start: XML_StartElementHandler,
        end: XML_EndElementHandler,
    );

    #[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
    fn XML_SetCharacterDataHandler(parser: XML_Parser, handler: XML_CharacterDataHandler);

    #[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
    fn XML_Parse(parser: XML_Parser, s: *const u8, len: i32, isFinal: i32) -> XML_Status;

    #[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
    fn XML_SetUserData(parser: XML_Parser, userData: *mut ());

    #[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
    fn XML_ParserFree(parser: XML_Parser);

    #[cfg(HAVE_BZLIB_H)]
    fn BZ2_bzDecompressInit(strm: *mut bz_stream, verbosity: i32, small: i32) -> i32;

    #[cfg(HAVE_BZLIB_H)]
    fn BZ2_bzDecompress(strm: *mut bz_stream) -> i32;

    #[cfg(HAVE_BZLIB_H)]
    fn BZ2_bzDecompressEnd(strm: *mut bz_stream) -> i32;

    #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
    fn lzma_stream_decoder(strm: *mut lzma_stream, memlimit: uint64_t, flags: uint32_t)
        -> lzma_ret;
    #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
    fn lzma_alone_decoder(strm: *mut lzma_stream, memlimit: uint64_t) -> lzma_ret;
    #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
    fn lzma_code(strm: *mut lzma_stream, action: lzma_action) -> lzma_ret;

    #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
    fn lzma_end(strm: *mut lzma_stream);

    #[cfg(HAVE_TIMEGM)]
    fn timegm(__tp: *mut tm) -> time_t;

    #[cfg_attr(HAVE__MKGMTIME64, cfg(not(HAVE_TIMEGM)))]
    fn _mkgmtime(__tp: *mut tm) -> time_t;
}

#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
fn XML_ParserCreate_safe(encoding: *const XML_Char) -> XML_Parser {
    return unsafe { XML_ParserCreate(encoding) };
}

#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
fn XML_SetElementHandler_safe(
    parser: XML_Parser,
    start: XML_StartElementHandler,
    end: XML_EndElementHandler,
) {
    return unsafe { XML_SetElementHandler(parser, start, end) };
}

#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
fn XML_SetCharacterDataHandler_safe(parser: XML_Parser, handler: XML_CharacterDataHandler) {
    return unsafe { XML_SetCharacterDataHandler(parser, handler) };
}

#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
fn XML_Parse_safe(parser: XML_Parser, s: *const u8, len: i32, isFinal: i32) -> XML_Status {
    return unsafe { XML_Parse(parser, s, len, isFinal) };
}

#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
fn XML_SetUserData_safe(parser: XML_Parser, userData: *mut ()) {
    return unsafe { XML_SetUserData(parser, userData) };
}

#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
fn XML_ParserFree_safe(parser: XML_Parser) {
    return unsafe { XML_ParserFree(parser) };
}

#[cfg(HAVE_BZLIB_H)]
fn BZ2_bzDecompressInit_safe(strm: *mut bz_stream, verbosity: i32, small: i32) -> i32 {
    return unsafe { BZ2_bzDecompressInit(strm, verbosity, small) };
}

#[cfg(HAVE_BZLIB_H)]
fn BZ2_bzDecompress_safe(strm: *mut bz_stream) -> i32 {
    return unsafe { BZ2_bzDecompress(strm) };
}

#[cfg(HAVE_BZLIB_H)]
fn BZ2_bzDecompressEnd_safe(strm: *mut bz_stream) -> i32 {
    return unsafe { BZ2_bzDecompressEnd(strm) };
}

#[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
fn lzma_stream_decoder_safe(
    strm: *mut lzma_stream,
    memlimit: uint64_t,
    flags: uint32_t,
) -> lzma_ret {
    return unsafe { lzma_stream_decoder(strm, memlimit, flags) };
}
#[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
fn lzma_alone_decoder_safe(strm: *mut lzma_stream, memlimit: uint64_t) -> lzma_ret {
    return unsafe { lzma_alone_decoder(strm, memlimit) };
}
#[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
fn lzma_code_safe(strm: *mut lzma_stream, action: lzma_action) -> lzma_ret {
    return unsafe { lzma_code(strm, action) };
}

#[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
fn lzma_end_safe(strm: *mut lzma_stream) {
    return unsafe { lzma_end(strm) };
}

#[cfg(HAVE_TIMEGM)]
fn timegm_safe(__tp: *mut tm) -> time_t {
    return unsafe { timegm(__tp) };
}

#[cfg_attr(HAVE__MKGMTIME64, cfg(not(HAVE_TIMEGM)))]
fn _mkgmtime_safe(__tp: *mut tm) -> time_t {
    return unsafe { _mkgmtime(__tp) };
}

#[no_mangle]
pub unsafe fn archive_read_support_format_xar(mut _a: *mut archive) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    let mut a: *mut archive_read = _a as *mut archive_read;
    let mut r: i32 = 0;
    let mut magic_test: i32 = __archive_check_magic_safe(
        _a,
        ARCHIVE_XAR_DEFINED_PARAM.archive_read_magic,
        ARCHIVE_XAR_DEFINED_PARAM.archive_state_new,
        b"archive_read_support_format_xar\x00" as *const u8,
    );
    if magic_test == ARCHIVE_XAR_DEFINED_PARAM.archive_fatal {
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    xar = calloc_safe(1 as i32 as u64, ::std::mem::size_of::<xar>() as u64) as *mut xar;
    let mut safe_a = unsafe { &mut *a };
    let mut safe_xar = unsafe { &mut *xar };
    if xar.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.enomem,
            b"Can\'t allocate xar data\x00" as *const u8
        );
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    /* initialize xar->file_queue */
    safe_xar.file_queue.allocated = 0 as i32;
    safe_xar.file_queue.used = 0 as i32;
    safe_xar.file_queue.files = 0 as *mut *mut xar_file;
    r = __archive_read_register_format_safe(
        a,
        xar as *mut (),
        b"xar\x00" as *const u8,
        Some(xar_bid as unsafe fn(_: *mut archive_read, _: i32) -> i32),
        None,
        Some(xar_read_header as unsafe fn(_: *mut archive_read, _: *mut archive_entry) -> i32),
        Some(
            xar_read_data
                as unsafe fn(
                    _: *mut archive_read,
                    _: *mut *const (),
                    _: *mut size_t,
                    _: *mut int64_t,
                ) -> i32,
        ),
        Some(xar_read_data_skip as unsafe fn(_: *mut archive_read) -> i32),
        None,
        Some(xar_cleanup as unsafe fn(_: *mut archive_read) -> i32),
        None,
        None,
    );
    if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        free_safe(xar as *mut ());
    }
    return r;
}

unsafe fn PRINT_TOC(mut d: i32, mut outbytes: i32) {
    match () {
        #[cfg(DEBUG_PRINT_TOC)]
        _ => {
            let mut x: *mut u8 = 0 as *mut u8;
            let mut c: u8 = unsafe { *x.offset((outbytes - 1 as i32) as isize) };
            unsafe { *x.offset((outbytes - 1 as i32) as isize) = 0 as i32 as u8 };
            unsafe { *x.offset((outbytes - 1 as i32) as isize) = c };
            panic!("Reached end of non-void function without returning");
        }

        _ => {}
    }
}

unsafe fn xar_bid(mut a: *mut archive_read, mut best_bid: i32) -> i32 {
    let mut b: *const u8 = 0 as *const u8;
    let mut bid: i32 = 0;
    /* UNUSED */
    b = __archive_read_ahead_safe(a, HEADER_SIZE as size_t, 0 as *mut ssize_t) as *const u8;
    if b.is_null() {
        return -(1 as i32);
    }
    bid = 0 as i32;
    /*
     * Verify magic code
     */
    if archive_be32dec(b as *const ()) != HEADER_MAGIC as u32 {
        return 0 as i32;
    }
    bid += 32 as i32;
    /*
     * Verify header size
     */
    if archive_be16dec(unsafe { b.offset(4 as i32 as isize) as *const () }) as i32 != HEADER_SIZE {
        return 0 as i32;
    }
    bid += 16 as i32;
    /*
     * Verify header version
     */
    if archive_be16dec(unsafe { b.offset(6 as i32 as isize) as *const () }) as i32 != HEADER_VERSION
    {
        return 0 as i32;
    }
    bid += 16 as i32;
    /*
     * Verify type of checksum
     */
    match archive_be32dec(unsafe { b.offset(24 as i32 as isize) as *const () }) as i32 {
        CKSUM_NONE | CKSUM_SHA1 | CKSUM_MD5 => bid += 32 as i32,
        _ => return 0 as i32,
    }
    return bid;
}

unsafe fn read_toc(mut a: *mut archive_read) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    let mut file: *mut xar_file = 0 as *mut xar_file;
    let mut b: *const u8 = 0 as *const u8;
    let mut toc_compressed_size: uint64_t = 0;
    let mut toc_uncompressed_size: uint64_t = 0;
    let mut toc_chksum_alg: uint32_t = 0;
    let mut bytes: ssize_t = 0;
    let mut r: i32 = 0;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    let mut safe_a = unsafe { &mut *a };
    /*
     * Read xar header.
     */
    b = __archive_read_ahead_safe(a, HEADER_SIZE as size_t, &mut bytes) as *const u8;
    if bytes < 0 as i32 as i64 {
        return bytes as i32;
    }
    if bytes < HEADER_SIZE as i64 {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.archive_errno_file_format,
            b"Truncated archive header\x00" as *const u8
        );
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    if archive_be32dec(b as *const ()) != HEADER_MAGIC as u32 {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.archive_errno_file_format,
            b"Invalid header magic\x00" as *const u8
        );
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    if archive_be16dec(unsafe { b.offset(6 as i32 as isize) } as *const ()) as i32 != HEADER_VERSION
    {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.archive_errno_file_format,
            b"Unsupported header version(%d)\x00" as *const u8,
            archive_be16dec(unsafe { b.offset(6 as i32 as isize) } as *const ()) as i32
        );

        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    toc_compressed_size = archive_be64dec(unsafe { b.offset(8 as i32 as isize) } as *const ());
    safe_xar.toc_remaining = toc_compressed_size;
    toc_uncompressed_size = archive_be64dec(unsafe { b.offset(16 as i32 as isize) } as *const ());
    toc_chksum_alg = archive_be32dec(unsafe { b.offset(24 as i32 as isize) } as *const ());
    __archive_read_consume_safe(a, HEADER_SIZE as int64_t);
    safe_xar.offset =
        (safe_xar.offset as u64).wrapping_add(HEADER_SIZE as u64) as uint64_t as uint64_t;
    safe_xar.toc_total = 0 as i32 as uint64_t;
    /*
     * Read TOC(Table of Contents).
     */
    /* Initialize reading contents. */
    r = move_reading_point(a, HEADER_SIZE as uint64_t);
    if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        return r;
    }
    r = rd_contents_init(a, GZIP, toc_chksum_alg as i32, CKSUM_NONE);
    if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        return r;
    }

    match () {
        #[cfg(HAVE_LIBXML_XMLREADER_H)]
        _ => {
            r = xml2_read_toc(a);
        }
        #[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
        _ => {
            r = expat_read_toc(a);
        }
        _ => {}
    }

    if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        return r;
    }
    /* Set 'The HEAP' base. */
    safe_xar.h_base = safe_xar.offset;
    if safe_xar.toc_total != toc_uncompressed_size {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
            b"TOC uncompressed size error\x00" as *const u8
        );
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    /*
     * Checksum TOC
     */
    if toc_chksum_alg != CKSUM_NONE as u32 {
        r = move_reading_point(a, safe_xar.toc_chksum_offset);
        if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
            return r;
        }
        b = __archive_read_ahead_safe(a, safe_xar.toc_chksum_size, &mut bytes) as *const u8;
        if bytes < 0 as i32 as i64 {
            return bytes as i32;
        }
        if (bytes as uint64_t) < safe_xar.toc_chksum_size {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.archive_errno_file_format,
                b"Truncated archive file\x00" as *const u8
            );
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }
        r = checksum_final(
            a,
            b as *const (),
            safe_xar.toc_chksum_size,
            0 as *const (),
            0 as i32 as size_t,
        );
        __archive_read_consume_safe(a, safe_xar.toc_chksum_size as int64_t);
        safe_xar.offset =
            (safe_xar.offset as u64).wrapping_add(safe_xar.toc_chksum_size) as uint64_t as uint64_t;
        if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }
    }
    /*
     * Connect hardlinked files.
     */
    file = safe_xar.hdlink_orgs;
    unsafe {
        while !file.is_null() {
            let mut hdlink: *mut *mut hdlink = 0 as *mut *mut hdlink;
            hdlink = &mut safe_xar.hdlink_list;
            while !(*hdlink).is_null() {
                if (**hdlink).id as u64 == (*file).id {
                    let mut hltmp: *mut hdlink = 0 as *mut hdlink;
                    let mut f2: *mut xar_file = 0 as *mut xar_file;
                    let mut nlink: i32 = (**hdlink).cnt + 1 as i32;
                    (*file).nlink = nlink as u32;
                    f2 = (**hdlink).files;
                    while !f2.is_null() {
                        (*f2).nlink = nlink as u32;
                        (*f2).hardlink.length = 0 as i32 as size_t;
                        archive_string_concat(&mut (*f2).hardlink, &mut (*file).pathname);
                        f2 = (*f2).hdnext
                    }
                    /* Remove resolved files from hdlist_list. */
                    hltmp = *hdlink;
                    *hdlink = (*hltmp).next;
                    free(hltmp as *mut ());
                    break;
                } else {
                    hdlink = &mut (**hdlink).next
                }
            }
            file = (*file).hdnext
        }
    }

    safe_a.archive.archive_format = ARCHIVE_XAR_DEFINED_PARAM.archive_format_xar;
    safe_a.archive.archive_format_name = b"xar\x00" as *const u8;
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn xar_read_header(mut a: *mut archive_read, mut entry: *mut archive_entry) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    let mut file: *mut xar_file = 0 as *mut xar_file;
    let mut xattr: *mut xattr = 0 as *mut xattr;
    let mut r: i32 = 0;
    xar = unsafe { (*(*a).format) }.data as *mut xar;
    let mut safe_xar = unsafe { &mut *xar };
    let mut safe_a = unsafe { &mut *a };
    r = ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
    if safe_xar.offset == 0 as i32 as u64 {
        /* Create a character conversion object. */
        if safe_xar.sconv.is_null() {
            safe_xar.sconv = archive_string_conversion_from_charset_safe(
                &mut safe_a.archive,
                b"UTF-8\x00" as *const u8,
                1 as i32,
            );
            if safe_xar.sconv.is_null() {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        /* Read TOC. */
        r = read_toc(a);
        if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
            return r;
        }
    }
    let mut safe_file = unsafe { &mut *file };
    loop {
        safe_xar.file = heap_get_entry(&mut safe_xar.file_queue);
        file = safe_xar.file;
        safe_file = unsafe { &mut *file };
        if file.is_null() {
            safe_xar.end_of_file = 1 as i32;
            return ARCHIVE_XAR_DEFINED_PARAM.archive_eof;
        }
        if safe_file.mode & ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t
            != ARCHIVE_XAR_DEFINED_PARAM.ae_ifdir as mode_t
        {
            break;
        }
        if safe_file.has != (HAS_PATHNAME | HAS_TYPE) as u32 {
            break;
        }
        /*
         * If a file type is a directory and it does not have
         * any metadata, do not export.
         */
        file_free(file);
    }
    if safe_file.has & HAS_ATIME_XAR as u32 != 0 {
        archive_entry_set_atime_safe(entry, safe_file.atime, 0 as i32 as i64);
    }
    if safe_file.has & HAS_CTIME_XAR as u32 != 0 {
        archive_entry_set_ctime_safe(entry, safe_file.ctime, 0 as i32 as i64);
    }
    if safe_file.has & HAS_MTIME_XAR as u32 != 0 {
        archive_entry_set_mtime_safe(entry, safe_file.mtime, 0 as i32 as i64);
    }
    archive_entry_set_gid_safe(entry, safe_file.gid);
    if safe_file.gname.length > 0 as i32 as u64
        && _archive_entry_copy_gname_l_safe(
            entry,
            safe_file.gname.s,
            safe_file.gname.length,
            safe_xar.sconv,
        ) != 0 as i32
    {
        if unsafe { *__errno_location() } == ARCHIVE_XAR_DEFINED_PARAM.enomem {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.enomem,
                b"Can\'t allocate memory for Gname\x00" as *const u8
            );
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }

        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.archive_errno_file_format,
            b"Gname cannot be converted from %s to current locale.\x00" as *const u8,
            archive_string_conversion_charset_name_safe(safe_xar.sconv)
        );

        r = ARCHIVE_XAR_DEFINED_PARAM.archive_warn
    }
    archive_entry_set_uid_safe(entry, safe_file.uid);
    if safe_file.uname.length > 0 as i32 as u64
        && _archive_entry_copy_uname_l_safe(
            entry,
            safe_file.uname.s,
            safe_file.uname.length,
            safe_xar.sconv,
        ) != 0 as i32
    {
        if unsafe { *__errno_location() } == ARCHIVE_XAR_DEFINED_PARAM.enomem {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.enomem,
                b"Can\'t allocate memory for Uname\x00" as *const u8
            );
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.archive_errno_file_format,
            b"Uname cannot be converted from %s to current locale.\x00" as *const u8,
            archive_string_conversion_charset_name(safe_xar.sconv)
        );

        r = -(20 as i32)
    }
    archive_entry_set_mode_safe(entry, safe_file.mode);
    if _archive_entry_copy_pathname_l_safe(
        entry,
        safe_file.pathname.s,
        safe_file.pathname.length,
        safe_xar.sconv,
    ) != 0 as i32
    {
        if unsafe { *__errno_location() } == ARCHIVE_XAR_DEFINED_PARAM.enomem {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.enomem,
                b"Can\'t allocate memory for Pathname\x00" as *const u8
            );
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }

        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.archive_errno_file_format,
            b"Pathname cannot be converted from %s to current locale.\x00" as *const u8
                as *const u8,
            archive_string_conversion_charset_name_safe(safe_xar.sconv)
        );

        r = ARCHIVE_XAR_DEFINED_PARAM.archive_warn
    }
    if safe_file.symlink.length > 0 as i32 as u64
        && _archive_entry_copy_symlink_l_safe(
            entry,
            safe_file.symlink.s,
            safe_file.symlink.length,
            safe_xar.sconv,
        ) != 0 as i32
    {
        if unsafe { *__errno_location() } == ARCHIVE_XAR_DEFINED_PARAM.enomem {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.enomem,
                b"Can\'t allocate memory for Linkname\x00" as *const u8
            );
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }

        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.archive_errno_file_format,
            b"Linkname cannot be converted from %s to current locale.\x00" as *const u8
                as *const u8,
            archive_string_conversion_charset_name_safe(safe_xar.sconv)
        );

        r = -ARCHIVE_XAR_DEFINED_PARAM.archive_warn
    }
    /* Set proper nlink. */
    if safe_file.mode & ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t
        == ARCHIVE_XAR_DEFINED_PARAM.ae_ifdir as mode_t
    {
        archive_entry_set_nlink_safe(entry, (safe_file.subdirs + 2 as i32) as u32);
    } else {
        archive_entry_set_nlink_safe(entry, safe_file.nlink);
    }
    archive_entry_set_size_safe(entry, safe_file.size as la_int64_t);
    if safe_file.hardlink.length > 0 as i32 as u64 {
        archive_entry_set_hardlink_safe(entry, safe_file.hardlink.s);
    }
    archive_entry_set_ino64_safe(entry, safe_file.ino64);
    if safe_file.has & HAS_DEV as u32 != 0 {
        archive_entry_set_dev_safe(entry, safe_file.dev);
    }
    if safe_file.has & HAS_DEVMAJOR as u32 != 0 {
        archive_entry_set_devmajor_safe(entry, safe_file.devmajor);
    }
    if safe_file.has & HAS_DEVMINOR as u32 != 0 {
        archive_entry_set_devminor_safe(entry, safe_file.devminor);
    }
    if safe_file.fflags_text.length > 0 as i32 as u64 {
        archive_entry_copy_fflags_text_safe(entry, safe_file.fflags_text.s);
    }
    safe_xar.entry_init = 1 as i32;
    safe_xar.entry_total = 0 as i32 as uint64_t;
    safe_xar.entry_remaining = safe_file.length;
    safe_xar.entry_size = safe_file.size;
    safe_xar.entry_encoding = safe_file.encoding;
    safe_xar.entry_a_sum = safe_file.a_sum;
    safe_xar.entry_e_sum = safe_file.e_sum;
    /*
     * Read extended attributes.
     */
    xattr = safe_file.xattr_list;
    let mut safe_xattr = unsafe { &mut *xattr };
    while !xattr.is_null() {
        let mut d: *const () = 0 as *const ();
        let mut outbytes: size_t = 0 as i32 as size_t;
        let mut used: size_t = 0 as i32 as size_t;
        r = move_reading_point(a, safe_xattr.offset);
        if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
            break;
        }
        r = rd_contents_init(
            a,
            safe_xattr.encoding,
            safe_xattr.a_sum.alg,
            safe_xattr.e_sum.alg,
        );
        if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
            break;
        }
        d = 0 as *const ();
        r = rd_contents(a, &mut d, &mut outbytes, &mut used, safe_xattr.length);
        if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
            break;
        }
        if outbytes != safe_xattr.size {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                b"Decompressed size error\x00" as *const u8
            );
            r = ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            break;
        } else {
            r = checksum_final(
                a,
                safe_xattr.a_sum.val.as_mut_ptr() as *const (),
                safe_xattr.a_sum.len,
                safe_xattr.e_sum.val.as_mut_ptr() as *const (),
                safe_xattr.e_sum.len,
            );
            if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                archive_set_error_safe!(
                    &mut safe_a.archive as *mut archive,
                    ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                    b"Xattr checksum error\x00" as *const u8
                );
                r = ARCHIVE_XAR_DEFINED_PARAM.archive_warn;
                break;
            } else if safe_xattr.name.s.is_null() {
                archive_set_error_safe!(
                    &mut safe_a.archive as *mut archive,
                    ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                    b"Xattr name error\x00" as *const u8
                );
                r = ARCHIVE_XAR_DEFINED_PARAM.archive_warn;
                break;
            } else {
                archive_entry_xattr_add_entry_safe(entry, safe_xattr.name.s, d, outbytes);
                xattr = safe_xattr.next;
                safe_xattr = unsafe { &mut *xattr };
            }
        }
    }
    if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        file_free(file);
        return r;
    }
    if safe_xar.entry_remaining > 0 as i32 as u64 {
        /* Move reading point to the beginning of current
         * file contents. */
        r = move_reading_point(a, safe_file.offset)
    } else {
        r = ARCHIVE_XAR_DEFINED_PARAM.archive_ok
    }
    file_free(file);
    return r;
}

unsafe fn xar_read_data(
    mut a: *mut archive_read,
    mut buff: *mut *const (),
    mut size: *mut size_t,
    mut offset: *mut int64_t,
) -> i32 {
    let mut current_block: u64;
    let mut xar: *mut xar = 0 as *mut xar;
    let mut used: size_t = 0 as i32 as size_t;
    let mut r: i32 = 0;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    let mut safe_buff = unsafe { &mut *buff };
    let mut safe_a = unsafe { &mut *a };
    if safe_xar.entry_unconsumed != 0 {
        __archive_read_consume_safe(a, safe_xar.entry_unconsumed as int64_t);
        safe_xar.entry_unconsumed = 0 as i32 as size_t
    }
    if safe_xar.end_of_file != 0 || safe_xar.entry_remaining <= 0 as i32 as u64 {
        r = ARCHIVE_XAR_DEFINED_PARAM.archive_eof
    } else {
        if safe_xar.entry_init != 0 {
            r = rd_contents_init(
                a,
                safe_xar.entry_encoding,
                safe_xar.entry_a_sum.alg,
                safe_xar.entry_e_sum.alg,
            );
            if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                safe_xar.entry_remaining = 0 as i32 as uint64_t;
                return r;
            }
            safe_xar.entry_init = 0 as i32
        }
        *safe_buff = 0 as *const ();
        r = rd_contents(a, buff, size, &mut used, safe_xar.entry_remaining);
        if !(r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok) {
            unsafe { *offset = safe_xar.entry_total as int64_t };
            safe_xar.entry_total = (safe_xar.entry_total as u64).wrapping_add(unsafe { *size })
                as uint64_t as uint64_t;
            safe_xar.total =
                (safe_xar.total as u64).wrapping_add(unsafe { *size }) as int64_t as int64_t;
            safe_xar.offset = (safe_xar.offset as u64).wrapping_add(used) as uint64_t as uint64_t;
            safe_xar.entry_remaining =
                (safe_xar.entry_remaining as u64).wrapping_sub(used) as uint64_t as uint64_t;
            safe_xar.entry_unconsumed = used;
            if safe_xar.entry_remaining == 0 as i32 as u64 {
                if safe_xar.entry_total != safe_xar.entry_size {
                    archive_set_error_safe!(
                        &mut safe_a.archive as *mut archive,
                        ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                        b"Decompressed size error\x00" as *const u8
                    );
                    r = ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                    current_block = 1800826227261287704;
                } else {
                    r = checksum_final(
                        a,
                        safe_xar.entry_a_sum.val.as_mut_ptr() as *const (),
                        safe_xar.entry_a_sum.len,
                        safe_xar.entry_e_sum.val.as_mut_ptr() as *const (),
                        safe_xar.entry_e_sum.len,
                    );
                    if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                        current_block = 1800826227261287704;
                    } else {
                        current_block = 7205609094909031804;
                    }
                }
            } else {
                current_block = 7205609094909031804;
            }
            match current_block {
                1800826227261287704 => {}
                _ => return 0 as i32,
            }
        }
    }
    unsafe {
        *buff = 0 as *const ();
        *size = 0 as i32 as size_t;
        *offset = safe_xar.total
    };
    return r;
}

unsafe fn xar_read_data_skip(mut a: *mut archive_read) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    let mut bytes_skipped: int64_t = 0;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    if safe_xar.end_of_file != 0 {
        return ARCHIVE_XAR_DEFINED_PARAM.archive_eof;
    }
    bytes_skipped = __archive_read_consume_safe(
        a,
        safe_xar
            .entry_remaining
            .wrapping_add(safe_xar.entry_unconsumed) as int64_t,
    );
    if bytes_skipped < 0 as i32 as i64 {
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    safe_xar.offset =
        (safe_xar.offset as u64).wrapping_add(bytes_skipped as u64) as uint64_t as uint64_t;
    safe_xar.entry_unconsumed = 0 as i32 as size_t;
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn xar_cleanup(mut a: *mut archive_read) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    let mut hdlink: *mut hdlink = 0 as *mut hdlink;
    let mut i: i32 = 0;
    let mut r: i32 = 0;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    checksum_cleanup(a);
    r = decompression_cleanup(a);
    hdlink = safe_xar.hdlink_list;
    while !hdlink.is_null() {
        let mut next: *mut hdlink = unsafe { *hdlink }.next;
        free_safe(hdlink as *mut ());
        hdlink = next
    }
    i = 0 as i32;
    while i < safe_xar.file_queue.used {
        file_free(unsafe { *safe_xar.file_queue.files.offset(i as isize) });
        i += 1
    }
    free_safe(safe_xar.file_queue.files as *mut ());
    while !safe_xar.unknowntags.is_null() {
        let mut tag: *mut unknown_tag = 0 as *mut unknown_tag;
        tag = safe_xar.unknowntags;
        safe_xar.unknowntags = unsafe { *tag }.next;
        archive_string_free_safe(&mut unsafe { *tag }.name);
        free_safe(tag as *mut ());
    }
    free_safe(safe_xar.outbuff as *mut ());
    free_safe(xar as *mut ());
    unsafe { (*(*a).format).data = 0 as *mut () };
    return r;
}

unsafe fn move_reading_point(mut a: *mut archive_read, mut offset: uint64_t) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    let mut safe_a = unsafe { &mut *a };
    if safe_xar.offset.wrapping_sub(safe_xar.h_base) != offset {
        /* Seek forward to the start of file contents. */
        let mut step: int64_t = 0;
        step = offset.wrapping_sub(safe_xar.offset.wrapping_sub(safe_xar.h_base)) as int64_t;
        if step > 0 as i32 as i64 {
            step = __archive_read_consume_safe(a, step);
            if step < 0 as i32 as i64 {
                return step as i32;
            }
            safe_xar.offset =
                (safe_xar.offset as u64).wrapping_add(step as u64) as uint64_t as uint64_t
        } else {
            let mut pos: int64_t = __archive_read_seek_safe(
                a,
                safe_xar.h_base.wrapping_add(offset) as int64_t,
                ARCHIVE_XAR_DEFINED_PARAM.seek_set,
            );
            if pos == ARCHIVE_XAR_DEFINED_PARAM.archive_failed as i64 {
                archive_set_error_safe!(
                    &mut safe_a.archive as *mut archive,
                    ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                    b"Cannot seek.\x00" as *const u8
                );
                return ARCHIVE_XAR_DEFINED_PARAM.archive_failed;
            }
            safe_xar.offset = pos as uint64_t
        }
    }
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn rd_contents_init(
    mut a: *mut archive_read,
    mut encoding: enctype,
    mut a_sum_alg: i32,
    mut e_sum_alg: i32,
) -> i32 {
    let mut r: i32 = 0;
    /* Init decompress library. */
    r = decompression_init(a, encoding);
    if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        return r;
    }
    /* Init checksum library. */
    checksum_init(a, a_sum_alg, e_sum_alg);
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn rd_contents(
    mut a: *mut archive_read,
    mut buff: *mut *const (),
    mut size: *mut size_t,
    mut used: *mut size_t,
    mut remaining: uint64_t,
) -> i32 {
    let mut b: *const u8 = 0 as *const u8;
    let mut bytes: ssize_t = 0;
    let mut safe_a = unsafe { &mut *a };
    /* Get whatever bytes are immediately available. */
    b = __archive_read_ahead_safe(a, 1 as i32 as size_t, &mut bytes) as *const u8;
    if bytes < 0 as i32 as i64 {
        return bytes as i32;
    }
    if bytes == 0 as i32 as i64 {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
            b"Truncated archive file\x00" as *const u8
        );
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    if bytes as uint64_t > remaining {
        bytes = remaining as ssize_t
    }
    /*
     * Decompress contents of file.
     */
    unsafe { *used = bytes as size_t };
    if decompress(a, buff, size, b as *const (), used) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    /*
     * Update checksum of a compressed data and a extracted data.
     */
    checksum_update(
        a,
        b as *const (),
        unsafe { *used },
        unsafe { *buff },
        unsafe { *size },
    );
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}
/*
 * Note that this implementation does not (and should not!) obey
 * locale settings; you cannot simply substitute strtol here, since
 * it does obey locale.
 */
unsafe fn atol10(mut p: *const u8, mut char_cnt: size_t) -> uint64_t {
    let mut l: uint64_t = 0;
    let mut digit: i32 = 0;
    if char_cnt == 0 as i32 as u64 {
        return 0 as i32 as uint64_t;
    }
    l = 0 as i32 as uint64_t;
    digit = unsafe { *p as i32 - '0' as i32 };
    while digit >= 0 as i32 && digit < 10 as i32 && {
        let fresh0 = char_cnt;
        char_cnt = char_cnt.wrapping_sub(1);
        (fresh0) > 0 as i32 as u64
    } {
        l = l.wrapping_mul(10 as i32 as u64).wrapping_add(digit as u64);
        unsafe {
            p = p.offset(1);
            digit = *p as i32 - '0' as i32
        }
    }
    return l;
}

unsafe fn atol8(mut p: *const u8, mut char_cnt: size_t) -> int64_t {
    let mut l: int64_t = 0;
    let mut digit: i32 = 0;
    if char_cnt == 0 as i32 as u64 {
        return 0 as i32 as int64_t;
    }
    l = 0 as i32 as int64_t;
    loop {
        let fresh1 = char_cnt;
        char_cnt = char_cnt.wrapping_sub(1);
        if !(fresh1 > 0 as i32 as u64) {
            break;
        }
        if !unsafe { *p as i32 >= '0' as i32 && *p as i32 <= '7' as i32 } {
            break;
        }
        digit = unsafe { *p as i32 - '0' as i32 };
        unsafe { p = p.offset(1) };
        l <<= 3 as i32;
        l |= digit as i64
    }
    return l;
}

unsafe fn atohex(mut b: *mut u8, mut bsize: size_t, mut p: *const u8, mut psize: size_t) -> size_t {
    let mut fbsize: size_t = bsize;
    while bsize != 0 && psize > 1 as i32 as u64 {
        let mut x: u8 = 0;
        if unsafe { *p.offset(0 as i32 as isize) as i32 } >= 'a' as i32
            && unsafe { *p.offset(0 as i32 as isize) as i32 } <= 'z' as i32
        {
            x = ((unsafe { *p.offset(0 as i32 as isize) } as i32 - 'a' as i32 + 0xa as i32)
                << 4 as i32) as u8
        } else if unsafe { *p.offset(0 as i32 as isize) } as i32 >= 'A' as i32
            && unsafe { *p.offset(0 as i32 as isize) } as i32 <= 'Z' as i32
        {
            x = ((unsafe { *p.offset(0 as i32 as isize) } as i32 - 'A' as i32 + 0xa as i32)
                << 4 as i32) as u8
        } else if unsafe { *p.offset(0 as i32 as isize) } as i32 >= '0' as i32
            && unsafe { *p.offset(0 as i32 as isize) } as i32 <= '9' as i32
        {
            x = ((unsafe { *p.offset(0 as i32 as isize) } as i32 - '0' as i32) << 4 as i32) as u8
        } else {
            return -(1 as i32) as size_t;
        }
        if unsafe { *p.offset(1 as i32 as isize) } as i32 >= 'a' as i32
            && unsafe { *p.offset(1 as i32 as isize) } as i32 <= 'z' as i32
        {
            x = (x as i32
                | unsafe { *p.offset(1 as i32 as isize) } as i32 - 'a' as i32 + 0xa as i32)
                as u8
        } else if unsafe { *p.offset(1 as i32 as isize) } as i32 >= 'A' as i32
            && unsafe { *p.offset(1 as i32 as isize) } as i32 <= 'Z' as i32
        {
            x = (x as i32
                | unsafe { *p.offset(1 as i32 as isize) } as i32 - 'A' as i32 + 0xa as i32)
                as u8
        } else if unsafe { *p.offset(1 as i32 as isize) } as i32 >= '0' as i32
            && unsafe { *p.offset(1 as i32 as isize) } as i32 <= '9' as i32
        {
            x = (x as i32 | unsafe { *p.offset(1 as i32 as isize) } as i32 - '0' as i32) as u8
        } else {
            return -(1 as i32) as size_t;
        }
        let fresh2 = b;
        b = unsafe { b.offset(1) };
        unsafe { *fresh2 = x };
        bsize = bsize.wrapping_sub(1);
        p = unsafe { p.offset(2 as i32 as isize) };
        psize = (psize as u64).wrapping_sub(2 as i32 as u64) as size_t as size_t
    }
    return fbsize.wrapping_sub(bsize);
}

unsafe fn time_from_tm(mut t: *mut tm) -> time_t {
    /* Use platform timegm() if available. */
    #[cfg(HAVE_TIMEGM)]
    return timegm_safe(t);
    #[cfg_attr(HAVE__MKGMTIME64, cfg(not(HAVE_TIMEGM)))]
    return _mkgmtime_safe(t);
    if mktime_safe(t) == -(1 as i32) as time_t {
        return -(1 as i32) as time_t;
    }
    let mut safe_t = unsafe { &mut *t };
    return (safe_t.tm_sec
        + safe_t.tm_min * 60 as i32
        + safe_t.tm_hour * 3600 as i32
        + safe_t.tm_yday * 86400 as i32
        + (safe_t.tm_year - 70 as i32) * 31536000 as i32
        + (safe_t.tm_year - 69 as i32) / 4 as i32 * 86400 as i32
        - (safe_t.tm_year - 1 as i32) / 100 as i32 * 86400 as i32
        + (safe_t.tm_year + 299 as i32) / 400 as i32 * 86400 as i32) as time_t;
}

unsafe fn parse_time(mut p: *const u8, mut n: size_t) -> time_t {
    let mut tm: tm = tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 0,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: 0 as *const u8,
    };
    let mut t: time_t = 0 as i32 as time_t;
    let mut data: int64_t = 0;
    memset_safe(
        &mut tm as *mut tm as *mut (),
        0 as i32,
        ::std::mem::size_of::<tm>() as u64,
    );
    if n != 20 as i32 as u64 {
        return t;
    }
    data = atol10(p, 4 as i32 as size_t) as int64_t;
    if data < 1900 as i32 as i64 {
        return t;
    }
    tm.tm_year = data as i32 - 1900 as i32;
    p = unsafe { p.offset(4 as i32 as isize) };
    let fresh3 = p;
    p = unsafe { p.offset(1) };
    if unsafe { *fresh3 } as i32 != '-' as i32 {
        return t;
    }
    data = atol10(p, 2 as i32 as size_t) as int64_t;
    if data < 1 as i32 as i64 || data > 12 as i32 as i64 {
        return t;
    }
    tm.tm_mon = data as i32 - 1 as i32;
    p = unsafe { p.offset(2 as i32 as isize) };
    let fresh4 = p;
    p = unsafe { p.offset(1) };
    if unsafe { *fresh4 as i32 } != '-' as i32 {
        return t;
    }
    data = atol10(p, 2 as i32 as size_t) as int64_t;
    if data < 1 as i32 as i64 || data > 31 as i32 as i64 {
        return t;
    }
    tm.tm_mday = data as i32;
    p = unsafe { p.offset(2 as i32 as isize) };
    let fresh5 = p;
    p = unsafe { p.offset(1) };
    if unsafe { *fresh5 as i32 } != 'T' as i32 {
        return t;
    }
    data = atol10(p, 2 as i32 as size_t) as int64_t;
    if data < 0 as i32 as i64 || data > 23 as i32 as i64 {
        return t;
    }
    tm.tm_hour = data as i32;
    p = unsafe { p.offset(2 as i32 as isize) };
    let fresh6 = p;
    p = unsafe { p.offset(1) };
    if unsafe { *fresh6 as i32 } != ':' as i32 {
        return t;
    }
    data = atol10(p, 2 as i32 as size_t) as int64_t;
    if data < 0 as i32 as i64 || data > 59 as i32 as i64 {
        return t;
    }
    tm.tm_min = data as i32;
    p = unsafe { p.offset(2 as i32 as isize) };
    let fresh7 = p;
    p = unsafe { p.offset(1) };
    if unsafe { *fresh7 as i32 } != ':' as i32 {
        return t;
    }
    data = atol10(p, 2 as i32 as size_t) as int64_t;
    if data < 0 as i32 as i64 || data > 60 as i32 as i64 {
        return t;
    }
    tm.tm_sec = data as i32;
    t = time_from_tm(&mut tm);
    return t;
}

unsafe fn heap_add_entry(
    mut a: *mut archive_read,
    mut heap: *mut heap_queue,
    mut file: *mut xar_file,
) -> i32 {
    let mut file_id: uint64_t = 0;
    let mut parent_id: uint64_t = 0;
    let mut hole: i32 = 0;
    let mut parent: i32 = 0;
    let mut safe_heap = unsafe { &mut *heap };
    let mut safe_a = unsafe { &mut *a };
    let mut safe_file = unsafe { &mut *file };
    /* Expand our pending files list as necessary. */
    if safe_heap.used >= safe_heap.allocated {
        let mut new_pending_files: *mut *mut xar_file = 0 as *mut *mut xar_file;
        let mut new_size: i32 = 0;
        if safe_heap.allocated < 1024 as i32 {
            new_size = 1024 as i32
        } else {
            new_size = safe_heap.allocated * 2 as i32
        }
        /* Overflow might keep us from growing the list. */
        if new_size <= safe_heap.allocated {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                12 as i32,
                b"Out of memory\x00" as *const u8
            );
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }
        new_pending_files = malloc_safe(
            (new_size as u64).wrapping_mul(::std::mem::size_of::<*mut xar_file>() as u64),
        ) as *mut *mut xar_file;
        if new_pending_files.is_null() {
            archive_set_error_safe!(
                &mut (*a).archive as *mut archive,
                12 as i32,
                b"Out of memory\x00" as *const u8
            );
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }
        if safe_heap.allocated != 0 {
            memcpy_safe(
                new_pending_files as *mut (),
                safe_heap.files as *const (),
                (safe_heap.allocated as u64)
                    .wrapping_mul(::std::mem::size_of::<*mut xar_file>() as u64),
            );
            free_safe(safe_heap.files as *mut ());
        }
        safe_heap.files = new_pending_files;
        safe_heap.allocated = new_size
    }
    file_id = safe_file.id;
    /*
     * Start with hole at end, walk it up tree to find insertion point.
     */
    let fresh8 = safe_heap.used;
    safe_heap.used = safe_heap.used + 1;
    hole = fresh8;
    while hole > 0 as i32 {
        parent = (hole - 1 as i32) / 2 as i32;
        parent_id = unsafe { (**safe_heap.files.offset(parent as isize)) }.id;
        if file_id >= parent_id {
            unsafe {
                let ref mut fresh9 = *safe_heap.files.offset(hole as isize);
                *fresh9 = file;
            }
            return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
        }
        /* Move parent into hole <==> move hole up tree. */
        unsafe {
            let ref mut fresh10 = *(*heap).files.offset(hole as isize);
            *fresh10 = *safe_heap.files.offset(parent as isize);
        }
        hole = parent
    }
    unsafe {
        let ref mut fresh11 = *safe_heap.files.offset(0 as i32 as isize);
        *fresh11 = file;
    }
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn heap_get_entry(mut heap: *mut heap_queue) -> *mut xar_file {
    let mut a_id: uint64_t = 0;
    let mut b_id: uint64_t = 0;
    let mut c_id: uint64_t = 0;
    let mut a: i32 = 0;
    let mut b: i32 = 0;
    let mut c: i32 = 0;
    let mut r: *mut xar_file = 0 as *mut xar_file;
    let mut tmp: *mut xar_file = 0 as *mut xar_file;
    let mut safe_heap = unsafe { &mut *heap };
    if safe_heap.used < 1 as i32 {
        return 0 as *mut xar_file;
    }
    /*
     * The first file in the list is the earliest; we'll return this.
     */
    r = unsafe { *safe_heap.files.offset(0 as i32 as isize) };
    /*
     * Move the last item in the heap to the root of the tree
     */
    safe_heap.used -= 1;
    unsafe {
        let ref mut fresh12 = *safe_heap.files.offset(0 as i32 as isize);
        *fresh12 = *safe_heap.files.offset(safe_heap.used as isize);
    }

    /*
     * Rebalance the heap.
     */
    a = 0 as i32; /* Starting element and its heap key */
    a_id = unsafe { (**safe_heap.files.offset(a as isize)).id }; /* First child */
    loop {
        b = a + a + 1 as i32; /* Use second child if it is smaller. */
        if b >= safe_heap.used {
            return r;
        }
        b_id = unsafe { (**safe_heap.files.offset(b as isize)).id };
        c = b + 1 as i32;
        if c < safe_heap.used {
            c_id = unsafe { (**safe_heap.files.offset(c as isize)).id };
            if c_id < b_id {
                b = c;
                b_id = c_id
            }
        }
        if a_id <= b_id {
            return r;
        }
        tmp = unsafe { *safe_heap.files.offset(a as isize) };
        unsafe {
            let ref mut fresh13 = *safe_heap.files.offset(a as isize);
            *fresh13 = *safe_heap.files.offset(b as isize);
            let ref mut fresh14 = *safe_heap.files.offset(b as isize);
            *fresh14 = tmp;
        }
        a = b
    }
}

unsafe fn add_link(mut a: *mut archive_read, mut xar: *mut xar, mut file: *mut xar_file) -> i32 {
    let mut hdlink: *mut hdlink = 0 as *mut hdlink;
    let mut safe_xar = unsafe { &mut *xar };
    hdlink = safe_xar.hdlink_list;
    let mut safe_hdlink = unsafe { &mut *hdlink };
    let mut safe_file = unsafe { &mut *file };
    let mut safe_a = unsafe { &mut *a };
    while !hdlink.is_null() {
        if safe_hdlink.id == safe_file.link {
            safe_file.hdnext = safe_hdlink.files;
            safe_hdlink.cnt += 1;
            safe_hdlink.files = file;
            return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
        }
        hdlink = safe_hdlink.next;
        safe_hdlink = unsafe { &mut *hdlink };
    }
    hdlink = malloc_safe(::std::mem::size_of::<hdlink>() as u64) as *mut hdlink;
    safe_hdlink = unsafe { &mut *hdlink };
    if hdlink.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            12 as i32,
            b"Out of memory\x00" as *const u8
        );
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    safe_file.hdnext = 0 as *mut xar_file;
    safe_hdlink.id = safe_file.link;
    safe_hdlink.cnt = 1 as i32;
    safe_hdlink.files = file;
    safe_hdlink.next = safe_xar.hdlink_list;
    safe_xar.hdlink_list = hdlink;
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn _checksum_init(mut sumwrk: *mut chksumwork, mut sum_alg: i32) {
    unsafe { (*sumwrk).alg = sum_alg };
    match sum_alg {
        CKSUM_SHA1 => {
            unsafe {
                __archive_digest
                    .sha1init
                    .expect("non-null function pointer")(&mut (*sumwrk).sha1ctx)
            };
        }
        CKSUM_MD5 => {
            unsafe {
                __archive_digest.md5init.expect("non-null function pointer")(&mut (*sumwrk).md5ctx)
            };
        }
        CKSUM_NONE | _ => {}
    };
}

unsafe fn _checksum_update(mut sumwrk: *mut chksumwork, mut buff: *const (), mut size: size_t) {
    let mut safe_sumwrk = unsafe { &mut *sumwrk };
    match safe_sumwrk.alg {
        CKSUM_SHA1 => {
            unsafe {
                __archive_digest
                    .sha1update
                    .expect("non-null function pointer")(
                    &mut safe_sumwrk.sha1ctx, buff, size
                )
            };
        }
        CKSUM_MD5 => {
            unsafe {
                __archive_digest
                    .md5update
                    .expect("non-null function pointer")(
                    &mut safe_sumwrk.md5ctx, buff, size
                )
            };
        }
        CKSUM_NONE | _ => {}
    };
}

unsafe fn _checksum_final(mut sumwrk: *mut chksumwork, mut val: *const (), mut len: size_t) -> i32 {
    let mut sum: [u8; 20] = [0; 20];
    let mut r: i32 = ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
    let mut safe_sumwrk = unsafe { &mut *sumwrk };
    match safe_sumwrk.alg {
        CKSUM_SHA1 => {
            unsafe {
                __archive_digest
                    .sha1final
                    .expect("non-null function pointer")(
                    &mut safe_sumwrk.sha1ctx,
                    sum.as_mut_ptr() as *mut (),
                );
            }
            if len != 20 as i32 as u64
                || memcmp_safe(val, sum.as_mut_ptr() as *const (), SHA1_SIZE as u64) != 0 as i32
            {
                r = ARCHIVE_XAR_DEFINED_PARAM.archive_failed
            }
        }
        CKSUM_MD5 => {
            unsafe {
                __archive_digest
                    .md5final
                    .expect("non-null function pointer")(
                    &mut safe_sumwrk.md5ctx,
                    sum.as_mut_ptr() as *mut (),
                );
            }
            if len != 16 as i32 as u64
                || memcmp_safe(val, sum.as_mut_ptr() as *const (), MD5_SIZE as u64) != 0 as i32
            {
                r = ARCHIVE_XAR_DEFINED_PARAM.archive_failed
            }
        }
        CKSUM_NONE | _ => {}
    }
    return r;
}

unsafe fn checksum_init(mut a: *mut archive_read, mut a_sum_alg: i32, mut e_sum_alg: i32) {
    let mut xar: *mut xar = 0 as *mut xar;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    _checksum_init(&mut safe_xar.a_sumwrk, a_sum_alg);
    _checksum_init(&mut safe_xar.e_sumwrk, e_sum_alg);
}

unsafe fn checksum_update(
    mut a: *mut archive_read,
    mut abuff: *const (),
    mut asize: size_t,
    mut ebuff: *const (),
    mut esize: size_t,
) {
    let mut xar: *mut xar = 0 as *mut xar;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    _checksum_update(&mut safe_xar.a_sumwrk, abuff, asize);
    _checksum_update(&mut safe_xar.e_sumwrk, ebuff, esize);
}

unsafe fn checksum_final(
    mut a: *mut archive_read,
    mut a_sum_val: *const (),
    mut a_sum_len: size_t,
    mut e_sum_val: *const (),
    mut e_sum_len: size_t,
) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    let mut r: i32 = 0;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    let mut safe_a = unsafe { &mut *a };
    r = _checksum_final(&mut safe_xar.a_sumwrk, a_sum_val, a_sum_len);
    if r == ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        r = _checksum_final(&mut safe_xar.e_sumwrk, e_sum_val, e_sum_len)
    }
    if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
            b"Sumcheck error\x00" as *const u8
        );
    }
    return r;
}

unsafe fn decompression_init(mut a: *mut archive_read, mut encoding: enctype) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    let mut detail: *const u8 = 0 as *const u8;
    let mut r: i32 = 0;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    safe_xar.rd_encoding = encoding;
    let mut safe_a = unsafe { &mut *a };
    match encoding as u32 {
        NONE => {}
        GZIP => {
            if safe_xar.stream_valid != 0 {
                r = inflateReset_safe(&mut safe_xar.stream)
            } else {
                r = inflateInit__safe(
                    &mut safe_xar.stream,
                    b"1.2.11\x00" as *const u8,
                    ::std::mem::size_of::<z_stream_s>() as u64 as i32,
                )
            }
            if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                archive_set_error_safe!(
                    &mut safe_a.archive as *mut archive,
                    -(1 as i32),
                    b"Couldn\'t initialize zlib stream.\x00" as *const u8
                );
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
            safe_xar.stream_valid = 1 as i32;
            safe_xar.stream.total_in = 0 as i32 as uLong;
            safe_xar.stream.total_out = 0 as i32 as uLong
        }
        BZIP2 => match () {
            #[cfg(HAVE_BZLIB_H)]
            _ => {
                if safe_xar.bzstream_valid != 0 {
                    BZ2_bzDecompressEnd_safe(&mut safe_xar.bzstream);
                    safe_xar.bzstream_valid = 0 as i32
                }
                r = BZ2_bzDecompressInit_safe(&mut safe_xar.bzstream, 0 as i32, 0 as i32);
                if r == -(3 as i32) {
                    r = BZ2_bzDecompressInit_safe(&mut safe_xar.bzstream, 0 as i32, 1 as i32)
                }
                if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                    let mut err: i32 = ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc;
                    detail = 0 as *const u8;
                    match r {
                        -2 => detail = b"invalid setup parameter\x00" as *const u8,
                        -3 => {
                            err = ARCHIVE_XAR_DEFINED_PARAM.enomem;
                            detail = b"out of memory\x00" as *const u8
                        }
                        -9 => detail = b"mis-compiled library\x00" as *const u8,
                        _ => {}
                    }

                    archive_set_error_safe!(
                        &mut safe_a.archive as *mut archive,
                        err,
                        b"Internal error initializing decompressor: %s\x00" as *const u8
                            as *const u8,
                        if detail.is_null() {
                            b"??\x00" as *const u8
                        } else {
                            detail
                        }
                    );

                    safe_xar.bzstream_valid = 0 as i32;
                    return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                }
                safe_xar.bzstream_valid = 1 as i32;
                safe_xar.bzstream.total_in_lo32 = 0 as i32 as u32;
                safe_xar.bzstream.total_in_hi32 = 0 as i32 as u32;
                safe_xar.bzstream.total_out_lo32 = 0 as i32 as u32;
                safe_xar.bzstream.total_out_hi32 = 0 as i32 as u32
            }
            #[cfg(not(HAVE_BZLIB_H))]
            _ => {}
        },
        XZ | LZMA => {
            match () {
                #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
                _ => {
                    let LZMA_MEMLIMIT: u64 = 18446744073709551615;
                    match () {
                        #[cfg(not(LZMA_VERSION_MAJOR))]
                        _ => {
                            let LZMA_MEMLIMIT = 1 << 30;
                        }
                        _ => {}
                    }
                    /* Effectively disable the limiter. */
                    if safe_xar.lzstream_valid != 0 {
                        lzma_end_safe(&mut safe_xar.lzstream); /* memlimit */
                        safe_xar.lzstream_valid = 0 as i32
                    }
                    if safe_xar.entry_encoding as u32 == XZ as i32 as u32 {
                        r = lzma_stream_decoder_safe(
                            &mut safe_xar.lzstream,
                            LZMA_MEMLIMIT as u64,
                            0x8 as u32,
                        ) as i32
                    } else {
                        r = lzma_alone_decoder_safe(
                            &mut safe_xar.lzstream,
                            18446744073709551615 as u64,
                        ) as i32
                    }
                    if r != LZMA_OK as i32 {
                        match r {
                            5 => {
                                archive_set_error_safe!(&mut safe_a.archive as *mut archive,
                                                       ARCHIVE_XAR_DEFINED_PARAM.enomem,
                                                       b"Internal error initializing compression library: Cannot allocate memory\x00"
                                                           as *const u8 as
                                                           *const u8);
                            }
                            8 => {
                                archive_set_error_safe!(&mut safe_a.archive as *mut archive,
                                                       ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                                                       b"Internal error initializing compression library: Invalid or unsupported options\x00"
                                                           as *const u8 as
                                                           *const u8);
                            }
                            _ => {
                                archive_set_error_safe!(
                                    &mut safe_a.archive as *mut archive,
                                    ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                                    b"Internal error initializing lzma library\x00" as *const u8
                                        as *const u8
                                );
                            }
                        }
                        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                    }
                    safe_xar.lzstream_valid = 1 as i32;
                    safe_xar.lzstream.total_in = 0 as i32 as uint64_t;
                    safe_xar.lzstream.total_out = 0 as i32 as uint64_t
                }
                #[cfg(not(any(HAVE_LZMA_H, HAVE_LIBLZMA)))]
                _ => {}
            }
        }
        _ => {
            /*
             * Unsupported compression.
             */
            match safe_xar.entry_encoding as u32 {
                BZIP2 => detail = b"bzip2\x00" as *const u8,
                LZMA => detail = b"lzma\x00" as *const u8,
                XZ => detail = b"xz\x00" as *const u8,
                _ => detail = b"??\x00" as *const u8,
            }

            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                b"%s compression not supported on this platform\x00" as *const u8,
                detail
            );

            return ARCHIVE_XAR_DEFINED_PARAM.archive_failed;
        }
    }
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn decompress(
    mut a: *mut archive_read,
    mut buff: *mut *const (),
    mut outbytes: *mut size_t,
    mut b: *const (),
    mut used: *mut size_t,
) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    let mut outbuff: *mut () = 0 as *mut ();
    let mut avail_in: size_t = 0;
    let mut avail_out: size_t = 0;
    let mut r: i32 = 0;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    let mut safe_used = unsafe { &mut *used };
    let mut safe_buff = unsafe { &mut *buff };
    let mut safe_a = unsafe { &mut *a };
    let mut safe_outbytes = unsafe { &mut *outbytes };
    avail_in = *safe_used;
    outbuff = *safe_buff as uintptr_t as *mut ();
    if outbuff.is_null() {
        if safe_xar.outbuff.is_null() {
            safe_xar.outbuff = malloc_safe((1024 as i32 * 64 as i32) as u64) as *mut u8;
            if safe_xar.outbuff.is_null() {
                archive_set_error_safe!(
                    &mut safe_a.archive as *mut archive,
                    12 as i32,
                    b"Couldn\'t allocate memory for out buffer\x00" as *const u8
                );
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        outbuff = safe_xar.outbuff as *mut ();
        *safe_buff = outbuff;
        avail_out = (1024 as i32 * 64 as i32) as size_t
    } else {
        avail_out = *safe_outbytes
    }
    match safe_xar.rd_encoding as u32 {
        GZIP => {
            safe_xar.stream.next_in = b as uintptr_t as *mut Bytef;
            safe_xar.stream.avail_in = avail_in as uInt;
            safe_xar.stream.next_out = outbuff as *mut u8;
            safe_xar.stream.avail_out = avail_out as uInt;
            r = inflate_safe(&mut safe_xar.stream, 0 as i32);
            match r {
                0 => {}
                1 => {}
                _ => {
                    archive_set_error_safe!(
                        &mut safe_a.archive as *mut archive,
                        -(1 as i32),
                        b"File decompression failed (%d)\x00" as *const u8,
                        r
                    );

                    return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                }
            }
            *safe_used = avail_in.wrapping_sub(safe_xar.stream.avail_in as u64);
            *safe_outbytes = avail_out.wrapping_sub(safe_xar.stream.avail_out as u64)
        }
        BZIP2 => {
            match () {
                #[cfg(HAVE_BZLIB_H)]
                _ => {
                    safe_xar.bzstream.next_in = b as uintptr_t as *mut u8;
                    safe_xar.bzstream.avail_in = avail_in as u32;
                    safe_xar.bzstream.next_out = outbuff as *mut u8;
                    safe_xar.bzstream.avail_out = avail_out as u32;
                    r = BZ2_bzDecompress_safe(&mut safe_xar.bzstream);
                    match r {
                        4 => {
                            /* Found end of stream. */
                            match BZ2_bzDecompressEnd_safe(&mut safe_xar.bzstream) {
                                0 => {}
                                _ => {
                                    archive_set_error_safe!(
                                        &mut safe_a.archive as *mut archive,
                                        ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                                        b"Failed to clean up decompressor\x00" as *const u8
                                            as *const u8
                                    );
                                    return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                                }
                            }
                            safe_xar.bzstream_valid = 0 as i32
                        }
                        0 => {}
                        _ => {
                            archive_set_error_safe!(
                                &mut safe_a.archive as *mut archive,
                                ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                                b"bzip decompression failed\x00" as *const u8
                            );
                            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                        }
                    }
                    *safe_used = avail_in.wrapping_sub(safe_xar.bzstream.avail_in as u64);
                    *safe_outbytes = avail_out.wrapping_sub(safe_xar.bzstream.avail_out as u64)
                }
                _ => {}
            }
        }
        LZMA | XZ => {
            match () {
                #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
                _ => {
                    safe_xar.lzstream.next_in = b as *const uint8_t;
                    safe_xar.lzstream.avail_in = avail_in;
                    safe_xar.lzstream.next_out = outbuff as *mut u8;
                    safe_xar.lzstream.avail_out = avail_out;
                    r = lzma_code_safe(&mut safe_xar.lzstream, LZMA_RUN) as i32;
                    match r as u32 {
                        LZMA_STREAM_END => {
                            /* Found end of stream. */
                            lzma_end_safe(&mut safe_xar.lzstream);
                            safe_xar.lzstream_valid = 0 as i32
                        }
                        LZMA_OK => {}
                        _ => {
                            archive_set_error_safe!(
                                &mut safe_a.archive as *mut archive,
                                ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                                b"%s decompression failed(%d)\x00" as *const u8,
                                if safe_xar.entry_encoding as u32 == XZ as i32 as u32 {
                                    b"xz\x00" as *const u8
                                } else {
                                    b"lzma\x00" as *const u8
                                },
                                r
                            );

                            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                        }
                    }
                    *safe_used = avail_in.wrapping_sub(safe_xar.lzstream.avail_in);
                    *safe_outbytes = avail_out.wrapping_sub(safe_xar.lzstream.avail_out)
                }
                _ => {}
            }
        }
        NONE | _ => {
            if outbuff == safe_xar.outbuff as *mut () {
                *safe_buff = b;
                *safe_used = avail_in;
                *safe_outbytes = avail_in
            } else {
                if avail_out > avail_in {
                    avail_out = avail_in
                }
                memcpy_safe(outbuff, b, avail_out);
                *safe_used = avail_out;
                *safe_outbytes = avail_out
            }
        }
    }
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn decompression_cleanup(mut a: *mut archive_read) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    let mut r: i32 = 0;
    xar = unsafe { (*(*a).format).data as *mut xar };
    r = 0 as i32;
    let mut safe_xar = unsafe { &mut *xar };
    let mut safe_a = unsafe { &mut *a };
    if safe_xar.stream_valid != 0 {
        if inflateEnd_safe(&mut safe_xar.stream) != 0 as i32 {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                -(1 as i32),
                b"Failed to clean up zlib decompressor\x00" as *const u8
            );
            r = ARCHIVE_XAR_DEFINED_PARAM.archive_fatal
        }
    }

    match () {
        #[cfg(HAVE_BZLIB_H)]
        _ => {
            if safe_xar.bzstream_valid != 0 {
                if BZ2_bzDecompressEnd_safe(&mut safe_xar.bzstream) != 0 as i32 {
                    archive_set_error_safe!(
                        &mut safe_a.archive as *mut archive,
                        ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                        b"Failed to clean up bzip2 decompressor\x00" as *const u8
                    );
                    r = ARCHIVE_XAR_DEFINED_PARAM.archive_fatal
                }
            }
        }
        #[cfg(not(HAVE_BZLIB_H))]
        _ => {}
    }
    match () {
        #[cfg(all(HAVE_LZMA_H, HAVE_LIBLZMA))]
        _ => {
            if safe_xar.lzstream_valid != 0 {
                lzma_end_safe(&mut safe_xar.lzstream);
            }
        }
        #[cfg(not(any(HAVE_LZMA_H, HAVE_LIBLZMA)))]
        _ => {}
    }
    return r;
}

unsafe fn checksum_cleanup(mut a: *mut archive_read) {
    let mut xar: *mut xar = 0 as *mut xar;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    _checksum_final(&mut safe_xar.a_sumwrk, 0 as *const (), 0 as i32 as size_t);
    _checksum_final(&mut safe_xar.e_sumwrk, 0 as *const (), 0 as i32 as size_t);
}

unsafe fn xmlattr_cleanup(mut list: *mut xmlattr_list) {
    let mut attr: *mut xmlattr = 0 as *mut xmlattr;
    let mut next: *mut xmlattr = 0 as *mut xmlattr;
    attr = unsafe { (*list).first };
    while !attr.is_null() {
        next = unsafe { (*attr).next };
        free_safe(unsafe { (*attr).name as *mut () });
        free_safe(unsafe { (*attr).value as *mut () });
        free_safe(attr as *mut ());
        attr = next
    }
    unsafe { (*list).first = 0 as *mut xmlattr };
    unsafe { (*list).last = &mut (*list).first };
}

unsafe fn file_new(
    mut a: *mut archive_read,
    mut xar: *mut xar,
    mut list: *mut xmlattr_list,
) -> i32 {
    let mut file: *mut xar_file = 0 as *mut xar_file;
    let mut attr: *mut xmlattr = 0 as *mut xmlattr;
    let mut safe_a = unsafe { &mut *a };
    file = calloc_safe(1 as i32 as u64, ::std::mem::size_of::<xar_file>() as u64) as *mut xar_file;
    if file.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.enomem,
            b"Out of memory\x00" as *const u8
        );
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    let mut safe_file = unsafe { &mut *file };
    let mut safe_xar = unsafe { &mut *xar };
    safe_file.parent = safe_xar.file;
    safe_file.mode = 0o777 as i32 as u32 | ARCHIVE_XAR_DEFINED_PARAM.ae_ifreg as mode_t;
    safe_file.atime = 0 as i32 as time_t;
    safe_file.mtime = 0 as i32 as time_t;
    safe_xar.file = file;
    safe_xar.xattr = 0 as *mut xattr;
    attr = unsafe { *list }.first;
    while !attr.is_null() {
        if strcmp_safe(unsafe { *attr }.name, b"id\x00" as *const u8) == 0 as i32 {
            safe_file.id = atol10(unsafe { *attr }.value, strlen_safe(unsafe { *attr }.value))
        }
        attr = unsafe { *attr }.next
    }
    safe_file.nlink = 1 as i32 as u32;
    if heap_add_entry(a, &mut safe_xar.file_queue, file) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn file_free(mut file: *mut xar_file) {
    let mut xattr: *mut xattr = 0 as *mut xattr;
    let mut safe_file = unsafe { &mut *file };
    archive_string_free_safe(&mut safe_file.pathname);
    archive_string_free_safe(&mut safe_file.symlink);
    archive_string_free_safe(&mut safe_file.uname);
    archive_string_free_safe(&mut safe_file.gname);
    archive_string_free_safe(&mut safe_file.hardlink);
    xattr = safe_file.xattr_list;
    while !xattr.is_null() {
        let mut next: *mut xattr = 0 as *mut xattr;
        next = unsafe { *xattr }.next;
        xattr_free(xattr);
        xattr = next
    }
    free_safe(file as *mut ());
}

unsafe fn xattr_new(
    mut a: *mut archive_read,
    mut xar: *mut xar,
    mut list: *mut xmlattr_list,
) -> i32 {
    let mut xattr: *mut xattr = 0 as *mut xattr;
    let mut nx: *mut *mut xattr = 0 as *mut *mut xattr;
    let mut attr: *mut xmlattr = 0 as *mut xmlattr;
    let mut safe_a = unsafe { &mut *a };
    let mut safe_xar = unsafe { &mut *xar };
    xattr = calloc_safe(1 as i32 as u64, ::std::mem::size_of::<xattr>() as u64) as *mut xattr;
    if xattr.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.enomem,
            b"Out of memory\x00" as *const u8
        );
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    safe_xar.xattr = xattr;
    attr = unsafe { (*list).first };
    let mut safe_xattr = unsafe { &mut *xattr };
    while !attr.is_null() {
        if strcmp_safe(unsafe { *attr }.name, b"id\x00" as *const u8) == 0 as i32 {
            safe_xattr.id = atol10(unsafe { *attr }.value, strlen_safe(unsafe { *attr }.value))
        }
        attr = unsafe { *attr }.next
    }
    /* Chain to xattr list. */
    nx = unsafe { &mut (*safe_xar.file).xattr_list };
    while !unsafe { (*nx).is_null() } {
        if safe_xattr.id < unsafe { (**nx).id } {
            break;
        }
        nx = unsafe { &mut (**nx).next }
    }
    safe_xattr.next = unsafe { *nx };
    unsafe { *nx = xattr };
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn xattr_free(mut xattr: *mut xattr) {
    archive_string_free_safe(&mut unsafe { *xattr }.name);
    free_safe(xattr as *mut ());
}

unsafe fn getencoding(mut list: *mut xmlattr_list) -> i32 {
    let mut attr: *mut xmlattr = 0 as *mut xmlattr;
    let mut encoding: enctype = NONE;
    attr = unsafe { *list }.first;
    while !attr.is_null() {
        if strcmp_safe(unsafe { *attr }.name, b"style\x00" as *const u8) == 0 as i32 {
            if strcmp_safe(
                unsafe { *attr }.value,
                b"application/octet-stream\x00" as *const u8,
            ) == 0 as i32
            {
                encoding = NONE
            } else if strcmp_safe(
                unsafe { *attr }.value,
                b"application/x-gzip\x00" as *const u8,
            ) == 0 as i32
            {
                encoding = GZIP
            } else if strcmp_safe(
                unsafe { *attr }.value,
                b"application/x-bzip2\x00" as *const u8,
            ) == 0 as i32
            {
                encoding = BZIP2
            } else if strcmp_safe(
                unsafe { *attr }.value,
                b"application/x-lzma\x00" as *const u8,
            ) == 0 as i32
            {
                encoding = LZMA
            } else if strcmp_safe(unsafe { *attr }.value, b"application/x-xz\x00" as *const u8)
                == 0 as i32
            {
                encoding = XZ
            }
        }
        attr = unsafe { *attr }.next
    }
    return encoding as i32;
}

unsafe fn getsumalgorithm(mut list: *mut xmlattr_list) -> i32 {
    let mut attr: *mut xmlattr = 0 as *mut xmlattr;
    let mut alg: i32 = CKSUM_NONE;
    unsafe {
        attr = (*list).first;
    }
    while !attr.is_null() {
        if strcmp_safe(unsafe { (*attr) }.name, b"style\x00" as *const u8) == 0 as i32 {
            let mut v: *const u8 = unsafe { (*attr) }.value;
            if unsafe {
                (*v.offset(0 as i32 as isize) as i32 == 'S' as i32
                    || *v.offset(0 as i32 as isize) as i32 == 's' as i32)
                    && (*v.offset(1 as i32 as isize) as i32 == 'H' as i32
                        || *v.offset(1 as i32 as isize) as i32 == 'h' as i32)
                    && (*v.offset(2 as i32 as isize) as i32 == 'A' as i32
                        || *v.offset(2 as i32 as isize) as i32 == 'a' as i32)
                    && *v.offset(3 as i32 as isize) as i32 == '1' as i32
                    && *v.offset(4 as i32 as isize) as i32 == '\u{0}' as i32
            } {
                alg = 1 as i32
            }
            if unsafe {
                (*v.offset(0 as i32 as isize) as i32 == 'M' as i32
                    || *v.offset(0 as i32 as isize) as i32 == 'm' as i32)
                    && (*v.offset(1 as i32 as isize) as i32 == 'D' as i32
                        || *v.offset(1 as i32 as isize) as i32 == 'd' as i32)
                    && *v.offset(2 as i32 as isize) as i32 == '5' as i32
                    && *v.offset(3 as i32 as isize) as i32 == '\u{0}' as i32
            } {
                alg = 2 as i32
            }
        }
        attr = unsafe { *attr }.next
    }
    return alg;
}

unsafe fn unknowntag_start(
    mut a: *mut archive_read,
    mut xar: *mut xar,
    mut name: *const u8,
) -> i32 {
    let mut tag: *mut unknown_tag = 0 as *mut unknown_tag;
    tag = malloc_safe(::std::mem::size_of::<unknown_tag>() as u64) as *mut unknown_tag;
    let mut safe_tag = unsafe { &mut *tag };
    let mut safe_a = unsafe { &mut *a };
    let mut safe_xar = unsafe { &mut *xar };
    if tag.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            12 as i32,
            b"Out of memory\x00" as *const u8
        );
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    safe_tag.next = safe_xar.unknowntags;
    safe_tag.name.s = 0 as *mut u8;
    safe_tag.name.length = 0 as i32 as size_t;
    safe_tag.name.buffer_length = 0 as i32 as size_t;
    safe_tag.name.length = 0 as i32 as size_t;
    archive_strncat_safe(
        &mut safe_tag.name,
        name as *const (),
        (if name.is_null() {
            0 as i32 as u64
        } else {
            strlen_safe(name)
        }),
    );
    if safe_xar.unknowntags.is_null() {
        safe_xar.xmlsts_unknown = safe_xar.xmlsts;
        safe_xar.xmlsts = UNKNOWN
    }
    safe_xar.unknowntags = tag;
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn unknowntag_end(mut xar: *mut xar, mut name: *const u8) {
    let mut tag: *mut unknown_tag = 0 as *mut unknown_tag;
    let mut safe_xar = unsafe { &mut *xar };
    tag = safe_xar.unknowntags;
    let mut safe_tag = unsafe { &mut *tag };
    if tag.is_null() || name.is_null() {
        return;
    }
    if strcmp_safe(safe_tag.name.s, name) == 0 as i32 {
        safe_xar.unknowntags = safe_tag.next;
        archive_string_free_safe(&mut safe_tag.name);
        free_safe(tag as *mut ());
        if safe_xar.unknowntags.is_null() {
            safe_xar.xmlsts = safe_xar.xmlsts_unknown
        }
    };
}

unsafe fn xml_start(
    mut a: *mut archive_read,
    mut name: *const u8,
    mut list: *mut xmlattr_list,
) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    let mut attr: *mut xmlattr = 0 as *mut xmlattr;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    let mut safe_file = unsafe { &mut *safe_xar.file };
    let mut safe_xattr = unsafe { &mut *safe_xar.xattr };
    safe_xar.base64text = 0 as i32;

    match safe_xar.xmlsts as u32 {
        INIT => {
            if strcmp_safe(name, b"xar\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = XAR
            } else if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        XAR => {
            if strcmp_safe(name, b"toc\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC
            } else if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        TOC => {
            if strcmp_safe(name, b"creation-time\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_CREATION_TIME
            } else if strcmp_safe(name, b"checksum\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_CHECKSUM
            } else if strcmp_safe(name, b"file\x00" as *const u8) == 0 as i32 {
                if file_new(a, xar, list) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                    return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                }
                safe_xar.xmlsts = TOC_FILE
            } else if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        TOC_CHECKSUM => {
            if strcmp_safe(name, b"offset\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_CHECKSUM_OFFSET
            } else if strcmp_safe(name, b"size\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_CHECKSUM_SIZE
            } else if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        TOC_FILE => {
            if strcmp_safe(name, b"file\x00" as *const u8) == 0 as i32 {
                if file_new(a, xar, list) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                    return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                }
            } else if strcmp_safe(name, b"data\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA
            } else if strcmp_safe(name, b"ea\x00" as *const u8) == 0 as i32 {
                if xattr_new(a, xar, list) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                    return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                }
                safe_xar.xmlsts = FILE_EA
            } else if strcmp_safe(name, b"ctime\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_CTIME
            } else if strcmp_safe(name, b"mtime\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_MTIME
            } else if strcmp_safe(name, b"atime\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_ATIME
            } else if strcmp_safe(name, b"group\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_GROUP
            } else if strcmp_safe(name, b"gid\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_GID
            } else if strcmp_safe(name, b"user\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_USER
            } else if strcmp_safe(name, b"uid\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_UID
            } else if strcmp_safe(name, b"mode\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_MODE
            } else if strcmp_safe(name, b"device\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DEVICE
            } else if strcmp_safe(name, b"deviceno\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DEVICENO
            } else if strcmp_safe(name, b"inode\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_INODE
            } else if strcmp_safe(name, b"link\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_LINK
            } else if strcmp_safe(name, b"type\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_TYPE;
                attr = unsafe { (*list).first };
                let mut safe_attr = unsafe { &mut *((*list).first) };
                while !attr.is_null() {
                    if !(strcmp_safe(safe_attr.name, b"link\x00" as *const u8) != 0 as i32) {
                        if strcmp_safe(safe_attr.value, b"original\x00" as *const u8) == 0 as i32 {
                            safe_file.hdnext = safe_xar.hdlink_orgs;
                            safe_xar.hdlink_orgs = safe_xar.file
                        } else {
                            safe_file.link =
                                atol10(safe_attr.value, strlen_safe(safe_attr.value)) as u32;
                            if safe_file.link > 0 as i32 as u32 {
                                if add_link(a, xar, safe_xar.file)
                                    != ARCHIVE_XAR_DEFINED_PARAM.archive_ok
                                {
                                    return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                                }
                            }
                        }
                    }
                    attr = unsafe { (*attr).next };
                    safe_attr = unsafe { &mut *(safe_attr.next) };
                }
            } else if strcmp_safe(name, b"name\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_NAME;
                attr = unsafe { (*list).first };
                let mut safe_attr = unsafe { &mut *((*list).first) };
                while !attr.is_null() {
                    if strcmp_safe(safe_attr.name, b"enctype\x00" as *const u8) == 0 as i32
                        && strcmp_safe(safe_attr.value, b"base64\x00" as *const u8) == 0 as i32
                    {
                        safe_xar.base64text = 1 as i32
                    }
                    safe_attr = unsafe { &mut *(safe_attr.next) };
                    attr = unsafe { (*attr).next }
                }
            } else if strcmp_safe(name, b"acl\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_ACL
            } else if strcmp_safe(name, b"flags\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_FLAGS
            } else if strcmp_safe(name, b"ext2\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            } else if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        FILE_DATA => {
            if strcmp_safe(name, b"length\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA_LENGTH
            } else if strcmp_safe(name, b"offset\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA_OFFSET
            } else if strcmp_safe(name, b"size\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA_SIZE
            } else if strcmp_safe(name, b"encoding\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA_ENCODING;
                safe_file.encoding = getencoding(list) as enctype
            } else if strcmp_safe(name, b"archived-checksum\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA_A_CHECKSUM;
                safe_file.a_sum.alg = getsumalgorithm(list)
            } else if strcmp_safe(name, b"extracted-checksum\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA_E_CHECKSUM;
                safe_file.e_sum.alg = getsumalgorithm(list)
            } else if strcmp_safe(name, b"content\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA_CONTENT
            } else if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        FILE_DEVICE => {
            if strcmp_safe(name, b"major\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DEVICE_MAJOR
            } else if strcmp_safe(name, b"minor\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DEVICE_MINOR
            } else if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        FILE_DATA_CONTENT => {
            if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        FILE_EA => {
            if strcmp_safe(name, b"length\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA_LENGTH
            } else if strcmp_safe(name, b"offset\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA_OFFSET
            } else if strcmp_safe(name, b"size\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA_SIZE
            } else if strcmp_safe(name, b"encoding\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA_ENCODING;
                safe_xattr.encoding = getencoding(list) as enctype
            } else if strcmp_safe(name, b"archived-checksum\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA_A_CHECKSUM
            } else if strcmp_safe(name, b"extracted-checksum\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA_E_CHECKSUM
            } else if strcmp_safe(name, b"name\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA_NAME
            } else if strcmp_safe(name, b"fstype\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA_FSTYPE
            } else if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        FILE_ACL => {
            if strcmp_safe(name, b"appleextended\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_ACL_APPLEEXTENDED
            } else if strcmp_safe(name, b"default\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_ACL_DEFAULT
            } else if strcmp_safe(name, b"access\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_ACL_ACCESS
            } else if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        FILE_FLAGS => {
            if xml_parse_file_flags(xar, name) == 0 {
                if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                    return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                }
            }
        }
        FILE_EXT2 => {
            if xml_parse_file_ext2(xar, name) == 0 {
                if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                    return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
                }
            }
        }
        TOC_CREATION_TIME
        | TOC_CHECKSUM_OFFSET
        | TOC_CHECKSUM_SIZE
        | FILE_DATA_LENGTH
        | FILE_DATA_OFFSET
        | FILE_DATA_SIZE
        | FILE_DATA_ENCODING
        | FILE_DATA_A_CHECKSUM
        | FILE_DATA_E_CHECKSUM
        | FILE_EA_LENGTH
        | FILE_EA_OFFSET
        | FILE_EA_SIZE
        | FILE_EA_ENCODING
        | FILE_EA_A_CHECKSUM
        | FILE_EA_E_CHECKSUM
        | FILE_EA_NAME
        | FILE_EA_FSTYPE
        | FILE_CTIME
        | FILE_MTIME
        | FILE_ATIME
        | FILE_GROUP
        | FILE_GID
        | FILE_USER
        | FILE_UID
        | FILE_INODE
        | FILE_DEVICE_MAJOR
        | FILE_DEVICE_MINOR
        | FILE_DEVICENO
        | FILE_MODE
        | FILE_TYPE
        | FILE_LINK
        | FILE_NAME
        | FILE_ACL_DEFAULT
        | FILE_ACL_ACCESS
        | FILE_ACL_APPLEEXTENDED
        | FILE_FLAGS_USER_NODUMP
        | FILE_FLAGS_USER_IMMUTABLE
        | FILE_FLAGS_USER_APPEND
        | FILE_FLAGS_USER_OPAQUE
        | FILE_FLAGS_USER_NOUNLINK
        | FILE_FLAGS_SYS_ARCHIVED
        | FILE_FLAGS_SYS_IMMUTABLE
        | FILE_FLAGS_SYS_APPEND
        | FILE_FLAGS_SYS_NOUNLINK
        | FILE_FLAGS_SYS_SNAPSHOT
        | FILE_EXT2_SecureDeletion
        | FILE_EXT2_Undelete
        | FILE_EXT2_Compress
        | FILE_EXT2_Synchronous
        | FILE_EXT2_Immutable
        | FILE_EXT2_AppendOnly
        | FILE_EXT2_NoDump
        | FILE_EXT2_NoAtime
        | FILE_EXT2_CompDirty
        | FILE_EXT2_CompBlock
        | FILE_EXT2_NoCompBlock
        | FILE_EXT2_CompError
        | FILE_EXT2_BTree
        | FILE_EXT2_HashIndexed
        | FILE_EXT2_iMagic
        | FILE_EXT2_Journaled
        | FILE_EXT2_NoTail
        | FILE_EXT2_DirSync
        | FILE_EXT2_TopDir
        | FILE_EXT2_Reserved
        | UNKNOWN => {
            if unknowntag_start(a, xar, name) != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
            }
        }
        _ => {}
    }
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

unsafe fn xml_end(mut userData: *mut (), mut name: *const u8) {
    let mut a: *mut archive_read = 0 as *mut archive_read;
    let mut xar: *mut xar = 0 as *mut xar;
    a = userData as *mut archive_read;
    xar = unsafe { (*(*a).format) }.data as *mut xar;
    let mut safe_xar = unsafe { &mut *xar };
    match safe_xar.xmlsts as u32 {
        XAR => {
            if strcmp_safe(name, b"xar\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = INIT
            }
        }
        TOC => {
            if strcmp_safe(name, b"toc\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = XAR
            }
        }
        TOC_CREATION_TIME => {
            if strcmp_safe(name, b"creation-time\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC
            }
        }
        TOC_CHECKSUM => {
            if strcmp_safe(name, b"checksum\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC
            }
        }
        TOC_CHECKSUM_OFFSET => {
            if strcmp_safe(name, b"offset\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_CHECKSUM
            }
        }
        TOC_CHECKSUM_SIZE => {
            if strcmp_safe(name, b"size\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_CHECKSUM
            }
        }
        TOC_FILE => {
            if strcmp_safe(name, b"file\x00" as *const u8) == 0 as i32 {
                if !unsafe { *safe_xar.file }.parent.is_null()
                    && unsafe { *safe_xar.file }.mode & ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t
                        == ARCHIVE_XAR_DEFINED_PARAM.ae_ifdir as mode_t
                {
                    unsafe { (*unsafe { *safe_xar.file }.parent).subdirs += 1 }
                }
                safe_xar.file = unsafe { *safe_xar.file }.parent;
                if safe_xar.file.is_null() {
                    safe_xar.xmlsts = TOC
                }
            }
        }
        FILE_DATA => {
            if strcmp_safe(name, b"data\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_DATA_LENGTH => {
            if strcmp_safe(name, b"length\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA
            }
        }
        FILE_DATA_OFFSET => {
            if strcmp_safe(name, b"offset\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA
            }
        }
        FILE_DATA_SIZE => {
            if strcmp_safe(name, b"size\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA
            }
        }
        FILE_DATA_ENCODING => {
            if strcmp_safe(name, b"encoding\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA
            }
        }
        FILE_DATA_A_CHECKSUM => {
            if strcmp_safe(name, b"archived-checksum\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA
            }
        }
        FILE_DATA_E_CHECKSUM => {
            if strcmp_safe(name, b"extracted-checksum\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA
            }
        }
        FILE_DATA_CONTENT => {
            if strcmp_safe(name, b"content\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DATA
            }
        }
        FILE_EA => {
            if strcmp_safe(name, b"ea\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE;
                safe_xar.xattr = 0 as *mut xattr
            }
        }
        FILE_EA_LENGTH => {
            if strcmp_safe(name, b"length\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA
            }
        }
        FILE_EA_OFFSET => {
            if strcmp_safe(name, b"offset\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA
            }
        }
        FILE_EA_SIZE => {
            if strcmp_safe(name, b"size\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA
            }
        }
        FILE_EA_ENCODING => {
            if strcmp_safe(name, b"encoding\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA
            }
        }
        FILE_EA_A_CHECKSUM => {
            if strcmp_safe(name, b"archived-checksum\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA
            }
        }
        FILE_EA_E_CHECKSUM => {
            if strcmp_safe(name, b"extracted-checksum\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA
            }
        }
        FILE_EA_NAME => {
            if strcmp_safe(name, b"name\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA
            }
        }
        FILE_EA_FSTYPE => {
            if strcmp_safe(name, b"fstype\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EA
            }
        }
        FILE_CTIME => {
            if strcmp_safe(name, b"ctime\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_MTIME => {
            if strcmp_safe(name, b"mtime\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_ATIME => {
            if strcmp_safe(name, b"atime\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_GROUP => {
            if strcmp_safe(name, b"group\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_GID => {
            if strcmp_safe(name, b"gid\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_USER => {
            if strcmp_safe(name, b"user\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_UID => {
            if strcmp_safe(name, b"uid\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_MODE => {
            if strcmp_safe(name, b"mode\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_DEVICE => {
            if strcmp_safe(name, b"device\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_DEVICE_MAJOR => {
            if strcmp_safe(name, b"major\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DEVICE
            }
        }
        FILE_DEVICE_MINOR => {
            if strcmp_safe(name, b"minor\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_DEVICE
            }
        }
        FILE_DEVICENO => {
            if strcmp_safe(name, b"deviceno\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_INODE => {
            if strcmp_safe(name, b"inode\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_LINK => {
            if strcmp_safe(name, b"link\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_TYPE => {
            if strcmp_safe(name, b"type\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_NAME => {
            if strcmp_safe(name, b"name\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_ACL => {
            if strcmp_safe(name, b"acl\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_ACL_DEFAULT => {
            if strcmp_safe(name, b"default\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_ACL
            }
        }
        FILE_ACL_ACCESS => {
            if strcmp_safe(name, b"access\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_ACL
            }
        }
        FILE_ACL_APPLEEXTENDED => {
            if strcmp_safe(name, b"appleextended\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_ACL
            }
        }
        FILE_FLAGS => {
            if strcmp_safe(name, b"flags\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_FLAGS_USER_NODUMP => {
            if strcmp_safe(name, b"UserNoDump\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_FLAGS
            }
        }
        FILE_FLAGS_USER_IMMUTABLE => {
            if strcmp_safe(name, b"UserImmutable\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_FLAGS
            }
        }
        FILE_FLAGS_USER_APPEND => {
            if strcmp_safe(name, b"UserAppend\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_FLAGS
            }
        }
        FILE_FLAGS_USER_OPAQUE => {
            if strcmp_safe(name, b"UserOpaque\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_FLAGS
            }
        }
        FILE_FLAGS_USER_NOUNLINK => {
            if strcmp_safe(name, b"UserNoUnlink\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_FLAGS
            }
        }
        FILE_FLAGS_SYS_ARCHIVED => {
            if strcmp_safe(name, b"SystemArchived\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_FLAGS
            }
        }
        FILE_FLAGS_SYS_IMMUTABLE => {
            if strcmp_safe(name, b"SystemImmutable\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_FLAGS
            }
        }
        FILE_FLAGS_SYS_APPEND => {
            if strcmp_safe(name, b"SystemAppend\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_FLAGS
            }
        }
        FILE_FLAGS_SYS_NOUNLINK => {
            if strcmp_safe(name, b"SystemNoUnlink\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_FLAGS
            }
        }
        FILE_FLAGS_SYS_SNAPSHOT => {
            if strcmp_safe(name, b"SystemSnapshot\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_FLAGS
            }
        }
        FILE_EXT2 => {
            if strcmp_safe(name, b"ext2\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = TOC_FILE
            }
        }
        FILE_EXT2_SecureDeletion => {
            if strcmp_safe(name, b"SecureDeletion\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_Undelete => {
            if strcmp_safe(name, b"Undelete\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_Compress => {
            if strcmp_safe(name, b"Compress\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_Synchronous => {
            if strcmp_safe(name, b"Synchronous\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_Immutable => {
            if strcmp_safe(name, b"Immutable\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_AppendOnly => {
            if strcmp_safe(name, b"AppendOnly\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_NoDump => {
            if strcmp_safe(name, b"NoDump\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_NoAtime => {
            if strcmp_safe(name, b"NoAtime\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_CompDirty => {
            if strcmp_safe(name, b"CompDirty\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_CompBlock => {
            if strcmp_safe(name, b"CompBlock\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_NoCompBlock => {
            if strcmp_safe(name, b"NoCompBlock\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_CompError => {
            if strcmp_safe(name, b"CompError\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_BTree => {
            if strcmp_safe(name, b"BTree\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_HashIndexed => {
            if strcmp_safe(name, b"HashIndexed\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_iMagic => {
            if strcmp_safe(name, b"iMagic\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_Journaled => {
            if strcmp_safe(name, b"Journaled\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_NoTail => {
            if strcmp_safe(name, b"NoTail\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_DirSync => {
            if strcmp_safe(name, b"DirSync\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_TopDir => {
            if strcmp_safe(name, b"TopDir\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        FILE_EXT2_Reserved => {
            if strcmp_safe(name, b"Reserved\x00" as *const u8) == 0 as i32 {
                safe_xar.xmlsts = FILE_EXT2
            }
        }
        UNKNOWN => {
            unknowntag_end(xar, name);
        }
        0 | _ => {}
    };
}

static mut base64: [i32; 256] = [
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    62 as i32,
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    63 as i32,
    52 as i32,
    53 as i32,
    54 as i32,
    55 as i32,
    56 as i32,
    57 as i32,
    58 as i32,
    59 as i32,
    60 as i32,
    61 as i32,
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    0 as i32,
    1 as i32,
    2 as i32,
    3 as i32,
    4 as i32,
    5 as i32,
    6 as i32,
    7 as i32,
    8 as i32,
    9 as i32,
    10 as i32,
    11 as i32,
    12 as i32,
    13 as i32,
    14 as i32,
    15 as i32,
    16 as i32,
    17 as i32,
    18 as i32,
    19 as i32,
    20 as i32,
    21 as i32,
    22 as i32,
    23 as i32,
    24 as i32,
    25 as i32,
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    26 as i32,
    27 as i32,
    28 as i32,
    29 as i32,
    30 as i32,
    31 as i32,
    32 as i32,
    33 as i32,
    34 as i32,
    35 as i32,
    36 as i32,
    37 as i32,
    38 as i32,
    39 as i32,
    40 as i32,
    41 as i32,
    42 as i32,
    43 as i32,
    44 as i32,
    45 as i32,
    46 as i32,
    47 as i32,
    48 as i32,
    49 as i32,
    50 as i32,
    51 as i32,
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
    -(1 as i32),
];

unsafe fn strappend_base64(
    mut xar: *mut xar,
    mut as_0: *mut archive_string,
    mut s: *const u8,
    mut l: size_t,
) {
    let mut buff: [u8; 256] = [0; 256];
    let mut out: *mut u8 = 0 as *mut u8;
    let mut b: *const u8 = 0 as *const u8;
    let mut len: size_t = 0;
    /* UNUSED */
    len = 0 as i32 as size_t;
    out = buff.as_mut_ptr();
    b = s as *const u8;
    while l > 0 as i32 as u64 {
        let mut n: i32 = 0 as i32;
        if unsafe { base64[*b.offset(0 as i32 as isize) as usize] } < 0 as i32
            || unsafe { base64[*b.offset(1 as i32 as isize) as usize] } < 0 as i32
        {
            break;
        }
        let fresh15 = b;
        unsafe { b = b.offset(1) };
        unsafe { n = base64[*fresh15 as usize] << 18 as i32 };
        let fresh16 = b;
        unsafe { b = b.offset(1) };
        unsafe { n |= base64[*fresh16 as usize] << 12 as i32 };
        let fresh17 = out;
        unsafe { out = out.offset(1) };
        unsafe { *fresh17 = (n >> 16 as i32) as u8 };
        len = len.wrapping_add(1);
        l = (l as u64).wrapping_sub(2 as i32 as u64) as size_t as size_t;
        if l > 0 as i32 as u64 {
            if unsafe { base64[*b as usize] } < 0 as i32 {
                break;
            }
            let fresh18 = b;
            unsafe { b = b.offset(1) };
            unsafe { n |= base64[*fresh18 as usize] << 6 as i32 };
            let fresh19 = out;
            unsafe { out = out.offset(1) };
            unsafe { *fresh19 = (n >> 8 as i32 & 0xff as i32) as u8 };
            len = len.wrapping_add(1);
            l = l.wrapping_sub(1)
        }
        if l > 0 as i32 as u64 {
            if unsafe { base64[*b as usize] } < 0 as i32 {
                break;
            }
            let fresh20 = b;
            unsafe { b = b.offset(1) };
            unsafe { n |= base64[*fresh20 as usize] };
            let fresh21 = out;
            unsafe { out = out.offset(1) };
            unsafe { *fresh21 = (n & 0xff as i32) as u8 };
            len = len.wrapping_add(1);
            l = l.wrapping_sub(1)
        }
        if len.wrapping_add(3 as i32 as u64) >= ::std::mem::size_of::<[u8; 256]>() as u64 {
            archive_strncat_safe(as_0, buff.as_mut_ptr() as *const u8 as *const (), len);
            len = 0 as i32 as size_t;
            out = buff.as_mut_ptr()
        }
    }
    if len > 0 as i32 as u64 {
        archive_strncat_safe(as_0, buff.as_mut_ptr() as *const u8 as *const (), len);
    };
}

unsafe fn is_string(mut known: *const u8, mut data: *const u8, mut len: size_t) -> i32 {
    if strlen_safe(known) != len {
        return -(1 as i32);
    }
    return memcmp_safe(data as *const (), known as *const (), len);
}

unsafe fn xml_data(mut userData: *mut (), mut s: *const u8, mut len: i32) {
    let mut a: *mut archive_read = 0 as *mut archive_read;
    let mut xar: *mut xar = 0 as *mut xar;
    a = userData as *mut archive_read;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    let mut safe_file = unsafe { &mut *safe_xar.file };
    let mut safe_xattr = unsafe { &mut *safe_xar.xattr };
    match safe_xar.xmlsts as u32 {
        TOC_CHECKSUM_OFFSET => safe_xar.toc_chksum_offset = atol10(s, len as size_t),
        TOC_CHECKSUM_SIZE => safe_xar.toc_chksum_size = atol10(s, len as size_t),
        _ => {}
    }
    if safe_xar.file.is_null() {
        return;
    }
    match safe_xar.xmlsts as u32 {
        FILE_NAME => {
            if !safe_file.parent.is_null() {
                unsafe {
                    archive_string_concat_safe(
                        &mut (*safe_xar.file).pathname,
                        &mut (*(*safe_xar.file).parent).pathname,
                    );
                    archive_strappend_char_safe(&mut (*safe_xar.file).pathname, '/' as i32 as u8);
                }
            }
            safe_file.has |= HAS_PATHNAME as u32;
            if safe_xar.base64text != 0 {
                strappend_base64(xar, &mut safe_file.pathname, s, len as size_t);
            } else {
                archive_strncat_safe(&mut safe_file.pathname, s as *const (), len as size_t);
            }
        }
        FILE_LINK => {
            safe_file.has |= 0x4 as i32 as u32;
            safe_file.symlink.length = 0 as i32 as size_t;
            archive_strncat_safe(&mut safe_file.symlink, s as *const (), len as size_t);
        }
        FILE_TYPE => {
            if is_string(b"file\x00" as *const u8, s, len as size_t) == 0 as i32
                || is_string(b"hardlink\x00" as *const u8, s, len as size_t) == 0 as i32
            {
                safe_file.mode = safe_file.mode & !(ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t)
                    | ARCHIVE_XAR_DEFINED_PARAM.ae_ifreg as mode_t
            }
            if is_string(b"directory\x00" as *const u8, s, len as size_t) == 0 as i32 {
                safe_file.mode = safe_file.mode & !(ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t)
                    | ARCHIVE_XAR_DEFINED_PARAM.ae_ifdir as mode_t
            }
            if is_string(b"symlink\x00" as *const u8, s, len as size_t) == 0 as i32 {
                safe_file.mode = safe_file.mode & !(ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t)
                    | ARCHIVE_XAR_DEFINED_PARAM.ae_iflnk as mode_t
            }
            if is_string(b"character special\x00" as *const u8, s, len as size_t) == 0 as i32 {
                safe_file.mode = safe_file.mode & !(ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t)
                    | ARCHIVE_XAR_DEFINED_PARAM.ae_ifchr as mode_t
            }
            if is_string(b"block special\x00" as *const u8, s, len as size_t) == 0 as i32 {
                safe_file.mode = safe_file.mode & !(ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t)
                    | ARCHIVE_XAR_DEFINED_PARAM.ae_ifblk as mode_t
            }
            if is_string(b"socket\x00" as *const u8, s, len as size_t) == 0 as i32 {
                safe_file.mode = safe_file.mode & !(ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t)
                    | ARCHIVE_XAR_DEFINED_PARAM.ae_ifsock as mode_t
            }
            if is_string(b"fifo\x00" as *const u8, s, len as size_t) == 0 as i32 {
                safe_file.mode = safe_file.mode & !(ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t)
                    | ARCHIVE_XAR_DEFINED_PARAM.ae_ififo as mode_t
            }
            safe_file.has |= HAS_TYPE as u32
        }
        FILE_INODE => {
            safe_file.has |= HAS_INO as u32;
            safe_file.ino64 = atol10(s, len as size_t) as int64_t
        }
        FILE_DEVICE_MAJOR => {
            safe_file.has |= HAS_DEVMAJOR as u32;
            safe_file.devmajor = atol10(s, len as size_t)
        }
        FILE_DEVICE_MINOR => {
            safe_file.has |= HAS_DEVMINOR as u32;
            safe_file.devminor = atol10(s, len as size_t)
        }
        FILE_DEVICENO => {
            safe_file.has |= HAS_DEV as u32;
            safe_file.dev = atol10(s, len as size_t)
        }
        FILE_MODE => {
            safe_file.has |= HAS_MODE as u32;
            safe_file.mode = safe_file.mode & ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t
                | atol8(s, len as size_t) as mode_t & !(ARCHIVE_XAR_DEFINED_PARAM.ae_ifmt as mode_t)
        }
        FILE_GROUP => {
            safe_file.has |= HAS_GID as u32;
            safe_file.gname.length = 0 as i32 as size_t;
            archive_strncat_safe(&mut safe_file.gname, s as *const (), len as size_t);
        }
        FILE_GID => {
            safe_file.has |= HAS_GID as u32;
            safe_file.gid = atol10(s, len as size_t) as int64_t
        }
        FILE_USER => {
            safe_file.has |= HAS_UID as u32;
            safe_file.uname.length = 0 as i32 as size_t;
            archive_strncat_safe(&mut safe_file.uname, s as *const (), len as size_t);
        }
        FILE_UID => {
            safe_file.has |= HAS_UID as u32;
            safe_file.uid = atol10(s, len as size_t) as int64_t
        }
        FILE_CTIME => {
            safe_file.has |= (HAS_TIME | HAS_CTIME_XAR) as u32;
            safe_file.ctime = parse_time(s, len as size_t)
        }
        FILE_MTIME => {
            safe_file.has |= (HAS_TIME | HAS_MTIME_XAR) as u32;
            safe_file.mtime = parse_time(s, len as size_t)
        }
        FILE_ATIME => {
            safe_file.has |= (HAS_TIME | HAS_ATIME_XAR) as u32;
            safe_file.atime = parse_time(s, len as size_t)
        }
        FILE_DATA_LENGTH => {
            safe_file.has |= HAS_DATA as u32;
            safe_file.length = atol10(s, len as size_t)
        }
        FILE_DATA_OFFSET => {
            safe_file.has |= HAS_DATA as u32;
            safe_file.offset = atol10(s, len as size_t)
        }
        FILE_DATA_SIZE => {
            safe_file.has |= HAS_DATA as u32;
            safe_file.size = atol10(s, len as size_t)
        }
        FILE_DATA_A_CHECKSUM => {
            safe_file.a_sum.len = atohex(
                safe_file.a_sum.val.as_mut_ptr(),
                ::std::mem::size_of::<[u8; 20]>() as u64,
                s,
                len as size_t,
            )
        }
        FILE_DATA_E_CHECKSUM => {
            safe_file.e_sum.len = atohex(
                safe_file.e_sum.val.as_mut_ptr(),
                ::std::mem::size_of::<[u8; 20]>() as u64,
                s,
                len as size_t,
            )
        }
        FILE_EA_LENGTH => {
            safe_file.has |= HAS_XATTR as u32;
            safe_xattr.length = atol10(s, len as size_t)
        }
        FILE_EA_OFFSET => {
            safe_file.has |= HAS_XATTR as u32;
            safe_xattr.offset = atol10(s, len as size_t)
        }
        FILE_EA_SIZE => {
            safe_file.has |= HAS_XATTR as u32;
            safe_xattr.size = atol10(s, len as size_t)
        }
        FILE_EA_A_CHECKSUM => {
            safe_file.has |= HAS_XATTR as u32;
            safe_xattr.a_sum.len = atohex(
                safe_xattr.a_sum.val.as_mut_ptr(),
                ::std::mem::size_of::<[u8; 20]>() as u64,
                s,
                len as size_t,
            )
        }
        FILE_EA_E_CHECKSUM => {
            safe_file.has |= HAS_XATTR as u32;
            safe_xattr.e_sum.len = atohex(
                safe_xattr.e_sum.val.as_mut_ptr(),
                ::std::mem::size_of::<[u8; 20]>() as u64,
                s,
                len as size_t,
            )
        }
        FILE_EA_NAME => {
            safe_file.has |= HAS_XATTR as u32;
            safe_xattr.name.length = 0 as i32 as size_t;
            archive_strncat_safe(&mut safe_xattr.name, s as *const (), len as size_t);
        }
        FILE_EA_FSTYPE => {
            safe_file.has |= HAS_XATTR as u32;
            safe_xattr.fstype.length = 0 as i32 as size_t;
            archive_strncat_safe(&mut safe_xattr.fstype, s as *const (), len as size_t);
        }
        FILE_ACL_DEFAULT | FILE_ACL_ACCESS | FILE_ACL_APPLEEXTENDED => {
            safe_file.has |= HAS_ACL as u32
        }
        INIT
        | XAR
        | TOC
        | TOC_CREATION_TIME
        | TOC_CHECKSUM
        | TOC_CHECKSUM_OFFSET
        | TOC_CHECKSUM_SIZE
        | TOC_FILE
        | FILE_DATA
        | FILE_DATA_ENCODING
        | FILE_DATA_CONTENT
        | FILE_DEVICE
        | FILE_EA
        | FILE_EA_ENCODING
        | FILE_ACL
        | FILE_FLAGS
        | FILE_FLAGS_USER_NODUMP
        | FILE_FLAGS_USER_IMMUTABLE
        | FILE_FLAGS_USER_APPEND
        | FILE_FLAGS_USER_OPAQUE
        | FILE_FLAGS_USER_NOUNLINK
        | FILE_FLAGS_SYS_ARCHIVED
        | FILE_FLAGS_SYS_IMMUTABLE
        | FILE_FLAGS_SYS_APPEND
        | FILE_FLAGS_SYS_NOUNLINK
        | FILE_FLAGS_SYS_SNAPSHOT
        | FILE_EXT2
        | FILE_EXT2_SecureDeletion
        | FILE_EXT2_Undelete
        | FILE_EXT2_Compress
        | FILE_EXT2_Synchronous
        | FILE_EXT2_Immutable
        | FILE_EXT2_AppendOnly
        | FILE_EXT2_NoDump
        | FILE_EXT2_NoAtime
        | FILE_EXT2_CompDirty
        | FILE_EXT2_CompBlock
        | FILE_EXT2_NoCompBlock
        | FILE_EXT2_CompError
        | FILE_EXT2_BTree
        | FILE_EXT2_HashIndexed
        | FILE_EXT2_iMagic
        | FILE_EXT2_Journaled
        | FILE_EXT2_NoTail
        | FILE_EXT2_DirSync
        | FILE_EXT2_TopDir
        | FILE_EXT2_Reserved
        | UNKNOWN
        | _ => {}
    };
}
/*
 * BSD file flags.
 */
unsafe fn xml_parse_file_flags(mut xar: *mut xar, mut name: *const u8) -> i32 {
    let mut safe_xar = unsafe { &mut *xar };
    let mut flag: *const u8 = 0 as *const u8;
    if strcmp_safe(name, b"UserNoDump\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_FLAGS_USER_NODUMP;
        flag = b"nodump\x00" as *const u8
    } else if strcmp_safe(name, b"UserImmutable\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_FLAGS_USER_IMMUTABLE;
        flag = b"uimmutable\x00" as *const u8
    } else if strcmp_safe(name, b"UserAppend\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_FLAGS_USER_APPEND;
        flag = b"uappend\x00" as *const u8
    } else if strcmp_safe(name, b"UserOpaque\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_FLAGS_USER_OPAQUE;
        flag = b"opaque\x00" as *const u8
    } else if strcmp_safe(name, b"UserNoUnlink\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_FLAGS_USER_NOUNLINK;
        flag = b"nouunlink\x00" as *const u8
    } else if strcmp_safe(name, b"SystemArchived\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_FLAGS_SYS_ARCHIVED;
        flag = b"archived\x00" as *const u8
    } else if strcmp_safe(name, b"SystemImmutable\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_FLAGS_SYS_IMMUTABLE;
        flag = b"simmutable\x00" as *const u8
    } else if strcmp_safe(name, b"SystemAppend\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_FLAGS_SYS_APPEND;
        flag = b"sappend\x00" as *const u8
    } else if strcmp_safe(name, b"SystemNoUnlink\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_FLAGS_SYS_NOUNLINK;
        flag = b"nosunlink\x00" as *const u8
    } else if strcmp_safe(name, b"SystemSnapshot\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_FLAGS_SYS_SNAPSHOT;
        flag = b"snapshot\x00" as *const u8
    }
    if flag.is_null() {
        return 0 as i32;
    }
    unsafe { *safe_xar.file }.has |= HAS_FFLAGS as u32;
    if unsafe { *safe_xar.file }.fflags_text.length > 0 as i32 as u64 {
        archive_strappend_char_safe(&mut unsafe { *safe_xar.file }.fflags_text, ',' as i32 as u8);
    }
    archive_strcat_safe(
        &mut unsafe { *safe_xar.file }.fflags_text,
        flag as *const (),
    );
    return ARCHIVE_XAR_DEFINED_PARAM.archive_eof;
}
/*
 * Linux file flags.
 */
unsafe fn xml_parse_file_ext2(mut xar: *mut xar, mut name: *const u8) -> i32 {
    let mut flag: *const u8 = 0 as *const u8;
    let mut safe_xar = unsafe { &mut *xar };
    if strcmp_safe(name, b"SecureDeletion\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_SecureDeletion;
        flag = b"securedeletion\x00" as *const u8
    } else if strcmp_safe(name, b"Undelete\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_Undelete;
        flag = b"nouunlink\x00" as *const u8
    } else if strcmp_safe(name, b"Compress\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_Compress;
        flag = b"compress\x00" as *const u8
    } else if strcmp_safe(name, b"Synchronous\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_Synchronous;
        flag = b"sync\x00" as *const u8
    } else if strcmp_safe(name, b"Immutable\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_Immutable;
        flag = b"simmutable\x00" as *const u8
    } else if strcmp_safe(name, b"AppendOnly\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_AppendOnly;
        flag = b"sappend\x00" as *const u8
    } else if strcmp_safe(name, b"NoDump\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_NoDump;
        flag = b"nodump\x00" as *const u8
    } else if strcmp_safe(name, b"NoAtime\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_NoAtime;
        flag = b"noatime\x00" as *const u8
    } else if strcmp_safe(name, b"CompDirty\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_CompDirty;
        flag = b"compdirty\x00" as *const u8
    } else if strcmp_safe(name, b"CompBlock\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_CompBlock;
        flag = b"comprblk\x00" as *const u8
    } else if strcmp_safe(name, b"NoCompBlock\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_NoCompBlock;
        flag = b"nocomprblk\x00" as *const u8
    } else if strcmp_safe(name, b"CompError\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_CompError;
        flag = b"comperr\x00" as *const u8
    } else if strcmp_safe(name, b"BTree\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_BTree;
        flag = b"btree\x00" as *const u8
    } else if strcmp_safe(name, b"HashIndexed\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_HashIndexed;
        flag = b"hashidx\x00" as *const u8
    } else if strcmp_safe(name, b"iMagic\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_iMagic;
        flag = b"imagic\x00" as *const u8
    } else if strcmp_safe(name, b"Journaled\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_Journaled;
        flag = b"journal\x00" as *const u8
    } else if strcmp_safe(name, b"NoTail\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_NoTail;
        flag = b"notail\x00" as *const u8
    } else if strcmp_safe(name, b"DirSync\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_DirSync;
        flag = b"dirsync\x00" as *const u8
    } else if strcmp_safe(name, b"TopDir\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_TopDir;
        flag = b"topdir\x00" as *const u8
    } else if strcmp_safe(name, b"Reserved\x00" as *const u8) == 0 as i32 {
        safe_xar.xmlsts = FILE_EXT2_Reserved;
        flag = b"reserved\x00" as *const u8
    }
    if flag.is_null() {
        return 0 as i32;
    }
    if unsafe { *safe_xar.file }.fflags_text.length > 0 as i32 as u64 {
        archive_strappend_char_safe(&mut unsafe { *safe_xar.file }.fflags_text, ',' as i32 as u8);
    }
    archive_strcat_safe(
        &mut unsafe { *safe_xar.file }.fflags_text,
        flag as *const (),
    );
    return ARCHIVE_XAR_DEFINED_PARAM.archive_eof;
}

#[cfg(HAVE_LIBXML_XMLREADER_H)]
#[cfg(HAVE_LIBXML_XMLREADER_H)]
unsafe fn xml2_xmlattr_setup(
    mut a: *mut archive_read,
    mut list: *mut xmlattr_list,
    mut reader: xmlTextReaderPtr,
) -> i32 {
    let mut attr: *mut xmlattr = 0 as *mut xmlattr;
    let mut r: i32 = 0;
    unsafe {
        (*list).first = 0 as *mut xmlattr;
        (*list).last = &mut (*list).first;
    }
    let mut safe_a = unsafe { &mut *a };
    r = xmlTextReaderMoveToFirstAttribute_safe(reader);
    while r == 1 as i32 {
        attr = malloc_safe(::std::mem::size_of::<xmlattr>() as u64) as *mut xmlattr;
        if attr.is_null() {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.enomem,
                b"Out of memory\x00" as *const u8
            );
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }
        unsafe {
            (*attr).name = strdup_safe(xmlTextReaderConstLocalName_safe(reader) as *const u8);
        }
        if unsafe { (*attr).name.is_null() } {
            free_safe(attr as *mut ());
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.enomem,
                b"Out of memory\x00" as *const u8
            );
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }
        unsafe {
            (*attr).value = strdup_safe(xmlTextReaderConstValue_safe(reader) as *const u8);
        }

        if unsafe { (*attr).value.is_null() } {
            free_safe(unsafe { (*attr).name as *mut () });
            free_safe(attr as *mut ());
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                12 as i32,
                b"Out of memory\x00" as *const u8
            );
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }
        unsafe {
            (*attr).next = 0 as *mut xmlattr;
            *(*list).last = attr;
            (*list).last = &mut (*attr).next;
        }
        r = xmlTextReaderMoveToNextAttribute_safe(reader)
    }
    return r;
}

#[cfg(HAVE_LIBXML_XMLREADER_H)]
unsafe fn xml2_read_cb(mut context: *mut (), mut buffer: *mut u8, mut len: i32) -> i32 {
    let mut a: *mut archive_read = 0 as *mut archive_read;
    let mut xar: *mut xar = 0 as *mut xar;
    let mut d: *const () = 0 as *const ();
    let mut outbytes: size_t = 0;
    let mut used: size_t = 0 as i32 as size_t;
    let mut r: i32 = 0;
    a = context as *mut archive_read;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    if safe_xar.toc_remaining <= 0 as i32 as u64 {
        return 0 as i32;
    }
    d = buffer as *const ();
    outbytes = len as size_t;
    r = rd_contents(a, &mut d, &mut outbytes, &mut used, safe_xar.toc_remaining);
    if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        return r;
    }
    __archive_read_consume_safe(a, used as int64_t);
    safe_xar.toc_remaining =
        (safe_xar.toc_remaining as u64).wrapping_sub(used) as uint64_t as uint64_t;
    safe_xar.offset = (safe_xar.offset as u64).wrapping_add(used) as uint64_t as uint64_t;
    safe_xar.toc_total = (safe_xar.toc_total as u64).wrapping_add(outbytes) as uint64_t as uint64_t;
    return outbytes as i32;
}

#[cfg(HAVE_LIBXML_XMLREADER_H)]
unsafe fn xml2_close_cb(mut context: *mut ()) -> i32 {
    /* UNUSED */
    return 0 as i32;
}

#[cfg(HAVE_LIBXML_XMLREADER_H)]
unsafe fn xml2_error_hdr(
    mut arg: *mut (),
    mut msg: *const u8,
    mut severity: xmlParserSeverities,
    mut locator: xmlTextReaderLocatorPtr,
) {
    let mut a: *mut archive_read = 0 as *mut archive_read;
    /* UNUSED */
    a = arg as *mut archive_read;
    let mut safe_a = unsafe { &mut *a };
    match severity as u32 {
        XML_PARSER_SEVERITY_VALIDITY_WARNING | XML_PARSER_SEVERITY_WARNING => {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                b"XML Parsing error: %s\x00" as *const u8,
                msg
            );
        }
        XML_PARSER_SEVERITY_VALIDITY_ERROR | XML_PARSER_SEVERITY_ERROR => {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.archive_errno_misc,
                b"XML Parsing error: %s\x00" as *const u8,
                msg
            )
        }
        _ => {}
    };
}

#[cfg(HAVE_LIBXML_XMLREADER_H)]
unsafe fn xml2_read_toc(mut a: *mut archive_read) -> i32 {
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut list: xmlattr_list = xmlattr_list {
        first: 0 as *mut xmlattr,
        last: 0 as *mut *mut xmlattr,
    };
    let mut r: i32 = 0;
    let mut safe_a = unsafe { &mut *a };
    reader = xmlReaderForIO_safe(
        Some(xml2_read_cb as unsafe fn(_: *mut (), _: *mut u8, _: i32) -> i32),
        Some(xml2_close_cb as unsafe fn(_: *mut ()) -> i32),
        a as *mut (),
        0 as *const u8,
        0 as *const u8,
        0 as i32,
    );
    if reader.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            ARCHIVE_XAR_DEFINED_PARAM.enomem,
            b"Couldn\'t allocate memory for xml parser\x00" as *const u8
        );
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    xmlTextReaderSetErrorHandler_safe(
        reader,
        Some(
            xml2_error_hdr
                as unsafe fn(
                    _: *mut (),
                    _: *const u8,
                    _: xmlParserSeverities,
                    _: xmlTextReaderLocatorPtr,
                ) -> (),
        ),
        a as *mut (),
    );
    loop {
        r = xmlTextReaderRead_safe(reader);
        if !(r == 1 as i32) {
            break;
        }
        let mut name: *const u8 = 0 as *const u8;
        let mut value: *const u8 = 0 as *const u8;
        let mut type_0: i32 = 0;
        let mut empty: i32 = 0;
        type_0 = xmlTextReaderNodeType_safe(reader);
        name = xmlTextReaderConstLocalName_safe(reader) as *const u8;
        match type_0 as u32 {
            XML_READER_TYPE_ELEMENT => {
                empty = xmlTextReaderIsEmptyElement_safe(reader);
                r = xml2_xmlattr_setup(a, &mut list, reader);
                if r == ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                    r = xml_start(a, name, &mut list)
                }
                xmlattr_cleanup(&mut list);
                if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
                    return r;
                }
                if empty != 0 {
                    xml_end(a as *mut (), name);
                }
            }
            XML_READER_TYPE_END_ELEMENT => {
                xml_end(a as *mut (), name);
            }
            XML_READER_TYPE_TEXT => {
                value = xmlTextReaderConstValue_safe(reader) as *const u8;
                xml_data(a as *mut (), value, strlen_safe(value) as i32);
            }
            XML_READER_TYPE_SIGNIFICANT_WHITESPACE | _ => {}
        }
        if r < 0 as i32 {
            break;
        }
    }
    xmlFreeTextReader_safe(reader);
    xmlCleanupParser_safe();
    return if r == ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        ARCHIVE_XAR_DEFINED_PARAM.archive_ok
    } else {
        ARCHIVE_XAR_DEFINED_PARAM.archive_fatal
    };
}
/* Support xar format */
/* defined(HAVE_BSDXML_H) || defined(HAVE_EXPAT_H) */
#[no_mangle]
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
unsafe fn expat_xmlattr_setup(
    mut a: *mut archive_read,
    mut list: *mut xmlattr_list,
    mut atts: *mut *const XML_Char,
) -> i32 {
    let mut attr: *mut xmlattr = 0 as *mut xmlattr;
    let mut name: *mut u8 = 0 as *mut u8;
    let mut value: *mut u8 = 0 as *mut u8;
    let mut safe_a = unsafe { &mut *a };
    unsafe { (*list).first = 0 as *mut xmlattr };
    unsafe { (*list).last = &mut (*list).first };
    if atts.is_null() {
        return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
    }
    while unsafe {
        !(*atts.offset(0 as i32 as isize)).is_null() && !(*atts.offset(1 as i32 as isize)).is_null()
    } {
        attr = malloc_safe(::std::mem::size_of::<xmlattr>() as u64) as *mut xmlattr;
        name = strdup_safe(unsafe { *atts.offset(0 as i32 as isize) });
        value = strdup_safe(unsafe { *atts.offset(1 as i32 as isize) });
        if attr.is_null() || name.is_null() || value.is_null() {
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.enomem,
                b"Out of memory\x00" as *const u8
            );
            free_safe(attr as *mut ());
            free_safe(name as *mut ());
            free_safe(value as *mut ());
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }
        unsafe {
            (*attr).name = name;
            (*attr).value = value;
            (*attr).next = 0 as *mut xmlattr;
            *(*list).last = attr;
            (*list).last = &mut (*attr).next;
            atts = atts.offset(2 as i32 as isize)
        }
    }
    return ARCHIVE_XAR_DEFINED_PARAM.archive_ok;
}

#[no_mangle]
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
unsafe fn expat_start_cb(
    mut userData: *mut (),
    mut name: *const XML_Char,
    mut atts: *mut *const XML_Char,
) {
    let mut ud: *mut expat_userData = userData as *mut expat_userData;
    let mut safe_ud = unsafe { &mut *ud };
    let mut a: *mut archive_read = safe_ud.archive;
    let mut list: xmlattr_list = xmlattr_list {
        first: 0 as *mut xmlattr,
        last: 0 as *mut *mut xmlattr,
    };
    let mut r: i32 = 0;
    r = expat_xmlattr_setup(a, &mut list, atts);
    if r == ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        r = unsafe { xml_start(a, name as *const u8, &mut list) }
    }
    xmlattr_cleanup(&mut list);
    safe_ud.state = r;
}

#[no_mangle]
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
unsafe fn expat_end_cb(mut userData: *mut (), mut name: *const XML_Char) {
    let mut ud: *mut expat_userData = userData as *mut expat_userData;
    xml_end(unsafe { (*ud).archive as *mut () }, name as *const u8);
}

#[no_mangle]
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
unsafe fn expat_data_cb(mut userData: *mut (), mut s: *const XML_Char, mut len: i32) {
    let mut ud: *mut expat_userData = userData as *mut expat_userData;
    xml_data(unsafe { (*ud) }.archive as *mut (), s, len);
}

#[no_mangle]
#[cfg(any(HAVE_EXPAT_H, HAVE_BSDXML_H))]
unsafe fn expat_read_toc(mut a: *mut archive_read) -> i32 {
    let mut xar: *mut xar = 0 as *mut xar;
    let mut parser: XML_Parser = 0 as *mut XML_ParserStruct;
    let mut ud: expat_userData = expat_userData {
        state: 0,
        archive: 0 as *mut archive_read,
    };
    ud.state = 0 as i32;
    ud.archive = a;
    xar = unsafe { (*(*a).format).data as *mut xar };
    let mut safe_xar = unsafe { &mut *xar };
    let mut safe_a = unsafe { &mut *a };
    /* Initialize XML Parser library. */
    parser = XML_ParserCreate_safe(0 as *const XML_Char);
    if parser.is_null() {
        archive_set_error_safe!(
            &mut safe_a.archive as *mut archive,
            12 as i32,
            b"Couldn\'t allocate memory for xml parser\x00" as *const u8
        );
        return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
    }
    XML_SetUserData_safe(parser, &mut ud as *mut expat_userData as *mut ());
    XML_SetElementHandler_safe(
        parser,
        Some(
            expat_start_cb
                as unsafe fn(_: *mut (), _: *const XML_Char, _: *mut *const XML_Char) -> (),
        ),
        Some(expat_end_cb as unsafe fn(_: *mut (), _: *const XML_Char) -> ()),
    );
    XML_SetCharacterDataHandler_safe(
        parser,
        Some(expat_data_cb as unsafe fn(_: *mut (), _: *const XML_Char, _: i32) -> ()),
    );
    safe_xar.xmlsts = INIT;
    while safe_xar.toc_remaining != 0 && ud.state == ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
        let mut xr: XML_Status = XML_STATUS_ERROR;
        let mut d: *const () = 0 as *const ();
        let mut outbytes: size_t = 0;
        let mut used: size_t = 0;
        let mut r: i32 = 0;
        d = 0 as *const ();
        r = rd_contents(a, &mut d, &mut outbytes, &mut used, safe_xar.toc_remaining);
        if r != ARCHIVE_XAR_DEFINED_PARAM.archive_ok {
            return r;
        }
        safe_xar.toc_remaining =
            (safe_xar.toc_remaining as u64).wrapping_sub(used) as uint64_t as uint64_t;
        safe_xar.offset = (safe_xar.offset as u64).wrapping_add(used) as uint64_t as uint64_t;
        safe_xar.toc_total =
            (safe_xar.toc_total as u64).wrapping_add(outbytes) as uint64_t as uint64_t;
        xr = XML_Parse_safe(
            parser,
            d as *const u8,
            outbytes as i32,
            (safe_xar.toc_remaining == 0 as i32 as u64) as i32,
        );
        __archive_read_consume_safe(a, used as int64_t);
        if xr as u32 == XML_STATUS_ERROR as i32 as u32 {
            XML_ParserFree_safe(parser);
            archive_set_error_safe!(
                &mut safe_a.archive as *mut archive,
                ARCHIVE_XAR_DEFINED_PARAM.archive_errnok_misc,
                b"XML Parsing failed\x00" as *const u8
            );
            return ARCHIVE_XAR_DEFINED_PARAM.archive_fatal;
        }
    }
    XML_Parserfree_safe(parser);
    return ud.state;
}
