use c2rust_bitfields::*;
use ffi_alias::alias_set::*;

pub type archive_read_callback = unsafe extern "C" fn(
    _: *mut archive,
    _: *mut libc::c_void,
    _: *mut *const libc::c_void,
) -> la_ssize_t;

pub type archive_skip_callback =
    unsafe extern "C" fn(_: *mut archive, _: *mut libc::c_void, _: la_int64_t) -> la_int64_t;

pub type archive_seek_callback = unsafe extern "C" fn(
    _: *mut archive,
    _: *mut libc::c_void,
    _: la_int64_t,
    _: libc::c_int,
) -> la_int64_t;
pub type archive_open_callback =
    unsafe extern "C" fn(_: *mut archive, _: *mut libc::c_void) -> libc::c_int;
pub type archive_close_callback =
    unsafe extern "C" fn(_: *mut archive, _: *mut libc::c_void) -> libc::c_int;

pub type archive_switch_callback = unsafe extern "C" fn(
    _: *mut archive,
    _: *mut libc::c_void,
    _: *mut libc::c_void,
) -> libc::c_int;

pub type archive_passphrase_callback =
    unsafe extern "C" fn(_: *mut archive, _: *mut libc::c_void) -> *const libc::c_char;

pub type archive_write_callback = unsafe extern "C" fn(
    _: *mut archive,
    _: *mut libc::c_void,
    _: *const libc::c_void,
    _: size_t,
) -> la_ssize_t;

pub type archive_free_callback =
    unsafe extern "C" fn(_: *mut archive, _: *mut libc::c_void) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive {
    pub magic: libc::c_uint,
    pub state: libc::c_uint,
    pub vtable: *mut archive_vtable,
    pub archive_format: libc::c_int,
    pub archive_format_name: *const libc::c_char,
    pub compression_code: libc::c_int,
    pub compression_name: *const libc::c_char,
    pub file_count: libc::c_int,
    pub archive_error_number: libc::c_int,
    pub error: *const libc::c_char,
    pub error_string: archive_string,
    pub current_code: *mut libc::c_char,
    pub current_codepage: libc::c_uint,
    pub current_oemcp: libc::c_uint,
    pub sconv: *mut archive_string_conv,
    pub read_data_block: *const libc::c_char,
    pub read_data_offset: int64_t,
    pub read_data_output_offset: int64_t,
    pub read_data_remaining: size_t,
    pub read_data_is_posix_read: libc::c_char,
    pub read_data_requested: size_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_string {
    pub s: *mut libc::c_char,
    pub length: size_t,
    pub buffer_length: size_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_vtable {
    pub archive_close: Option<unsafe extern "C" fn(_: *mut archive) -> libc::c_int>,
    pub archive_free: Option<unsafe extern "C" fn(_: *mut archive) -> libc::c_int>,
    pub archive_write_header:
        Option<unsafe extern "C" fn(_: *mut archive, _: *mut archive_entry) -> libc::c_int>,
    pub archive_write_finish_entry: Option<unsafe extern "C" fn(_: *mut archive) -> libc::c_int>,
    pub archive_write_data:
        Option<unsafe extern "C" fn(_: *mut archive, _: *const libc::c_void, _: size_t) -> ssize_t>,
    pub archive_write_data_block: Option<
        unsafe extern "C" fn(
            _: *mut archive,
            _: *const libc::c_void,
            _: size_t,
            _: int64_t,
        ) -> ssize_t,
    >,
    pub archive_read_next_header:
        Option<unsafe extern "C" fn(_: *mut archive, _: *mut *mut archive_entry) -> libc::c_int>,
    pub archive_read_next_header2:
        Option<unsafe extern "C" fn(_: *mut archive, _: *mut archive_entry) -> libc::c_int>,
    pub archive_read_data_block: Option<
        unsafe extern "C" fn(
            _: *mut archive,
            _: *mut *const libc::c_void,
            _: *mut size_t,
            _: *mut int64_t,
        ) -> libc::c_int,
    >,
    pub archive_filter_count: Option<unsafe extern "C" fn(_: *mut archive) -> libc::c_int>,
    pub archive_filter_bytes:
        Option<unsafe extern "C" fn(_: *mut archive, _: libc::c_int) -> int64_t>,
    pub archive_filter_code:
        Option<unsafe extern "C" fn(_: *mut archive, _: libc::c_int) -> libc::c_int>,
    pub archive_filter_name:
        Option<unsafe extern "C" fn(_: *mut archive, _: libc::c_int) -> *const libc::c_char>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_read {
    pub archive: archive,
    pub entry: *mut archive_entry,
    pub skip_file_set: libc::c_int,
    pub skip_file_dev: int64_t,
    pub skip_file_ino: int64_t,
    pub client: archive_read_client,
    pub bidders: [archive_read_filter_bidder; 16],
    pub filter: *mut archive_read_filter,
    pub bypass_filter_bidding: libc::c_int,
    pub header_position: int64_t,
    pub data_start_node: libc::c_uint,
    pub data_end_node: libc::c_uint,
    pub formats: [archive_format_descriptor; 16],
    pub format: *mut archive_format_descriptor,
    pub extract: *mut archive_read_extract,
    pub cleanup_archive_extract: Option<unsafe extern "C" fn(_: *mut archive_read) -> libc::c_int>,
    pub passphrases: archive_passphrases,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_passphrases {
    pub first: *mut archive_read_passphrase,
    pub last: *mut *mut archive_read_passphrase,
    pub candidate: libc::c_int,
    pub callback: Option<archive_passphrase_callback>,
    pub client_data: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_read_passphrase {
    pub passphrase: *mut libc::c_char,
    pub next: *mut archive_read_passphrase,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_read_extract {
    pub ad: *mut archive,
    pub extract_progress: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> ()>,
    pub extract_progress_user_data: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_format_descriptor {
    pub data: *mut libc::c_void,
    pub name: *const libc::c_char,
    pub bid: Option<unsafe extern "C" fn(_: *mut archive_read, _: libc::c_int) -> libc::c_int>,
    pub options: Option<
        unsafe extern "C" fn(
            _: *mut archive_read,
            _: *const libc::c_char,
            _: *const libc::c_char,
        ) -> libc::c_int,
    >,
    pub read_header:
        Option<unsafe extern "C" fn(_: *mut archive_read, _: *mut archive_entry) -> libc::c_int>,
    pub read_data: Option<
        unsafe extern "C" fn(
            _: *mut archive_read,
            _: *mut *const libc::c_void,
            _: *mut size_t,
            _: *mut int64_t,
        ) -> libc::c_int,
    >,
    pub read_data_skip: Option<unsafe extern "C" fn(_: *mut archive_read) -> libc::c_int>,
    pub seek_data:
        Option<unsafe extern "C" fn(_: *mut archive_read, _: int64_t, _: libc::c_int) -> int64_t>,
    pub cleanup: Option<unsafe extern "C" fn(_: *mut archive_read) -> libc::c_int>,
    pub format_capabilties: Option<unsafe extern "C" fn(_: *mut archive_read) -> libc::c_int>,
    pub has_encrypted_entries: Option<unsafe extern "C" fn(_: *mut archive_read) -> libc::c_int>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_read_filter {
    pub position: int64_t,
    pub bidder: *mut archive_read_filter_bidder,
    pub upstream: *mut archive_read_filter,
    pub archive: *mut archive_read,
    pub open: Option<unsafe extern "C" fn(_: *mut archive_read_filter) -> libc::c_int>,
    pub read: Option<
        unsafe extern "C" fn(_: *mut archive_read_filter, _: *mut *const libc::c_void) -> ssize_t,
    >,
    pub skip: Option<unsafe extern "C" fn(_: *mut archive_read_filter, _: int64_t) -> int64_t>,
    pub seek: Option<
        unsafe extern "C" fn(_: *mut archive_read_filter, _: int64_t, _: libc::c_int) -> int64_t,
    >,
    pub close: Option<unsafe extern "C" fn(_: *mut archive_read_filter) -> libc::c_int>,
    pub sswitch:
        Option<unsafe extern "C" fn(_: *mut archive_read_filter, _: libc::c_uint) -> libc::c_int>,
    pub read_header: Option<
        unsafe extern "C" fn(_: *mut archive_read_filter, _: *mut archive_entry) -> libc::c_int,
    >,
    pub data: *mut libc::c_void,
    pub name: *const libc::c_char,
    pub code: libc::c_int,
    pub buffer: *mut libc::c_char,
    pub buffer_size: size_t,
    pub next: *mut libc::c_char,
    pub avail: size_t,
    pub client_buff: *const libc::c_void,
    pub client_total: size_t,
    pub client_next: *const libc::c_char,
    pub client_avail: size_t,
    pub end_of_file: libc::c_char,
    pub closed: libc::c_char,
    pub fatal: libc::c_char,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_read_filter_bidder {
    pub data: *mut libc::c_void,
    pub name: *const libc::c_char,
    pub bid: Option<
        unsafe extern "C" fn(
            _: *mut archive_read_filter_bidder,
            _: *mut archive_read_filter,
        ) -> libc::c_int,
    >,
    pub init: Option<unsafe extern "C" fn(_: *mut archive_read_filter) -> libc::c_int>,
    pub options: Option<
        unsafe extern "C" fn(
            _: *mut archive_read_filter_bidder,
            _: *const libc::c_char,
            _: *const libc::c_char,
        ) -> libc::c_int,
    >,
    pub free: Option<unsafe extern "C" fn(_: *mut archive_read_filter_bidder) -> libc::c_int>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_read_client {
    pub opener: Option<archive_open_callback>,
    pub reader: Option<archive_read_callback>,
    pub skipper: Option<archive_skip_callback>,
    pub seeker: Option<archive_seek_callback>,
    pub closer: Option<archive_close_callback>,
    pub switcher: Option<archive_switch_callback>,
    pub nodes: libc::c_uint,
    pub cursor: libc::c_uint,
    pub position: int64_t,
    pub dataset: *mut archive_read_data_node,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_read_data_node {
    pub begin_position: int64_t,
    pub total_size: int64_t,
    pub data: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_string_conv {
    pub next: *mut archive_string_conv,
    pub from_charset: *mut libc::c_char,
    pub to_charset: *mut libc::c_char,
    pub from_cp: libc::c_uint,
    pub to_cp: libc::c_uint,
    pub same: libc::c_int,
    pub flag: libc::c_int,
    pub cd: iconv_t,
    pub cd_w: iconv_t,
    pub utftmp: archive_string,
    pub converter: [Option<
        unsafe extern "C" fn(
            _: *mut archive_string,
            _: *const libc::c_void,
            _: size_t,
            _: *mut archive_string_conv,
        ) -> libc::c_int,
    >; 2],
    pub nconverter: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_entry {
    pub archive: *mut archive,
    pub stat: *mut libc::c_void,
    pub stat_valid: libc::c_int,
    pub ae_stat: aest,
    pub ae_set: libc::c_int,
    pub ae_fflags_text: archive_mstring,
    pub ae_fflags_set: libc::c_ulong,
    pub ae_fflags_clear: libc::c_ulong,
    pub ae_gname: archive_mstring,
    pub ae_hardlink: archive_mstring,
    pub ae_pathname: archive_mstring,
    pub ae_symlink: archive_mstring,
    pub ae_uname: archive_mstring,
    pub ae_sourcepath: archive_mstring,
    pub encryption: libc::c_char,
    pub mac_metadata: *mut libc::c_void,
    pub mac_metadata_size: size_t,
    pub digest: ae_digest,
    pub acl: archive_acl,
    pub xattr_head: *mut ae_xattr,
    pub xattr_p: *mut ae_xattr,
    pub sparse_head: *mut ae_sparse,
    pub sparse_tail: *mut ae_sparse,
    pub sparse_p: *mut ae_sparse,
    pub strmode: [libc::c_char; 12],
    pub ae_symlink_type: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ae_xattr {
    pub next: *mut ae_xattr,
    pub name: *mut libc::c_char,
    pub value: *mut libc::c_void,
    pub size: size_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_acl {
    pub mode: mode_t,
    pub acl_head: *mut archive_acl_entry,
    pub acl_p: *mut archive_acl_entry,
    pub acl_state: libc::c_int,
    pub acl_text_w: *mut wchar_t,
    pub acl_text: *mut libc::c_char,
    pub acl_types: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_acl_entry {
    pub next: *mut archive_acl_entry,
    pub type_0: libc::c_int,
    pub tag: libc::c_int,
    pub permset: libc::c_int,
    pub id: libc::c_int,
    pub name: archive_mstring,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_mstring {
    pub aes_mbs: archive_string,
    pub aes_utf8: archive_string,
    pub aes_wcs: archive_wstring,
    pub aes_mbs_in_locale: archive_string,
    pub aes_set: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_wstring {
    pub s: *mut wchar_t,
    pub length: size_t,
    pub buffer_length: size_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ae_digest {
    pub md5: [libc::c_uchar; 16],
    pub rmd160: [libc::c_uchar; 20],
    pub sha1: [libc::c_uchar; 20],
    pub sha256: [libc::c_uchar; 32],
    pub sha384: [libc::c_uchar; 48],
    pub sha512: [libc::c_uchar; 64],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct aest {
    pub aest_atime: int64_t,
    pub aest_atime_nsec: uint32_t,
    pub aest_ctime: int64_t,
    pub aest_ctime_nsec: uint32_t,
    pub aest_mtime: int64_t,
    pub aest_mtime_nsec: uint32_t,
    pub aest_birthtime: int64_t,
    pub aest_birthtime_nsec: uint32_t,
    pub aest_gid: int64_t,
    pub aest_ino: int64_t,
    pub aest_nlink: uint32_t,
    pub aest_size: uint64_t,
    pub aest_uid: int64_t,
    pub aest_dev_is_broken_down: libc::c_int,
    pub aest_dev: dev_t,
    pub aest_devmajor: dev_t,
    pub aest_devminor: dev_t,
    pub aest_rdev_is_broken_down: libc::c_int,
    pub aest_rdev: dev_t,
    pub aest_rdevmajor: dev_t,
    pub aest_rdevminor: dev_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ae_sparse {
    pub next: *mut ae_sparse,
    pub offset: int64_t,
    pub length: int64_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub tm_gmtoff: libc::c_long,
    pub tm_zone: *const libc::c_char,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct rar {
    pub main_flags: libc::c_uint,
    pub file_crc: libc::c_ulong,
    pub reserved1: [libc::c_char; 2],
    pub reserved2: [libc::c_char; 4],
    pub encryptver: libc::c_char,
    pub compression_method: libc::c_char,
    pub file_flags: libc::c_uint,
    pub packed_size: int64_t,
    pub unp_size: int64_t,
    pub mtime: time_t,
    pub mnsec: libc::c_long,
    pub mode: mode_t,
    pub filename: *mut libc::c_char,
    pub filename_save: *mut libc::c_char,
    pub filename_save_size: size_t,
    pub filename_allocated: size_t,
    pub salt: [libc::c_char; 8],
    pub atime: time_t,
    pub ansec: libc::c_long,
    pub ctime: time_t,
    pub cnsec: libc::c_long,
    pub arctime: time_t,
    pub arcnsec: libc::c_long,
    pub bytes_unconsumed: int64_t,
    pub bytes_remaining: int64_t,
    pub bytes_uncopied: int64_t,
    pub offset: int64_t,
    pub offset_outgoing: int64_t,
    pub offset_seek: int64_t,
    pub valid: libc::c_char,
    pub unp_offset: libc::c_uint,
    pub unp_buffer_size: libc::c_uint,
    pub unp_buffer: *mut libc::c_uchar,
    pub dictionary_size: libc::c_uint,
    pub start_new_block: libc::c_char,
    pub entry_eof: libc::c_char,
    pub crc_calculated: libc::c_ulong,
    pub found_first_header: libc::c_int,
    pub has_endarc_header: libc::c_char,
    pub dbo: *mut data_block_offsets,
    pub cursor: libc::c_uint,
    pub nodes: libc::c_uint,
    pub filename_must_match: libc::c_char,
    pub maincode: huffman_code,
    pub offsetcode: huffman_code,
    pub lowoffsetcode: huffman_code,
    pub lengthcode: huffman_code,
    pub lengthtable: [libc::c_uchar; 404],
    pub lzss: lzss,
    pub output_last_match: libc::c_char,
    pub lastlength: libc::c_uint,
    pub lastoffset: libc::c_uint,
    pub oldoffset: [libc::c_uint; 4],
    pub lastlowoffset: libc::c_uint,
    pub numlowoffsetrepeats: libc::c_uint,
    pub filterstart: int64_t,
    pub start_new_table: libc::c_char,
    pub ppmd_valid: libc::c_char,
    pub ppmd_eod: libc::c_char,
    pub is_ppmd_block: libc::c_char,
    pub ppmd_escape: libc::c_int,
    pub ppmd7_context: CPpmd7,
    pub range_dec: CPpmd7z_RangeDec,
    pub bytein: IByteIn,
    pub init_default_conversion: libc::c_int,
    pub sconv_default: *mut archive_string_conv,
    pub opt_sconv: *mut archive_string_conv,
    pub sconv_utf8: *mut archive_string_conv,
    pub sconv_utf16be: *mut archive_string_conv,
    pub br: rar_br,
    pub has_encrypted_entries: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct rar_br {
    pub cache_buffer: uint64_t,
    pub cache_avail: libc::c_int,
    pub avail_in: ssize_t,
    pub next_in: *const libc::c_uchar,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IByteIn {
    pub a: *mut archive_read,
    pub Read: Option<unsafe extern "C" fn(_: *mut libc::c_void) -> Byte>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct object {
    pub first: *mut archive_read_passphrase,
    pub last: *mut *mut archive_read_passphrase,
    pub candidate: libc::c_int,
    pub callback: Option<archive_passphrase_callback>,
    pub client_data: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct CPpmd7z_RangeDec {
    pub p: IPpmd7_RangeDec,
    pub Range: UInt32,
    pub Code: UInt32,
    pub Low: UInt32,
    pub Bottom: UInt32,
    pub Stream: *mut IByteIn,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IPpmd7_RangeDec {
    pub GetThreshold: Option<unsafe extern "C" fn(_: *mut libc::c_void, _: UInt32) -> UInt32>,
    pub Decode: Option<unsafe extern "C" fn(_: *mut libc::c_void, _: UInt32, _: UInt32) -> ()>,
    pub DecodeBit: Option<unsafe extern "C" fn(_: *mut libc::c_void, _: UInt32) -> UInt32>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct CPpmd7 {
    pub MinContext: *mut CPpmd7_Context,
    pub MaxContext: *mut CPpmd7_Context,
    pub FoundState: *mut CPpmd_State,
    pub OrderFall: libc::c_uint,
    pub InitEsc: libc::c_uint,
    pub PrevSuccess: libc::c_uint,
    pub MaxOrder: libc::c_uint,
    pub HiBitsFlag: libc::c_uint,
    pub RunLength: Int32,
    pub InitRL: Int32,
    pub Size: UInt32,
    pub GlueCount: UInt32,
    pub Base: *mut Byte,
    pub LoUnit: *mut Byte,
    pub HiUnit: *mut Byte,
    pub Text: *mut Byte,
    pub UnitsStart: *mut Byte,
    pub AlignOffset: UInt32,
    pub Indx2Units: [Byte; 38],
    pub Units2Indx: [Byte; 128],
    pub FreeList: [CPpmd_Void_Ref; 38],
    pub NS2Indx: [Byte; 256],
    pub NS2BSIndx: [Byte; 256],
    pub HB2Flag: [Byte; 256],
    pub DummySee: CPpmd_See,
    pub See: [[CPpmd_See; 16]; 25],
    pub BinSumm: [[UInt16; 64]; 128],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct CPpmd_See {
    pub Summ: UInt16,
    pub Shift: Byte,
    pub Count: Byte,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct CPpmd_State {
    pub Symbol: Byte,
    pub Freq: Byte,
    pub SuccessorLow: UInt16,
    pub SuccessorHigh: UInt16,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct CPpmd7_Context_ {
    pub NumStats: UInt16,
    pub SummFreq: UInt16,
    pub Stats: CPpmd_State_Ref,
    pub Suffix: CPpmd7_Context_Ref,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lzss {
    pub window: *mut libc::c_uchar,
    pub mask: libc::c_int,
    pub position: int64_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct huffman_code {
    pub tree: *mut huffman_tree_node,
    pub numentries: libc::c_int,
    pub numallocatedentries: libc::c_int,
    pub minlength: libc::c_int,
    pub maxlength: libc::c_int,
    pub tablesize: libc::c_int,
    pub table: *mut huffman_table_entry,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct huffman_table_entry {
    pub length: libc::c_uint,
    pub value: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct huffman_tree_node {
    pub branches: [libc::c_int; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct data_block_offsets {
    pub header_size: int64_t,
    pub start_offset: int64_t,
    pub end_offset: int64_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IPpmd7 {
    pub Ppmd7_Construct: Option<unsafe extern "C" fn(_: *mut CPpmd7) -> ()>,
    pub Ppmd7_Alloc: Option<unsafe extern "C" fn(_: *mut CPpmd7, _: UInt32) -> Bool>,
    pub Ppmd7_Free: Option<unsafe extern "C" fn(_: *mut CPpmd7) -> ()>,
    pub Ppmd7_Init: Option<unsafe extern "C" fn(_: *mut CPpmd7, _: libc::c_uint) -> ()>,
    pub Ppmd7z_RangeDec_CreateVTable: Option<unsafe extern "C" fn(_: *mut CPpmd7z_RangeDec) -> ()>,
    pub PpmdRAR_RangeDec_CreateVTable: Option<unsafe extern "C" fn(_: *mut CPpmd7z_RangeDec) -> ()>,
    pub Ppmd7z_RangeDec_Init: Option<unsafe extern "C" fn(_: *mut CPpmd7z_RangeDec) -> Bool>,
    pub PpmdRAR_RangeDec_Init: Option<unsafe extern "C" fn(_: *mut CPpmd7z_RangeDec) -> Bool>,
    pub Ppmd7_DecodeSymbol:
        Option<unsafe extern "C" fn(_: *mut CPpmd7, _: *mut IPpmd7_RangeDec) -> libc::c_int>,
    pub Ppmd7z_RangeEnc_Init: Option<unsafe extern "C" fn(_: *mut CPpmd7z_RangeEnc) -> ()>,
    pub Ppmd7z_RangeEnc_FlushData: Option<unsafe extern "C" fn(_: *mut CPpmd7z_RangeEnc) -> ()>,
    pub Ppmd7_EncodeSymbol: Option<
        unsafe extern "C" fn(_: *mut CPpmd7, _: *mut CPpmd7z_RangeEnc, _: libc::c_int) -> (),
    >,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct CPpmd7z_RangeEnc {
    pub Low: UInt64,
    pub Range: UInt32,
    pub Cache: Byte,
    pub CacheSize: UInt64,
    pub Stream: *mut IByteOut,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IByteOut {
    pub a: *mut archive_write,
    pub Write: Option<unsafe extern "C" fn(_: *mut libc::c_void, _: Byte) -> ()>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct rar_file_header {
    pub pack_size: [libc::c_char; 4],
    pub unp_size: [libc::c_char; 4],
    pub host_os: libc::c_char,
    pub file_crc: [libc::c_char; 4],
    pub file_time: [libc::c_char; 4],
    pub unp_ver: libc::c_char,
    pub method: libc::c_char,
    pub name_size: [libc::c_char; 2],
    pub file_attr: [libc::c_char; 4],
}

/* Fields common to all headers */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rar_header {
    pub crc: [libc::c_char; 2],
    pub type_0: libc::c_char,
    pub flags: [libc::c_char; 2],
    pub size: [libc::c_char; 2],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_write {
    pub archive: archive,
    pub skip_file_set: libc::c_int,
    pub skip_file_dev: int64_t,
    pub skip_file_ino: int64_t,
    pub nulls: *const libc::c_uchar,
    pub null_length: size_t,
    pub client_opener: Option<archive_open_callback>,
    pub client_writer: Option<archive_write_callback>,
    pub client_closer: Option<archive_close_callback>,
    pub client_freer: Option<archive_free_callback>,
    pub client_data: *mut libc::c_void,
    pub bytes_per_block: libc::c_int,
    pub bytes_in_last_block: libc::c_int,
    pub filter_first: *mut archive_write_filter,
    pub filter_last: *mut archive_write_filter,
    pub format_data: *mut libc::c_void,
    pub format_name: *const libc::c_char,
    pub format_init: Option<unsafe extern "C" fn(_: *mut archive_write) -> libc::c_int>,
    pub format_options: Option<
        unsafe extern "C" fn(
            _: *mut archive_write,
            _: *const libc::c_char,
            _: *const libc::c_char,
        ) -> libc::c_int,
    >,
    pub format_finish_entry: Option<unsafe extern "C" fn(_: *mut archive_write) -> libc::c_int>,
    pub format_write_header:
        Option<unsafe extern "C" fn(_: *mut archive_write, _: *mut archive_entry) -> libc::c_int>,
    pub format_write_data: Option<
        unsafe extern "C" fn(_: *mut archive_write, _: *const libc::c_void, _: size_t) -> ssize_t,
    >,
    pub format_close: Option<unsafe extern "C" fn(_: *mut archive_write) -> libc::c_int>,
    pub format_free: Option<unsafe extern "C" fn(_: *mut archive_write) -> libc::c_int>,
    pub passphrase: *mut libc::c_char,
    pub passphrase_callback: Option<archive_passphrase_callback>,
    pub passphrase_client_data: *mut libc::c_void,
}

pub struct archive_write_filter {
    pub bytes_written: int64_t,
    pub archive: *mut archive,
    pub next_filter: *mut archive_write_filter,
    pub options: Option<
        unsafe extern "C" fn(
            _: *mut archive_write_filter,
            _: *const libc::c_char,
            _: *const libc::c_char,
        ) -> libc::c_int,
    >,
    pub open: Option<unsafe extern "C" fn(_: *mut archive_write_filter) -> libc::c_int>,
    pub write: Option<
        unsafe extern "C" fn(
            _: *mut archive_write_filter,
            _: *const libc::c_void,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub close: Option<unsafe extern "C" fn(_: *mut archive_write_filter) -> libc::c_int>,
    pub free: Option<unsafe extern "C" fn(_: *mut archive_write_filter) -> libc::c_int>,
    pub data: *mut libc::c_void,
    pub name: *const libc::c_char,
    pub code: libc::c_int,
    pub bytes_per_block: libc::c_int,
    pub bytes_in_last_block: libc::c_int,
    pub state: libc::c_int,
}

pub type CPpmd7_Context_Ref = UInt32;
pub type CPpmd7_Context = CPpmd7_Context_;

/* Main context structure. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rar5 {
    pub header_initialized: libc::c_int,
    pub skipped_magic: libc::c_int,
    pub skip_mode: libc::c_int,
    pub merge_mode: libc::c_int,
    pub qlist_offset: uint64_t,
    pub rr_offset: uint64_t,
    pub generic: generic_header,
    pub main: main_header,
    pub cstate: comp_state,
    pub file: file_header,
    pub bits: bit_reader,
    pub vol: multivolume,
    pub last_block_hdr: compressed_block_header,
}
/* Current byte pointer. */
/* RARv5 block header structure. Use bf_* functions to get values from
 * block_flags_u8 field. I.e. bf_byte_count, etc. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct compressed_block_header {
    pub block_flags_u8: uint8_t,
    pub block_cksum: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct multivolume {
    pub expected_vol_no: libc::c_uint,
    pub push_buf: *mut uint8_t,
}
/* Bit reader state. */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bit_reader {
    pub bit_addr: int8_t,
    pub in_addr: libc::c_int,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct file_header {
    pub bytes_remaining: ssize_t,
    pub unpacked_size: ssize_t,
    pub last_offset: int64_t,
    pub last_size: int64_t,
    #[bitfield(name = "solid", ty = "uint8_t", bits = "0..=0")]
    #[bitfield(name = "service", ty = "uint8_t", bits = "1..=1")]
    #[bitfield(name = "eof", ty = "uint8_t", bits = "2..=2")]
    #[bitfield(name = "dir", ty = "uint8_t", bits = "3..=3")]
    pub solid_service_eof_dir: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
    pub e_mtime: uint64_t,
    pub e_ctime: uint64_t,
    pub e_atime: uint64_t,
    pub e_unix_ns: uint32_t,
    pub stored_crc32: uint32_t,
    pub calculated_crc32: uint32_t,
    pub blake2sp: [uint8_t; 32],
    pub b2state: blake2sp_state,
    pub has_blake2: libc::c_char,
    pub redir_type: uint64_t,
    pub redir_flags: uint64_t,
    pub solid_window_size: ssize_t,
}
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct __blake2sp_state {
    pub S: [[blake2s_state; 1]; 8],
    pub R: [blake2s_state; 1],
    pub buf: [uint8_t; 512],
    pub buflen: uint32_t,
    pub outlen: uint8_t,
}
pub type blake2s_state = __blake2s_state;
pub type blake2sp_state = __blake2sp_state;

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct __blake2s_state {
    pub h: [uint32_t; 8],
    pub t: [uint32_t; 2],
    pub f: [uint32_t; 2],
    pub buf: [uint8_t; 128],
    pub buflen: uint32_t,
    pub outlen: uint8_t,
    pub last_node: uint8_t,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct comp_state {
    #[bitfield(name = "initialized", ty = "uint8_t", bits = "0..=0")]
    #[bitfield(name = "all_filters_applied", ty = "uint8_t", bits = "1..=1")]
    #[bitfield(name = "switch_multivolume", ty = "uint8_t", bits = "2..=2")]
    #[bitfield(name = "block_parsing_finished", ty = "uint8_t", bits = "3..=3")]
    #[bitfield(name = "notused", ty = "libc::c_int", bits = "4..=7")]
    pub initialized_all_filters_applied_switch_multivolume_block_parsing_finished_notused: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
    pub flags: libc::c_int,
    pub method: libc::c_int,
    pub version: libc::c_int,
    pub window_size: ssize_t,
    pub window_buf: *mut uint8_t,
    pub filtered_buf: *mut uint8_t,
    pub block_buf: *const uint8_t,
    pub window_mask: size_t,
    pub write_ptr: int64_t,
    pub last_write_ptr: int64_t,
    pub last_unstore_ptr: int64_t,
    pub solid_offset: int64_t,
    pub cur_block_size: ssize_t,
    pub last_len: libc::c_int,
    pub bd: decode_table,
    pub ld: decode_table,
    pub dd: decode_table,
    pub ldd: decode_table,
    pub rd: decode_table,
    pub filters: cdeque,
    pub last_block_start: int64_t,
    pub last_block_length: ssize_t,
    pub dist_cache: [libc::c_int; 4],
    pub dready: [data_ready; 2],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct data_ready {
    pub used: libc::c_char,
    pub buf: *const uint8_t,
    pub size: size_t,
    pub offset: int64_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cdeque {
    pub beg_pos: uint16_t,
    pub end_pos: uint16_t,
    pub cap_mask: uint16_t,
    pub size: uint16_t,
    pub arr: *mut size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct decode_table {
    pub size: uint32_t,
    pub decode_len: [int32_t; 16],
    pub decode_pos: [uint32_t; 16],
    pub quick_bits: uint32_t,
    pub quick_len: [uint8_t; 1024],
    pub quick_num: [uint16_t; 1024],
    pub decode_num: [uint16_t; 306],
}
/* RARv5 main header structure. */
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct main_header {
    #[bitfield(name = "solid", ty = "uint8_t", bits = "0..=0")]
    #[bitfield(name = "volume", ty = "uint8_t", bits = "1..=1")]
    #[bitfield(name = "endarc", ty = "uint8_t", bits = "2..=2")]
    #[bitfield(name = "notused", ty = "uint8_t", bits = "3..=7")]
    pub solid_volume_endarc_notused: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
    pub vol_no: libc::c_uint,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct generic_header {
    #[bitfield(name = "split_after", ty = "uint8_t", bits = "0..=0")]
    #[bitfield(name = "split_before", ty = "uint8_t", bits = "1..=1")]
    #[bitfield(name = "padding", ty = "uint8_t", bits = "2..=7")]
    pub split_after_split_before_padding: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
    pub size: libc::c_int,
    pub last_header_id: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct filter_info {
    pub type_0: libc::c_int,
    pub channels: libc::c_int,
    pub pos_r: libc::c_int,
    pub block_start: int64_t,
    pub block_length: ssize_t,
    pub width: uint16_t,
}

pub type mbstate_t = __mbstate_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __mbstate_t {
    pub __count: libc::c_int,
    pub __value: archive_string_shift_state,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union archive_string_shift_state {
    pub __wch: libc::c_uint,
    pub __wchb: [libc::c_char; 4],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nfsv4_acl_perm_map_struct {
    pub perm: libc::c_int,
    pub c: libc::c_char,
    pub wc: wchar_t,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct nfsv4_acl_flag_map_struct {
    pub perm: libc::c_int,
    pub c: libc::c_char,
    pub wc: wchar_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_string_temporary_field_1 {
    pub start: *const wchar_t,
    pub end: *const wchar_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_string_temporary_field_2 {
    pub start: *const libc::c_char,
    pub end: *const libc::c_char,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct unicode_decomposition_table {
    pub nfc: uint32_t,
    pub cp1: uint32_t,
    pub cp2: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct unicode_composition_table {
    pub cp1: uint32_t,
    pub cp2: uint32_t,
    pub nfc: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_string_fdc {
    pub uc: uint32_t,
    pub ccc: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ar {
    pub entry_bytes_remaining: int64_t,
    pub entry_bytes_unconsumed: size_t,
    pub entry_offset: int64_t,
    pub entry_padding: int64_t,
    pub strtab: *mut libc::c_char,
    pub strtab_size: size_t,
    pub read_global_header: libc::c_char,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct warc_s {
    pub cntlen: size_t,
    pub cntoff: size_t,
    pub unconsumed: size_t,
    pub pool: warc_strbuf_t,
    pub pver: libc::c_uint,
    pub sver: archive_string,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct warc_strbuf_t {
    pub len: size_t,
    pub str_0: *mut libc::c_char,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct warc_string_t {
    pub len: size_t,
    pub str_0: *const libc::c_char,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _xmlTextReader {
    _unused: [u8; 0],
}
pub enum lzma_internal_s {}
pub enum internal_state {}
pub type lzma_internal = lzma_internal_s;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lzma_allocator {
    pub alloc: Option<
        unsafe extern "C" fn(_: *mut libc::c_void, _: size_t, _: size_t) -> *mut libc::c_void,
    >,
    pub free: Option<unsafe extern "C" fn(_: *mut libc::c_void, _: *mut libc::c_void) -> ()>,
    pub opaque: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct z_stream_s {
    pub next_in: *mut Bytef,
    pub avail_in: uInt,
    pub total_in: uLong,
    pub next_out: *mut Bytef,
    pub avail_out: uInt,
    pub total_out: uLong,
    pub msg: *mut libc::c_char,
    pub state: *mut internal_state,
    pub zalloc: alloc_func,
    pub zfree: free_func,
    pub opaque: voidpf,
    pub data_type: libc::c_int,
    pub adler: uLong,
    pub reserved: uLong,
}

pub type z_stream_t = *mut z_stream_s;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct chksumval {
    pub alg: libc::c_int,
    pub len: size_t,
    pub val: [libc::c_uchar; 20],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct hdlink {
    pub next: *mut hdlink,
    pub id: libc::c_uint,
    pub cnt: libc::c_int,
    pub files: *mut xar_file,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xar_file {
    pub next: *mut xar_file,
    pub hdnext: *mut xar_file,
    pub parent: *mut xar_file,
    pub subdirs: libc::c_int,
    pub has: libc::c_uint,
    pub id: uint64_t,
    pub length: uint64_t,
    pub offset: uint64_t,
    pub size: uint64_t,
    pub encoding: enctype,
    pub a_sum: chksumval,
    pub e_sum: chksumval,
    pub pathname: archive_string,
    pub symlink: archive_string,
    pub ctime: time_t,
    pub mtime: time_t,
    pub atime: time_t,
    pub uname: archive_string,
    pub uid: int64_t,
    pub gname: archive_string,
    pub gid: int64_t,
    pub mode: mode_t,
    pub dev: dev_t,
    pub devmajor: dev_t,
    pub devminor: dev_t,
    pub ino64: int64_t,
    pub fflags_text: archive_string,
    pub link: libc::c_uint,
    pub nlink: libc::c_uint,
    pub hardlink: archive_string,
    pub xattr_list: *mut xattr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xattr {
    pub next: *mut xattr,
    pub name: archive_string,
    pub id: uint64_t,
    pub length: uint64_t,
    pub offset: uint64_t,
    pub size: uint64_t,
    pub encoding: enctype,
    pub a_sum: chksumval,
    pub e_sum: chksumval,
    pub fstype: archive_string,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct heap_queue {
    pub files: *mut *mut xar_file,
    pub allocated: libc::c_int,
    pub used: libc::c_int,
}

pub enum EVP_MD {}
pub enum ENGINE {}
pub enum EVP_PKEY_CTX {}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EVP_MD_CTX {
    digest: *mut EVP_MD,
    engine: *mut ENGINE,
    flags: libc::c_ulong,
    md_data: *mut libc::c_void,
    pctx: *mut EVP_PKEY_CTX,
    update: *mut libc::c_void,
}

pub type archive_sha1_ctx = *mut EVP_MD_CTX;
pub type archive_md5_ctx = *mut EVP_MD_CTX;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct unknown_tag {
    pub next: *mut unknown_tag,
    pub name: archive_string,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_digest {
    pub md5init: Option<unsafe extern "C" fn(_: *mut archive_md5_ctx) -> libc::c_int>,
    pub md5update: Option<
        unsafe extern "C" fn(
            _: *mut archive_md5_ctx,
            _: *const libc::c_void,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub md5final:
        Option<unsafe extern "C" fn(_: *mut archive_md5_ctx, _: *mut libc::c_void) -> libc::c_int>,
    pub rmd160init: Option<unsafe extern "C" fn(_: *mut archive_rmd160_ctx) -> libc::c_int>,
    pub rmd160update: Option<
        unsafe extern "C" fn(
            _: *mut archive_rmd160_ctx,
            _: *const libc::c_void,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub rmd160final: Option<
        unsafe extern "C" fn(_: *mut archive_rmd160_ctx, _: *mut libc::c_void) -> libc::c_int,
    >,
    pub sha1init: Option<unsafe extern "C" fn(_: *mut archive_sha1_ctx) -> libc::c_int>,
    pub sha1update: Option<
        unsafe extern "C" fn(
            _: *mut archive_sha1_ctx,
            _: *const libc::c_void,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub sha1final:
        Option<unsafe extern "C" fn(_: *mut archive_sha1_ctx, _: *mut libc::c_void) -> libc::c_int>,
    pub sha256init: Option<unsafe extern "C" fn(_: *mut archive_sha256_ctx) -> libc::c_int>,
    pub sha256update: Option<
        unsafe extern "C" fn(
            _: *mut archive_sha256_ctx,
            _: *const libc::c_void,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub sha256final: Option<
        unsafe extern "C" fn(_: *mut archive_sha256_ctx, _: *mut libc::c_void) -> libc::c_int,
    >,
    pub sha384init: Option<unsafe extern "C" fn(_: *mut archive_sha384_ctx) -> libc::c_int>,
    pub sha384update: Option<
        unsafe extern "C" fn(
            _: *mut archive_sha384_ctx,
            _: *const libc::c_void,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub sha384final: Option<
        unsafe extern "C" fn(_: *mut archive_sha384_ctx, _: *mut libc::c_void) -> libc::c_int,
    >,
    pub sha512init: Option<unsafe extern "C" fn(_: *mut archive_sha512_ctx) -> libc::c_int>,
    pub sha512update: Option<
        unsafe extern "C" fn(
            _: *mut archive_sha512_ctx,
            _: *const libc::c_void,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub sha512final: Option<
        unsafe extern "C" fn(_: *mut archive_sha512_ctx, _: *mut libc::c_void) -> libc::c_int,
    >,
}
pub type archive_sha512_ctx = *mut EVP_MD_CTX;
pub type archive_sha384_ctx = *mut EVP_MD_CTX;
pub type archive_sha256_ctx = *mut EVP_MD_CTX;
pub type archive_rmd160_ctx = *mut EVP_MD_CTX;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlattr_list {
    pub first: *mut xmlattr,
    pub last: *mut *mut xmlattr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlattr {
    pub next: *mut xmlattr,
    pub name: *mut libc::c_char,
    pub value: *mut libc::c_char,
}
pub type xmlTextReader = _xmlTextReader;
pub type xmlTextReaderPtr = *mut xmlTextReader;
pub type xmlTextReaderLocatorPtr = *mut libc::c_void;

pub type xmlTextReaderErrorFunc = Option<
    unsafe extern "C" fn(
        _: *mut libc::c_void,
        _: *const libc::c_char,
        _: xmlParserSeverities,
        _: xmlTextReaderLocatorPtr,
    ) -> (),
>;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct tar {
    pub acl_text: archive_string,
    pub entry_pathname: archive_string,
    pub entry_pathname_override: archive_string,
    pub entry_linkpath: archive_string,
    pub entry_uname: archive_string,
    pub entry_gname: archive_string,
    pub longlink: archive_string,
    pub longname: archive_string,
    pub pax_header: archive_string,
    pub pax_global: archive_string,
    pub line: archive_string,
    pub pax_hdrcharset_binary: libc::c_int,
    pub header_recursion_depth: libc::c_int,
    pub entry_bytes_remaining: int64_t,
    pub entry_offset: int64_t,
    pub entry_padding: int64_t,
    pub entry_bytes_unconsumed: int64_t,
    pub realsize: int64_t,
    pub sparse_allowed: libc::c_int,
    pub sparse_list: *mut sparse_block,
    pub sparse_last: *mut sparse_block,
    pub sparse_offset: int64_t,
    pub sparse_numbytes: int64_t,
    pub sparse_gnu_major: libc::c_int,
    pub sparse_gnu_minor: libc::c_int,
    pub sparse_gnu_pending: libc::c_char,
    pub localname: archive_string,
    pub opt_sconv: *mut archive_string_conv,
    pub sconv: *mut archive_string_conv,
    pub sconv_acl: *mut archive_string_conv,
    pub sconv_default: *mut archive_string_conv,
    pub init_default_conversion: libc::c_int,
    pub compat_2x: libc::c_int,
    pub process_mac_extensions: libc::c_int,
    pub read_concatenated_archives: libc::c_int,
    pub realsize_override: libc::c_int,
}
/*
 * Old GNU format doesn't use POSIX 'prefix' field; they use
 * the 'L' (longname) entry instead.
 */
/*
 * Data specific to this format.
 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sparse_block {
    pub next: *mut sparse_block,
    pub offset: int64_t,
    pub remaining: int64_t,
    pub hole: libc::c_int,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_entry_header_ustar {
    pub name: [libc::c_char; 100],
    pub mode: [libc::c_char; 8],
    pub uid: [libc::c_char; 8],
    pub gid: [libc::c_char; 8],
    pub size: [libc::c_char; 12],
    pub mtime: [libc::c_char; 12],
    pub checksum: [libc::c_char; 8],
    pub typeflag: [libc::c_char; 1],
    pub linkname: [libc::c_char; 100],
    pub magic: [libc::c_char; 6],
    pub version: [libc::c_char; 2],
    pub uname: [libc::c_char; 32],
    pub gname: [libc::c_char; 32],
    pub rdevmajor: [libc::c_char; 8],
    pub rdevminor: [libc::c_char; 8],
    pub prefix: [libc::c_char; 155],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_entry_header_gnutar {
    pub name: [libc::c_char; 100],
    pub mode: [libc::c_char; 8],
    pub uid: [libc::c_char; 8],
    pub gid: [libc::c_char; 8],
    pub size: [libc::c_char; 12],
    pub mtime: [libc::c_char; 12],
    pub checksum: [libc::c_char; 8],
    pub typeflag: [libc::c_char; 1],
    pub linkname: [libc::c_char; 100],
    pub magic: [libc::c_char; 8],
    pub uname: [libc::c_char; 32],
    pub gname: [libc::c_char; 32],
    pub rdevmajor: [libc::c_char; 8],
    pub rdevminor: [libc::c_char; 8],
    pub atime: [libc::c_char; 12],
    pub ctime: [libc::c_char; 12],
    pub offset: [libc::c_char; 12],
    pub longnames: [libc::c_char; 4],
    pub unused: [libc::c_char; 1],
    pub sparse: [gnu_sparse; 4],
    pub isextended: [libc::c_char; 1],
    pub realsize: [libc::c_char; 12],
}
/*
 * Structure of GNU tar header
 */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct gnu_sparse {
    pub offset: [libc::c_char; 12],
    pub numbytes: [libc::c_char; 12],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct extended {
    pub sparse: [gnu_sparse; 21],
    pub isextended: [libc::c_char; 1],
    pub padding: [libc::c_char; 7],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_entry_linkresolver;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_rb_node {
    pub rb_nodes: [*mut archive_rb_node; 2],
    pub rb_info: uintptr_t,
}

pub type archive_rbto_compare_key_fn =
    Option<unsafe extern "C" fn(_: *const archive_rb_node, _: *const libc::c_void) -> libc::c_int>;

pub type archive_rbto_compare_nodes_fn = Option<
    unsafe extern "C" fn(_: *const archive_rb_node, _: *const archive_rb_node) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_rb_tree_ops {
    pub rbto_compare_nodes: archive_rbto_compare_nodes_fn,
    pub rbto_compare_key: archive_rbto_compare_key_fn,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_rb_tree {
    pub rbt_root: *mut archive_rb_node,
    pub rbt_ops: *const archive_rb_tree_ops,
}

pub type pack_t = unsafe extern "C" fn(
    _: libc::c_int,
    _: *mut libc::c_ulong,
    _: *mut *const libc::c_char,
) -> dev_t;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct bz_stream {
    pub next_in: *mut libc::c_char,
    pub avail_in: libc::c_uint,
    pub total_in_lo32: libc::c_uint,
    pub total_in_hi32: libc::c_uint,
    pub next_out: *mut libc::c_char,
    pub avail_out: libc::c_uint,
    pub total_out_lo32: libc::c_uint,
    pub total_out_hi32: libc::c_uint,
    pub state: *mut libc::c_void,
    pub bzalloc: Option<
        unsafe extern "C" fn(
            _: *mut libc::c_void,
            _: libc::c_int,
            _: libc::c_int,
        ) -> *mut libc::c_void,
    >,
    pub bzfree: Option<unsafe extern "C" fn(_: *mut libc::c_void, _: *mut libc::c_void) -> ()>,
    pub opaque: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lzma_stream {
    pub next_in: *const uint8_t,
    pub avail_in: size_t,
    pub total_in: uint64_t,
    pub next_out: *mut uint8_t,
    pub avail_out: size_t,
    pub total_out: uint64_t,
    pub allocator: *const lzma_allocator,
    pub internal: *mut lzma_internal,
    pub reserved_ptr1: *mut libc::c_void,
    pub reserved_ptr2: *mut libc::c_void,
    pub reserved_ptr3: *mut libc::c_void,
    pub reserved_ptr4: *mut libc::c_void,
    pub reserved_int1: uint64_t,
    pub reserved_int2: uint64_t,
    pub reserved_int3: size_t,
    pub reserved_int4: size_t,
    pub reserved_enum1: lzma_reserved_enum,
    pub reserved_enum2: lzma_reserved_enum,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lzma_filter {
    pub id: lzma_vli,
    pub options: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct lzma_options_delta {
    pub type_0: lzma_delta_type,
    pub dist: uint32_t,
    pub reserved_int1: uint32_t,
    pub reserved_int2: uint32_t,
    pub reserved_int3: uint32_t,
    pub reserved_int4: uint32_t,
    pub reserved_ptr1: *mut libc::c_void,
    pub reserved_ptr2: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct IPpmd8 {
    pub Ppmd8_Construct: Option<unsafe extern "C" fn(_: *mut CPpmd8) -> ()>,
    pub Ppmd8_Alloc: Option<unsafe extern "C" fn(_: *mut CPpmd8, _: UInt32) -> Bool>,
    pub Ppmd8_Free: Option<unsafe extern "C" fn(_: *mut CPpmd8) -> ()>,
    pub Ppmd8_Init:
        Option<unsafe extern "C" fn(_: *mut CPpmd8, _: libc::c_uint, _: libc::c_uint) -> ()>,
    pub Ppmd8_RangeDec_Init: Option<unsafe extern "C" fn(_: *mut CPpmd8) -> libc::c_int>,
    pub Ppmd8_DecodeSymbol: Option<unsafe extern "C" fn(_: *mut CPpmd8) -> libc::c_int>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_cryptor {
    pub pbkdf2sha1: Option<
        unsafe extern "C" fn(
            _: *const libc::c_char,
            _: size_t,
            _: *const uint8_t,
            _: size_t,
            _: libc::c_uint,
            _: *mut uint8_t,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub decrypto_aes_ctr_init: Option<
        unsafe extern "C" fn(
            _: *mut archive_crypto_ctx,
            _: *const uint8_t,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub decrypto_aes_ctr_update: Option<
        unsafe extern "C" fn(
            _: *mut archive_crypto_ctx,
            _: *const uint8_t,
            _: size_t,
            _: *mut uint8_t,
            _: *mut size_t,
        ) -> libc::c_int,
    >,
    pub decrypto_aes_ctr_release:
        Option<unsafe extern "C" fn(_: *mut archive_crypto_ctx) -> libc::c_int>,
    pub encrypto_aes_ctr_init: Option<
        unsafe extern "C" fn(
            _: *mut archive_crypto_ctx,
            _: *const uint8_t,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub encrypto_aes_ctr_update: Option<
        unsafe extern "C" fn(
            _: *mut archive_crypto_ctx,
            _: *const uint8_t,
            _: size_t,
            _: *mut uint8_t,
            _: *mut size_t,
        ) -> libc::c_int,
    >,
    pub encrypto_aes_ctr_release:
        Option<unsafe extern "C" fn(_: *mut archive_crypto_ctx) -> libc::c_int>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_hmac {
    pub __hmac_sha1_init: Option<
        unsafe extern "C" fn(
            _: *mut archive_hmac_sha1_ctx,
            _: *const uint8_t,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub __hmac_sha1_update: Option<
        unsafe extern "C" fn(_: *mut archive_hmac_sha1_ctx, _: *const uint8_t, _: size_t) -> (),
    >,
    pub __hmac_sha1_final: Option<
        unsafe extern "C" fn(_: *mut archive_hmac_sha1_ctx, _: *mut uint8_t, _: *mut size_t) -> (),
    >,
    pub __hmac_sha1_cleanup: Option<unsafe extern "C" fn(_: *mut archive_hmac_sha1_ctx) -> ()>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct CPpmd8 {
    pub MinContext: *mut CPpmd8_Context,
    pub MaxContext: *mut CPpmd8_Context,
    pub FoundState: *mut CPpmd_State,
    pub OrderFall: libc::c_uint,
    pub InitEsc: libc::c_uint,
    pub PrevSuccess: libc::c_uint,
    pub MaxOrder: libc::c_uint,
    pub RunLength: Int32,
    pub InitRL: Int32,
    pub Size: UInt32,
    pub GlueCount: UInt32,
    pub Base: *mut Byte,
    pub LoUnit: *mut Byte,
    pub HiUnit: *mut Byte,
    pub Text: *mut Byte,
    pub UnitsStart: *mut Byte,
    pub AlignOffset: UInt32,
    pub RestoreMethod: libc::c_uint,
    pub Range: UInt32,
    pub Code: UInt32,
    pub Low: UInt32,
    pub Stream: obj_zip,
    pub Indx2Units: [Byte; 38],
    pub Units2Indx: [Byte; 128],
    pub FreeList: [CPpmd_Void_Ref; 38],
    pub Stamps: [UInt32; 38],
    pub NS2BSIndx: [Byte; 256],
    pub NS2Indx: [Byte; 260],
    pub DummySee: CPpmd_See,
    pub See: [[CPpmd_See; 32]; 24],
    pub BinSumm: [[UInt16; 64]; 25],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_crypto_ctx {
    pub ctx: *mut EVP_CIPHER_CTX,
    pub type_0: *const EVP_CIPHER,
    pub key: [uint8_t; 32],
    pub key_len: libc::c_uint,
    pub nonce: [uint8_t; 16],
    pub encr_buf: [uint8_t; 16],
    pub encr_pos: libc::c_uint,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct hmac_ctx_st {
    pub md: *const EVP_MD,
    pub md_ctx: EVP_MD_CTX,
    pub i_ctx: EVP_MD_CTX,
    pub o_ctx: EVP_MD_CTX,
    pub key_length: libc::c_uint,
    pub key: [libc::c_uchar; 128],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_st {
    pub nid: libc::c_int,
    pub block_size: libc::c_int,
    pub key_len: libc::c_int,
    pub iv_len: libc::c_int,
    pub flags: libc::c_ulong,
    pub init: Option<
        unsafe extern "C" fn(
            _: *mut EVP_CIPHER_CTX,
            _: *const libc::c_uchar,
            _: *const libc::c_uchar,
            _: libc::c_int,
        ) -> libc::c_int,
    >,
    pub do_cipher: Option<
        unsafe extern "C" fn(
            _: *mut EVP_CIPHER_CTX,
            _: *mut libc::c_uchar,
            _: *const libc::c_uchar,
            _: size_t,
        ) -> libc::c_int,
    >,
    pub cleanup: Option<unsafe extern "C" fn(_: *mut EVP_CIPHER_CTX) -> libc::c_int>,
    pub ctx_size: libc::c_int,
    pub set_asn1_parameters:
        Option<unsafe extern "C" fn(_: *mut EVP_CIPHER_CTX, _: *mut ASN1_TYPE) -> libc::c_int>,
    pub get_asn1_parameters:
        Option<unsafe extern "C" fn(_: *mut EVP_CIPHER_CTX, _: *mut ASN1_TYPE) -> libc::c_int>,
    pub ctrl: Option<
        unsafe extern "C" fn(
            _: *mut EVP_CIPHER_CTX,
            _: libc::c_int,
            _: libc::c_int,
            _: *mut libc::c_void,
        ) -> libc::c_int,
    >,
    pub app_data: *mut libc::c_void,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_ctx_st {
    pub cipher: *const EVP_CIPHER,
    pub engine: *mut ENGINE,
    pub encrypt: libc::c_int,
    pub buf_len: libc::c_int,
    pub oiv: [libc::c_uchar; 16],
    pub iv: [libc::c_uchar; 16],
    pub buf: [libc::c_uchar; 32],
    pub num: libc::c_int,
    pub app_data: *mut libc::c_void,
    pub key_len: libc::c_int,
    pub flags: libc::c_ulong,
    pub cipher_data: *mut libc::c_void,
    pub final_used: libc::c_int,
    pub block_mask: libc::c_int,
    pub final_0: [libc::c_uchar; 32],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct CPpmd8_Context_ {
    pub NumStats: Byte,
    pub Flags: Byte,
    pub SummFreq: UInt16,
    pub Stats: CPpmd_State_Ref,
    pub Suffix: CPpmd8_Context_Ref,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_type_st {
    pub type_0: libc::c_int,
    pub value: obj_zip,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct engine_st {
    _unused: [u8; 0],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct env_md_ctx_st {
    pub digest: *const EVP_MD,
    pub engine: *mut ENGINE,
    pub flags: libc::c_ulong,
    pub md_data: *mut libc::c_void,
    pub pctx: *mut EVP_PKEY_CTX,
    pub update: Option<
        unsafe extern "C" fn(_: *mut EVP_MD_CTX, _: *const libc::c_void, _: size_t) -> libc::c_int,
    >,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct env_md_st {
    pub type_0: libc::c_int,
    pub pkey_type: libc::c_int,
    pub md_size: libc::c_int,
    pub flags: libc::c_ulong,
    pub init: Option<unsafe extern "C" fn(_: *mut EVP_MD_CTX) -> libc::c_int>,
    pub update: Option<
        unsafe extern "C" fn(_: *mut EVP_MD_CTX, _: *const libc::c_void, _: size_t) -> libc::c_int,
    >,
    pub final_0:
        Option<unsafe extern "C" fn(_: *mut EVP_MD_CTX, _: *mut libc::c_uchar) -> libc::c_int>,
    pub copy: Option<unsafe extern "C" fn(_: *mut EVP_MD_CTX, _: *const EVP_MD_CTX) -> libc::c_int>,
    pub cleanup: Option<unsafe extern "C" fn(_: *mut EVP_MD_CTX) -> libc::c_int>,
    pub sign: Option<
        unsafe extern "C" fn(
            _: libc::c_int,
            _: *const libc::c_uchar,
            _: libc::c_uint,
            _: *mut libc::c_uchar,
            _: *mut libc::c_uint,
            _: *mut libc::c_void,
        ) -> libc::c_int,
    >,
    pub verify: Option<
        unsafe extern "C" fn(
            _: libc::c_int,
            _: *const libc::c_uchar,
            _: libc::c_uint,
            _: *const libc::c_uchar,
            _: libc::c_uint,
            _: *mut libc::c_void,
        ) -> libc::c_int,
    >,
    pub required_pkey_type: [libc::c_int; 5],
    pub block_size: libc::c_int,
    pub ctx_size: libc::c_int,
    pub md_ctrl: Option<
        unsafe extern "C" fn(
            _: *mut EVP_MD_CTX,
            _: libc::c_int,
            _: libc::c_int,
            _: *mut libc::c_void,
        ) -> libc::c_int,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct trad_enc_ctx {
    pub keys: [uint32_t; 3],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct zip_entry {
    pub node: archive_rb_node,
    pub next: *mut zip_entry,
    pub local_header_offset: int64_t,
    pub compressed_size: int64_t,
    pub uncompressed_size: int64_t,
    pub gid: int64_t,
    pub uid: int64_t,
    pub rsrcname: archive_string,
    pub mtime: time_t,
    pub atime: time_t,
    pub ctime: time_t,
    pub crc32: uint32_t,
    pub mode: uint16_t,
    pub zip_flags: uint16_t,
    pub compression: libc::c_uchar,
    pub system: libc::c_uchar,
    pub flags: libc::c_uchar,
    pub decdat: libc::c_uchar,
    pub aes_extra: obj1_zip,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct obj1_zip {
    pub vendor: libc::c_uint,
    pub strength: libc::c_uint,
    pub compression: libc::c_uchar,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union obj_zip {
    pub In: *mut IByteIn,
    pub Out: *mut IByteOut,
}

pub type evp_pkey_ctx_st = libc::c_void;
pub type HMAC_CTX = hmac_ctx_st;
pub type archive_hmac_sha1_ctx = *mut HMAC_CTX;
pub type EVP_CIPHER = evp_cipher_st;
pub type EVP_CIPHER_CTX = evp_cipher_ctx_st;
pub type CPpmd8_Context = CPpmd8_Context_;
pub type ASN1_TYPE = asn1_type_st;
