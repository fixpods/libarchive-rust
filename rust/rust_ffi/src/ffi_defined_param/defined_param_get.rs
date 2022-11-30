extern "C" {
    fn get_archive_empty_defined_param() -> archive_empty_defined_param;

    fn get_archive_7zip_defined_param() -> archive_7zip_defined_param;

    fn get_archive_zip_defined_param() -> archive_zip_defined_param;

    fn get_archive_all_defined_param() -> archive_all_defined_param;

    fn get_archive_iso9660_defined_param() -> archive_iso9660_defined_param;

    fn get_archive_lha_defined_param() -> archive_lha_defined_param;

    fn get_archive_raw_defined_param() -> archive_raw_defined_param;

    fn get_archive_rar_defined_param() -> archive_rar_defined_param;

    fn get_archive_rar5_defined_param() -> archive_rar5_defined_param;

    fn get_archive_acl_defined_param() -> archive_acl_defined_param;
    fn get_archive_ar_defined_param() -> archive_ar_defined_param;

    fn get_archive_warc_defined_param() -> archive_warc_defined_param;

    fn get_archive_xar_defined_param() -> archive_xar_defined_param;

    fn get_archive_tar_defined_param() -> archive_tar_defined_param;

    fn get_archive_by_code_defined_param() -> archive_by_code_defined_param;

    fn get_archive_cab_defined_param() -> archive_cab_defined_param;

    fn get_archive_mtree_defined_param() -> archive_mtree_defined_param;

    fn get_archive_cpio_defined_param() -> archive_cpio_defined_param;
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_empty_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub archive_format_empty: i32,
    pub archive_eof: i32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_iso9660_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub enomem: i32,
    pub iso9660_magic: i32,
    pub logical_block_size: i32,
    pub reserved_area: i32,
    pub archive_format_iso9660: i32,
    pub archive_format_iso9660_rockridge: i32,
    pub archive_errno_misc: i32,
    pub archive_ok: i32,
    pub archive_fatal: i32,
    pub archive_warn: i32,
    pub archive_failed: i32,
    pub archive_errno_file_format: i32,
    pub archive_eof: i32,
    pub ae_ifmt: i32,
    pub ae_iflnk: i32,
    pub ae_ifdir: i32,
    pub ae_ifreg: i32,
    pub utf16_name_max: i32,
    pub system_area_block: i32,
    pub seek_set: i32,
    pub dr_extent_offset: i32,
    pub dr_extent_size: i32,
    pub dr_ext_attr_length_offset: i32,
    pub dr_ext_attr_length_size: i32,
    pub dr_size_offset: i32,
    pub dr_size_size: i32,
    pub dr_length_offset: i32,
    pub dr_length_size: i32,
    pub dr_date_offset: i32,
    pub dr_flags_offset: i32,
    pub dr_flags_size: i32,
    pub dr_file_unit_size_offset: i32,
    pub dr_file_unit_size_size: i32,
    pub dr_interleave_offset: i32,
    pub dr_interleave_size: i32,
    pub dr_name_len_offset: i32,
    pub dr_name_len_size: i32,
    pub dr_name_offset: i32,
    pub dr_volume_sequence_number_offset: i32,
    pub dr_volume_sequence_number_size: i32,
    pub svd_type_offset: i32,
    pub svd_reserved1_offset: i32,
    pub svd_reserved1_size: i32,
    pub svd_reserved2_offset: i32,
    pub svd_reserved2_size: i32,
    pub svd_reserved3_offset: i32,
    pub svd_reserved3_size: i32,
    pub svd_logical_block_size_offset: i32,
    pub svd_volume_space_size_offset: i32,
    pub svd_file_structure_version_offset: i32,
    pub svd_type_l_path_table_offset: i32,
    pub svd_type_m_path_table_offset: i32,
    pub svd_root_directory_record_offset: i32,
    pub svd_escape_sequences_offset: i32,
    pub pvd_type_offset: i32,
    pub pvd_version_offset: i32,
    pub pvd_reserved1_offset: i32,
    pub pvd_reserved2_offset: i32,
    pub pvd_reserved2_size: i32,
    pub pvd_reserved3_offset: i32,
    pub pvd_reserved3_size: i32,
    pub pvd_reserved4_offset: i32,
    pub pvd_reserved4_size: i32,
    pub pvd_reserved5_offset: i32,
    pub pvd_reserved5_size: i32,
    pub pvd_logical_block_size_offset: i32,
    pub pvd_volume_space_size_offset: i32,
    pub pvd_file_structure_version_offset: i32,
    pub pvd_type_1_path_table_offset: i32,
    pub pvd_type_m_path_table_offset: i32,
    pub pvd_root_directory_record_offset: i32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_7zip_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub enomem: i32,
    pub archive_ok: i32,
    pub archive_fatal: i32,
    pub archive_errno_misc: i32,
    pub ae_ifreg: i32,
    pub archive_eof: i32,
    pub archive_errno_file_format: i32,
    pub archive_warn: i32,
    pub sfx_min_addr: i32,
    pub sfx_max_addr: i32,
    pub _7z_copy: i32,
    pub _7z_lzma: i32,
    pub _7z_lzma2: i32,
    pub _7z_deflate: i32,
    pub _7z_bz2: i32,
    pub _7z_ppmd: i32,
    pub _7z_delta: i32,
    pub _7z_crypto_main_zip: i32,
    pub _7z_crypto_rar_29: i32,
    pub _7z_crypto_aes_256_sha_256: i32,
    pub _7z_x86: i32,
    pub _7z_x86_bcj2: i32,
    pub _7z_powerpc: i32,
    pub _7z_ia64: i32,
    pub _7z_arm: i32,
    pub _7z_armthumb: i32,
    pub _7z_sparc: i32,
    pub kend: i32,
    pub kheader: i32,
    pub karchiveproperties: i32,
    pub kadditionalstreamsinfo: i32,
    pub kmainstreamsinfo: i32,
    pub kfilesinfo: i32,
    pub kpackinfo: i32,
    pub kunpackinfo: i32,
    pub ksubstreamsinfo: i32,
    pub ksize: i32,
    pub kcrc: i32,
    pub kfolder: i32,
    pub kcodersunpacksize: i32,
    pub knumunpackstream: i32,
    pub kemptystream: i32,
    pub kemptyfile: i32,
    pub kanti: i32,
    pub kname: i32,
    pub kctime: i32,
    pub katime: i32,
    pub kmtime: i32,
    pub kattributes: i32,
    pub kencodedheader: i32,
    pub kdummy: i32,
    pub mtime_is_set: i32,
    pub atime_is_set: i32,
    pub ctime_is_set: i32,
    pub crc32_is_set: i32,
    pub has_stream: i32,
    pub ubuff_size: i32,
    pub sz_error_data: i32,
    pub knumtopbits: i32,
    pub knumbitmodeltotalbits: i32,
    pub kbitmodeltotal: i32,
    pub knummovebits: i32,
    pub archive_failed: i32,
    pub lzma_stream_end: i32,
    pub lzma_ok: i32,
    pub lzma_mem_error: i32,
    pub lzma_memlimit_error: i32,
    pub lzma_format_error: i32,
    pub lzma_options_error: i32,
    pub lzma_data_error: i32,
    pub lzma_buf_error: i32,
    pub bz_stream_end: i32,
    pub bz_ok: i32,
    pub bz_param_error: i32,
    pub bz_mem_error: i32,
    pub bz_config_error: i32,
    pub z_stream_end: i32,
    pub z_ok: i32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_all_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub archive_ok: i32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_zip_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub ae_ifdir: u32,
    pub ae_ifmt: u32,
    pub ae_ififo: u32,
    pub ae_iflnk: u32,
    pub ae_ifreg: u32,
    pub uint32_max: i64,
    pub enomem: i32,
    pub archive_ok: i32,
    pub archive_fatal: i32,
    pub archive_errno_misc: i32,
    pub archive_errno_programmer: i32,
    pub archive_read_format_encryption_dont_know: i32,
    pub archive_eof: i32,
    pub archive_errno_file_format: i32,
    pub archive_warn: i32,
    pub archive_read_format_caps_encrypt_metadata: i32,
    pub archive_read_format_caps_encrypt_data: i32,
    pub archive_format_zip: i32,
    pub seek_set: i32,
    pub seek_end: i32,
    pub archive_rb_dir_right: i32,
    pub aes_vendor_ae_1: i32,
    pub aes_vendor_ae_2: i32,
    pub zip_encrypted: i32,
    pub zip_length_at_end: i32,
    pub zip_strong_encrypted: i32,
    pub zip_utf8_name: i32,
    pub zip_central_directory_encrypted: i32,
    pub la_used_zip64: i32,
    pub la_from_central_directory: i32,
    pub winzip_aes_encryption: i32,
    pub auth_code_size: i32,
    pub max_derived_key_buf_size: i32,
    pub md_size: i32,
    pub enc_header_size: i32,
    pub archive_failed: i32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_lha_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub enomem: i32,
    pub h_method_offset: i32,
    pub h_level_offset: i32,
    pub h_attr_offset: i32,
    pub h_size: i32,
    pub archive_failed: i32,
    pub archive_errno_misc: i32,
    pub archive_ok: i32,
    pub archive_fatal: i32,
    pub archive_warn: i32,
    pub archive_errno_file_format: i32,
    pub archive_format_lha: i32,
    pub archive_eof: i32,
    pub ae_ifmt: i32,
    pub ae_iflnk: i32,
    pub ae_ifdir: i32,
    pub ae_ifreg: i32,
    pub atime_is_set: i32,
    pub birthtime_is_set: i32,
    pub crc_is_set: i32,
    pub unix_mode_is_set: i32,
    pub h0_fixed_size: i32,
    pub h0_header_size_offset: i32,
    pub h0_header_sum_offset: i32,
    pub h0_comp_size_offset: i32,
    pub h0_orig_size_offset: i32,
    pub h0_dos_time_offset: i32,
    pub h0_name_len_offset: i32,
    pub h0_file_name_offset: i32,
    pub h1_header_size_offset: i32,
    pub h1_header_sum_offset: i32,
    pub h1_comp_size_offset: i32,
    pub h1_orig_size_offset: i32,
    pub h1_dos_time_offset: i32,
    pub h1_name_len_offset: i32,
    pub h1_file_name_offset: i32,
    pub h1_fixed_size: i32,
    pub h2_header_size_offset: i32,
    pub h2_comp_size_offset: i32,
    pub h2_orig_size_offset: i32,
    pub h2_time_offset: i32,
    pub h2_crc_offset: i32,
    pub h2_fixed_size: i32,
    pub h3_field_len_offset: i32,
    pub h3_comp_size_offset: i32,
    pub h3_orig_size_offset: i32,
    pub h3_time_offset: i32,
    pub h3_crc_offset: i32,
    pub h3_header_size_offset: i32,
    pub h3_fixed_size: i32,
    pub ext_header_crc: i32,
    pub ext_filename: i32,
    pub ext_utf16_filename: i32,
    pub ext_directory: i32,
    pub ext_utf16_directory: i32,
    pub ext_dos_attr: i32,
    pub ext_timestamp: i32,
    pub ext_filesize: i32,
    pub ext_codepage: i32,
    pub ext_unix_mode: i32,
    pub ext_unix_gid_uid: i32,
    pub ext_unix_gname: i32,
    pub ext_unix_uname: i32,
    pub ext_unix_mtime: i32,
    pub ext_os2_new_attr: i32,
    pub ext_new_attr: i32,
    pub ext_timezone: i32,
    pub epoc_time: u64,
    pub pt_bitlen_size: i32,
    pub lt_bitlen_size: i32,
    pub st_get_literal: i32,
    pub st_rd_block: i32,
    pub st_rd_pt_1: i32,
    pub st_rd_pt_2: i32,
    pub st_rd_pt_3: i32,
    pub st_rd_pt_4: i32,
    pub st_rd_literal_1: i32,
    pub st_rd_literal_2: i32,
    pub st_rd_literal_3: i32,
    pub st_rd_pos_data_1: i32,
    pub st_get_pos_1: i32,
    pub st_get_pos_2: i32,
    pub st_copy_data: i32,
    pub uchar_max: i32,
    pub minmatch: i32,
    pub cache_bits: i32,
    pub htbl_bits: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_raw_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub archive_format_raw: i32,
    pub enomem: i32,
    pub archive_ok: i32,
    pub archive_eof: i32,
    pub archive_fatal: i32,
    pub ae_ifreg: u32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_rar_defined_param {
    pub cache_bits: i32,
    pub archive_errno_file_format: i32,
    pub archive_fatal: i32,
    pub archive_ok: i32,
    pub archive_read_format_caps_encrypt_data: i32,
    pub archive_read_format_caps_encrypt_metadata: i32,
    pub archive_read_format_encryption_dont_know: i32,
    pub archive_failed: i32,
    pub archive_errno_misc: i32,
    pub archive_warn: i32,
    pub archive_format_rar: i32,
    pub archive_eof: i32,
    pub mark_head: i32,
    pub main_head: i32,
    pub mhd_encryptver: i32,
    pub mhd_password: i32,
    pub file_head: i32,
    pub comm_head: i32,
    pub av_head: i32,
    pub sub_head: i32,
    pub protect_head: i32,
    pub sign_head: i32,
    pub endarc_head: i32,
    pub hd_add_size_present: i32,
    pub newsub_head: i32,
    pub compress_method_store: i32,
    pub compress_method_fastest: i32,
    pub compress_method_fast: i32,
    pub compress_method_normal: i32,
    pub compress_method_good: i32,
    pub compress_method_best: i32,
    pub mhd_volume: i32,
    pub fhd_split_after: i32,
    pub seek_cur: i32,
    pub seek_end: i32,
    pub seek_set: i32,
    pub fhd_split_before: i32,
    pub fhd_solid: i32,
    pub fhd_password: i32,
    pub fhd_large: i32,
    pub enomem: i32,
    pub fhd_unicode: i32,
    pub os_msdos: i32,
    pub os_os2: i32,
    pub os_win32: i32,
    pub file_attribute_directory: i32,
    pub ae_ifdir: i32,
    pub s_ixusr: i32,
    pub s_ixgrp: i32,
    pub s_ixoth: i32,
    pub ae_ifreg: i32,
    pub s_irusr: i32,
    pub s_iwusr: i32,
    pub s_irgrp: i32,
    pub s_iroth: i32,
    pub os_unix: i32,
    pub os_mac_os: i32,
    pub os_beos: i32,
    pub unp_buffer_size: i32,
    pub ae_ifmt: i32,
    pub ae_iflnk: i32,
    pub ns_unit: i32,
    pub max_compress_depth: i32,
    pub int64_max: i64,
    pub max_symbols: i32,
    pub max_symbol_length: i32,
    pub huffman_table_size: i32,
    pub maincode_size: i32,
    pub offsetcode_size: i32,
    pub lowoffsetcode_size: i32,
    pub lengthcode_size: i32,
    pub dictionary_max_size: i32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_rar5_defined_param {
    pub archive_ok: i32,
    pub enomem: i32,
    pub archive_fatal: i32,
    pub archive_errno_file_format: i32,
    pub archive_errno_programmer: i32,
    pub archive_retry: i32,
    pub archive_warn: i32,
    pub archive_format_rar_v5: i32,
    pub archive_eof: i32,
    pub max_name_in_bytes: i32,
    pub max_name_in_chars: i32,
    pub ae_iflnk: i32,
    pub redir_symlink_is_dir: i32,
    pub ae_symlink_type_directory: i32,
    pub ae_symlink_type_file: i32,
    pub ae_ifreg: i32,
    pub owner_maxnamelen: i32,
    pub owner_user_name: i32,
    pub owner_group_name: i32,
    pub owner_user_uid: i32,
    pub owner_group_gid: i32,
    pub ae_ifdir: i32,
    pub uint_max: i32,
    pub huff_nc: i32,
    pub huff_bc: i32,
    pub huff_table_size: i32,
    pub huff_dc: i32,
    pub huff_ldc: i32,
    pub huff_rc: i32,
    pub int_max: i32,
    pub archive_failed: i32,
    pub archive_read_format_encryption_unsupported: i32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_acl_defined_param {
    pub archive_ok: i32,
    pub archvie_failed: i32,
    pub archive_fatal: i32,
    pub archive_warn: i32,
    pub archive_eof: i32,
    pub enomem: i32,
    pub archive_entry_acl_append_data: i32,
    pub archive_entry_acl_delete: i32,
    pub archive_entry_acl_delete_child: i32,
    pub archive_entry_acl_read_attributes: i32,
    pub archive_entry_acl_read_named_attrs: i32,
    pub archive_entry_acl_read: i32,
    pub archive_entry_acl_read_data: i32,
    pub archive_entry_acl_write: i32,
    pub archive_entry_acl_write_named_attrs: i32,
    pub archive_entry_acl_write_attributes: i32,
    pub archive_entry_acl_write_owner: i32,
    pub archive_entry_acl_synchronize: i32,
    pub archive_entry_acl_write_data: i32,
    pub archive_entry_acl_execute: i32,
    pub archive_entry_acl_everyone: i32,
    pub archive_entry_acl_mask: i32,
    pub archive_entry_acl_other: i32,
    pub archive_entry_acl_user: i32,
    pub archive_entry_acl_group: i32,
    pub archive_entry_acl_user_obj: i32,
    pub archive_entry_acl_group_obj: i32,
    pub archive_entry_acl_type_allow: i32,
    pub archive_entry_acl_type_alram: i32,
    pub archive_entry_acl_type_audit: i32,
    pub archive_entry_acl_type_deny: i32,
    pub archive_entry_acl_type_nfs4: i32,
    pub archive_entry_acl_type_posix1e: i32,
    pub archive_entry_acl_type_access: i32,
    pub archive_entry_acl_type_default: i32,
    pub archive_entry_acl_perms_nfs4: i32,
    pub archive_entry_acl_perms_posix1e: i32,
    pub archive_entry_acl_inheritance_nfs4: i32,
    pub archive_entry_acl_style_compact: i32,
    pub archive_entry_acl_style_extra_id: i32,
    pub archive_entry_acl_style_solaris: i32,
    pub archive_entry_acl_style_mark_default: i32,
    pub archive_entry_acl_style_separator_comma: i32,
    pub archive_entry_acl_entry_file_inherit: i32,
    pub archive_entry_acl_entry_directory_inherit: i32,
    pub archive_entry_acl_entry_inherit_only: i32,
    pub archive_entry_acl_entry_no_propagate_inherit: i32,
    pub archive_entry_acl_entry_successful_access: i32,
    pub archive_entry_acl_entry_failed_access: i32,
    pub archive_entry_acl_entry_inherited: i32,
    pub archive_entry_acl_read_acl: i32,
    pub archive_entry_acl_write_acl: i32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_ar_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub enomem: i32,
    pub archive_ok: i32,
    pub einval: i32,
    pub archive_fatal: i32,
    pub ar_name_size: i32,
    pub ar_name_offset: i32,
    pub archive_format_ar: i32,
    pub archive_format_ar_bsd: i32,
    pub archive_format_ar_gnu: i32,
    pub archive_errno_misc: i32,
    pub ae_ifreg: i32,
    pub ar_size_offset: i32,
    pub ar_size_size: i32,
    pub archive_eof: i32,
    pub ar_date_offset: i32,
    pub ar_date_size: i32,
    pub ar_uid_offset: i32,
    pub ar_uid_size: i32,
    pub ar_gid_offset: i32,
    pub ar_gid_size: i32,
    pub ar_mode_offset: i32,
    pub ar_mode_size: i32,
    pub uint64_max: u64,
    pub ar_fmag_offset: i32,
    pub ar_fmag_size: i32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_warc_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub hdr_probe_len: u32,
    pub enomem: i32,
    pub archive_fatal: i32,
    pub archive_ok: i32,
    pub archive_errno_misc: i32,
    pub archive_eof: i32,
    pub einval: i32,
    pub archive_format_warc: i32,
    pub ae_ifreg: i32,
}
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_xar_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub enomem: i32,
    pub archive_fatal: i32,
    pub archive_ok: i32,
    pub archive_eof: i32,
    pub archive_warn: i32,
    pub archive_failed: i32,
    pub archive_errno_file_format: i32,
    pub archive_errno_misc: i32,
    pub archive_format_xar: i32,
    pub seek_set: i32,
    pub ae_ifreg: u32,
    pub ae_ifmt: u32,
    pub ae_ifdir: u32,
    pub ae_iflnk: u32,
    pub ae_ifchr: u32,
    pub ae_ifblk: u32,
    pub ae_ifsock: u32,
    pub ae_ififo: u32,
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct archive_tar_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub enomem: i32,
    pub archive_fatal: i32,
    pub archive_ok: i32,
    pub archive_errno_misc: i32,
    pub archive_eof: i32,
    pub einval: i32,
    pub archive_format_warc: i32,
    pub ae_ifreg: u32,
    pub archive_failed: i32,
    pub archive_warn: i32,
    pub ae_ifdir: u32,
    pub archive_errno_file_format: i32,
    pub archive_format_tar: i32,
    pub archive_format_tar_pax_interchange: i32,
    pub archive_format_tar_gnutar: i32,
    pub archive_format_tar_ustar: i32,
    pub archive_entry_acl_type_nfs4: i32,
    pub archive_entry_acl_type_access: i32,
    pub ae_iflnk: u32,
    pub ae_ifchr: u32,
    pub ae_ifblk: u32,
    pub ae_ififo: u32,
    pub sconv_set_opt_utf8_libarchive2x: i32,
    pub archive_entry_acl_type_default: i32,
    pub ae_symlink_type_directory: i32,
    pub archive_retry: i32,
    pub ae_symlink_type_file: i32,
    pub int64_max: i64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_by_code_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub archive_format_base_mask: i32,
    pub archive_format_7zip: i32,
    pub archive_format_ar: i32,
    pub archive_format_cab: i32,
    pub archive_format_cpio: i32,
    pub archive_format_empty: i32,
    pub archive_format_iso9660: i32,
    pub archive_format_lha: i32,
    pub archive_format_mtree: i32,
    pub archive_format_rar: i32,
    pub archive_format_rar_v5: i32,
    pub archive_format_raw: i32,
    pub archive_format_tar: i32,
    pub archive_format_warc: i32,
    pub archive_format_xar: i32,
    pub archive_format_zip: i32,
    pub archive_fatal: i32,
    pub archive_errno_programmer: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_cab_defined_param {
    pub archive_ok: i32,
    pub archive_fatal: i32,
    pub archive_warn: i32,
    pub archive_failed: i32,
    pub archive_eof: i32,
    pub archive_errno_misc: i32,
    pub archive_errno_file_format: i32,
    pub attr_name_is_utf: i32,
    pub archive_format_cab: i32,
    pub cfheader_signature: i32,
    pub cfheader_cbcabinet: i32,
    pub cfheader_cofffiles: i32,
    pub cfheader_versionminor: i32,
    pub cfheader_cfolders: i32,
    pub cfheader_cfiles: i32,
    pub cfheader_flags: i32,
    pub cfheader_setid: i32,
    pub cfheader_icabinet: i32,
    pub cfheader_cbcfheader: i32,
    pub cfheader_cbcffolder: i32,
    pub cfheader_cbcfdata: i32,
    pub prev_cabinet: i32,
    pub next_cabinet: i32,
    pub reserve_present: i32,
    pub cffolder_coffcabstart: i32,
    pub cffolder_ccfdata: i32,
    pub cffolder_typecompress: i32,
    pub cffile_cbfile: i32,
    pub cffile_uofffolderstart: i32,
    pub cffile_ifolder: i32,
    pub cffile_date_time: i32,
    pub cffile_attribs: i32,
    pub enomem: i32,
    pub attr_rdonly: i32,
    pub ae_ifreg: i32,
    pub cfdata_cbdata: i32,
    pub cfdata_csum: i32,
    pub cfdata_cbuncomp: i32,
    pub comptype_none: i32,
    pub z_ok: i32,
    pub z_stream_end: i32,
    pub z_mem_error: i32,
    pub ifoldcontinued_to_next: i32,
    pub ifoldcontinued_prev_and_next: i32,
    pub ifoldcontinued_from_prev: i32,
    pub slot_base: i32,
    pub slot_max: i32,
    pub st_main: i32,
    pub st_rd_translation: i32,
    pub st_rd_translation_size: i32,
    pub st_rd_block_type: i32,
    pub st_rd_block_size: i32,
    pub uncompressed_block: i32,
    pub verbatim_block: i32,
    pub st_rd_verbatim: i32,
    pub st_rd_aligned_offset: i32,
    pub st_rd_alignment: i32,
    pub st_rd_r0: i32,
    pub st_rd_r1: i32,
    pub st_rd_r2: i32,
    pub st_copy_uncomp1: i32,
    pub st_copy_uncomp2: i32,
    pub st_rd_pre_main_tree_256: i32,
    pub st_main_tree_256: i32,
    pub st_rd_pre_main_tree_rem: i32,
    pub st_main_tree_rem: i32,
    pub st_rd_pre_length_tree: i32,
    pub st_length_tree: i32,
    pub st_length: i32,
    pub st_real_pos: i32,
    pub aligned_offset_block: i32,
    pub st_offset: i32,
    pub st_copy: i32,
    pub cfheader_versionmajor: i32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_mtree_defined_param {
    pub s_iflnk: i32,
    pub s_ifsock: i32,
    pub s_ifchr: i32,
    pub s_ifblk: i32,
    pub s_ififo: i32,
    pub s_ifmt: i32,
    pub s_ifreg: i32,
    pub ae_ifreg: i32,
    pub ae_iflnk: i32,
    pub ae_ifsock: i32,
    pub ae_ifchr: i32,
    pub ae_ifblk: i32,
    pub ae_ifdir: i32,
    pub ae_ififo: i32,
    pub s_ifdir: i32,
    pub archive_ok: i32,
    pub archive_fatal: i32,
    pub archive_warn: i32,
    pub archive_failed: i32,
    pub archive_eof: i32,
    pub enomem: i32,
    pub max_line_len: i64,
    pub max_bid_entry: i32,
    pub archive_errno_misc: i32,
    pub archive_format_mtree: i32,
    pub archive_errno_file_format: i32,
    pub o_rdonly: i32,
    pub o_binary: i32,
    pub o_cloexec: i32,
    pub enoent: i32,
    pub mtree_has_optional: i32,
    pub mtree_has_device: i32,
    pub mtree_has_nochange: i32,
    pub mtree_has_gid: i32,
    pub mtree_has_gname: i32,
    pub mtree_has_uid: i32,
    pub mtree_has_uname: i32,
    pub mtree_has_mtime: i32,
    pub mtree_has_nlink: i32,
    pub mtree_has_perm: i32,
    pub mtree_has_size: i32,
    pub mtree_has_type: i32,
    pub max_pack_args: i32,
    pub archive_entry_digest_md5: i32,
    pub archive_entry_digest_rmd160: i32,
    pub archive_entry_digest_sha1: i32,
    pub archive_entry_digest_sha256: i32,
    pub archive_entry_digest_sha384: i32,
    pub archive_entry_digest_sha512: i32,
    pub archive_errno_programmer: i32,
    pub mtree_has_fflags: i32,
    pub int64_max: i64,
    pub int32_max: i64,
    pub int64_min: i64,
    pub int32_min: i64,
    pub time_t_min: i64,
    pub time_t_max: i64,
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct archive_cpio_defined_param {
    pub archive_read_magic: u32,
    pub archive_state_new: u32,
    pub enomem: i32,
    pub archive_errno_misc: i32,
    pub archive_ok: i32,
    pub archive_fatal: i32,
    pub archive_warn: i32,
    pub archive_failed: i32,
    pub archive_errno_file_format: i32,
    pub archive_eof: i32,
    pub ae_ifmt: i32,
    pub ae_iflnk: u32,
    pub ae_ifreg: i32,
    pub BIN_MAGIC_OFFSET: i32,
    pub BIN_MAGIC_SIZE: i32,
    pub BIN_DEV_OFFSET: i32,
    pub BIN_DEV_SIZE: i32,
    pub BIN_INO_OFFSET: i32,
    pub BIN_INO_SIZE: i32,
    pub BIN_MODE_OFFSET: i32,
    pub BIN_MODE_SIZE: i32,
    pub BIN_UID_OFFSET: i32,
    pub BIN_UID_SIZE: i32,
    pub BIN_GID_OFFSET: i32,
    pub BIN_GID_SIZE: i32,
    pub BIN_NLINK_OFFSET: i32,
    pub BIN_NLINK_SIZE: i32,
    pub BIN_RDEV_OFFSET: i32,
    pub BIN_RDEV_SIZE: i32,
    pub BIN_MTIME_OFFSET: i32,
    pub BIN_MTIME_SIZE: i32,
    pub BIN_NAMESIZE_OFFSET: i32,
    pub BIN_NAMESIZE_SIZE: i32,
    pub BIN_FILESIZE_OFFSET: i32,
    pub BIN_FILESIZE_SIZE: i32,
    pub BIN_HEADER_SIZE: i32,

    pub ODC_MAGIC_OFFSET: i32,
    pub ODC_MAGIC_SIZE: i32,
    pub ODC_DEV_OFFSET: i32,
    pub ODC_DEV_SIZE: i32,
    pub ODC_INO_OFFSET: i32,
    pub ODC_INO_SIZE: i32,
    pub ODC_MODE_OFFSET: i32,
    pub ODC_MODE_SIZE: i32,
    pub ODC_UID_OFFSET: i32,
    pub ODC_UID_SIZE: i32,
    pub ODC_GID_OFFSET: i32,
    pub ODC_GID_SIZE: i32,
    pub ODC_NLINK_OFFSET: i32,
    pub ODC_NLINK_SIZE: i32,
    pub ODC_RDEV_OFFSET: i32,
    pub ODC_RDEV_SIZE: i32,
    pub ODC_MTIME_OFFSET: i32,
    pub ODC_MTIME_SIZE: i32,
    pub ODC_NAMESIZE_OFFSET: i32,
    pub ODC_NAMESIZE_SIZE: i32,
    pub ODC_FILESIZE_OFFSET: i32,
    pub ODC_FILESIZE_SIZE: i32,
    pub ODC_HEADER_SIZE: i32,

    pub NEWC_MAGIC_OFFSET: i32,
    pub NEWC_MAGIC_SIZE: i32,
    pub NEWC_INO_OFFSET: i32,
    pub NEWC_INO_SIZE: i32,
    pub NEWC_MODE_OFFSET: i32,
    pub NEWC_MODE_SIZE: i32,
    pub NEWC_UID_OFFSET: i32,
    pub NEWC_UID_SIZE: i32,
    pub NEWC_GID_OFFSET: i32,
    pub NEWC_GID_SIZE: i32,
    pub NEWC_NLINK_OFFSET: i32,
    pub NEWC_NLINK_SIZE: i32,
    pub NEWC_MTIME_OFFSET: i32,
    pub NEWC_MTIME_SIZE: i32,
    pub NEWC_FILESIZE_OFFSET: i32,
    pub NEWC_FILESIZE_SIZE: i32,
    pub NEWC_DEVMAJOR_OFFSET: i32,
    pub NEWC_DEVMAJOR_SIZE: i32,
    pub NEWC_DEVMINOR_OFFSET: i32,
    pub NEWC_DEVMINOR_SIZE: i32,
    pub NEWC_RDEVMAJOR_OFFSET: i32,
    pub NEWC_RDEVMAJOR_SIZE: i32,
    pub NEWC_RDEVMINOR_OFFSET: i32,
    pub NEWC_RDEVMINOR_SIZE: i32,
    pub NEWC_NAMESIZE_OFFSET: i32,
    pub NEWC_NAMESIZE_SIZE: i32,
    pub NEWC_CHECKSUM_OFFSET: i32,
    pub NEWC_CHECKSUM_SIZE: i32,
    pub NEWC_HEADER_SIZE: u64,

    pub AFIOL_MAGIC_OFFSET: i32,
    pub AFIOL_MAGIC_SIZE: i32,
    pub AFIOL_DEV_OFFSET: i32,
    pub AFIOL_DEV_SIZE: i32,
    pub AFIOL_INO_OFFSET: i32,
    pub AFIOL_INO_SIZE: i32,
    pub AFIOL_INO_M_OFFSET: i32,
    pub AFIOL_MODE_OFFSET: i32,
    pub AFIOL_MODE_SIZE: i32,
    pub AFIOL_UID_OFFSET: i32,
    pub AFIOL_UID_SIZE: i32,
    pub AFIOL_GID_OFFSET: i32,
    pub AFIOL_GID_SIZE: i32,
    pub AFIOL_NLINK_OFFSET: i32,
    pub AFIOL_NLINK_SIZE: i32,
    pub AFIOL_RDEV_OFFSET: i32,
    pub AFIOL_RDEV_SIZE: i32,
    pub AFIOL_MTIME_OFFSET: i32,
    pub AFIOL_MTIME_SIZE: i32,
    pub AFIOL_MTIME_N_OFFSET: i32,
    pub AFIOL_NAMESIZE_OFFSET: i32,
    pub AFIOL_NAMESIZE_SIZE: i32,
    pub AFIOL_FLAG_OFFSET: i32,
    pub AFIOL_FLAG_SIZE: i32,
    pub AFIOL_XSIZE_OFFSET: i32,
    pub AFIOL_XSIZE_SIZE: i32,
    pub AFIOL_XSIZE_S_OFFSET: i32,
    pub AFIOL_FILESIZE_OFFSET: i32,
    pub AFIOL_FILESIZE_SIZE: i32,
    pub AFIOL_FILESIZE_C_OFFSET: i32,
    pub AFIOL_HEADER_SIZE: i32,
    pub cpio_magic: i32,
    pub archive_format_cpio_svr4_nocrc: i32,
    pub archive_format_cpio_svr4_crc: i32,
    pub archive_format_cpio_afio_large: i32,
    pub archive_format_cpio_posix: i32,
    pub archive_format_cpio_bin_le: i32,
    pub archive_format_cpio_bin_be: i32,

    pub size_max: u64,
}

lazy_static! {
    pub static ref ARCHIVE_EMPTY_DEFINED_PARAM: archive_empty_defined_param =
        unsafe { get_archive_empty_defined_param() };
    pub static ref ARCHIVE_ISO9660_DEFINED_PARAM: archive_iso9660_defined_param =
        unsafe { get_archive_iso9660_defined_param() };
    pub static ref ARCHIVE_7ZIP_DEFINED_PARAM: archive_7zip_defined_param =
        unsafe { get_archive_7zip_defined_param() };
    pub static ref ARCHIVE_ZIP_DEFINED_PARAM: archive_zip_defined_param =
        unsafe { get_archive_zip_defined_param() };
    pub static ref ARCHIVE_ALL_DEFINED_PARAM: archive_all_defined_param =
        unsafe { get_archive_all_defined_param() };
    pub static ref ARCHIVE_LHA_DEFINED_PARAM: archive_lha_defined_param =
        unsafe { get_archive_lha_defined_param() };
    pub static ref ARCHIVE_RAW_DEFINED_PARAM: archive_raw_defined_param =
        unsafe { get_archive_raw_defined_param() };
    pub static ref ARCHIVE_RAR_DEFINED_PARAM: archive_rar_defined_param =
        unsafe { get_archive_rar_defined_param() };
    pub static ref ARCHIVE_RAR5_DEFINED_PARAM: archive_rar5_defined_param =
        unsafe { get_archive_rar5_defined_param() };
    pub static ref ARCHIVE_AR_DEFINED_PARAM: archive_ar_defined_param =
        unsafe { get_archive_ar_defined_param() };
    pub static ref ARCHIVE_WARC_DEFINED_PARAM: archive_warc_defined_param =
        unsafe { get_archive_warc_defined_param() };
    pub static ref ARCHIVE_XAR_DEFINED_PARAM: archive_xar_defined_param =
        unsafe { get_archive_xar_defined_param() };
    pub static ref ARCHIVE_TAR_DEFINED_PARAM: archive_tar_defined_param =
        unsafe { get_archive_tar_defined_param() };
    pub static ref ARCHIVE_ACL_DEFINED_PARAM: archive_acl_defined_param =
        unsafe { get_archive_acl_defined_param() };
    pub static ref ARCHIVE_BY_CODE_DEFINED_PARAM: archive_by_code_defined_param =
        unsafe { get_archive_by_code_defined_param() };
    pub static ref ARCHIVE_CAB_DEFINED_PARAM: archive_cab_defined_param =
        unsafe { get_archive_cab_defined_param() };
    pub static ref ARCHIVE_MTREE_DEFINED_PARAM: archive_mtree_defined_param =
        unsafe { get_archive_mtree_defined_param() };
    pub static ref ARCHIVE_CPIO_DEFINED_PARAM: archive_cpio_defined_param =
        unsafe { get_archive_cpio_defined_param() };
}
