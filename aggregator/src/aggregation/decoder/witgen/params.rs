/// Number of bits to represent a byte.
pub const N_BITS_PER_BYTE: usize = 8;

/// Number of bytes used to specify block header.
pub const N_BLOCK_HEADER_BYTES: usize = 3;

/// Constants for zstd-compressed block
pub const N_MAX_LITERAL_HEADER_BYTES: usize = 3;

/// Number of bits used to represent the tag in binary form.
pub const N_BITS_ZSTD_TAG: usize = 4;

/// Number of bits in the repeat bits that follow value=1 in reconstructing FSE table.
pub const N_BITS_REPEAT_FLAG: usize = 2;

use std::io::Write;

/// re-export constants in zstd-encoder
pub use zstd_encoder::{N_BLOCK_SIZE_TARGET, N_MAX_BLOCKS};

use zstd_encoder::{init_zstd_encoder as init_zstd_encoder_n, zstd};

/// Zstd encoder configuration
pub fn init_zstd_encoder(
    target_block_size: Option<u32>,
) -> zstd::stream::Encoder<'static, Vec<u8>> {
    init_zstd_encoder_n(target_block_size.unwrap_or(N_BLOCK_SIZE_TARGET))
}

/// Encode input bytes by using the default encoder.
pub fn zstd_encode(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = init_zstd_encoder(None);
    encoder
        .set_pledged_src_size(Some(bytes.len() as u64))
        .expect("infallible");
    encoder.write_all(bytes).expect("infallible");
    encoder.finish().expect("infallible")
}
