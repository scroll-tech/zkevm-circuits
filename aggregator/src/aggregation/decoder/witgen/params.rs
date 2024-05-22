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

// we use offset window no more than = 17
// TODO: use for multi-block zstd.
#[allow(dead_code)]
pub const CL_WINDOW_LIMIT: usize = 17;

/// zstd block size target.
pub const N_BLOCK_SIZE_TARGET: u32 = 124 * 1024;

/// Maximum number of blocks that we can expect in the encoded data.
pub const N_MAX_BLOCKS: u64 = 10;

/// Zstd encoder configuration
pub fn init_zstd_encoder(
    target_block_size: Option<u32>,
) -> zstd::stream::Encoder<'static, Vec<u8>> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).expect("infallible");

    // disable compression of literals, i.e. literals will be raw bytes.
    encoder
        .set_parameter(zstd::stream::raw::CParameter::LiteralCompressionMode(
            zstd::zstd_safe::ParamSwitch::Disable,
        ))
        .expect("infallible");
    // with a hack in zstd we can set window log <= 17 with single segment kept
    encoder
        .set_parameter(zstd::stream::raw::CParameter::WindowLog(17))
        .expect("infallible");
    // set target block size to fit within a single block.
    encoder
        .set_parameter(zstd::stream::raw::CParameter::TargetCBlockSize(
            target_block_size.unwrap_or(N_BLOCK_SIZE_TARGET),
        ))
        .expect("infallible");
    // do not include the checksum at the end of the encoded data.
    encoder.include_checksum(false).expect("infallible");
    // do not include magic bytes at the start of the frame since we will have a single
    // frame.
    encoder.include_magicbytes(false).expect("infallible");
    // do not include dictionary id so we have more simple content
    encoder.include_dictid(false).expect("infallible");
    // include the content size to know at decode time the expected size of decoded
    // data.
    encoder.include_contentsize(true).expect("infallible");

    encoder
}
