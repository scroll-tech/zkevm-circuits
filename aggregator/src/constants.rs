use halo2_proofs::halo2curves::bn256::{Fq, Fr, G1Affine};
use std::sync::LazyLock;

// A chain_id is u64 and uses 8 bytes
pub(crate) const CHAIN_ID_LEN: usize = 8;

// ================================
// hash parameters
// ================================

/// Digest length
pub(crate) const DIGEST_LEN: usize = 32;

// TODO: make this dynamic
pub(crate) const LOG_DEGREE: u32 = 21;

// ================================
// indices for chunk pi hash table
// ================================
//
// the preimages are arranged as
// - chain_id:          8 bytes
// - prev_state_root    32 bytes
// - post_state_root    32 bytes
// - withdraw_root      32 bytes
// - chunk_data_hash    32 bytes
// - chunk_tx_data_hash 32 bytes

pub(crate) const CHUNK_CHAIN_ID_INDEX: usize = 0;
pub(crate) const PREV_STATE_ROOT_INDEX: usize = 8;
pub(crate) const POST_STATE_ROOT_INDEX: usize = 40;
pub(crate) const WITHDRAW_ROOT_INDEX: usize = 72;
pub(crate) const CHUNK_DATA_HASH_INDEX: usize = 104;
pub(crate) const CHUNK_TX_DATA_HASH_INDEX: usize = 136;

// ================================
// indices for batch hash table
// ================================
//
// the preimages are arranged as
// - version:                  1 byte
// - batch_index:              8 bytes
// - l1_message_popped         8 bytes
// - total_l1_message_popped   8 bytes
// - data_hash                 32 bytes
// - blob_versioned_hash       32 bytes
// - parent_batch_hash         32 bytes
// - last_block_timestamp      8 bytes
// - z                         32 bytes
// - y                         32 bytes

pub(crate) const BATCH_DATA_HASH_OFFSET: usize = 25;
pub(crate) const BATCH_BLOB_VERSIONED_HASH_OFFSET: usize = 57;
pub(crate) const BATCH_PARENT_BATCH_HASH: usize = 89;
pub(crate) const BATCH_Z_OFFSET: usize = 129;
pub(crate) const BATCH_Y_OFFSET: usize = 161;

// ================================
// indices for public inputs
// ================================
//
// - parent state root (2 cells: hi, lo)
// - parent batch hash ..
// - current state root ..
// - current batch hash ..
// - chain id (1 Fr cell)
// - current withdraw root ..
pub(crate) const PI_PARENT_STATE_ROOT: usize = ACC_LEN;
pub(crate) const PI_PARENT_BATCH_HASH: usize = ACC_LEN + 2;
pub(crate) const PI_CURRENT_STATE_ROOT: usize = ACC_LEN + 4;
pub(crate) const PI_CURRENT_BATCH_HASH: usize = ACC_LEN + 6;
pub(crate) const PI_CHAIN_ID: usize = ACC_LEN + 8;
pub(crate) const PI_CURRENT_WITHDRAW_ROOT: usize = ACC_LEN + 9;

// ================================
// aggregator parameters
// ================================

/// An decomposed accumulator consists of 12 field elements
pub(crate) const ACC_LEN: usize = 12;

/// number of limbs when decomposing a field element in the ECC chip
pub(crate) const LIMBS: usize = 3;
/// number of bits in each limb in the ECC chip
pub(crate) const BITS: usize = 88;

/// Max number of snarks to be aggregated in a chunk.
/// If the input size is less than this, dummy snarks
/// will be padded.
pub const MAX_AGG_SNARKS: usize = 45;

/// The [`Batch Circuit`] supports aggregation of up to [`MAX_AGG_SNARKS`] SNARKs, where either
/// SNARK is of 2 kinds, namely:
///
/// 1. halo2-based [`SuperCircuit`] -> [`CompressionCircuit`] (wide) -> `CompressionCircuit` (thin)
/// 2. sp1-based STARK -> halo2-based backend -> `CompressionCircuit` (thin)
///
/// For each SNARK witness provided for aggregation, we require that the commitments to the
/// preprocessed polynomials and the transcript's initial state belong to a fixed set, one
/// belonging to each of the above SNARK kinds.
///
/// Represents the fixed commitments to the preprocessed polynomials for [`ChunkKind::Halo2`].
pub type PreprocessedPolyCommits = Vec<G1Affine>;
pub type TranscriptInitState = Fr;
pub type FixedProtocol = (PreprocessedPolyCommits, TranscriptInitState);

pub static FIXED_PROTOCOL_HALO2: LazyLock<FixedProtocol> = LazyLock::new(|| {
    let name =
        std::env::var("HALO2_CHUNK_PROTOCOL").unwrap_or("chunk_chunk_halo2.protocol".to_string());
    let dir =
        std::env::var("SCROLL_PROVER_ASSETS_DIR").unwrap_or("./tests/test_assets".to_string());
    let path = std::path::Path::new(&dir).join(name);
    let file = std::fs::File::open(&path).expect("could not open file");
    let reader = std::io::BufReader::new(file);
    let protocol: snark_verifier::Protocol<G1Affine> =
        serde_json::from_reader(reader).expect("could not deserialise protocol");
    (
        protocol.preprocessed,
        protocol
            .transcript_initial_state
            .expect("transcript initial state is None"),
    )
});
pub static FIXED_PROTOCOL_SP1: LazyLock<FixedProtocol> = LazyLock::new(|| {
    let name =
        std::env::var("SP1_CHUNK_PROTOCOL").unwrap_or("chunk_chunk_sp1.protocol".to_string());
    let dir =
        std::env::var("SCROLL_PROVER_ASSETS_DIR").unwrap_or("./tests/test_assets".to_string());
    let path = std::path::Path::new(&dir).join(name);
    let file = std::fs::File::open(&path).expect("could not open file");
    let reader = std::io::BufReader::new(file);
    let protocol: snark_verifier::Protocol<G1Affine> =
        serde_json::from_reader(reader).expect("could not deserialise protocol");
    (
        protocol.preprocessed,
        protocol
            .transcript_initial_state
            .expect("transcript initial state is None"),
    )
});

pub static PREPROCESSED_POLYS_HALO2: LazyLock<Vec<G1Affine>> = LazyLock::new(|| {
    vec![
        G1Affine {
            x: Fq::from_raw([
                4541478842587617678,
                7188475718571567728,
                239378696823010373,
                179342154257362491,
            ]),
            y: Fq::from_raw([
                2102960765482384605,
                18163083796572731063,
                17943480866217266774,
                85103875006328896,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                4093061539863783111,
                194291308596025748,
                11369022891089479442,
                1463255879024205618,
            ]),
            y: Fq::from_raw([
                16700532425791245072,
                7378851796565816368,
                17346566642486298786,
                970075911594951367,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                6315321914675870134,
                1582860689439567350,
                15739400164232855740,
                1223439486676386684,
            ]),
            y: Fq::from_raw([
                13096458462745381806,
                11924041770036958177,
                12977682459629830027,
                1912305792904139855,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                408389462232057354,
                10888945426883186814,
                9738219244958428216,
                3343776552242400005,
            ]),
            y: Fq::from_raw([
                2204271371398632469,
                3229396059398198493,
                15594587291868236687,
                1533897200726072018,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                14778744839025706557,
                7305439111399726684,
                14617960481571289161,
                2468165792866445337,
            ]),
            y: Fq::from_raw([
                15298503060320124348,
                16948478742631860463,
                10983004142833888255,
                70418435200471011,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                10682202061899776328,
                12746133157404224107,
                10194303803070492548,
                3314924930376820519,
            ]),
            y: Fq::from_raw([
                10891118471780302094,
                7166241992404117528,
                6263062724619736264,
                340188705380829494,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                9240035288364311447,
                16941312289372401027,
                15915874119483357666,
                2647144763697367565,
            ]),
            y: Fq::from_raw([
                11086173928117658245,
                3518116464318723439,
                13832518766777794466,
                2351978436917361063,
            ]),
        },
    ]
});

/// Represents the fixed commitments to the preprocessed polynomials for [`ChunkKind::Sp1`].
pub static PREPROCESSED_POLYS_SP1: LazyLock<Vec<G1Affine>> = LazyLock::new(|| {
    vec![
        G1Affine {
            x: Fq::from_raw([
                4541478842587617678,
                7188475718571567728,
                239378696823010373,
                179342154257362491,
            ]),
            y: Fq::from_raw([
                2102960765482384605,
                18163083796572731063,
                17943480866217266774,
                85103875006328896,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                14482602916982982999,
                2357100016965177442,
                18431616353722806990,
                1632384859399911320,
            ]),
            y: Fq::from_raw([
                9341870623509249436,
                10625117674485803345,
                11602556742997327241,
                588490870283709105,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                1695984461415246698,
                16627531726212442277,
                7436715082446168910,
                1334937499741146447,
            ]),
            y: Fq::from_raw([
                10378694966954049300,
                14869436676005235944,
                8183056858201575129,
                2775754316985040075,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                10696015357775661092,
                16365831078551355495,
                6432053641301558040,
                3332063291233986333,
            ]),
            y: Fq::from_raw([
                15981342105615776301,
                12342977772828558934,
                12118653449154188133,
                528988368198712851,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                4303830904018986544,
                12892574281015932006,
                12553056811812850723,
                3211210156168296116,
            ]),
            y: Fq::from_raw([
                4036545931324298107,
                7599907392816691312,
                15293245440448741876,
                212143551489911410,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                10931155675221794876,
                4312691987032924781,
                9804797475001633245,
                3451890802936893314,
            ]),
            y: Fq::from_raw([
                11180962733343570413,
                10484712170183330434,
                14444948151863902680,
                2123487521383807780,
            ]),
        },
        G1Affine {
            x: Fq::from_raw([
                1814367689437931729,
                8489483461414090990,
                10000388380055359653,
                1286074470617787276,
            ]),
            y: Fq::from_raw([
                7726546312100213647,
                1034780786427294399,
                6531068821869198065,
                517274402271116562,
            ]),
        },
    ]
});

/// Represents the initial state of the transcript for [`ChunkKind::Halo2`].
pub static TRANSCRIPT_INIT_STATE_HALO2: LazyLock<Fr> = LazyLock::new(|| {
    Fr::from_raw([
        3505826241380660566,
        11473746322117040456,
        14075887197298535585,
        1737617936020314372,
    ])
});

/// Represents the initial state of the transcript for [`ChunkKind::Sp1`].
pub static TRANSCRIPT_INIT_STATE_SP1: LazyLock<Fr> = LazyLock::new(|| {
    Fr::from_raw([
        1678899198020618715,
        10231258143962228858,
        12365017456265435574,
        841984517048583699,
    ])
});
