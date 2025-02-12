use std::{
    collections::HashSet,
    fmt,
    fs::File,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use crate::utils::read_env_var;

/// Degree (k) used for the inner circuit, i.e.
/// [`SuperCircuit`][zkevm_circuits::super_circuit::SuperCircuit].
pub static INNER_DEGREE: LazyLock<u32> =
    LazyLock::new(|| read_env_var("SCROLL_PROVER_INNER_DEGREE", 20));

/// Name of the directory to find asset files on disk.
pub static ASSETS_DIR: LazyLock<PathBuf> =
    LazyLock::new(|| read_env_var("SCROLL_PROVER_ASSETS_DIR", PathBuf::from("configs")));

/// The path to the [`Config Parameters`][aggregator::ConfigParams] JSON file that define the shape
/// of the [`Layer-1`][LayerId::Layer1] [`Circuit`][halo2_proofs::plonk::Circuit].
pub static LAYER1_CONFIG_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| asset_file_path("layer1.config"));

/// The path to the [`Config Parameters`][aggregator::ConfigParams] JSON file that define the shape
/// of the [`Layer-2`][LayerId::Layer2] [`Circuit`][halo2_proofs::plonk::Circuit].
pub static LAYER2_CONFIG_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| asset_file_path("layer2.config"));

/// The path to the [`Config Parameters`][aggregator::ConfigParams] JSON file that define the shape
/// of the [`Layer-3`][LayerId::Layer3] [`Circuit`][halo2_proofs::plonk::Circuit].
pub static LAYER3_CONFIG_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| asset_file_path("layer3.config"));

/// The path to the [`Config Parameters`][aggregator::ConfigParams] JSON file that define the shape
/// of the [`Layer-4`][LayerId::Layer4] [`Circuit`][halo2_proofs::plonk::Circuit].
pub static LAYER4_CONFIG_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| asset_file_path("layer4.config"));

/// The path to the [`Config Parameters`][aggregator::ConfigParams] JSON file that define the shape
/// of the [`Layer-5`][LayerId::Layer5] [`Circuit`][halo2_proofs::plonk::Circuit].
pub static LAYER5_CONFIG_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| asset_file_path("layer5.config"));

/// The path to the [`Config Parameters`][aggregator::ConfigParams] JSON file that define the shape
/// of the [`Layer-6`][LayerId::Layer6] [`Circuit`][halo2_proofs::plonk::Circuit].
pub static LAYER6_CONFIG_PATH: LazyLock<PathBuf> =
    LazyLock::new(|| asset_file_path("layer6.config"));

/// The degree (k) for the halo2 [`Circuit`][halo2_proofs::plonk::Circuit] at
/// [`Layer-1`][LayerId::Layer1].
pub static LAYER1_DEGREE: LazyLock<u32> = LazyLock::new(|| layer_degree(&*LAYER1_CONFIG_PATH));

/// The degree (k) for the halo2 [`Circuit`][halo2_proofs::plonk::Circuit] at
/// [`Layer-2`][LayerId::Layer2].
pub static LAYER2_DEGREE: LazyLock<u32> = LazyLock::new(|| layer_degree(&*LAYER2_CONFIG_PATH));

/// The degree (k) for the halo2 [`Circuit`][halo2_proofs::plonk::Circuit] at
/// [`Layer-3`][LayerId::Layer3].
pub static LAYER3_DEGREE: LazyLock<u32> = LazyLock::new(|| layer_degree(&*LAYER3_CONFIG_PATH));

/// The degree (k) for the halo2 [`Circuit`][halo2_proofs::plonk::Circuit] at
/// [`Layer-4`][LayerId::Layer4].
pub static LAYER4_DEGREE: LazyLock<u32> = LazyLock::new(|| layer_degree(&*LAYER4_CONFIG_PATH));

/// The degree (k) for the halo2 [`Circuit`][halo2_proofs::plonk::Circuit] at
/// [`Layer-5`][LayerId::Layer5].
pub static LAYER5_DEGREE: LazyLock<u32> = LazyLock::new(|| layer_degree(&*LAYER5_CONFIG_PATH));

/// The degree (k) for the halo2 [`Circuit`][halo2_proofs::plonk::Circuit] at
/// [`Layer-6`][LayerId::Layer6].
pub static LAYER6_DEGREE: LazyLock<u32> = LazyLock::new(|| layer_degree(&*LAYER6_CONFIG_PATH));

/// The list of degrees for Inner, Layer-1 and Layer-2, i.e. the proof generation [`layers`][LayerId]
/// covered by the [`ChunkProver`][crate::ChunkProver].
pub static CHUNK_PROVER_DEGREES: LazyLock<Vec<u32>> = LazyLock::new(|| {
    Vec::from_iter(HashSet::from([
        *INNER_DEGREE,
        *LAYER1_DEGREE,
        *LAYER2_DEGREE,
    ]))
});

/// The list of degrees for Layer-3, Layer-4, Layer-5 and Layer-6, i.e. the proof generation [`layers`][LayerId]
/// covered by the [`BatchProver`][crate::BatchProver].
pub static BATCH_PROVER_DEGREES: LazyLock<Vec<u32>> = LazyLock::new(|| {
    Vec::from_iter(HashSet::from([
        *LAYER3_DEGREE,
        *LAYER4_DEGREE,
        *LAYER5_DEGREE,
        *LAYER6_DEGREE,
    ]))
});

/// The various proof layers in the proof generation pipeline.
#[derive(Clone, Copy, Debug)]
pub enum LayerId {
    /// Super (inner) circuit layer
    Inner,
    /// Compression wide layer
    Layer1,
    /// Compression thin layer (to generate chunk-proof)
    Layer2,
    /// Layer to batch multiple chunk proofs
    Layer3,
    /// Compression thin layer (to generate batch-proof)
    Layer4,
    /// Recurse over a bundle of batches
    Layer5,
    /// Compression thin layer (to generate bundle-proof verifiable in EVM)
    Layer6,
}

impl fmt::Display for LayerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id())
    }
}

impl LayerId {
    /// Returns the identifier by layer.
    pub fn id(&self) -> &str {
        match self {
            Self::Inner => "inner",
            Self::Layer1 => "layer1",
            Self::Layer2 => "layer2",
            Self::Layer3 => "layer3",
            Self::Layer4 => "layer4",
            Self::Layer5 => "layer5",
            Self::Layer6 => "layer6",
        }
    }

    /// The degree (k) for the [`Circuit`][halo2_proofs::plonk::Circuit] by layer.
    pub fn degree(&self) -> u32 {
        match self {
            Self::Inner => *INNER_DEGREE,
            Self::Layer1 => *LAYER1_DEGREE,
            Self::Layer2 => *LAYER2_DEGREE,
            Self::Layer3 => *LAYER3_DEGREE,
            Self::Layer4 => *LAYER4_DEGREE,
            Self::Layer5 => *LAYER5_DEGREE,
            Self::Layer6 => *LAYER6_DEGREE,
        }
    }

    /// The path to the [`Config Parameters`][aggregator::ConfigParams] used to configure the shape
    /// of the [`Circuit`][halo2_proofs::plonk::Circuit].
    pub fn config_path(&self) -> PathBuf {
        match self {
            Self::Layer1 => LAYER1_CONFIG_PATH.to_path_buf(),
            Self::Layer2 => LAYER2_CONFIG_PATH.to_path_buf(),
            Self::Layer3 => LAYER3_CONFIG_PATH.to_path_buf(),
            Self::Layer4 => LAYER4_CONFIG_PATH.to_path_buf(),
            Self::Layer5 => LAYER5_CONFIG_PATH.to_path_buf(),
            Self::Layer6 => LAYER6_CONFIG_PATH.to_path_buf(),
            Self::Inner => unreachable!("No config file for super (inner) circuit"),
        }
    }

    /// Whether or not the [`Snark`][snark_verifier_sdk::Snark] generated at this layer has an
    /// accumulator.
    ///
    /// Every SNARK layer on top of the [`innermost layer`][LayerId::Inner] has an accumulator.
    pub fn accumulator(&self) -> bool {
        !matches!(self, Self::Inner)
    }
}

/// Returns the path to the [`Config Parameters`][aggregator::ConfigParams] that configure the
/// shape of the [`Circuit`][halo2_proofs::plonk::Circuit] given the [`id`][LayerId::id] of the
/// layer.
pub fn layer_config_path(id: &str) -> PathBuf {
    match id {
        "layer1" => LAYER1_CONFIG_PATH.to_path_buf(),
        "layer2" => LAYER2_CONFIG_PATH.to_path_buf(),
        "layer3" => LAYER3_CONFIG_PATH.to_path_buf(),
        "layer4" => LAYER4_CONFIG_PATH.to_path_buf(),
        "layer5" => LAYER5_CONFIG_PATH.to_path_buf(),
        "layer6" => LAYER6_CONFIG_PATH.to_path_buf(),
        _ => panic!("Wrong id-{id} to get layer config path"),
    }
}

fn asset_file_path(filename: &str) -> PathBuf {
    ASSETS_DIR.join(filename)
}

fn layer_degree<P: AsRef<Path> + fmt::Debug>(path: P) -> u32 {
    let f = File::open(&path).unwrap_or_else(|_| panic!("Failed to open {path:?}"));

    let params = serde_json::from_reader::<_, aggregator::ConfigParams>(f)
        .unwrap_or_else(|_| panic!("Failed to parse {path:?}"));

    params.degree
}
