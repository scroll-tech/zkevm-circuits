use crate::utils::read_env_var;
use aggregator::ConfigParams;
use once_cell::sync::Lazy;
use std::{collections::HashSet, fmt, fs::File, path::Path};

pub static INNER_DEGREE: Lazy<u32> = Lazy::new(|| read_env_var("SCROLL_PROVER_INNER_DEGREE", 20));

pub static ASSETS_DIR: Lazy<String> =
    Lazy::new(|| read_env_var("SCROLL_PROVER_ASSETS_DIR", "configs".to_string()));

pub static LAYER1_CONFIG_PATH: Lazy<String> = Lazy::new(|| asset_file_path("layer1.config"));
pub static LAYER2_CONFIG_PATH: Lazy<String> = Lazy::new(|| asset_file_path("layer2.config"));
pub static LAYER3_CONFIG_PATH: Lazy<String> = Lazy::new(|| asset_file_path("layer3.config"));
pub static LAYER4_CONFIG_PATH: Lazy<String> = Lazy::new(|| asset_file_path("layer4.config"));

pub static LAYER1_DEGREE: Lazy<u32> = Lazy::new(|| layer_degree(&LAYER1_CONFIG_PATH));
pub static LAYER2_DEGREE: Lazy<u32> = Lazy::new(|| layer_degree(&LAYER2_CONFIG_PATH));
pub static LAYER3_DEGREE: Lazy<u32> = Lazy::new(|| layer_degree(&LAYER3_CONFIG_PATH));
pub static LAYER4_DEGREE: Lazy<u32> = Lazy::new(|| layer_degree(&LAYER4_CONFIG_PATH));

pub static ZKEVM_DEGREES: Lazy<Vec<u32>> = Lazy::new(|| {
    Vec::from_iter(HashSet::from([
        *INNER_DEGREE,
        *LAYER1_DEGREE,
        *LAYER2_DEGREE,
    ]))
});

pub static AGG_DEGREES: Lazy<Vec<u32>> =
    Lazy::new(|| Vec::from_iter(HashSet::from([*LAYER3_DEGREE, *LAYER4_DEGREE])));

#[derive(Clone, Copy, Debug)]
pub enum LayerId {
    /// Super (inner) circuit layer
    Inner,
    /// Compression wide layer
    Layer1,
    /// Compression thin layer (to generate chunk-proof)
    Layer2,
    /// Aggregation layer
    Layer3,
    /// Compression thin layer (to generate batch-proof)
    Layer4,
}

impl fmt::Display for LayerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id())
    }
}

impl LayerId {
    pub fn id(&self) -> &str {
        match self {
            Self::Inner => "inner",
            Self::Layer1 => "layer1",
            Self::Layer2 => "layer2",
            Self::Layer3 => "layer3",
            Self::Layer4 => "layer4",
        }
    }

    pub fn degree(&self) -> u32 {
        match self {
            Self::Inner => *INNER_DEGREE,
            Self::Layer1 => *LAYER1_DEGREE,
            Self::Layer2 => *LAYER2_DEGREE,
            Self::Layer3 => *LAYER3_DEGREE,
            Self::Layer4 => *LAYER4_DEGREE,
        }
    }

    pub fn config_path(&self) -> &str {
        match self {
            Self::Layer1 => &LAYER1_CONFIG_PATH,
            Self::Layer2 => &LAYER2_CONFIG_PATH,
            Self::Layer3 => &LAYER3_CONFIG_PATH,
            Self::Layer4 => &LAYER4_CONFIG_PATH,
            Self::Inner => unreachable!("No config file for super (inner) circuit"),
        }
    }
}

pub fn asset_file_path(filename: &str) -> String {
    Path::new(&*ASSETS_DIR)
        .join(filename)
        .to_string_lossy()
        .into_owned()
}

pub fn layer_config_path(id: &str) -> &str {
    match id {
        "layer1" => &LAYER1_CONFIG_PATH,
        "layer2" => &LAYER2_CONFIG_PATH,
        "layer3" => &LAYER3_CONFIG_PATH,
        "layer4" => &LAYER4_CONFIG_PATH,
        _ => panic!("Wrong id-{id} to get layer config path"),
    }
}

fn layer_degree(config_file: &str) -> u32 {
    let f = File::open(config_file).unwrap_or_else(|_| panic!("Failed to open {config_file}"));

    let params: ConfigParams =
        serde_json::from_reader(f).unwrap_or_else(|_| panic!("Failed to parse {config_file}"));

    params.degree
}
