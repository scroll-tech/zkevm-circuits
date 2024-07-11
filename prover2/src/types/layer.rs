use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
pub enum ProofLayer {
    Layer0,
    Layer1,
    Layer2,
    Layer3,
    Layer4,
    Layer5,
    Layer6,
}

impl ToString for ProofLayer {
    fn to_string(&self) -> String {
        String::from(match self {
            Self::Layer0 => "layer0",
            Self::Layer1 => "layer1",
            Self::Layer2 => "layer2",
            Self::Layer3 => "layer3",
            Self::Layer4 => "layer4",
            Self::Layer5 => "layer5",
            Self::Layer6 => "layer6",
        })
    }
}
