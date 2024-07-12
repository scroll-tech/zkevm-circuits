use serde::{Deserialize, Serialize};

/// Various layers in the proof generation process.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum ProofLayer {
    /// The super circuit (ZkEVM) layer. This is the innermost proof layer.
    Layer0,
    /// The compression layer on top of layer0.
    Layer1,
    /// The compression layer on top of layer1. The proof from this layer is the [`ChunkProof`].
    Layer2,
    /// The batch circuit layer. At this layer, we batch multiple [`ChunkProof`]s.
    Layer3,
    /// The compression layer on top of layer3. The proof from this layer is the [`BatchProof`].
    Layer4,
    /// The recursion circuit layer. At this layer, we construct proofs recursively over a previous
    /// SNARK from the recursion circuit.
    Layer5,
    /// The compression layer on top of layer5. The proof from this layer is the [`BundleProof`],
    /// which is verified in EVM.
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
