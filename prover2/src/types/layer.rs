use serde::{Deserialize, Serialize};

/// Various layers in the proof generation process.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum ProofLayer {
    /// The [`SuperCircuit`][super_circuit] (ZkEVM) layer. This is the innermost proof layer.
    ///
    /// [super_circuit]: zkevm_circuits::super_circuit::SuperCircuit
    Layer0,
    /// The compression layer on top of layer0.
    Layer1,
    /// The compression layer on top of layer1. The proof from this layer is the [`Proof`][proof] returned
    /// by the [`ChunkProver`][gen_proof].
    ///
    /// [proof]: crate::Proof
    /// [gen_proof]: crate::prover::ChunkProver::gen_proof
    Layer2,
    /// The batch circuit layer. At this layer, we batch multiple `ChunkProof`s.
    Layer3,
    /// The compression layer on top of layer3. The proof from this layer is the [`Proof`][proof] returned
    /// by the [`BatchProver`][gen_proof].
    ///
    /// [proof]: crate::Proof
    /// [gen_proof]: crate::prover::BatchProver::gen_proof
    Layer4,
    /// The recursion circuit layer. At this layer, we construct proofs recursively over a previous
    /// SNARK from the recursion circuit.
    Layer5,
    /// The compression layer on top of layer5. The proof from this layer is the [`Proof`][proof] returned
    /// by the [`BundleProver`][gen_proof].
    ///
    /// [proof]: crate::Proof
    /// [gen_proof]: crate::prover::BundleProver::gen_proof
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
