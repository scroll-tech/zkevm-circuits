use crate::{ProofLayer, ProvingTask};

use self::task::{BatchProvingTask, BundleProvingTask, ChunkProvingTask};

pub mod layer;
pub mod proof;
pub mod task;

pub trait ProverType: std::fmt::Debug {
    type Task: ProvingTask;

    /// The prover supports proof generation at the following layers.
    fn layers() -> Vec<ProofLayer>;
}

/// The chunk prover that constructs proofs at layer0, layer1 and layer2.
#[derive(Default, Debug)]
pub struct ProverTypeChunk;

/// The batch prover that constructs proofs at layer3 and layer4.
#[derive(Default, Debug)]
pub struct ProverTypeBatch;

/// The bundle prover that constructs proofs at layer5 and layer6.
#[derive(Default, Debug)]
pub struct ProverTypeBundle;

impl ProverType for ProverTypeChunk {
    type Task = ChunkProvingTask;

    fn layers() -> Vec<ProofLayer> {
        vec![ProofLayer::Layer0, ProofLayer::Layer1, ProofLayer::Layer2]
    }
}

impl ProverType for ProverTypeBatch {
    type Task = BatchProvingTask;

    fn layers() -> Vec<ProofLayer> {
        vec![ProofLayer::Layer3, ProofLayer::Layer4]
    }
}

impl ProverType for ProverTypeBundle {
    type Task = BundleProvingTask;

    fn layers() -> Vec<ProofLayer> {
        vec![ProofLayer::Layer5, ProofLayer::Layer6]
    }
}
