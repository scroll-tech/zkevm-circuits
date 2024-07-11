use crate::ProofLayer;

pub mod layer;
pub mod proof;
pub mod task;

pub trait ProverType {
    fn layers() -> Vec<ProofLayer>;
}

pub struct ProverTypeChunk;
pub struct ProverTypeBatch;
pub struct ProverTypeBundle;

impl ProverType for ProverTypeChunk {
    fn layers() -> Vec<ProofLayer> {
        vec![ProofLayer::Layer0, ProofLayer::Layer1, ProofLayer::Layer2]
    }
}

impl ProverType for ProverTypeBatch {
    fn layers() -> Vec<ProofLayer> {
        vec![ProofLayer::Layer3, ProofLayer::Layer4]
    }
}

impl ProverType for ProverTypeBundle {
    fn layers() -> Vec<ProofLayer> {
        vec![ProofLayer::Layer5, ProofLayer::Layer6]
    }
}
