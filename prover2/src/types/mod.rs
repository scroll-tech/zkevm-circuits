use aggregator::{AggregationCircuit, CompressionCircuit};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::Circuit,
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::{CircuitExt, Snark};
use zkevm_circuits::super_circuit::params::ScrollSuperCircuit;

use crate::{ProofLayer, ProverError, ProvingTask};

pub mod layer;

pub mod proof;

pub mod task;
use task::{BatchProvingTask, ChunkProvingTask};

pub trait ProverType: std::fmt::Debug {
    /// The name of the prover.
    const NAME: &'static str;

    /// The proving task that provides the relevant values required by the prover type to build its
    /// base circuit.
    type Task: ProvingTask;

    /// The circuit used at the base layer of this prover type.
    type BaseCircuit: Circuit<Fr> + CircuitExt<Fr>;

    /// The compression circuit used to compress the base layer SNARK one or more times before
    /// finally producing the outermost layer's SNARK.
    type CompressionCircuit: Circuit<Fr> + CircuitExt<Fr>;

    /// The prover supports proof generation at the following layers.
    fn layers() -> Vec<ProofLayer>;

    /// Returns the base layer.
    fn base_layer() -> Result<ProofLayer, ProverError> {
        Self::layers()
            .first()
            .ok_or(ProverError::Custom(format!(
                "no base layer for {}",
                Self::NAME
            )))
            .copied()
    }

    /// Returns the subsequent layers after the base layer, i.e. the layers where the previous
    /// layer's SNARK is compressed.
    fn compression_layers() -> Vec<ProofLayer> {
        Self::layers()[1..].to_vec()
    }

    /// Builds the base circuit given witness in the proving task.
    fn build_base(task: Self::Task) -> Self::BaseCircuit;

    /// Builds the compression circuit given the previous layer's SNARK.
    fn build_compression(
        kzg_params: &ParamsKZG<Bn256>,
        prev_snark: Snark,
        layer: ProofLayer,
    ) -> Self::CompressionCircuit;
}

/// The chunk prover that constructs proofs at layer0, layer1 and layer2.
#[derive(Default, Debug)]
pub struct ProverTypeChunk;

/// The batch prover that constructs proofs at layer3 and layer4.
#[derive(Default, Debug)]
pub struct ProverTypeBatch<const N_SNARKS: usize>;

/// The bundle prover that constructs proofs at layer5 and layer6.
#[derive(Default, Debug)]
pub struct ProverTypeBundle;

impl ProverType for ProverTypeChunk {
    const NAME: &'static str = "ChunkProver";

    type Task = ChunkProvingTask;

    type BaseCircuit = ScrollSuperCircuit;

    type CompressionCircuit = CompressionCircuit;

    fn layers() -> Vec<ProofLayer> {
        vec![ProofLayer::Layer0, ProofLayer::Layer1, ProofLayer::Layer2]
    }

    fn build_base(_task: Self::Task) -> Self::BaseCircuit {
        unimplemented!()
    }

    fn build_compression(
        _params: &ParamsKZG<Bn256>,
        _prev_snark: Snark,
        _layer: ProofLayer,
    ) -> Self::CompressionCircuit {
        unimplemented!()
    }
}

impl<const N_SNARKS: usize> ProverType for ProverTypeBatch<N_SNARKS> {
    const NAME: &'static str = "BatchProver";

    type Task = BatchProvingTask<N_SNARKS>;

    type BaseCircuit = AggregationCircuit<N_SNARKS>;

    type CompressionCircuit = CompressionCircuit;

    fn layers() -> Vec<ProofLayer> {
        vec![ProofLayer::Layer3, ProofLayer::Layer4]
    }

    fn build_base(_task: Self::Task) -> Self::BaseCircuit {
        unimplemented!()
    }

    fn build_compression(
        _params: &ParamsKZG<Bn256>,
        _prev_snark: Snark,
        _layer: ProofLayer,
    ) -> Self::CompressionCircuit {
        unimplemented!()
    }
}
