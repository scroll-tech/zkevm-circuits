use crate::{get_client, GenDataOutput};
use bus_mapping::circuit_input_builder::{BuilderClient, CircuitInputBuilder, CircuitsParams};
use bus_mapping::mock::BlockData;
use eth_types::geth_types::GethData;
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey,
};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use lazy_static::lazy_static;
use mock::test_ctx::TestContext;
use rand_chacha::rand_core::SeedableRng;
use rand_core::RngCore;
use rand_xorshift::XorShiftRng;
use std::collections::HashMap;
use std::sync::Mutex;
use zkevm_circuits::bytecode_circuit::bytecode_unroller::BytecodeCircuit;
use zkevm_circuits::copy_circuit::CopyCircuit;
use zkevm_circuits::evm_circuit::test::{get_test_degree, get_test_instance};
use zkevm_circuits::evm_circuit::{test::get_test_cicuit_from_block, witness::block_convert};
use zkevm_circuits::state_circuit::StateCircuit;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::tx_circuit::TxCircuit;
use zkevm_circuits::util::SubCircuit;
use zkevm_circuits::witness::Block;

const CIRCUITS_PARAMS: CircuitsParams = CircuitsParams {
    max_rws: 16384,
    max_txs: 4,
    max_calldata: 4000,
    max_bytecode: 4000,
    keccak_padding: None,
};

const STATE_CIRCUIT_DEGREE: u32 = 17;
const TX_CIRCUIT_DEGREE: u32 = 20;
const BYTECODE_CIRCUIT_DEGREE: u32 = 16;
const COPY_CIRCUIT_DEGREE: u32 = 16;

lazy_static! {
    /// Data generation.
    pub static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
    static ref RNG: XorShiftRng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
}

lazy_static! {
    static ref GEN_PARAMS: Mutex<HashMap<u32, ParamsKZG<Bn256>>> = Mutex::new(HashMap::new());
}

lazy_static! {
    static ref STATE_CIRCUIT_KEY: ProvingKey<G1Affine> = {
        let block = new_empty_block();
        let circuit = StateCircuit::<Fr>::new_from_block(&block);
        let general_params = get_general_params(STATE_CIRCUIT_DEGREE);

        let verifying_key =
            keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        keygen_pk(&general_params, verifying_key, &circuit).expect("keygen_pk should not fail")
    };
    static ref TX_CIRCUIT_KEY: ProvingKey<G1Affine> = {
        let block = new_empty_block();
        let circuit = TxCircuit::<Fr>::new_from_block(&block);
        let general_params = get_general_params(TX_CIRCUIT_DEGREE);

        let verifying_key =
            keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        keygen_pk(&general_params, verifying_key, &circuit).expect("keygen_pk should not fail")
    };
    static ref BYTECODE_CIRCUIT_KEY: ProvingKey<G1Affine> = {
        let block = new_empty_block();
        let circuit = BytecodeCircuit::<Fr>::new_from_block(&block);
        let general_params = get_general_params(BYTECODE_CIRCUIT_DEGREE);

        let verifying_key =
            keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        keygen_pk(&general_params, verifying_key, &circuit).expect("keygen_pk should not fail")
    };
    static ref COPY_CIRCUIT_KEY: ProvingKey<G1Affine> = {
        let block = new_empty_block();
        let circuit = CopyCircuit::<Fr>::new_from_block(&block);
        let general_params = get_general_params(COPY_CIRCUIT_DEGREE);

        let verifying_key =
            keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        keygen_pk(&general_params, verifying_key, &circuit).expect("keygen_pk should not fail")
    };
}

fn new_empty_block() -> Block<Fr> {
    let block: GethData = TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b)
        .unwrap()
        .into();
    let mut builder = BlockData::new_from_geth_data_with_params(block.clone(), CIRCUITS_PARAMS)
        .new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();
    block_convert(&builder.block, &builder.code_db).unwrap()
}

fn get_general_params(degree: u32) -> ParamsKZG<Bn256> {
    let mut map = GEN_PARAMS.lock().unwrap();
    match map.get(&degree) {
        Some(params) => params.clone(),
        None => {
            let params = ParamsKZG::<Bn256>::setup(degree, RNG.clone());
            map.insert(degree, params.clone());
            params
        }
    }
}

async fn gen_inputs(
    block_num: u64,
) -> (
    CircuitInputBuilder,
    eth_types::Block<eth_types::Transaction>,
) {
    let cli = get_client();
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();

    cli.gen_inputs(block_num).await.unwrap()
}

fn test_actual<C: Circuit<Fr>>(
    degree: u32,
    circuit: C,
    instance: Vec<Vec<Fr>>,
    proving_key: Option<ProvingKey<G1Affine>>,
) {
    fn test_gen_proof<C: Circuit<Fr>, R: RngCore>(
        rng: R,
        circuit: C,
        general_params: &ParamsKZG<Bn256>,
        proving_key: &ProvingKey<G1Affine>,
        mut transcript: Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        instances: &[&[Fr]],
    ) -> Vec<u8> {
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            R,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            C,
        >(
            general_params,
            proving_key,
            &[circuit],
            &[instances],
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");

        transcript.finalize()
    }

    fn test_verify(
        general_params: &ParamsKZG<Bn256>,
        verifier_params: &ParamsKZG<Bn256>,
        verifying_key: &VerifyingKey<G1Affine>,
        proof: &[u8],
        instances: &[&[Fr]],
    ) {
        let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof);
        let strategy = SingleStrategy::new(general_params);

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            verifier_params,
            verifying_key,
            strategy,
            &[instances],
            &mut verifier_transcript,
        )
        .expect("failed to verify circuit");
    }

    let general_params = get_general_params(degree);
    let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();

    let proving_key = match proving_key {
        Some(pk) => pk,
        None => {
            let verifying_key =
                keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&general_params, verifying_key, &circuit).expect("keygen_pk should not fail")
        }
    };

    let transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    // change instace to slice
    let instance: Vec<&[Fr]> = instance.iter().map(|v| v.as_slice()).collect();

    let proof = test_gen_proof(
        RNG.clone(),
        circuit,
        &general_params,
        &proving_key,
        transcript,
        &instance,
    );

    let verifying_key = proving_key.get_vk();
    test_verify(
        &general_params,
        &verifier_params,
        verifying_key,
        &proof,
        &instance,
    );
}

fn test_mock<C: Circuit<Fr>>(degree: u32, circuit: &C, instance: Vec<Vec<Fr>>) {
    let mock_prover = MockProver::<Fr>::run(degree, circuit, instance).unwrap();
    mock_prover
        .verify_par()
        .expect("mock prover verification failed");
}

/// Integration test for evm circuit.
pub async fn test_evm_circuit_block(block_num: u64, actual: bool) {
    log::info!("test evm circuit, block number: {}", block_num);
    let (builder, _) = gen_inputs(block_num).await;

    let block = block_convert(&builder.block, &builder.code_db).unwrap();

    let degree = get_test_degree(&block);
    let instance = get_test_instance(&block);
    let circuit = get_test_cicuit_from_block(block);

    if actual {
        test_actual(degree, circuit, instance, None);
    } else {
        test_mock(degree, &circuit, instance);
    }
}

/// Integration test for state circuit.
pub async fn test_state_circuit_block(block_num: u64, actual: bool) {
    log::info!("test state circuit, block number: {}", block_num);

    let (builder, _) = gen_inputs(block_num).await;
    let block = block_convert(&builder.block, &builder.code_db).unwrap();

    let circuit = StateCircuit::<Fr>::new_from_block(&block);
    let instance = circuit.instance();

    if actual {
        test_actual(
            STATE_CIRCUIT_DEGREE,
            circuit,
            instance,
            Some((*STATE_CIRCUIT_KEY).clone()),
        );
    } else {
        test_mock(STATE_CIRCUIT_DEGREE, &circuit, instance);
    }
}

/// Integration test for tx circuit.
pub async fn test_tx_circuit_block(block_num: u64, actual: bool) {
    log::info!("test tx circuit, block number: {}", block_num);

    let (builder, _) = gen_inputs(block_num).await;

    let block = block_convert(&builder.block, &builder.code_db).unwrap();
    let circuit = TxCircuit::<Fr>::new_from_block(&block);

    if actual {
        test_actual(
            TX_CIRCUIT_DEGREE,
            circuit,
            vec![vec![]],
            Some((*TX_CIRCUIT_KEY).clone()),
        );
    } else {
        test_mock(TX_CIRCUIT_DEGREE, &circuit, vec![vec![]]);
    }
}

/// Integration test for bytecode circuit.
pub async fn test_bytecode_circuit_block(block_num: u64, actual: bool) {
    log::info!("test bytecode circuit, block number: {}", block_num);
    let (builder, _) = gen_inputs(block_num).await;

    let block = block_convert(&builder.block, &builder.code_db).unwrap();
    let circuit =
        BytecodeCircuit::<Fr>::new_from_block_sized(&block, 2usize.pow(BYTECODE_CIRCUIT_DEGREE));

    if actual {
        test_actual(
            BYTECODE_CIRCUIT_DEGREE,
            circuit,
            Vec::new(),
            Some((*BYTECODE_CIRCUIT_KEY).clone()),
        );
    } else {
        test_mock(BYTECODE_CIRCUIT_DEGREE, &circuit, Vec::new());
    }
}

/// Integration test for copy circuit.
pub async fn test_copy_circuit_block(block_num: u64, actual: bool) {
    log::info!("test copy circuit, block number: {}", block_num);
    let (builder, _) = gen_inputs(block_num).await;
    let block = block_convert(&builder.block, &builder.code_db).unwrap();

    let circuit = CopyCircuit::<Fr>::new_from_block(&block);

    if actual {
        test_actual(
            COPY_CIRCUIT_DEGREE,
            circuit,
            vec![],
            Some((*COPY_CIRCUIT_KEY).clone()),
        );
    } else {
        test_mock(COPY_CIRCUIT_DEGREE, &circuit, vec![]);
    }
}

/// Integration test for super circuit.
pub async fn test_super_circuit_block(block_num: u64) {
    const MAX_TXS: usize = 4;
    const MAX_CALLDATA: usize = 512;
    const MAX_RWS: usize = 5888;
    const MAX_BYTECODE: usize = 5000;

    log::info!("test super circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(
        cli,
        CircuitsParams {
            max_rws: MAX_RWS,
            max_txs: MAX_TXS,
            max_calldata: MAX_CALLDATA,
            max_bytecode: MAX_BYTECODE,
            keccak_padding: None,
        },
    )
    .await
    .unwrap();
    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();
    let (k, circuit, instance) =
        SuperCircuit::<_, MAX_TXS, MAX_CALLDATA, MAX_RWS>::build_from_circuit_input_builder(
            &builder,
        )
        .unwrap();
    // TODO: add actual prover
    let prover = MockProver::run(k, &circuit, instance).unwrap();
    let res = prover.verify_par();
    if let Err(err) = res {
        eprintln!("Verification failures:");
        eprintln!("{:#?}", err);
        panic!("Failed verification");
    }
}
