use bus_mapping::Error;
use eth_types::{
    geth_types::TxType,
    sign_types::{get_dummy_tx, pk_bytes_le, pk_bytes_swap_endianness, SignData},
    ToBigEndian, ToWord, Word, H256,
};
use ethers_core::utils::keccak256;
use itertools::Itertools;

use super::{Block, BlockContexts, Transaction};

/// Return all the keccak inputs used during the processing of the current
/// block.
pub fn keccak_inputs(block: &Block) -> Result<Vec<Vec<u8>>, Error> {
    let mut keccak_inputs = Vec::new();
    // Tx Circuit
    keccak_inputs.extend_from_slice(&keccak_inputs_tx_circuit(&block.txs)?);
    log::debug!(
        "keccak total len after txs: {}",
        keccak_inputs.iter().map(|i| i.len()).sum::<usize>()
    );
    // Ecrecover
    keccak_inputs.extend_from_slice(&keccak_inputs_sign_verify(
        &block.precompile_events.get_ecrecover_events(),
    ));
    log::debug!(
        "keccak total len after ecrecover: {}",
        keccak_inputs.iter().map(|i| i.len()).sum::<usize>()
    );
    // PI circuit
    keccak_inputs.extend(keccak_inputs_pi_circuit(
        block.chain_id,
        block.start_l1_queue_index,
        block.prev_state_root.to_word(),
        block.post_state_root().to_word(),
        block.withdraw_root,
        &block.context,
        &block.txs,
    ));
    /*
    // Bytecode Circuit don't use keccak code hash
    for bytecode in block.code_db.0.values() {
        keccak_inputs.push(bytecode.clone());
    }
    */
    log::debug!(
        "keccak total len after bytecodes: {}",
        keccak_inputs.iter().map(|i| i.len()).sum::<usize>()
    );
    // EVM Circuit
    keccak_inputs.extend_from_slice(&block.sha3_inputs);
    log::debug!(
        "keccak total len after opcodes: {}",
        keccak_inputs.iter().map(|i| i.len()).sum::<usize>()
    );

    let inputs_len: usize = keccak_inputs.iter().map(|k| k.len()).sum();
    let inputs_num = keccak_inputs.len();
    let keccak_inputs: Vec<_> = keccak_inputs.into_iter().unique().collect();
    let inputs_len2: usize = keccak_inputs.iter().map(|k| k.len()).sum();
    let inputs_num2 = keccak_inputs.len();
    log::debug!("keccak inputs after dedup: input num {inputs_num}->{inputs_num2}, input total len {inputs_len}->{inputs_len2}");

    // MPT Circuit
    // TODO https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/696
    Ok(keccak_inputs)
}

/// Generate the keccak inputs required by the SignVerify Chip from the
/// signature datas.
pub fn keccak_inputs_sign_verify(sigs: &[SignData]) -> Vec<Vec<u8>> {
    let mut inputs = Vec::new();
    let dummy_sign_data = SignData::default();
    for sig in sigs.iter().chain(std::iter::once(&dummy_sign_data)) {
        let pk_le = pk_bytes_le(&sig.pk);
        let pk_be = pk_bytes_swap_endianness(&pk_le);
        inputs.push(pk_be.to_vec());
        inputs.push(sig.msg.to_vec());
    }
    inputs
}

fn keccak_inputs_pi_circuit(
    chain_id: u64,
    start_l1_queue_index: u64,
    prev_state_root: Word,
    after_state_root: Word,
    withdraw_trie_root: Word,
    block_headers: &BlockContexts,
    transactions: &[Transaction],
) -> Vec<Vec<u8>> {
    let mut total_l1_popped = start_l1_queue_index;
    log::debug!(
        "start_l1_queue_index in keccak_inputs: {}",
        start_l1_queue_index
    );
    let l1transactions = transactions
        .iter()
        .filter(|&tx| tx.tx_type == TxType::L1Msg)
        .collect::<Vec<&Transaction>>();
    let data_bytes = std::iter::empty()
        .chain(block_headers.ctxs.iter().flat_map(|(&block_num, block)| {
            let num_l2_txs = transactions
                .iter()
                .filter(|tx| !tx.tx_type.is_l1_msg() && tx.block_number == block_num)
                .count() as u64;
            let num_l1_msgs = transactions
                .iter()
                .filter(|tx| tx.tx_type.is_l1_msg() && tx.block_number == block_num)
                // tx.nonce alias for queue_index for l1 msg tx
                .map(|tx| tx.nonce)
                .max()
                .map_or(0, |max_queue_index| max_queue_index - total_l1_popped + 1);
            total_l1_popped += num_l1_msgs;

            let num_txs = (num_l2_txs + num_l1_msgs) as u16;
            log::debug!(
                "[block {}] total_l1_popped: {}, num_l1_msgs: {}, num_l2_txs: {}, num_txs: {}",
                block_num,
                total_l1_popped,
                num_l1_msgs,
                num_l2_txs,
                num_txs,
            );

            std::iter::empty()
                // Block Values
                .chain(block.number.as_u64().to_be_bytes())
                .chain(block.timestamp.as_u64().to_be_bytes())
                .chain(block.base_fee.to_be_bytes())
                .chain(block.gas_limit.to_be_bytes())
                .chain(num_txs.to_be_bytes())
        }))
        // Tx Hashes
        .chain(
            l1transactions
                .iter()
                .flat_map(|&tx| tx.hash.to_fixed_bytes()),
        )
        .collect::<Vec<u8>>();
    let data_hash = H256(keccak256(&data_bytes));
    log::debug!(
        "chunk data hash: {}",
        hex::encode(data_hash.to_fixed_bytes())
    );

    let chunk_txbytes = transactions
        .iter()
        .filter(|&tx| tx.tx_type != TxType::L1Msg)
        .flat_map(|tx| tx.rlp_signed.clone())
        .collect::<Vec<u8>>();
    let chunk_txbytes_hash = H256(keccak256(chunk_txbytes));
    let pi_bytes = std::iter::empty()
        .chain(chain_id.to_be_bytes())
        .chain(prev_state_root.to_be_bytes())
        .chain(after_state_root.to_be_bytes())
        .chain(withdraw_trie_root.to_be_bytes())
        .chain(data_hash.to_fixed_bytes())
        .chain(chunk_txbytes_hash.to_fixed_bytes())
        .collect::<Vec<u8>>();

    vec![data_bytes, pi_bytes]
}

/// Generate the keccak inputs required by the Tx Circuit from the transactions.
pub fn keccak_inputs_tx_circuit(txs: &[Transaction]) -> Result<Vec<Vec<u8>>, Error> {
    let mut inputs = Vec::new();

    let hash_datas = txs
        .iter()
        .filter(|tx| tx.tx_type == TxType::L1Msg)
        .map(|tx| tx.rlp_signed.clone())
        .collect::<Vec<Vec<u8>>>();
    let dummy_hash_data = {
        // dummy tx is a legacy tx.
        let (dummy_tx, dummy_sig) = get_dummy_tx();
        dummy_tx.rlp_signed(&dummy_sig).to_vec()
    };
    inputs.extend_from_slice(&hash_datas);
    inputs.push(dummy_hash_data);

    let chunk_txbytes = txs
        .iter()
        .filter(|tx| tx.tx_type != TxType::L1Msg)
        .flat_map(|tx| tx.rlp_signed.clone())
        .collect::<Vec<u8>>();
    inputs.push(chunk_txbytes);

    let sign_datas: Vec<SignData> = txs
        .iter()
        .enumerate()
        .filter(|(i, tx)| {
            if !tx.tx_type.is_l1_msg() && tx.v == 0 && tx.r.is_zero() && tx.s.is_zero() {
                log::warn!(
                    "tx {} is not signed and is not L1Msg, skipping tx circuit keccak input",
                    i
                );
                false
            } else {
                true
            }
        })
        .map(|(_, tx)| {
            if tx.tx_type.is_l1_msg() {
                Ok(SignData::default())
            } else {
                tx.sign_data()
            }
        })
        .try_collect()?;
    // Keccak inputs from SignVerify Chip
    let sign_verify_inputs = keccak_inputs_sign_verify(&sign_datas);
    inputs.extend_from_slice(&sign_verify_inputs);

    Ok(inputs)
}
