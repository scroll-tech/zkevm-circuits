//! The transaction circuit implementation.

// Naming notes:
// - *_be: Big-Endian bytes
// - *_le: Little-Endian bytes

pub mod sign_verify;

use crate::table::{KeccakTable, TxFieldTag, TxTable};
use crate::util::{power_of_randomness_from_instance, random_linear_combine_word as rlc};
use eth_types::{
    geth_types::Transaction, Address, Field, ToBigEndian, ToLittleEndian, ToScalar, Word,
};
use ff::PrimeField;
use group::GroupEncoding;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression},
};
use itertools::Itertools;
use lazy_static::lazy_static;
use libsecp256k1;
use log::error;
use num::Integer;
use num_bigint::BigUint;
// use rand_core::RngCore;
use rlp::RlpStream;
pub use secp256k1::Secp256k1Affine;
use sha3::{Digest, Keccak256};
use sign_verify::{pk_bytes_swap_endianness, SignData, SignVerifyChip, SignVerifyConfig};
pub use sign_verify::{POW_RAND_SIZE, VERIF_HEIGHT};
use std::marker::PhantomData;
use subtle::CtOption;

lazy_static! {
    // Curve Scalar.  Referece: Section 2.4.1 (parameter `n`) in "SEC 2: Recommended Elliptic Curve
    // Domain Parameters" document at http://www.secg.org/sec2-v2.pdf
    static ref SECP256K1_Q: BigUint = BigUint::from_slice(&[
        0xd0364141, 0xbfd25e8c,
        0xaf48a03b, 0xbaaedce6,
        0xfffffffe, 0xffffffff,
        0xffffffff, 0xffffffff,
    ]);
}

fn recover_pk(v: u8, r: &Word, s: &Word, msg_hash: &[u8; 32]) -> Result<Secp256k1Affine, Error> {
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r.to_be_bytes());
    sig_bytes[32..].copy_from_slice(&s.to_be_bytes());
    let signature = libsecp256k1::Signature::parse_standard(&sig_bytes).map_err(|e| {
        error!("Failed parsing signature from (r, s): {:?}", e);
        Error::Synthesis
    })?;
    let msg_hash = libsecp256k1::Message::parse_slice(msg_hash.as_slice()).map_err(|e| {
        error!("Message hash parsing from slice failed: {:?}", e);
        Error::Synthesis
    })?;
    let recovery_id = libsecp256k1::RecoveryId::parse(v).map_err(|e| {
        error!("secp256k1::RecoveriId::parse error: {:?}", e);
        Error::Synthesis
    })?;
    let pk = libsecp256k1::recover(&msg_hash, &signature, &recovery_id).map_err(|e| {
        error!("Public key recovery failed: {:?}", e);
        Error::Synthesis
    })?;
    let pk_be = pk.serialize();
    let pk_le = pk_bytes_swap_endianness(&pk_be[1..]);
    let mut pk_bytes = secp256k1::Serialized::default();
    pk_bytes.as_mut().copy_from_slice(&pk_le[..]);
    let pk = Secp256k1Affine::from_bytes(&pk_bytes);
    ct_option_ok_or(pk, Error::Synthesis).map_err(|e| {
        error!("Invalid public key little endian bytes");
        e
    })
}

fn biguint_to_32bytes_le(v: BigUint) -> [u8; 32] {
    let mut res = [0u8; 32];
    let v_le = v.to_bytes_le();
    res[..v_le.len()].copy_from_slice(&v_le);
    res
}

fn ct_option_ok_or<T, E>(v: CtOption<T>, err: E) -> Result<T, E> {
    Option::<T>::from(v).ok_or(err)
}

/// Return all the keccak inputs that the Tx Circuit requires.
pub fn keccak_inputs(txs: &[Transaction], chain_id: u64) -> Result<Vec<Vec<u8>>, Error> {
    let mut inputs = Vec::new();
    let sign_datas: Vec<SignData> = txs
        .iter()
        .map(|tx| tx_to_sign_data(tx, chain_id))
        .try_collect()?;
    // Keccak inputs from SignVerify Chip
    let sign_verify_inputs = sign_verify::keccak_inputs(&sign_datas);
    inputs.extend_from_slice(&sign_verify_inputs);
    // NOTE: We don't verify the Tx Hash in the circuit yet, so we don't have more
    // hash inputs.
    Ok(inputs)
}

fn tx_to_sign_data(tx: &Transaction, chain_id: u64) -> Result<SignData, Error> {
    let sig_r_le = tx.r.to_le_bytes();
    let sig_s_le = tx.s.to_le_bytes();
    let sig_r =
        ct_option_ok_or(secp256k1::Fq::from_repr(sig_r_le), Error::Synthesis).map_err(|e| {
            error!("Invalid 'r' signature value");
            e
        })?;
    let sig_s =
        ct_option_ok_or(secp256k1::Fq::from_repr(sig_s_le), Error::Synthesis).map_err(|e| {
            error!("Invalid 's' signature value");
            e
        })?;
    // msg = rlp([nonce, gasPrice, gas, to, value, data, sig_v, r, s])
    let mut stream = RlpStream::new_list(9);
    stream
        .append(&tx.nonce)
        .append(&tx.gas_price)
        .append(&tx.gas_limit)
        .append(&tx.to.unwrap_or_else(Address::zero))
        .append(&tx.value)
        .append(&tx.call_data.0)
        .append(&chain_id)
        .append(&0u32)
        .append(&0u32);
    let msg = stream.out();
    let msg_hash: [u8; 32] = Keccak256::digest(&msg)
        .as_slice()
        .to_vec()
        .try_into()
        .expect("hash length isn't 32 bytes");
    let v = (tx.v - 35 - chain_id * 2) as u8;
    let pk = recover_pk(v, &tx.r, &tx.s, &msg_hash)?;
    // msg_hash = msg_hash % q
    let msg_hash = BigUint::from_bytes_be(msg_hash.as_slice());
    let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
    let msg_hash_le = biguint_to_32bytes_le(msg_hash);
    let msg_hash = ct_option_ok_or(secp256k1::Fq::from_repr(msg_hash_le), Error::Synthesis)
        .map_err(|e| {
            error!("Invalid msg hash value");
            e
        })?;
    Ok(SignData {
        signature: (sig_r, sig_s),
        pk,
        msg_hash,
    })
}

/// Config for TxCircuit
#[derive(Clone, Debug)]
pub struct TxCircuitConfig<F: Field> {
    tx_id: Column<Advice>,
    tag: Column<Advice>,
    index: Column<Advice>,
    value: Column<Advice>,
    sign_verify: SignVerifyConfig<F>,
    keccak_table: KeccakTable,
    _marker: PhantomData<F>,
}

impl<F: Field> TxCircuitConfig<F> {
    /// Return a new TxCircuitConfig
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        power_of_randomness: [Expression<F>; sign_verify::POW_RAND_SIZE],
        tx_table: TxTable,
        keccak_table: KeccakTable,
    ) -> Self {
        let tx_id = tx_table.tx_id;
        let tag = tx_table.tag;
        let index = tx_table.index;
        let value = tx_table.value;
        meta.enable_equality(value);

        let sign_verify = SignVerifyConfig::new(meta, power_of_randomness, keccak_table.clone());

        Self {
            tx_id,
            tag,
            index,
            value,
            sign_verify,
            keccak_table,
            _marker: PhantomData,
        }
    }

    /// Assigns a tx circuit row and returns the assigned cell of the value in
    /// the row.
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        tx_id: usize,
        tag: TxFieldTag,
        index: usize,
        value: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice(|| "tx_id", self.tx_id, offset, || Ok(F::from(tx_id as u64)))?;
        region.assign_advice(|| "tag", self.tag, offset, || Ok(F::from(tag as u64)))?;
        region.assign_advice(|| "index", self.index, offset, || Ok(F::from(index as u64)))?;
        region.assign_advice(|| "value", self.value, offset, || Ok(value))
    }
}

/// Tx Circuit for verifying transaction signatures
#[derive(Clone, Default)]
pub struct TxCircuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    /// SignVerify chip
    pub sign_verify: SignVerifyChip<F, MAX_TXS>,
    /// Randomness for RLC encoding
    pub randomness: F,
    /// List of Transactions
    pub txs: Vec<Transaction>,
    /// Chain ID
    pub chain_id: u64,
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>
    TxCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    /// Return a new TxCircuit
    pub fn new(
        aux_generator: Secp256k1Affine,
        randomness: F,
        chain_id: u64,
        txs: Vec<Transaction>,
    ) -> Self {
        TxCircuit::<F, MAX_TXS, MAX_CALLDATA> {
            sign_verify: SignVerifyChip {
                aux_generator,
                window_size: 2,
                _marker: PhantomData,
            },
            randomness,
            txs,
            chain_id,
        }
    }

    /// Make the assignments to the TxCircuit
    pub fn assign(
        &self,
        config: &TxCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        assert!(self.txs.len() <= MAX_TXS);
        let sign_datas: Vec<SignData> = self
            .txs
            .iter()
            .map(|tx| {
                tx_to_sign_data(tx, self.chain_id).map_err(|e| {
                    error!("tx_to_sign_data error for tx {:?}", tx);
                    e
                })
            })
            .try_collect()?;
        let assigned_sig_verifs =
            self.sign_verify
                .assign(&config.sign_verify, layouter, self.randomness, &sign_datas)?;

        layouter.assign_region(
            || "tx table",
            |mut region| {
                let mut offset = 0;
                // Empty entry
                config.assign_row(&mut region, offset, 0, TxFieldTag::Null, 0, F::zero())?;
                offset += 1;
                // Assign al Tx fields except for call data
                let tx_default = Transaction::default();
                // for i in 0..MAX_TXS
                for (i, assigned_sig_verif) in assigned_sig_verifs.iter().enumerate() {
                    let tx = if i < self.txs.len() {
                        &self.txs[i]
                    } else {
                        &tx_default
                    };
                    let address_cell = assigned_sig_verif.address.cell();
                    let msg_hash_rlc_cell = assigned_sig_verif.msg_hash_rlc.cell();
                    let msg_hash_rlc_value = assigned_sig_verif.msg_hash_rlc.value();
                    for (tag, value) in &[
                        (
                            TxFieldTag::Nonce,
                            rlc(tx.nonce.to_le_bytes(), self.randomness),
                        ),
                        (TxFieldTag::Gas, F::from(tx.gas_limit.as_u64())),
                        (
                            TxFieldTag::GasPrice,
                            rlc(tx.gas_price.to_le_bytes(), self.randomness),
                        ),
                        (
                            TxFieldTag::CallerAddress,
                            tx.from.to_scalar().expect("tx.from too big"),
                        ),
                        (
                            TxFieldTag::CalleeAddress,
                            tx.to
                                .unwrap_or_else(Address::zero)
                                .to_scalar()
                                .expect("tx.to too big"),
                        ),
                        (TxFieldTag::IsCreate, F::from(tx.to.is_none() as u64)),
                        (
                            TxFieldTag::Value,
                            rlc(tx.value.to_le_bytes(), self.randomness),
                        ),
                        (
                            TxFieldTag::CallDataLength,
                            F::from(tx.call_data.0.len() as u64),
                        ),
                        (
                            TxFieldTag::CallDataGasCost,
                            F::from(
                                tx.call_data
                                    .0
                                    .iter()
                                    .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
                            ),
                        ),
                        (
                            TxFieldTag::TxSignHash,
                            *msg_hash_rlc_value.unwrap_or(&F::zero()),
                        ),
                    ] {
                        let assigned_cell =
                            config.assign_row(&mut region, offset, i + 1, *tag, 0, *value)?;
                        offset += 1;

                        // Ref. spec 0. Copy constraints using fixed offsets between the tx rows and
                        // the SignVerifyChip
                        match tag {
                            TxFieldTag::CallerAddress => {
                                region.constrain_equal(assigned_cell.cell(), address_cell)?
                            }
                            TxFieldTag::TxSignHash => {
                                region.constrain_equal(assigned_cell.cell(), msg_hash_rlc_cell)?
                            }
                            _ => (),
                        }
                    }
                }

                // Assign call data
                let mut calldata_count = 0;
                for (i, tx) in self.txs.iter().enumerate() {
                    for (index, byte) in tx.call_data.0.iter().enumerate() {
                        assert!(calldata_count < MAX_CALLDATA);
                        config.assign_row(
                            &mut region,
                            offset,
                            i + 1, // tx_id
                            TxFieldTag::CallData,
                            index,
                            F::from(*byte as u64),
                        )?;
                        offset += 1;
                        calldata_count += 1;
                    }
                }
                for _ in calldata_count..MAX_CALLDATA {
                    config.assign_row(
                        &mut region,
                        offset,
                        0, // tx_id
                        TxFieldTag::CallData,
                        0,
                        F::zero(),
                    )?;
                    offset += 1;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> Circuit<F>
    for TxCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    type Config = TxCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable {
            tx_id: meta.advice_column(),
            tag: meta.advice_column(),
            index: meta.advice_column(),
            value: meta.advice_column(),
        };

        let power_of_randomness = power_of_randomness_from_instance(meta);
        let keccak_table = KeccakTable::construct(meta);
        TxCircuitConfig::new(meta, power_of_randomness, tx_table, keccak_table)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.assign(&config, &mut layouter)?;
        config.keccak_table.load(
            &mut layouter,
            keccak_inputs(&self.txs, self.chain_id)?,
            self.randomness,
        )
    }
}

#[cfg(test)]
mod tx_circuit_tests {
    use super::*;
    use eth_types::{address, word, Bytes};
    use ethers_core::{
        types::{NameOrAddress, TransactionRequest},
        utils::keccak256,
    };
    use ethers_signers::{LocalWallet, Signer};
    use group::{Curve, Group};
    use halo2_proofs::{
        arithmetic::CurveAffine,
        dev::{MockProver, VerifyFailure},
        pairing::bn256::Fr,
    };
    use pretty_assertions::assert_eq;
    use rand::{CryptoRng, Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn run<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
        k: u32,
        txs: Vec<Transaction>,
        chain_id: u64,
    ) -> Result<(), Vec<VerifyFailure>> {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let aux_generator =
            <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();

        let randomness = F::random(&mut rng);
        let mut instance: Vec<Vec<F>> = (1..POW_RAND_SIZE + 1)
            .map(|exp| vec![randomness.pow(&[exp as u64, 0, 0, 0]); txs.len() * VERIF_HEIGHT])
            .collect();
        // SignVerifyChip -> ECDSAChip -> MainGate instance column
        instance.push(vec![]);
        let circuit = TxCircuit::<F, MAX_TXS, MAX_CALLDATA> {
            sign_verify: SignVerifyChip {
                aux_generator,
                window_size: 2,
                _marker: PhantomData,
            },
            randomness,
            txs,
            chain_id,
        };

        let prover = match MockProver::run(k, &circuit, instance) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    fn rand_tx<R: Rng + CryptoRng>(mut rng: R, chain_id: u64) -> Transaction {
        let wallet0 = LocalWallet::new(&mut rng).with_chain_id(chain_id);
        let wallet1 = LocalWallet::new(&mut rng).with_chain_id(chain_id);
        let from = wallet0.address();
        let to = wallet1.address();
        let data = b"hello";
        let tx = TransactionRequest::new()
            .from(from)
            .to(to)
            .nonce(3)
            .value(1000)
            .data(data)
            .gas(500_000)
            .gas_price(1234);
        let tx_rlp = tx.rlp(chain_id);
        let sighash = keccak256(tx_rlp.as_ref()).into();
        let sig = wallet0.sign_hash(sighash, true);
        let to = tx.to.map(|to| match to {
            NameOrAddress::Address(a) => a,
            _ => unreachable!(),
        });
        Transaction {
            from: tx.from.unwrap(),
            to,
            gas_limit: tx.gas.unwrap(),
            gas_price: tx.gas_price.unwrap(),
            value: tx.value.unwrap(),
            call_data: tx.data.unwrap(),
            nonce: tx.nonce.unwrap(),
            v: sig.v,
            r: sig.r,
            s: sig.s,
            ..Transaction::default()
        }
    }

    // High memory usage test.  Run in serial with:
    // `cargo test [...] serial_ -- --ignored --test-threads 1`
    #[ignore]
    #[test]
    fn serial_test_tx_circuit_rng() {
        const NUM_TXS: usize = 2;
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 32;

        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let chain_id: u64 = 1337;
        let mut txs = Vec::new();
        for _ in 0..NUM_TXS {
            txs.push(rand_tx(&mut rng, chain_id));
        }

        let k = 19;
        assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, txs, chain_id), Ok(()));
    }

    // High memory usage test.  Run in serial with:
    // `cargo test [...] serial_ -- --ignored --test-threads 1`
    #[ignore]
    #[test]
    fn serial_test_tx_circuit_fixed() {
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;

        let chain_id: u64 = 1337;
        // Transaction generated with `rand_tx` using `rng =
        // ChaCha20Rng::seed_from_u64(42)`
        let tx = Transaction {
            from: address!("0x5f9b7e36af4ff81688f712fb738bbbc1b7348aae"),
            to: Some(address!("0x701653d7ae8ddaa5c8cee1ee056849f271827926")),
            nonce: word!("0x3"),
            gas_limit: word!("0x7a120"),
            value: word!("0x3e8"),
            gas_price: word!("0x4d2"),
            gas_fee_cap: word!("0x0"),
            gas_tip_cap: word!("0x0"),
            call_data: Bytes::from(b"hello"),
            access_list: None,
            v: 2710,
            r: word!("0xaf180d27f90b2b20808bc7670ce0aca862bc2b5fa39c195ab7b1a96225ee14d7"),
            s: word!("0x61159fa4664b698ea7d518526c96cd94cf4d8adf418000754be106a3a133f866"),
        };

        let k = 19;
        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA>(k, vec![tx], chain_id),
            Ok(())
        );
    }

    // High memory usage test.  Run in serial with:
    // `cargo test [...] serial_ -- --ignored --test-threads 1`
    #[ignore]
    #[test]
    fn serial_test_tx_circuit_bad_address() {
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;

        let chain_id: u64 = 1337;
        let tx = Transaction {
            // This address doesn't correspond to the account that signed this tx.
            from: address!("0x1230000000000000000000000000000000000456"),
            to: Some(address!("0x701653d7ae8ddaa5c8cee1ee056849f271827926")),
            nonce: word!("0x3"),
            gas_limit: word!("0x7a120"),
            value: word!("0x3e8"),
            gas_price: word!("0x4d2"),
            gas_fee_cap: word!("0x0"),
            gas_tip_cap: word!("0x0"),
            call_data: Bytes::from(b"hello"),
            access_list: None,
            v: 2710,
            r: word!("0xaf180d27f90b2b20808bc7670ce0aca862bc2b5fa39c195ab7b1a96225ee14d7"),
            s: word!("0x61159fa4664b698ea7d518526c96cd94cf4d8adf418000754be106a3a133f866"),
        };

        let k = 19;
        assert!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, vec![tx], chain_id).is_err(),);
    }
}
