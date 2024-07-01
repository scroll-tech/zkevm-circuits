use crate::{
    common,
    config::{LayerId, AGG_DEGREES},
    consts::{AGG_KECCAK_ROW, AGG_VK_FILENAME, CHUNK_PROTOCOL_FILENAME},
    io::{force_to_read, try_to_read},
    BatchProof, BatchProvingTask, ChunkProof,
};
use aggregator::{ChunkInfo, MAX_AGG_SNARKS};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use snark_verifier_sdk::Snark;
use std::{env, iter::repeat};

#[derive(Debug)]
pub struct Prover {
    pub prover_impl: common::Prover,
    pub batch_protocol: Vec<u8>,
    raw_vk: Option<Vec<u8>>,
}
