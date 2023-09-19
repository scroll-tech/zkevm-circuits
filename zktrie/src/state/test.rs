use super::*;
use eth_types::{Bytes, Word};
use log::info;
use serde::Deserialize;
use std::collections::HashMap;

type AccountTrieProofs = HashMap<Address, Vec<Bytes>>;
type StorageTrieProofs = HashMap<Address, HashMap<Word, Vec<Bytes>>>;

type AccountDatas = HashMap<Address, AccountData>;
type StorageDatas = HashMap<(Address, Word), StorageData>;

#[derive(Deserialize, Default, Debug, Clone)]
struct StorageTrace {
    #[serde(rename = "rootBefore")]
    pub root_before: Hash,
    #[serde(rename = "rootAfter")]
    pub root_after: Hash,
    pub proofs: Option<AccountTrieProofs>,
    #[serde(rename = "storageProofs", default)]
    pub storage_proofs: StorageTrieProofs,
}

#[derive(Deserialize, Default, Debug, Clone)]
struct BlockTrace {
    #[serde(rename = "storageTrace")]
    pub storage_trace: StorageTrace,
}

fn build_state_from_string(sample_str: &str) -> (ZktrieState, AccountDatas, StorageDatas) {
    let trace: StorageTrace = serde_json::from_str(sample_str).unwrap();

    let account_traces = trace.proofs.iter().flat_map(|kv_map|{
            kv_map.iter().map(|(k, bts)| (k, bts.iter().map(Bytes::as_ref)))
        });

    let storage_traces = trace.storage_proofs.iter().flat_map(|(k, kv_map)| {
            kv_map
            .iter()
            .map(move |(sk, bts)| (k, sk, bts.iter().map(Bytes::as_ref)))
        });

    let account_datas = ZktrieState::parse_account_from_proofs(account_traces.clone())
        .map(|r|r.unwrap()).collect::<AccountDatas>();

    let storage_datas = ZktrieState::parse_storage_from_proofs(storage_traces.clone())
        .map(|r|r.unwrap()).collect::<StorageDatas>();

    (
        ZktrieState::from_trace_with_additional(
            trace.root_before,
            account_traces,
            storage_traces,
            std::iter::empty(),
        )
        .unwrap(),
        account_datas, storage_datas,
    )
}


const EXAMPLE_TRACE: &str = 
    r#"
    {
        "proofs": {
            "0x1C5A77d9FA7eF466951B2F01F724BCa3A5820b63": [
                "0x0917e72849d9c0d67bb31746101cf4895de34892b24d1486daa024a660abc37d860ddffa0c24af819b6e3c1a8b94699fedcdc77656184edc5a39eb81ca0bed790a",
                "0x0927fb0f5d23170a387eba5ab2e6d4353fd2ec8ab81022f981548d9acdc07c637a2048ec88c007fbe8be0b597adcb2ce40b5f4581e0cc058d67e8e12528d3e6917",
                "0x0921b2b32fa1ee730a507859d58adc1e3f03eac97c1c38ffd8bd1e5e940233fa1301e6296bc35577d87cbfd3bc018c967217ed782d80e3ac023a5f9266f48e3e0a",
                "0x09257a991b89aa51317b15269eb70790e0803ee6e0d5538b8a47160d7da2a9a0e52e9f943364bcb33bf65e07fc546385a3ad38275445465fd06d258d45da867911",
                "0x082bfe09e985d916d891cefd063e0a4e85cb623b2822d9991960e5976252e0e97f2bf9bb78779eabc2ae7590830e67f163171f978ae7116107d2d092b6d6137599",
                "0x0627fe0e20e21d984acac7defe4fbc7decc711efb1190c2abe0c6205e3701945d7231809d3f2acabf42f8d33b76be108af5914ca497c4ec7d82c8fe9fba181778b",
                "0x041822829dca763241624d1f8dd4cf59018fc5f69931d579f8e8a4c3addd6633e605080000000000000000000000000000000000000000000000000000000000000000002d007fffffffffffffffffffffffffffffffffffffffffc078f7390f013506e29d0000000000000000000000000000000000000000000000000000000000000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864201c5a77d9fa7ef466951b2f01f724bca3a5820b63000000000000000000000000",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
            ],
            "0x5300000000000000000000000000000000000000": [
                "0x0917e72849d9c0d67bb31746101cf4895de34892b24d1486daa024a660abc37d860ddffa0c24af819b6e3c1a8b94699fedcdc77656184edc5a39eb81ca0bed790a",
                "0x0927fb0f5d23170a387eba5ab2e6d4353fd2ec8ab81022f981548d9acdc07c637a2048ec88c007fbe8be0b597adcb2ce40b5f4581e0cc058d67e8e12528d3e6917",
                "0x0921b2b32fa1ee730a507859d58adc1e3f03eac97c1c38ffd8bd1e5e940233fa1301e6296bc35577d87cbfd3bc018c967217ed782d80e3ac023a5f9266f48e3e0a",
                "0x09257a991b89aa51317b15269eb70790e0803ee6e0d5538b8a47160d7da2a9a0e52e9f943364bcb33bf65e07fc546385a3ad38275445465fd06d258d45da867911",
                "0x07000000000000000000000000000000000000000000000000000000000000000003b55c8d0d38991f88a85866f2761582f6406e64948c312400a939c2e91f9add",
                "0x05",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
            ],
            "0x5300000000000000000000000000000000000002": [
                "0x0917e72849d9c0d67bb31746101cf4895de34892b24d1486daa024a660abc37d860ddffa0c24af819b6e3c1a8b94699fedcdc77656184edc5a39eb81ca0bed790a",
                "0x091b204534c37ac203794c08e52119dc660abcc864cdb6f2075322915e31b65e551773f6dc1cefdc735b427c9caf30e5a56967fd8e5acc572e67b8e182a741e88e",
                "0x092c931a2e09736360d6db7cc0ba65f0da7023755cc347e4cd06876942f178357429a62ba9ff4ad321a1efc63248664c87e0d0f77669fbe9d33826201d28310f57",
                "0x0810a513bd289b88f45942986cce068223def56384d1b943f9448ed65dfc86c76d301dc3e787d41a3db0710353073f18eaebab31ac37d69e25983caf72f6c08178",
                "0x04139a6815e4d1fb05c969e6a8036aa5cc06b88751d713326d681bd90448ea64c905080000000000000000000000000000000000000000000000000874000000000000000000000000000000000000000000000000000000000000000000000000000000002c3c54d9c8b2d411ccd6458eaea5c644392b097de2ee416f5c923f3b01c7b8b80fabb5b0f58ec2922e2969f4dadb6d1395b49ecd40feff93e01212ae848355d410e77cae1c507f967948c6cd114e74ed65f662e365c7d6993e97f78ce898252800",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
            ],
            "0x5300000000000000000000000000000000000005": [
                "0x0917e72849d9c0d67bb31746101cf4895de34892b24d1486daa024a660abc37d860ddffa0c24af819b6e3c1a8b94699fedcdc77656184edc5a39eb81ca0bed790a",
                "0x091b204534c37ac203794c08e52119dc660abcc864cdb6f2075322915e31b65e551773f6dc1cefdc735b427c9caf30e5a56967fd8e5acc572e67b8e182a741e88e",
                "0x092c931a2e09736360d6db7cc0ba65f0da7023755cc347e4cd06876942f178357429a62ba9ff4ad321a1efc63248664c87e0d0f77669fbe9d33826201d28310f57",
                "0x0810a513bd289b88f45942986cce068223def56384d1b943f9448ed65dfc86c76d301dc3e787d41a3db0710353073f18eaebab31ac37d69e25983caf72f6c08178",
                "0x0700000000000000000000000000000000000000000000000000000000000000002f50fafb9ade43f0863208e700a30a6c38b0f61c71d6b5a8d63b26cea263c304",
                "0x0811a6bc666ad72d376eb65e0a1b89284eadab8c2540f1897a540b06a62d32e608096c33b369382285822d8f0acf8097ca6f095334750a42f869e513c8ec3779a7",
                "0x08261d70525dea5d9a404e59443e7288da6b5e8eb67220ee02b1690708cb211b600000000000000000000000000000000000000000000000000000000000000000",
                "0x0700000000000000000000000000000000000000000000000000000000000000000d5dad10d619a4035d148cbee268b10fdb63e8a690796394c44718c38e542ffa",
                "0x070000000000000000000000000000000000000000000000000000000000000000078947de592c917b37a2fef56798b4c0f6dc88ff90e73c335d0124cc8b2868f2",
                "0x062909a1a348c8f4ba007916d070ebd79bb41550449bb369d43c0fd2349e2e5ca92c2cc500f3d3a26e685bbb70f7a6e10f9df1be5962ae38a04361b8ebf4e7d2a1",
                "0x04287b801ba8950befe82147f88e71eff6b85eb921845d754c9c2a165a4ec8679105080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000944b701a819ff30000000000000000000000000000000000000000000000000000000000000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864205300000000000000000000000000000000000005000000000000000000000000",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
            ],
            "0x66613A02924ca4171675f3793b4eB3908A480D55": [
                "0x0917e72849d9c0d67bb31746101cf4895de34892b24d1486daa024a660abc37d860ddffa0c24af819b6e3c1a8b94699fedcdc77656184edc5a39eb81ca0bed790a",
                "0x0927fb0f5d23170a387eba5ab2e6d4353fd2ec8ab81022f981548d9acdc07c637a2048ec88c007fbe8be0b597adcb2ce40b5f4581e0cc058d67e8e12528d3e6917",
                "0x0921b2b32fa1ee730a507859d58adc1e3f03eac97c1c38ffd8bd1e5e940233fa1301e6296bc35577d87cbfd3bc018c967217ed782d80e3ac023a5f9266f48e3e0a",
                "0x0715c17bf538c62ca0e099396928857a0be6d6dca109eba6c338d62c199410a9bf2fe42431a564bcfd3b464819934c1dca3aa031fd49ed4c7c9724e991dc38ed15",
                "0x08205a520af27de994c9eeef1ab0a6145e1f0f90e59aefdb73a3674484bc6a8d3f2671e331081527a983a7610159b13af138a164596c8280d1553b6578f7759e88",
                "0x04072e5dd3f196958c52140078f2407e11cf80f414c2a3ae3f3bd641c92f7d693a050800000000000000000000000000000000000000000000000000e4000000000000000100000000000000000000000000000000000000000000000000000000000000000d24d8b8043e372c52c8e686ff0998ec5f85e26a5f882c5b9026925a1d23f4fc1f5b06141eb3afb77b6dc6873756a9fdc88f90c2b1937e4b523358664a3f894108cc5fe38e7c93fa53a7f1da1e46529e3e1aff66ef93e078a014794238d5fe332066613a02924ca4171675f3793b4eb3908a480d55000000000000000000000000",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
            ]
            },
        "rootAfter": "0x2a68d57b081310708d5ea3debf78ff0ede609cff7e4e622025379212044b554c",
        "rootBefore": "0x24c368802ea77a0d8d49d8ccce69cdb7aead98533c77aebbd7605358a592f3aa",
        "storageProofs": {
            "0x5300000000000000000000000000000000000000": {
                "0x0000000000000000000000000000000000000000000000000000000000000000": [
                "0x05",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
                ]
            },
            "0x5300000000000000000000000000000000000002": {
                "0x0000000000000000000000000000000000000000000000000000000000000001": [
                "0x080a639a06ff193b9ab132db86545f81c4539ced774b7c66a710799c0e74aebe0d19c4b6fecc8df35dbeb90e48cc838e8df15c05c37230403e144af7dfd0ad7e6e",
                "0x081c8562edca41192eb53d47f84e6e3e75ef936a5db0204312f1fcc5a6cc8dfd52219f351123d5de3428077892a32046effcf21ea6464f7e154b56171facc664e8",
                "0x08247eaef322d76a2cc5bc3def50b5499b636270811928cf94a9553136d8a12e182c60e31a75eefcdc66dad994396a7e42327a2fd04d5f2628a7efd06bfe288b1b",
                "0x082699b6a24c3e9f728bbf81d8b478a89532f62d7dd90b661a5f593b78c506178c0000000000000000000000000000000000000000000000000000000000000000",
                "0x0700000000000000000000000000000000000000000000000000000000000000002dee0af1874f4020b28b87f4ee0b83e70f37ec0a8431a05e839af1beb84b1c74",
                "0x082b5774df25a3fbd3e4fb8afb512ccdf26f1bee61f068f843ab3de6ca05d1b5d90000000000000000000000000000000000000000000000000000000000000000",
                "0x0700000000000000000000000000000000000000000000000000000000000000002a58476ab614c08bcc7ec1b76a32c1e042ba9c0e7375230151dd8e15e5763cd9",
                "0x082d1480889354a6403a0f8c383b4b3bbbe6c0c04b91ca1cad3889067296301aca0000000000000000000000000000000000000000000000000000000000000000",
                "0x0802437779d2f9307c1740a480612491d5fa678120af3feb0a05a2b1a49f7e31aa0000000000000000000000000000000000000000000000000000000000000000",
                "0x07000000000000000000000000000000000000000000000000000000000000000025779e74373d78c2cb4ba4f274db6c97339d159c64c78ec58acab0dd015aa3dc",
                "0x06117d34d74a18b069a21756f797f9f540dde234c57d1934c46572c46d445ed3331be984c8f0565383e1b3c8716daf78661d65a4707650973cef954e35ab4d09a1",
                "0x0426049ba6de63003492eb078a01a8aa4f4a0e67f28f0955c2eba9101d5d2eea50010100000000000000000000000000000000000000000000000000000000000000000064200000000000000000000000000000000000000000000000000000000000000001",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
                ],
                "0x0000000000000000000000000000000000000000000000000000000000000002": [
                "0x080a639a06ff193b9ab132db86545f81c4539ced774b7c66a710799c0e74aebe0d19c4b6fecc8df35dbeb90e48cc838e8df15c05c37230403e144af7dfd0ad7e6e",
                "0x081c8562edca41192eb53d47f84e6e3e75ef936a5db0204312f1fcc5a6cc8dfd52219f351123d5de3428077892a32046effcf21ea6464f7e154b56171facc664e8",
                "0x08247eaef322d76a2cc5bc3def50b5499b636270811928cf94a9553136d8a12e182c60e31a75eefcdc66dad994396a7e42327a2fd04d5f2628a7efd06bfe288b1b",
                "0x04020953ad52de135367a1ba2629636216ed5174cce5629d11b5d97fe733f07dcc0101000000000000000000000000000000000000000000000000000000000000000017d4200000000000000000000000000000000000000000000000000000000000000002",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
                ],
                "0x0000000000000000000000000000000000000000000000000000000000000003": [
                "0x080a639a06ff193b9ab132db86545f81c4539ced774b7c66a710799c0e74aebe0d19c4b6fecc8df35dbeb90e48cc838e8df15c05c37230403e144af7dfd0ad7e6e",
                "0x0406c50541f08911ad149aa545dd3d606f86ee63c751a795c7d57f0d3f85e6bdeb01010000000000000000000000000000000000000000000000000000000000004a42fc80200000000000000000000000000000000000000000000000000000000000000003",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
                ]
            },
            "0x66613A02924ca4171675f3793b4eB3908A480D55": {
                "0x0000000000000000000000000000000000000000000000000000000000000000": [
                "0x041d3c5f8c36e5da873d45bfa1d2399a572ac77493ec089cbf88a37b9e9442842201010000000000000000000000000000000000000000000000000000000000000000000a200000000000000000000000000000000000000000000000000000000000000000",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
                ]
            }
        }
    }
    "#;

#[test]
fn deserialize_example() {
    let s_trace: StorageTrace = serde_json::from_str(EXAMPLE_TRACE).unwrap();
    let proofs = s_trace.proofs.as_ref().unwrap();
    for (_, proof) in proofs.iter() {
        let proof: builder::AccountProof = proof.as_slice().try_into().unwrap();
        info!("proof: {:?}", proof);
    }

    for (_, s_map) in s_trace.storage_proofs.iter() {
        for (k, val) in s_map {
            let val_proof: builder::StorageProof = val.as_slice().try_into().unwrap();
            info!("k: {}, v: {:?}", k, val_proof);
        }
    }
}

#[test]
fn witgen_init_writer() {
    use witness::WitnessGenerator;
    let (state, _, _) = build_state_from_string(EXAMPLE_TRACE);
    let w = WitnessGenerator::from(&state);

    let root_init = w.root();

    info!("root: {root_init:?}");

    assert_eq!(
        format!("{root_init:?}"),
        "0x24c368802ea77a0d8d49d8ccce69cdb7aead98533c77aebbd7605358a592f3aa"
    );
}

fn smt_bytes_to_hash(bt: &[u8]) -> [u8; 32] {
    let mut out: Vec<_> = bt.iter().copied().rev().collect();
    out.resize(32, 0);
    out.try_into().expect("extract size has been set")
}

#[test]
fn witgen_update_one() {
    use eth_types::U256;
    use witness::WitnessGenerator;
    let (state, accounts, storages) = build_state_from_string(EXAMPLE_TRACE);
    let mut w = WitnessGenerator::from(&state);

    let target_addr = Address::from_slice(
        hex::decode("1C5A77d9FA7eF466951B2F01F724BCa3A5820b63")
            .unwrap()
            .as_slice(),
    );

    let start_state = accounts.get(&target_addr);
    assert!(start_state.is_some(), "we picked an existed account");
    let start_state = start_state.unwrap();

    let trace = w.handle_new_state(
        MPTProofType::BalanceChanged,
        target_addr,
        start_state.balance + U256::from(1_u64),
        start_state.balance,
        None,
    );

    let new_root = w.root();

    let new_acc_root = smt_bytes_to_hash(trace.account_path[1].root.as_ref());
    assert_eq!(new_root.0, new_acc_root);

    info!("ret {:?}", trace);

    // create storage slot
    w.handle_new_state(
        MPTProofType::StorageChanged,
        target_addr,
        U256::from(1u32),
        U256::default(),
        Some(U256::zero()),
    );

    let target_addr = Address::from_slice(
        hex::decode("66613A02924ca4171675f3793b4eB3908A480D55")
            .unwrap()
            .as_slice(),
    );

    // check value of storage slot 0 is 10
    assert_eq!(Some(U256::from(10u32)), storages.get(&(target_addr, U256::zero())).map(AsRef::as_ref).copied());

    let trace = w.handle_new_state(
        MPTProofType::StorageChanged,
        target_addr,
        U256::from(11u32),
        U256::from(10u32),
        Some(U256::zero()),
    );

    let new_root = w.root();

    let new_acc_root = smt_bytes_to_hash(trace.account_path[1].root.as_ref());
    assert_eq!(new_root.0, new_acc_root);

    info!("ret {:?}", trace);
}
