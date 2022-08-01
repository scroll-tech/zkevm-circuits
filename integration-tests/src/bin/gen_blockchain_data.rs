use ethers::{
    abi::{self, Tokenize},
    contract::{builders::ContractCall, Contract, ContractFactory},
    core::types::{transaction::eip2718::TypedTransaction, Address, TransactionRequest, U256},
    core::utils::WEI_IN_ETHER,
    middleware::SignerMiddleware,
    prelude::{k256::ecdsa::SigningKey, Eip1559TransactionRequest, NonceManagerMiddleware, Wallet},
    providers::{Middleware, PendingTransaction},
    signers::Signer,
    solc::Solc,
};
use integration_tests::{
    get_client, get_provider, get_wallet, log_init, CompiledContract, GenDataOutput, CONTRACTS,
    CONTRACTS_PATH,
};
use log::{debug, info};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

async fn deploy<T, M>(prov: Arc<M>, compiled: &CompiledContract, args: T) -> Contract<M>
where
    T: Tokenize,
    M: Middleware,
{
    info!("Deploying {}...", compiled.name);
    let factory = ContractFactory::new(compiled.abi.clone(), compiled.bin.clone(), prov);
    factory
        .deploy(args)
        .expect("cannot deploy")
        .confirmations(0usize)
        .send()
        .await
        .expect("cannot confirm deploy")
}

fn erc20_transfer<M>(
    prov: Arc<M>,
    contract_address: Address,
    contract_abi: &abi::Contract,
    to: Address,
    amount: U256,
    legacy: bool,
) -> TypedTransaction
where
    M: Middleware,
{
    let contract = Contract::new(contract_address, contract_abi.clone(), prov);
    let call: ContractCall<M, _> = contract
        .method::<_, bool>("transfer", (to, amount))
        .expect("cannot construct ERC20 transfer call");
    // Set gas to avoid `eth_estimateGas` call
    let call = if legacy { call.legacy() } else { call };
    let call = call.gas(100_000);
    println!("typed erc20 tx {:?}", call.tx);
    call.tx
}

/*
async fn send_confirm_tx<M>(prov: &Arc<M>, tx: TypedTransaction) -> TransactionReceipt
where
    M: Middleware,
{
    prov.send_transaction(tx, None)
        .await
        .expect("cannot send ERC20 transfer call")
        .confirmations(0usize)
        .await
        .unwrap()
        .unwrap()
}
*/

#[tokio::main]
async fn main() {
    log_init();

    // Compile contracts
    info!("Compiling contracts...");
    let mut contracts = HashMap::new();
    for (name, contract_path) in CONTRACTS {
        let path_sol = Path::new(CONTRACTS_PATH).join(contract_path);
        let compiled = Solc::default()
            .compile_source(&path_sol)
            .expect("solc compile error");
        if !compiled.errors.is_empty() {
            panic!("Errors compiling {:?}:\n{:#?}", &path_sol, compiled.errors)
        }

        let contract = compiled
            .get(path_sol.to_str().expect("path is not str"), name)
            .expect("contract not found");
        let abi = contract.abi.expect("no abi found").clone();
        let bin = contract.bin.expect("no bin found").clone();
        let bin_runtime = contract.bin_runtime.expect("no bin_runtime found").clone();
        let compiled_contract = CompiledContract {
            path: path_sol.to_str().expect("path is not str").to_string(),
            name: name.to_string(),
            abi,
            bin,
            bin_runtime,
        };

        let mut path_json = path_sol.clone();
        path_json.set_extension("json");
        serde_json::to_writer(
            &File::create(&path_json).expect("cannot create file"),
            &compiled_contract,
        )
        .expect("cannot serialize json into file");

        contracts.insert(name.to_string(), compiled_contract);
    }

    let prov = get_provider();

    // Wait for geth to be online.
    loop {
        match prov.client_version().await {
            Ok(version) => {
                info!("Geth online: {}", version);
                break;
            }
            Err(err) => {
                debug!("Geth not available: {:?}", err);
                sleep(Duration::from_millis(500));
            }
        }
    }

    // Make sure the blockchain is in a clean state: block 0 is the last block.
    let block_number = prov
        .get_block_number()
        .await
        .expect("cannot get block number");
    if block_number.as_u64() != 0 {
        panic!(
            "Blockchain is not in a clean state.  Last block number: {}",
            block_number
        );
    }

    let stop_miner = |real: bool| async move {
        if real {
            get_client().miner_stop().await.expect("cannot stopx miner");
        }
    };
    let start_miner = |real: bool| async move {
        if real {
            get_client()
                .miner_start()
                .await
                .expect("cannot startx miner");
        }
    };

    let accounts = prov.get_accounts().await.expect("cannot get accounts");
    let wallet0 = get_wallet(0);
    info!("wallet0: {:x}", wallet0.address());

    let mut blocks = HashMap::new();

    //
    // ETH Transfer: Transfer funds to our account.
    //

    println!("wallet 0 is {:?}", wallet0.address());

    info!("Transferring funds from coinbase...");
    let tx = TransactionRequest::new()
        .to(wallet0.address())
        .value(WEI_IN_ETHER) // send 1 ETH
        .from(accounts[0]);
    prov.send_transaction(tx, None)
        .await
        .expect("cannot send tx")
        .await
        .expect("cannot confirm tx");
    let block_num = prov.get_block_number().await.expect("cannot get block_num");
    blocks.insert("Transfer 0".to_string(), block_num.as_u64());

    println!("coin base done;");
    //
    // Deploy smart contracts
    //

    let wallet_fn = |wallet0: Wallet<SigningKey>| {
        let p1 = NonceManagerMiddleware::new(get_provider(), wallet0.address());
        let p2 = SignerMiddleware::new(p1, wallet0);
        Arc::new(p2)
    };
    let mut deployments = HashMap::new();
    let wallets: Vec<_> = (0..NUM_TXS + 1)
        .map(|i| wallet_fn(get_wallet(i as u32)))
        .collect();

    let mut tx_hashes = Vec::new();

    use ethers::types::BlockNumber::Pending;
    // Fund NUM_TXS wallets from coinbase
    for wallet in &wallets[0..NUM_TXS] {
        let tx = TransactionRequest::new()
            .to(wallet.address())
            .value(WEI_IN_ETHER * 2u8) // send 2 ETH
            .from(accounts[0]);
        tx_hashes.push(
            *prov
                .send_transaction(tx, Some(Pending.into()))
                .await
                .expect("cannot send tx"),
        );
    }

    println!("pending {:?}", tx_hashes);

    for (i, tx_hash) in tx_hashes.iter().enumerate() {
        let pending_tx = PendingTransaction::new(*tx_hash, wallets[i].inner().inner());
        let receipt = pending_tx.confirmations(0usize).await.unwrap().unwrap();
        println!("native transfer state {:?}", receipt.status);
        /*
        let expected_status = if i % 2 == 0 { 1u64 } else { 0u64 };
        assert_eq!(
            receipt.status,
            Some(U64::from(expected_status)),
            "failed tx hash: {:?}, receipt: {:#?}",
            tx_hash,
            receipt
        );
        */
    }
    tx_hashes.clear();

    // OpenZeppelinERC20TestToken
    let contract = deploy(
        wallets[0].clone(),
        contracts
            .get("OpenZeppelinERC20TestToken")
            .expect("contract not found"),
        wallet0.address(),
    )
    .await;
    let block_num = prov.get_block_number().await.expect("cannot get block_num");
    blocks.insert(
        "Deploy OpenZeppelinERC20TestToken".to_string(),
        block_num.as_u64(),
    );
    deployments.insert(
        "OpenZeppelinERC20TestToken".to_string(),
        (block_num.as_u64(), contract.address()),
    );

    stop_miner(true).await;
    // Greeter

    println!("deploying greeter");
    let compiled = contracts.get("Greeter").expect("contract not found");

    let params = U256::from(42u64).into_tokens();
    let data = match (compiled.abi.constructor(), params.is_empty()) {
        (None, false) => panic!("hhh"),
        (None, true) => compiled.bin.clone(),
        (Some(constructor), _) => constructor
            .encode_input(compiled.bin.to_vec(), &params)
            .unwrap()
            .into(),
    };

    let tx = TransactionRequest {
        to: None,
        data: Some(data),
        ..Default::default()
    };
    //let tx = Eip1559TransactionRequest { to: None, data: Some(data),
    // ..Default::default() }; let tx = tx.into();

    let pending = ethers::prelude::BlockId::Number(Pending);
    let _tx = *wallets[0]
        .send_transaction(tx, Some(pending))
        .await
        .unwrap();

    println!("deploying greeter done");
    //
    // ETH transfers: Generate a block with multiple transfers
    //

    info!("Generating block with multiple transfers...");
    const NUM_TXS: usize = 4; // NUM_TXS must be >= 4 for the rest of the cases to work.

    for i in 0..NUM_TXS {
        println!("try i {}", i);
        let tx: TypedTransaction = if i % 2 == 0 {
            TransactionRequest::new()
                .to(wallets[i + 1].address())
                .value(WEI_IN_ETHER / (2 * (i + 1))) // send a fraction of an ETH
                .from(wallets[i].address())
                .into()
        } else {
            Eip1559TransactionRequest::new()
                .to(wallets[i + 1].address())
                .value(WEI_IN_ETHER / (2 * (i + 1))) // send a fraction of an ETH
                .from(wallets[i].address())
                .into()
        };
        tx_hashes.push(
            *wallets[i]
                .send_transaction(tx, Some(pending))
                .await
                .expect("cannot send tx"),
        );
        println!("i = {} hashes {:?}", i, tx_hashes);
    }

    //
    // ERC20 calls (OpenZeppelin)
    //

    info!("Generating ERC20 calls...");

    let contract_address = deployments
        .get("OpenZeppelinERC20TestToken")
        .expect("contract not found")
        .1;
    let contract_abi = &contracts
        .get("OpenZeppelinERC20TestToken")
        .expect("contract not found")
        .abi;

    // OpenZeppelin ERC20 multiple transfers in a single block (some successful,
    // some unsuccessful)
    // - wallet0 -> wallet1 (ok)
    // - wallet2 -> wallet3 (ko)
    // - wallet1 -> wallet0 (ok)
    // - wallet3 -> wallet2 (ko)
    info!("Doing OpenZeppelin ERC20 multiple transfers...");
    for (i, (from_i, to_i)) in [(0, 1), (2, 3), (1, 0), (3, 2)].iter().enumerate() {
        let amount = U256::from(0x800000000000000 / (i + 1));
        let prov_wallet = &wallets[*from_i];
        let mut tx = erc20_transfer(
            prov_wallet.clone(),
            contract_address,
            contract_abi,
            wallets[*to_i].address(),
            amount,
            i % 2 == 0,
        );

        prov_wallet
            .fill_transaction(&mut tx, Some(pending))
            .await
            .unwrap();
        tx.set_gas(100_000u64);

        let pending_tx = prov_wallet
            .send_transaction(tx, Some(pending))
            .await
            .expect("cannot send ERC20 transfer call");
        let tx_hash = *pending_tx; // Deref for PendingTransaction returns TxHash
        tx_hashes.push(tx_hash);
    }
    start_miner(true).await;
    for (i, tx_hash) in tx_hashes.iter().enumerate() {
        let pending_tx = PendingTransaction::new(*tx_hash, wallets[i % 4].inner().inner());
        let receipt = pending_tx.confirmations(0usize).await.unwrap().unwrap();
        println!("erc20 state {:?}", receipt.status);
    }
    let block_num = prov.get_block_number().await.expect("cannot get block_num");
    println!("block num is {}", block_num);
    blocks.insert(
        "Multiple ERC20 OpenZeppelin transfers".to_string(),
        block_num.as_u64(),
    );

    let gen_data = GenDataOutput {
        coinbase: accounts[0],
        wallets: wallets.iter().map(|w| w.address()).collect(),
        blocks,
        deployments,
    };
    gen_data.store();
}
