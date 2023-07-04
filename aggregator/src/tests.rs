pub(crate) mod compression;
pub(crate) mod mock_chunk;

#[macro_export]
macro_rules! layer_0 {
    // generate a snark for layer 0
    ($circuit: ident, $circuit_type: ident, $param: ident, $degree: ident, $path: ident) => {{
        let timer = start_timer!(|| "gen layer 0 snark");

        let mut rng = test_rng();
        let param = {
            let mut param = $param.clone();
            param.downsize($degree);
            param
        };

        let pk = gen_pk(
            &param,
            &$circuit,
            Some(&$path.join(Path::new("layer_0.pkey"))),
        );
        log::trace!("finished layer 0 pk generation for circuit");

        let snark = gen_snark_shplonk(&param, &pk, $circuit.clone(), &mut rng, None::<String>);
        log::trace!("finished layer 0 snark generation for circuit");

        assert!(verify_snark_shplonk::<$circuit_type>(
            &param,
            snark.clone(),
            pk.get_vk()
        ));

        log::trace!("finished layer 0 snark verification");
        log::trace!("proof size: {}", snark.proof.len());
        log::trace!(
            "pi size: {}",
            snark.instances.iter().map(|x| x.len()).sum::<usize>()
        );

        log::trace!("layer 0 circuit instances");
        for (i, e) in $circuit.instances()[0].iter().enumerate() {
            log::trace!("{}-th public input: {:?}", i, e);
        }
        end_timer!(timer);
        snark
    }};
}

#[macro_export]
macro_rules! compression_layer_snark {
    // generate a snark for compression layer
    ($previous_snark: ident, $param: ident, $degree: ident, $path: ident, $layer_index: expr) => {{
        let timer = start_timer!(|| format!("gen layer {} snark", $layer_index));

        let param = {
            let mut param = $param.clone();
            param.downsize($degree);
            param
        };

        let mut rng = test_rng();

        let is_fresh = if $layer_index == 1 { true } else { false };
        let compression_circuit =
            CompressionCircuit::new(&$param, $previous_snark.clone(), is_fresh, &mut rng).unwrap();

        let pk = gen_pk(&$param, &compression_circuit, None);
        // build the snark for next layer
        let snark = gen_snark_shplonk(
            &param,
            &pk,
            compression_circuit.clone(),
            &mut rng,
            None::<String>, // Some(&$path.join(Path::new("layer_1.snark"))),
        );
        log::trace!(
            "finished layer {} snark generation for circuit",
            $layer_index
        );

        assert!(verify_snark_shplonk::<CompressionCircuit>(
            &param,
            snark.clone(),
            pk.get_vk()
        ));

        end_timer!(timer);
        snark
    }};
}

#[macro_export]
macro_rules! compression_layer_evm {
    // generate a evm proof and verify it for compression layer
    ($previous_snark: ident, $param: ident, $degree: ident, $path: ident,$layer_index: expr) => {{
        let timer = start_timer!(|| format!("gen layer {} snark", $layer_index));

        let param = {
            let mut param = $param.clone();
            param.downsize($degree);
            param
        };

        let mut rng = test_rng();

        let compression_circuit =
            CompressionCircuit::new(&$param, $previous_snark, false, &mut rng).unwrap();

        let instances = compression_circuit.instances();

        let pk = gen_pk(&$param, &compression_circuit, None);
        // build the snark for next layer
        let proof = gen_evm_proof_shplonk(
            &param,
            &pk,
            compression_circuit.clone(),
            instances.clone(),
            &mut rng,
        );

        log::trace!("finished layer 4 aggregation generation");
        log::trace!("proof size: {}", proof.len());

        // verify proof via EVM
        let deployment_code = gen_evm_verifier::<CompressionCircuit, Kzg<Bn256, Bdfg21>>(
            &param,
            pk.get_vk(),
            compression_circuit.num_instance(),
            Some(&$path.join(Path::new("contract.sol"))),
        );
        log::trace!("finished layer 4 bytecode generation");

        evm_verify(
            deployment_code,
            compression_circuit.instances(),
            proof.clone(),
        );
        log::trace!("layer 2 evm verification finished");

        end_timer!(timer);
    }};
}

#[macro_export]
macro_rules! aggregation_layer_snark {
    // generate a snark for compression layer
    ($previous_snarks: ident, $param: ident, $degree: ident, $path: ident, $layer_index: expr, $chunks: ident) => {{
        let timer = start_timer!(|| format!("gen layer {} snark", $layer_index));

        let param = {
            let mut param = $param.clone();
            param.downsize($degree);
            param
        };

        let mut rng = test_rng();

        let aggregation_circuit = AggregationCircuit::new(
            &$param,
            $previous_snarks.as_ref(),
            &mut rng,
            $chunks.as_ref(),
        );

        let pk = gen_pk(&$param, &aggregation_circuit, None);
        // build the snark for next layer
        let snark = gen_snark_shplonk(
            &param,
            &pk,
            aggregation_circuit.clone(),
            &mut rng,
            None::<String>, // Some(&$path.join(Path::new("layer_3.snark"))),
        );
        log::trace!(
            "finished layer {} snark generation for circuit",
            $layer_index
        );

        assert!(verify_snark_shplonk::<AggregationCircuit>(
            &param,
            snark.clone(),
            pk.get_vk()
        ));

        end_timer!(timer);
        snark
    }};
}
