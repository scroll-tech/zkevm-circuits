mod aggregation;
mod blob;
mod rlc;

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
            &param, &$circuit, None,
            // Some(&$path.join(Path::new("layer_0.pkey"))),
        );
        log::trace!("finished layer 0 pk generation for circuit");

        let snark = gen_snark_shplonk(&param, &pk, $circuit.clone(), &mut rng, None::<String>)
            .expect("Snark generated successfully");
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

        let batch_circuit = BatchCircuit::new(
            &$param,
            $previous_snarks.as_ref(),
            &mut rng,
            $chunks.as_ref(),
        );

        let pk = gen_pk(&$param, &batch_circuit, None);
        // build the snark for next layer
        let snark = gen_snark_shplonk(
            &param,
            &pk,
            batch_circuit.clone(),
            &mut rng,
            None::<String>, // Some(&$path.join(Path::new("layer_3.snark"))),
        );
        log::trace!(
            "finished layer {} snark generation for circuit",
            $layer_index
        );

        assert!(verify_snark_shplonk::<BatchCircuit>(
            &param,
            snark.clone(),
            pk.get_vk()
        ));

        end_timer!(timer);
        snark
    }};
}
