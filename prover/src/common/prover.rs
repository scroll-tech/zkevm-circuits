use crate::utils::{load_params, param_path_for_degree};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use std::collections::{BTreeMap, BTreeSet, HashMap};

mod aggregation;
mod chunk;
mod compression;
mod evm;
mod inner;
mod mock;
mod utils;

#[derive(Debug)]
pub struct Prover {
    // degree -> params (use BTreeMap to find proper degree for params downsize)
    params_map: BTreeMap<u32, ParamsKZG<Bn256>>,
    // Cached id -> pk
    pk_map: HashMap<String, ProvingKey<G1Affine>>,
}

impl Prover {
    pub fn from_params(params_map: BTreeMap<u32, ParamsKZG<Bn256>>) -> Self {
        Self {
            params_map,
            pk_map: HashMap::new(),
        }
    }

    pub fn from_params_dir(params_dir: &str, degrees: &[u32]) -> Self {
        let degrees = BTreeSet::from_iter(degrees);
        let max_degree = **degrees.last().unwrap();

        // Downsize params if any params of degree doesn't exist.
        let mut params_map = BTreeMap::new();
        for d in BTreeSet::from_iter(degrees).into_iter().rev() {
            let params = match load_params(params_dir, *d, None) {
                Ok(params) => params,
                Err(_) => {
                    let params: &ParamsKZG<_> = params_map
                        .first_key_value()
                        .unwrap_or_else(|| {
                            panic!(
                                "File `{}` must exist",
                                param_path_for_degree(params_dir, max_degree)
                            )
                        })
                        .1;

                    let mut params: ParamsKZG<_> = params.clone();
                    params.downsize(*d);

                    log::warn!("Optimization: download params{d} to params dir",);

                    params
                }
            };

            params_map.insert(*d, params);
        }

        Self {
            params_map,
            pk_map: HashMap::new(),
        }
    }
}
