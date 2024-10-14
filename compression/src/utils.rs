pub fn snark_to_ce_snark(snark: snark_verifier_sdk::Snark) -> ce_snark_verifier_sdk::Snark {
    let s = serde_json::to_string(&snark).unwrap();
    let mut inner_deserializer = serde_json::Deserializer::from_str(&s);
    inner_deserializer.disable_recursion_limit();

    let deserializer = serde_stacker::Deserializer::new(&mut inner_deserializer);
    serde::Deserialize::deserialize(deserializer).unwrap()
}

pub fn ce_snark_to_snark(ce_snark: ce_snark_verifier_sdk::Snark) -> snark_verifier_sdk::Snark {
    serde_json::from_str(&serde_json::to_string(&ce_snark).unwrap()).unwrap()
}
