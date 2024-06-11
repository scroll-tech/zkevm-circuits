use std::{fs::File, path::Path};

/// Load struct from json file
pub fn from_json_file<'de, P: serde::Deserialize<'de>>(file_path: &str) -> std::io::Result<P> {
    if !Path::new(&file_path).exists() {
        log::error!("File {file_path} doesn't exist");
    }

    let fd = File::open(file_path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(fd);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);

    Ok(serde::Deserialize::deserialize(deserializer)?)
}
