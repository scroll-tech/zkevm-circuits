use std::{
    env,
    io::{self, Write},
};

fn main() {
    let lib_name = "go-geth-utils";
    let out_dir = env::var("OUT_DIR").unwrap();

    // Build
    let mut build = gobuild::Build::new();
    if cfg!(target_os = "macos") {
        build.ldflags("-w");
    }
    let target_files = if cfg!(feature = "scroll") {
        vec!["./l2geth/trace.go", "./l2geth/lib.go"]
    } else {
        vec!["./l1geth/trace.go", "./l1geth/lib.go"]
    };

    if let Err(e) = build.files(target_files).try_compile(lib_name) {
        // The error type is private so have to check the error string
        if format!("{e}").starts_with("Failed to find tool.") {
            fail(
                " Failed to find Go. Please install Go 1.18 or later \
                following the instructions at https://golang.org/doc/install.
                On linux it is also likely available as a package."
                    .to_string(),
            );
        } else {
            fail(format!("{e}"));
        }
    }

    // Files the lib depends on that should recompile the lib
    let dep_files = if cfg!(feature = "scroll") {
        vec![
            "./l2geth/trace.go",
            "./l2geth/lib.go",
            "./l2geth/go.mod",
            "./l2geth/go.sum",
        ]
    } else {
        vec![
            "./l1geth/trace.go",
            "./l1geth/lib.go",
            "./l1geth/go.mod",
            "./l1geth/go.sum",
        ]
    };

    for file in dep_files {
        println!("cargo:rerun-if-changed={file}");
    }

    // Link
    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static={lib_name}");
}

fn fail(message: String) {
    let _ = writeln!(
        io::stderr(),
        "\n\nError while building geth-utils: {message}\n\n"
    );
    std::process::exit(1);
}
