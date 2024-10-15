use anyhow::bail;
use clap::Parser;
use console::{style, Emoji};
use eth_types::l2_types::BlockTraceV2;
use eth_types::{ToBigEndian, U256};
use indicatif::{HumanDuration, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use testool::statetest::StateTest;
use testool::{
    compiler::Compiler, config::Config, load_tests, statetest::executor::into_traceconfig,
    statetest::load_statetests_suite, CODEHASH_FILE,
};

static LOOKING_GLASS: Emoji<'_, '_> = Emoji("🔍  ", "");
static PAPER: Emoji<'_, '_> = Emoji("📃  ", "");
static SPARKLE: Emoji<'_, '_> = Emoji("✨  ", ":-)");

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Suite (by default is "default")
    #[clap(long, default_value = "default")]
    suite: String,

    /// Specify a file including test IDs to run these tests
    #[clap(long)]
    test_ids: Option<PathBuf>,

    /// Specify a file excluding test IDs to run these tests
    #[clap(long)]
    exclude_test_ids: Option<PathBuf>,

    #[clap(long)]
    out_dir: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let started = Instant::now();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error"))
        .format_timestamp(None)
        .format_level(false)
        .format_module_path(false)
        .format_target(false)
        .init();

    let spinner_style = ProgressStyle::with_template("{prefix:.bold.dim} {spinner} {wide_msg}")?
        .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏");

    let args = Args::parse();

    println!(
        "{} {}Checking compiler...",
        style("[1/4]").bold().dim(),
        LOOKING_GLASS
    );
    let compiler = Compiler::new(true, Some(PathBuf::from(CODEHASH_FILE)))?;

    println!(
        "{} {}Loading config...",
        style("[2/4]").bold().dim(),
        LOOKING_GLASS
    );
    let config = Config::load()?;
    let suite = config.suite(&args.suite)?.clone();

    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_style(spinner_style.clone());
    pb.set_prefix(format!("[3/4] {}", PAPER));
    pb.set_message("Loading state suite...");
    let mut state_tests = load_statetests_suite(&suite, config, compiler)?;
    load_tests(&mut state_tests, args.test_ids, args.exclude_test_ids)?;
    pb.finish_and_clear();
    println!(
        "{} {}Loading state suite, done. {} tests collected in {}",
        style("[3/4]").bold().dim(),
        PAPER,
        state_tests.len(),
        suite.paths.join(", ")
    );

    let out_dir = args.out_dir;
    std::fs::create_dir_all(&out_dir)?;
    let error_report = Arc::new(Mutex::new(File::create(out_dir.join("errors.log"))?));
    let pb = ProgressBar::new(state_tests.len() as u64);
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_style(spinner_style.clone());
    pb.set_prefix(format!("[4/4] {}", SPARKLE));
    pb.set_message("Generating traces...");
    state_tests.into_par_iter().for_each(|st| {
        let error_report = error_report.clone();
        let id = st.id.clone();
        pb.set_message(st.id.clone());
        if let Err(e) = build_trace(st, &out_dir) {
            let mut error_report = error_report.lock().unwrap();
            writeln!(error_report, "{}: {}", id, e).unwrap();
            pb.set_message(format!("ERROR in {}: {}", id, e));
        }
    });
    pb.finish_and_clear();
    println!(
        "{} {}Done in {}",
        style("[4/4]").bold().dim(),
        SPARKLE,
        HumanDuration(started.elapsed())
    );
    Ok(())
}

fn build_trace(st: StateTest, out_dir: &Path) -> anyhow::Result<()> {
    let (_, mut trace_config, _) = into_traceconfig(st.clone());

    for (_, acc) in trace_config.accounts.iter_mut() {
        if acc.balance.to_be_bytes()[0] != 0u8 {
            acc.balance = U256::from(1u128 << 127);
        }
    }

    let block_trace = match (external_tracer::l2trace(&trace_config), st.exception) {
        (Ok(res), false) => res,
        (Ok(_), true) => bail!("expected exception"),
        (Err(e), false) => Err(e)?,
        (Err(_), true) => return Ok(()),
    };
    let block_trace = BlockTraceV2::from(block_trace);

    let mut block_trace = serde_json::to_value(&block_trace)?;

    // remove coinbase extras
    block_trace["coinbase"]
        .as_object_mut()
        .unwrap()
        .retain(|k, _| k == "address");

    // remove code hashes
    let codes = block_trace["codes"].as_array_mut().unwrap();
    for code in codes.iter_mut() {
        code.as_object_mut().unwrap().remove("hash");
    }

    // cleanup storage_trace
    let storage_trace = block_trace["storageTrace"].as_object_mut().unwrap();
    storage_trace.remove("addressHashes");
    storage_trace.remove("storeKeyHashes");

    let out_path = File::create(out_dir.join(format!("{}.json", st.id)))?;
    serde_json::to_writer_pretty(out_path, &block_trace)?;

    Ok(())
}
