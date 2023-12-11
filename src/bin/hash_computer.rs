use file_hash_tools::*;

use std::{collections::HashMap, fs::File, io::Write, path::PathBuf};

use clap::Parser;
use dashmap::DashMap;

/// Duplicate File Finder
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory to scan
    #[arg(short, long)]
    scan: String,

    /// Output file for results
    #[arg(short, long, default_value_t = String::from("./result_hashes.json"))]
    output: String,
}

fn write_results_to_json(
    hashes: &DashMap<PathBuf, FileData>,
    output_file: &str,
) -> std::io::Result<()> {
    // Convert DashMap to a standard HashMap for serialization
    let hashes_hashmap: HashMap<_, _> = hashes.clone().into_iter().collect();

    let json = serde_json::to_string_pretty(&hashes_hashmap)?;
    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    Ok(())
}

fn main() {
    println!("Starting hash file computer...");

    let args = Args::parse();
    let directory_path = args.scan;
    let dir = directory_path.to_owned();
    let result_file = args.output;

    println!("Scanning directory: {}", directory_path);
    println!("Output will be saved to: {}", result_file);

    let abs_path = to_absolute_path(&PathBuf::from(directory_path), &None);
    println!("Scanning directory <{}>...", abs_path.unwrap().display());
    let dirs = scan_directories(&dir);

    println!("Computing hashes...");
    let computed_files = process_files_in_parallel(dirs, &None);

    match write_results_to_json(&computed_files, &result_file) {
        Ok(_) => println!("Results written to {}", result_file),
        Err(e) => eprintln!("Failed to write results: {}", e),
    }
}
