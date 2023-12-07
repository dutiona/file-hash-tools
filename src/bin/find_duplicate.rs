use clap::Parser;
use file_hash_tools::*;
use std::path::PathBuf;

/// Duplicate File Finder
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory to scan
    #[arg(short, long)]
    scan: String,

    /// Output file for results
    #[arg(short, long, default_value_t = String::from("."))]
    output: String,
}

fn main() {
    println!("Starting duplicate file finder...");

    let args = Args::parse();
    let directory_path = args.scan;
    let dir = directory_path.to_owned();
    let result_file = args.output;

    println!("Scanning directory: {}", directory_path);
    println!("Output will be saved to: {}", result_file);

    let abs_path = to_absolute_path(&PathBuf::from(directory_path));
    println!("Scanning directory <{}>...", abs_path.unwrap().display());
    let dirs = scan_directories(&dir);

    println!("Computing hashes...");
    let computed_files = process_files_in_parallel(dirs);

    println!("Looking for duplicates...");
    let duplicates = find_duplicates_parallel(&computed_files);

    match write_results_to_json(duplicates, &result_file) {
        Ok(_) => println!("Results written to {}", result_file),
        Err(e) => eprintln!("Failed to write results: {}", e),
    }
}
