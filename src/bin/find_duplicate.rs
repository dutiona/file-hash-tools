use file_hash_tools::*;

use std::{collections::HashMap, fs::File, io::Write, path::PathBuf};

use clap::Parser;
use dashmap::DashMap;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

/// Duplicate File Finder
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory to scan
    #[arg(short, long)]
    scan: String,

    /// Output file for results
    #[arg(short, long, default_value_t = String::from("./result_duplicates.json"))]
    output: String,
}

fn find_duplicates_parallel(
    results: &DashMap<PathBuf, FileData>,
) -> DashMap<String, Vec<FileData>> {
    let hash_groups = DashMap::new();

    let progress_bar = ProgressBar::new((results.len() * 2) as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    results.par_iter().for_each(|entry| {
        let file_data = entry.value();
        hash_groups
            .entry(file_data.hash.clone())
            .or_insert_with(Vec::new)
            .push(file_data.clone());

        progress_bar.inc(1); // Update progress
    });

    let filtered_hash_groups = DashMap::new();

    hash_groups.par_iter().for_each(|entry| {
        if entry.value().len() > 1 {
            filtered_hash_groups.insert(entry.key().clone(), entry.value().clone());
        }

        progress_bar.inc(1); // Update progress
    });

    filtered_hash_groups
}

fn write_results_to_json(
    duplicates: &DashMap<String, Vec<FileData>>,
    output_file: &str,
) -> std::io::Result<()> {
    // Convert DashMap to a standard HashMap for serialization
    let duplicates_hashmap: HashMap<_, _> = duplicates.clone().into_iter().collect();

    let json = serde_json::to_string_pretty(&duplicates_hashmap)?;
    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    Ok(())
}

fn main() {
    println!("Starting duplicate file finder...");

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

    println!("Looking for duplicates...");
    let duplicates = find_duplicates_parallel(&computed_files);

    match write_results_to_json(&duplicates, &result_file) {
        Ok(_) => println!("Results written to {}", result_file),
        Err(e) => eprintln!("Failed to write results: {}", e),
    }
}
