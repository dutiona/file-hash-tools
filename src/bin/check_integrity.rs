use file_hash_tools::*;

use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use clap::Parser;
use dashmap::DashMap;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// Duplicate File Finder
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Left directory to compare
    #[arg(short, long)]
    left: String,

    /// Right directory to compare
    #[arg(short, long)]
    right: String,

    /// Output file for results
    #[arg(short, long, default_value_t = String::from("./result_integrity.json"))]
    output: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct DiffResults {
    left_dir: PathBuf,
    right_dir: PathBuf,
    mismatched_files: Vec<MismatchInfo>,
    missing_files: Vec<MissingInfo>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct MismatchInfo {
    path: PathBuf,
    hash_left: String,
    hash_right: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct MissingInfo {
    path: PathBuf,
    missing_left: bool,
    missing_right: bool,
}

fn write_results_to_json(results: &DiffResults, output_file: &str) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    Ok(())
}

fn check_integrity(
    left_dir: &Path,
    left_files: &DashMap<PathBuf, FileData>,
    right_dir: &Path,
    right_files: &DashMap<PathBuf, FileData>,
) -> DiffResults {
    let mismatched_files = Arc::new(Mutex::new(Vec::new()));
    let missing_files = Arc::new(Mutex::new(Vec::new()));

    // Check for mismatches and missing files in left
    left_files
        .par_iter()
        .for_each(|entry| match right_files.get(entry.key()) {
            Some(right_data) if right_data.hash != entry.value().hash => {
                mismatched_files.lock().unwrap().push(MismatchInfo {
                    path: entry.key().clone(),
                    hash_left: entry.value().hash.clone(),
                    hash_right: right_data.hash.clone(),
                });
            }
            None => missing_files.lock().unwrap().push(MissingInfo {
                path: entry.key().clone(),
                missing_left: false,
                missing_right: true,
            }),
            _ => {}
        });

    // Check for files missing in left
    right_files.par_iter().for_each(|entry| {
        if !left_files.contains_key(entry.key()) {
            missing_files.lock().unwrap().push(MissingInfo {
                path: entry.key().clone(),
                missing_left: true,
                missing_right: false,
            });
        }
    });

    let ret = DiffResults {
        left_dir: left_dir.to_path_buf(),
        right_dir: right_dir.to_path_buf(),
        mismatched_files: mismatched_files.lock().unwrap().to_vec(),
        missing_files: missing_files.lock().unwrap().to_vec(),
    };

    ret
}

fn write_results_to_json2(
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
    println!("Starting integrity file checker...");

    let args = Args::parse();
    let left_directory_path = args.left;
    let left_dir = left_directory_path.to_owned();
    let right_directory_path = args.right;
    let right_dir = right_directory_path.to_owned();
    let result_file = args.output;

    println!(
        "Comparing directories: left<{}> and right<{}> ",
        left_directory_path, right_directory_path
    );
    println!("Output will be saved to: {}", result_file);

    let left_abs_path = to_absolute_path(&PathBuf::from(left_directory_path), &None).unwrap();
    println!("Scanning directory <{}>...", left_abs_path.display());
    let left_dirs = scan_directories(&left_dir);

    println!("Computing hashes...");
    let left_computed_files = process_files_in_parallel(left_dirs, &Some(left_abs_path.clone()));

    let _ = write_results_to_json2(&left_computed_files, format!("left_{result_file}").as_str());

    let right_abs_path = to_absolute_path(&PathBuf::from(right_directory_path), &None).unwrap();
    println!("Scanning directory <{}>...", right_abs_path.display());
    let right_dirs = scan_directories(&right_dir);

    println!("Computing hashes...");
    let right_computed_files = process_files_in_parallel(right_dirs, &Some(right_abs_path.clone()));

    let _ = write_results_to_json2(
        &right_computed_files,
        format!("right_{result_file}").as_str(),
    );

    println!("Checking integrity...");
    let integrity_result = check_integrity(
        &left_abs_path,
        &left_computed_files,
        &right_abs_path,
        &right_computed_files,
    );

    match write_results_to_json(&integrity_result, &result_file) {
        Ok(_) => println!("Results written to {}", result_file),
        Err(e) => eprintln!("Failed to write results: {}", e),
    }
}
