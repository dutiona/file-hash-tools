use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::mpsc::channel;
use std::time::SystemTime;

use clap::Parser;
use dashmap::DashMap;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use threadpool::ThreadPool;
use walkdir::WalkDir;

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

#[derive(Debug, Clone, Copy)]
enum FileCategory {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone)]
struct FileData {
    path: PathBuf,
    hash: String,
    access_time: Option<SystemTime>,
    creation_time: Option<SystemTime>,
    modification_time: Option<SystemTime>,
    owner: Option<u32>,
    file_type: FileCategory,
    size: u64,
}

fn get_file_category(metadata: &fs::Metadata) -> FileCategory {
    if metadata.is_dir() {
        return FileCategory::Directory;
    }

    if metadata.is_file() {
        return FileCategory::File;
    }

    if metadata.is_symlink() {
        return FileCategory::Symlink;
    }

    FileCategory::Other
}

fn to_absolute_path(relative_path: &PathBuf) -> std::io::Result<PathBuf> {
    let current_dir = env::current_dir()?;
    Ok(current_dir.join(relative_path))
}

fn get_file_info(path: &PathBuf, hash: &str) -> std::io::Result<FileData> {
    let metadata = fs::metadata(path)?;

    Ok(FileData {
        path: to_absolute_path(path).unwrap(),
        hash: hash.to_owned(),
        access_time: metadata.accessed().ok(),
        creation_time: metadata.created().ok(),
        modification_time: metadata.modified().ok(),
        owner: Some(metadata.uid()),
        file_type: get_file_category(&metadata),
        size: metadata.len(),
    })
}

fn calculate_hash(file_path: &PathBuf) -> io::Result<String> {
    let mut file = fs::File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024]; // Read in chunks of 1024 bytes

    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn scan_directories(start_path: &str) -> Vec<PathBuf> {
    WalkDir::new(start_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_owned())
        .collect()
}

fn process_files_in_parallel(paths: Vec<PathBuf>) -> DashMap<PathBuf, FileData> {
    let pool = ThreadPool::new(4); // Number of threads
    let (tx, rx) = channel();

    for path in paths {
        let tx = tx.clone();
        pool.execute(move || {
            let hash = calculate_hash(&path).unwrap();
            let file_data = get_file_info(&path, &hash).unwrap();
            tx.send(file_data).unwrap();
        });
    }

    drop(tx); // Close the sending half

    let mut results = DashMap::new();
    for fdata in rx {
        let file_data = fdata;
        // println!("{} -> {:#?}", file_data.path.display(), file_data);
        let path = file_data.path.to_owned();
        results.insert(path, file_data);
    }

    results
}

fn find_duplicates(results: &DashMap<PathBuf, FileData>) -> DashMap<String, Vec<FileData>> {
    let mut hash_groups: DashMap<String, Vec<FileData>> = DashMap::new();

    for file_data in results.iter() {
        let cpy = file_data.clone();
        hash_groups
            .entry(file_data.hash.clone())
            .or_insert_with(Vec::new)
            .push(cpy);
    }

    hash_groups
}

fn find_duplicates_parallel(
    results: &DashMap<PathBuf, FileData>,
) -> DashMap<String, Vec<FileData>> {
    let mut hash_groups = DashMap::new();

    results.par_iter().for_each(|entry| {
        let file_data = entry.value();
        hash_groups
            .entry(file_data.hash.clone())
            .or_insert_with(|| Vec::new())
            .push(file_data.clone());
    });

    hash_groups
}

fn main() {
    println!("Starting duplicate file finder...");

    let args = Args::parse();
    let directory_path = args.scan;
    let result_file = args.output;

    println!("Scanning directory: {}", directory_path);
    println!("Output will be saved to: {}", result_file);

    let dirs = scan_directories(&directory_path);
    let computed_files = process_files_in_parallel(dirs);
    //for (path, fdata) in computed_files {
    //    println!("{} -> {:#?}", path.display(), fdata);
    //}
    let _duplicates = find_duplicates_parallel(&computed_files);
    // TODO
    // output nice file with the duplicates informations, sorting etc.
}
