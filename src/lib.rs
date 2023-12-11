use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, PathBuf};
use std::sync::mpsc::channel;
use std::time::SystemTime;

use dashmap::DashMap;
use indicatif::{ProgressBar, ProgressStyle};
use num_cpus;
use rayon::prelude::*;
use serde::Serialize;
use serde_json;
use threadpool::ThreadPool;
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, Serialize)]
pub enum FileCategory {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileData {
    path: PathBuf,
    hash: String,
    access_time: Option<SystemTime>,
    creation_time: Option<SystemTime>,
    modification_time: Option<SystemTime>,
    owner: Option<u32>,
    file_type: FileCategory,
    size: u64,
}

pub mod hash_tools {
    use hex;
    use openssl::hash::MessageDigest;
    use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, SHA512, SHA512_256};
    use sha2::{Digest, Sha224, Sha512_224};
    use std::fs::File;
    use std::io::{self, Error, ErrorKind, Read};
    use std::path::PathBuf;

    #[derive(PartialEq, Eq)]
    pub enum SupportedHashes {
        CRC32,      // crc32fast
        MD5,        // openssl
        SHA1,       // ring
        SHA224,     // sha2
        SHA256,     // ring
        SHA384,     // ring
        SHA512,     // ring
        SHA512_224, // sha2
        SHA512_256, // ring
    }

    fn compute_crc32_hash(file_path: &PathBuf) -> io::Result<String> {
        let mut file = File::open(file_path)?;
        let mut hasher = crc32fast::Hasher::new();
        let mut buffer = [0; 1024]; // Adjust the buffer size if needed

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&mut buffer);
        }

        let digest = hasher.finalize().to_ne_bytes();
        Ok(hex::encode(digest))
    }

    fn compute_md5_hash(file_path: &PathBuf) -> io::Result<String> {
        let mut file = File::open(file_path)?;
        let mut hasher = openssl::hash::Hasher::new(MessageDigest::md5()).unwrap();
        let mut buffer = [0; 1024]; // Adjust the buffer size if needed

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            let _ = hasher.update(&mut buffer);
        }

        let digest = hasher.finish().unwrap().to_vec();
        Ok(hex::encode(digest))
    }

    fn compute_sha_ring_hash(
        file_path: &PathBuf,
        hash_type: &'static ring::digest::Algorithm,
    ) -> io::Result<String> {
        let mut file = File::open(file_path)?;
        let mut hasher = Context::new(&hash_type);
        let mut buffer = [0; 1024]; // Adjust the buffer size if needed

        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }

        let digest = hasher.finish();
        Ok(hex::encode(digest.as_ref()))
    }

    fn compute_sha_sha2_hash(
        file_path: &PathBuf,
        hash_type: SupportedHashes,
    ) -> io::Result<String> {
        let mut file = File::open(file_path)?;
        let mut buffer = [0; 1024]; // Adjust the buffer size if needed

        if hash_type == SupportedHashes::SHA224 {
            let mut hasher = Sha224::new();
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }

            let digest = hasher.finalize();
            return Ok(hex::encode(digest));
        } else if hash_type == SupportedHashes::SHA512_224 {
            let mut hasher = Sha512_224::new();
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }

            let digest = hasher.finalize();
            return Ok(hex::encode(digest));
        } else {
            return Err(Error::new(ErrorKind::Unsupported, "Unsupported hash type."));
        }
    }

    pub fn compute_hash_file(
        file_path: &PathBuf,
        hash_type: SupportedHashes,
    ) -> io::Result<String> {
        match hash_type {
            SupportedHashes::CRC32 => compute_crc32_hash(file_path),
            SupportedHashes::MD5 => compute_md5_hash(file_path),
            SupportedHashes::SHA1 => compute_sha_ring_hash(file_path, &SHA1_FOR_LEGACY_USE_ONLY),
            SupportedHashes::SHA256 => compute_sha_ring_hash(file_path, &SHA256),
            SupportedHashes::SHA384 => compute_sha_ring_hash(file_path, &SHA384),
            SupportedHashes::SHA512 => compute_sha_ring_hash(file_path, &SHA512),
            SupportedHashes::SHA512_256 => compute_sha_ring_hash(file_path, &SHA512_256),
            SupportedHashes::SHA224 | SupportedHashes::SHA512_224 => {
                compute_sha_sha2_hash(file_path, hash_type)
            }
        }
    }
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

fn normalize_path(path: &PathBuf) -> PathBuf {
    let mut normalized_path = PathBuf::new();

    for component in path.components() {
        match component {
            Component::ParentDir => {
                normalized_path.pop();
            }
            Component::CurDir => {} // Do nothing for current directory components
            _ => normalized_path.push(component.as_os_str()),
        }
    }

    normalized_path
}

pub fn to_absolute_path(relative_path: &PathBuf) -> std::io::Result<PathBuf> {
    let current_dir = env::current_dir()?;
    Ok(normalize_path(&current_dir.join(relative_path)))
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

pub fn scan_directories(start_path: &str) -> Vec<PathBuf> {
    WalkDir::new(start_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_owned())
        .collect()
}

pub fn process_files_in_parallel(paths: Vec<PathBuf>) -> DashMap<PathBuf, FileData> {
    let num_cores = num_cpus::get();
    let pool = ThreadPool::new(num_cores); // Number of threads
    let (tx, rx) = channel();

    let progress_bar = ProgressBar::new(paths.len() as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    for path in paths {
        let tx = tx.clone();
        pool.execute(move || {
            let hash =
                hash_tools::compute_hash_file(&path, hash_tools::SupportedHashes::SHA256).unwrap();
            let file_data = get_file_info(&path, &hash).unwrap();
            tx.send(file_data).unwrap();
        });
    }

    drop(tx); // Close the sending half

    let results = DashMap::new();
    for fdata in rx {
        let file_data = fdata;
        // println!("{} -> {:#?}", file_data.path.display(), file_data);
        let path = file_data.path.to_owned();
        results.insert(path, file_data);
        progress_bar.inc(1); // Update progress
    }

    results
}

pub fn find_duplicates_parallel(
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
            .or_insert_with(|| Vec::new())
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

pub fn write_results_to_json(
    duplicates: DashMap<String, Vec<FileData>>,
    output_file: &str,
) -> std::io::Result<()> {
    // Convert DashMap to a standard HashMap for serialization
    let duplicates_hashmap: HashMap<_, _> = duplicates.into_iter().collect();

    let json = serde_json::to_string_pretty(&duplicates_hashmap)?;
    let mut file = File::create(output_file)?;
    file.write_all(json.as_bytes())?;

    Ok(())
}