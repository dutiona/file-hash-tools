use criterion::{black_box, criterion_group, criterion_main, Criterion};
use md5::compute as md5_compute;
use openssl::{
    hash::{Hasher, MessageDigest},
    sha::sha256,
};
use ring::digest;
use sha2::{Digest, Sha256};

fn bench_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn bench_ring_sha256(data: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, data);
    hex::encode(digest.as_ref())
}

fn bench_openssl_sha256(data: &[u8]) -> String {
    let result = sha256(data);
    hex::encode(result)
}

fn bench_md5(data: &[u8]) -> Vec<u8> {
    let digest = md5_compute(data);
    digest.to_vec()
}

fn bench_openssl_md5(data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new(MessageDigest::md5()).unwrap();
    let _ = hasher.update(data);
    hasher.finish().unwrap().to_vec()
}

fn criterion_benchmark_sha256(c: &mut Criterion) {
    let data = black_box([0u8; 1024]); // Or any other data you want to hash

    c.bench_function("sha256", |b| b.iter(|| bench_sha256(&data)));
    c.bench_function("ring_sha256", |b| b.iter(|| bench_ring_sha256(&data)));
    c.bench_function("openssl_sha256", |b| b.iter(|| bench_openssl_sha256(&data)));
}

fn criterion_benchmark_md5(c: &mut Criterion) {
    let data = black_box([0u8; 1024]); // Or any other data you want to hash

    c.bench_function("md5", |b| b.iter(|| bench_md5(&data)));
    c.bench_function("openssl_md5", |b| b.iter(|| bench_openssl_md5(&data)));
}

criterion_group!(benches_sha256, criterion_benchmark_sha256);
criterion_group!(benches_md5, criterion_benchmark_md5);
criterion_main!(benches_sha256, benches_md5);
