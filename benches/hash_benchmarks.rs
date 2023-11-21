use criterion::{black_box, criterion_group, criterion_main, Criterion};
use openssl::sha::sha256;
use ring::digest;
use sha2::{Digest, Sha256};

fn bench_sha2(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn bench_ring(data: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, data);
    hex::encode(digest.as_ref())
}

fn bench_openssl(data: &[u8]) -> String {
    let result = sha256(data);
    hex::encode(result)
}

fn criterion_benchmark(c: &mut Criterion) {
    let data = black_box([0u8; 1024]); // Or any other data you want to hash

    c.bench_function("sha2", |b| b.iter(|| bench_sha2(&data)));
    c.bench_function("ring", |b| b.iter(|| bench_ring(&data)));
    c.bench_function("openssl", |b| b.iter(|| bench_openssl(&data)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
