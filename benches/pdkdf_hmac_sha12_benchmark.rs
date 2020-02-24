use criterion::{criterion_group, criterion_main, Criterion};
use pbkdf2::pbkdf_hmac_sha512;

fn pbkdf_hmac_sha512_latency(c: &mut Criterion) {
    let password = "passDATAb00AB7YxDTT".as_bytes();
    let salt = "saltKEYbcTcXHCBxtjD".as_bytes();
    let mut mk: Vec<u8> = Vec::new();

    let mut group = c.benchmark_group("pbkdf_hmac_sha512_latency");
    //group.throughput(Throughput::Bytes(message.len() as u64));
    group.bench_function("pbkdf_hmac_sha512 data", |b| {
        b.iter(|| {
            pbkdf_hmac_sha512(&password, &salt, 1, 512, &mut mk);
        })
    });
    group.finish();
}

criterion_group!(benches, pbkdf_hmac_sha512_latency);
criterion_main!(benches);
