use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pqc::MlKem768;

fn keygen_benchmark(c: &mut Criterion) {
    c.bench_function("ml-kem-768 keygen", |b| {
        b.iter(|| MlKem768::generate_keypair().expect("Key generation failed"));
    });
}

fn encapsulate_benchmark(c: &mut Criterion) {
    let (pk, _sk) = MlKem768::generate_keypair().expect("Key generation failed");

    c.bench_function("ml-kem-768 encapsulate", |b| {
        b.iter(|| MlKem768::encapsulate(&pk).expect("Encapsulation failed"));
    });
}

fn decapsulate_benchmark(c: &mut Criterion) {
    let (pk, sk) = MlKem768::generate_keypair().expect("Key generation failed");
    let (ct, _ss) = MlKem768::encapsulate(&pk).expect("Encapsulation failed");

    c.bench_function("ml-kem-768 decapsulate", |b| {
        b.iter(|| MlKem768::decapsulate(&ct, &sk).expect("Decapsulation failed"));
    });
}

fn full_kem_benchmark(c: &mut Criterion) {
    c.bench_function("ml-kem-768 fullkem", |b| {
        b.iter(|| {
            let (pk, sk) = MlKem768::generate_keypair().expect("Key generation failed");
            let (ct, ss_send) = MlKem768::encapsulate(&pk).expect("Encapsulation failed");
            let ss_recv = MlKem768::decapsulate(&ct, &sk).expect("Decapsulation failed");
            assert_eq!(ss_send.0, ss_recv.0);
        });
    });
}

fn multiple_operations_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml-kem-768 batch");

    for i in [1, 10, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(i), i, |b, &i| {
            b.iter(|| {
                for _ in 0..i {
                    let (pk, sk) = MlKem768::generate_keypair().expect("Key generation failed");
                    let (ct, ss_send) = MlKem768::encapsulate(&pk).expect("Encapsulation failed");
                    let ss_recv = MlKem768::decapsulate(&ct, &sk).expect("Decapsulation failed");
                    assert_eq!(ss_send.0, ss_recv.0);
                }
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    keygen_benchmark,
    encapsulate_benchmark,
    decapsulate_benchmark,
    full_kem_benchmark,
    multiple_operations_benchmark
);
criterion_main!(benches);
