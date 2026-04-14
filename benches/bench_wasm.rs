use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use wasmtime::{Engine, Instance, Linker, Module, Store};

const TEST_WASM: &str = r#"
    (module
        (func (export "filter_request") (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
            (i32.const 0)
        )
        (func (export "handle_request") (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
            (i32.const 0)
        )
        (memory (export "memory") 1)
    )
"#;

fn compile_module(engine: &Engine) -> Module {
    Module::new(engine, TEST_WASM).expect("failed to compile module")
}

fn benchmark_fresh_instance(c: &mut Criterion) {
    let engine = Arc::new(Engine::default());
    let module = compile_module(&engine);

    c.benchmark_group("wasm_fresh_instance")
        .bench_function("instantiate_and_call", |b| {
            b.iter(|| {
                let mut store = Store::new(&engine, ());
                let linker = Linker::new(&engine);
                let instance = linker
                    .instantiate(&mut store, &module)
                    .expect("failed to instantiate");
                let func = instance
                    .get_typed_func::<(i32, i32, i32, i32, i32, i32, i32, i32), i32>(
                        &mut store,
                        "filter_request",
                    )
                    .expect("failed to get func");
                func.call(&mut store, (0, 0, 0, 0, 0, 0, 0, 0))
                    .expect("call failed")
            });
        });
}

struct PooledInstance {
    instance: Instance,
    store: Store<()>,
}

fn create_pool(engine: &Engine) -> Vec<PooledInstance> {
    let module = compile_module(engine);
    (0..10)
        .map(|_| {
            let mut store = Store::new(engine, ());
            let linker = Linker::new(engine);
            let instance = linker
                .instantiate(&mut store, &module)
                .expect("failed to instantiate");
            PooledInstance { instance, store }
        })
        .collect()
}

fn benchmark_pooled_instance(c: &mut Criterion) {
    let engine = Arc::new(Engine::default());
    let mut pool = create_pool(&engine);
    let pool_len = pool.len();

    c.benchmark_group("wasm_pooled_instance")
        .bench_function("get_from_pool_and_call", |b| {
            let mut index = 0usize;
            b.iter(|| {
                let pooled = &mut pool[index % pool_len];
                let func = pooled
                    .instance
                    .get_typed_func::<(i32, i32, i32, i32, i32, i32, i32, i32), i32>(
                        &mut pooled.store,
                        "filter_request",
                    )
                    .expect("failed to get func");
                let result = func
                    .call(&mut pooled.store, (0, 0, 0, 0, 0, 0, 0, 0))
                    .expect("call failed");
                index += 1;
                result
            });
        });
}

fn benchmark_pool_vs_fresh(c: &mut Criterion) {
    let engine = Arc::new(Engine::default());
    let module = compile_module(&engine);
    let mut pool = create_pool(&engine);
    let pool_len = pool.len();

    let mut group = c.benchmark_group("wasm_pool_vs_fresh");
    group.bench_function("fresh_instantiate", |b| {
        b.iter(|| {
            let mut store = Store::new(&engine, ());
            let linker = Linker::new(&engine);
            let instance = linker
                .instantiate(&mut store, &module)
                .expect("failed to instantiate");
            instance
                .get_typed_func::<(i32, i32, i32, i32, i32, i32, i32, i32), i32>(
                    &mut store,
                    "filter_request",
                )
                .expect("failed to get func")
                .call(&mut store, (0, 0, 0, 0, 0, 0, 0, 0))
                .expect("call failed")
        });
    });

    group.bench_function("pool_reuse", |b| {
        let mut index = 0usize;
        b.iter(|| {
            let pooled = &mut pool[index % pool_len];
            let func = pooled
                .instance
                .get_typed_func::<(i32, i32, i32, i32, i32, i32, i32, i32), i32>(
                    &mut pooled.store,
                    "filter_request",
                )
                .expect("failed to get func");
            let result = func
                .call(&mut pooled.store, (0, 0, 0, 0, 0, 0, 0, 0))
                .expect("call failed");
            index += 1;
            result
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_fresh_instance,
    benchmark_pooled_instance,
    benchmark_pool_vs_fresh
);
criterion_main!(benches);
