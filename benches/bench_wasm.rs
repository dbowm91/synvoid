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

/// Jail IPC round-trip overhead, isolated from WASM execution cost
/// (Phase 24 hot path). Pure in-process codec: envelope encode + framed
/// payload decode for a representative invoke pair.
fn benchmark_jail_ipc_roundtrip(c: &mut Criterion) {
    use synvoid_ipc::jail_protocol::{
        decode_request, decode_response, encode_request, encode_response, JailOperation,
        JailOutput, JailRequest, JailResponse, JailResult,
    };

    let request = JailRequest::new(
        1,
        JailOperation::WasmInvoke {
            module_id: "bench-mod".to_string(),
            method: "GET".to_string(),
            uri: "/bench".to_string(),
            headers: vec![("host".to_string(), "example.com".to_string())],
            body: b"benchmark-body".to_vec(),
        },
    );
    let response = JailResponse::new(1, JailResult::Ok(JailOutput::Pong));
    let req_frame = encode_request(&request).expect("bench request encodes");
    let res_frame = encode_response(&response).expect("bench response encodes");

    let mut group = c.benchmark_group("jail_ipc_roundtrip");
    group.bench_function("encode_request", |b| {
        b.iter(|| criterion::black_box(encode_request(&request)));
    });
    group.bench_function("decode_request", |b| {
        b.iter(|| criterion::black_box(decode_request(&req_frame[4..])));
    });
    group.bench_function("encode_response", |b| {
        b.iter(|| criterion::black_box(encode_response(&response)));
    });
    group.bench_function("decode_response", |b| {
        b.iter(|| criterion::black_box(decode_response(&res_frame[4..])));
    });
    group.finish();
}

criterion_group!(
    benches,
    benchmark_fresh_instance,
    benchmark_pooled_instance,
    benchmark_pool_vs_fresh,
    benchmark_jail_ipc_roundtrip
);
criterion_main!(benches);
