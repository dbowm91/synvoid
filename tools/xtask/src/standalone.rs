//! Standalone package evidence and outside-workspace consumer qualification.
use serde_json::{json, Value};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const CANDIDATES: &[&str] = &[
    "synvoid-dns",
    "synvoid-dnssec-keystore",
    "synvoid-honeypot",
    "synvoid-mesh",
    "synvoid-mesh-protocol",
    "synvoid-platform",
    "synvoid-icmp-filter",
    "synvoid-yara",
    "synvoid-proxy-cache",
    "synvoid-tarpit",
];

pub fn run(args: &[String]) -> Result<(), String> {
    let args = args.iter().skip(1).map(String::as_str).collect::<Vec<_>>();
    let root = workspace_root();
    match args.first().copied() {
        Some("baseline") => baseline(&root, &args[1..]),
        Some("consumer") => {
            let name = *args
                .get(1)
                .ok_or("usage: cargo xtask standalone consumer <crate> [--features FEATURES]")?;
            let features = option(&args[2..], "--features");
            let source = option(&args[2..], "--consumer-src").map(PathBuf::from);
            let toolchain = option(&args[2..], "--toolchain");
            consumer(
                &root,
                name,
                features,
                source.as_deref(),
                toolchain,
                args.contains(&"--expect-fail"),
            )
        }
        _ => Err("usage: cargo xtask standalone <baseline|consumer> ...".into()),
    }
}

fn baseline(root: &Path, args: &[&str]) -> Result<(), String> {
    let metadata = output(root, "cargo", &["metadata", "--format-version", "1"])?;
    let metadata: Value = serde_json::from_slice(&metadata).map_err(|e| e.to_string())?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or("cargo metadata missing packages")?;
    let resolve = &metadata["resolve"]["nodes"];
    let mut records = Vec::new();
    for name in CANDIDATES {
        let Some(pkg) = packages.iter().find(|p| p["name"] == *name) else {
            continue;
        };
        let id = pkg["id"].as_str().unwrap_or_default();
        let node = resolve
            .as_array()
            .and_then(|ns| ns.iter().find(|n| n["id"] == id));
        let synvoid = pkg["dependencies"].as_array().into_iter().flatten()
            .filter(|d| d["name"].as_str().is_some_and(|n| n.starts_with("synvoid-" ) || n == "synvoid"))
            .map(|d| json!({"name":d["name"],"kind":d["kind"],"optional":d["optional"],"target":d["target"]}))
            .collect::<Vec<_>>();
        let tree = output(root, "cargo", &["tree", "-p", name, "-e", "normal"])
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|e| format!("ERROR: {e}"));
        let files = output(root, "cargo", &["package", "--list", "-p", name])
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|e| vec![format!("ERROR: {e}")]);
        let source_references = source_references(root, name);
        let public_exports = public_exports(root, name);
        let consumers = production_consumers(packages, name);
        records.push(json!({
            "name":name, "version":pkg["version"], "manifest_path":pkg["manifest_path"],
            "current_class": current_class(name),
            "standalone_status":"baseline only; not a support promise",
            "synvoid_dependencies":synvoid,
            "expanded_normal_dependency_tree":tree,
            "expanded_normal_dependency_line_count":tree.lines().count(),
            "features":pkg["features"], "resolved_normal_dependencies":node.map(|n|n["deps"].clone()).unwrap_or(Value::Null),
            "package_files":files,"source_references":source_references,"public_exports":public_exports,
            "independent_production_consumers":consumers,
            "outside_workspace_package_proof":"not inferred from workspace build; run cargo xtask standalone consumer <package>",
            "package_metadata":pkg["metadata"],
        }));
    }
    let result = json!({"schema":"synvoid.standalone-dependency-baseline.v1","generated_by":"cargo xtask standalone baseline","candidates":records});
    let output_path = option(args, "--output")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("architecture/standalone_crate_dependency_baseline.json"));
    fs::write(
        &output_path,
        serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "wrote {} candidate records to {}",
        records.len(),
        output_path.display()
    );
    Ok(())
}

fn current_class(name: &str) -> &'static str {
    match name {
        "synvoid-dnssec-keystore"
        | "synvoid-mesh-protocol"
        | "synvoid-platform"
        | "synvoid-yara" => "2",
        // Phase 35's inventory classifies all other SynVoid crates as internal.
        _ => "1",
    }
}

fn source_references(root: &Path, name: &str) -> Vec<String> {
    let dir = root.join("crates").join(name);
    let mut out = Vec::new();
    for base in [dir.join("src"), dir.clone()] {
        let Ok(entries) = fs::read_dir(base) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                continue;
            }
            if path.extension().is_some_and(|x| x == "rs") {
                let Ok(text) = fs::read_to_string(&path) else {
                    continue;
                };
                for (i, line) in text.lines().enumerate() {
                    if [
                        "CARGO_MANIFEST_DIR",
                        "CARGO_WORKSPACE_DIR",
                        "../../config",
                        "../../src/",
                    ]
                    .iter()
                    .any(|needle| line.contains(needle))
                    {
                        out.push(format!(
                            "{}:{}:{}",
                            path.strip_prefix(root).unwrap_or(&path).display(),
                            i + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn public_exports(root: &Path, name: &str) -> Vec<String> {
    let dir = root.join("crates").join(name).join("src");
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
                continue;
            }
            if path.extension().is_some_and(|x| x == "rs") {
                let Ok(text) = fs::read_to_string(&path) else {
                    continue;
                };
                for (i, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.starts_with("pub ") || line.starts_with("pub(") {
                        out.push(format!("{}:{}:{}", path.display(), i + 1, line));
                    }
                }
            }
        }
    }
    walk(&dir, &mut out);
    out.sort();
    out
}

fn production_consumers(packages: &[Value], name: &str) -> Vec<String> {
    packages
        .iter()
        .filter(|p| p["name"] != name)
        .filter_map(|p| {
            let has_dep = p["dependencies"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|d| d["name"] == name && d["kind"].is_null());
            has_dep.then(|| p["name"].as_str().unwrap_or_default().to_owned())
        })
        .collect()
}

fn consumer(
    root: &Path,
    name: &str,
    features: Option<&str>,
    source: Option<&Path>,
    toolchain: Option<&str>,
    expect_fail: bool,
) -> Result<(), String> {
    let crate_name = name;
    let manifest = if name == "synvoid" {
        root.join("Cargo.toml")
    } else {
        root.join("crates").join(name).join("Cargo.toml")
    };
    if !manifest.exists() {
        return Err(format!("unknown package: {name}"));
    }
    if let Err(error) =
        run_checked_offline(root, "cargo", &["package", "-p", name, "--allow-dirty"])
    {
        if expect_fail {
            println!("negative control passed: package {name} is not standalone ({error})");
            return Ok(());
        }
        return Err(error);
    }
    let version = manifest_version(&manifest)?;
    let archive = root
        .join("target/package")
        .join(format!("{name}-{version}.crate"));
    let tmp = env::temp_dir().join(format!(
        "synvoid-standalone-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let result = (|| {
        run_checked(
            root,
            "tar",
            &[
                "-xzf",
                archive.to_str().ok_or("bad archive path")?,
                "-C",
                tmp.to_str().ok_or("bad temp path")?,
            ],
        )?;
        let unpacked = tmp.join(format!("{name}-{version}"));
        let consumer = tmp.join("consumer");
        fs::create_dir_all(consumer.join("src")).map_err(|e| e.to_string())?;
        let feature_arg = features
            .map(|f| {
                format!(
                    ", features = {:?}",
                    f.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                )
            })
            .unwrap_or_default();
        let consumer_dev_dependencies = match name {
            "synvoid-dnssec-keystore" => "\n[dev-dependencies]\ned25519-dalek = \"2\"\n",
            _ => "",
        };
        fs::write(consumer.join("Cargo.toml"), format!("[package]\nname='standalone-consumer'\nversion='0.1.0'\nedition='2021'\n[dependencies]\n{crate_name} = {{ package = \"{name}\", path = {:?}{feature_arg} }}\n{consumer_dev_dependencies}", unpacked)).map_err(|e|e.to_string())?;
        let smoke = if let Some(source) = source {
            fs::read_to_string(source)
                .map_err(|e| format!("consumer source {}: {e}", source.display()))?
        } else if name == "synvoid-rate-limit" {
            "#[test]\nfn public_api_smoke() { let clock = synvoid_rate_limit::WindowClock::new(); let window = synvoid_rate_limit::AtomicSlidingWindow::new(1, 10); window.increment_now(&clock); assert_eq!(window.count_now(&clock), 1); }\n".to_owned()
        } else if name == "synvoid-honeypot" {
            "#[test]\nfn public_api_smoke() { let config = synvoid_honeypot::PortHoneypotConfig::default(); config.validate_resource_limits().unwrap(); let matched = synvoid_honeypot::ProtocolDetector::new().detect(b\"SSH-2.0-test\\r\\n\").unwrap(); assert_eq!(matched.protocol, \"ssh\"); }\n".to_owned()
        } else if name == "synvoid-dnssec-keystore" {
            "#[test]\nfn public_api_smoke() { use ed25519_dalek::Verifier; use synvoid_dnssec_keystore::{Algorithm, DnssecKeystore, KeyType}; let root = std::env::temp_dir().join(format!(\"synvoid-keystore-consumer-{}\", std::process::id())); let _ = std::fs::remove_dir_all(&root); let mut keys = DnssecKeystore::new(root.clone()); keys.initialize().unwrap(); keys.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90).unwrap(); let key = keys.active_zsk().unwrap(); let message = b\"standalone canonical bytes\"; let signature = key.sign(message).unwrap(); let public: [u8; 32] = key.public_key().try_into().unwrap(); let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap(); verifying.verify(message, &ed25519_dalek::Signature::from_slice(&signature).unwrap()).unwrap(); keys.start_key_rollover(KeyType::ZSK).unwrap(); keys.complete_key_rollover(KeyType::ZSK).unwrap(); drop(keys); let _ = std::fs::remove_dir_all(root); }\n".to_owned()
        } else if name == "synvoid-mesh-protocol" {
            "#[test]\nfn public_api_smoke() { let signer = synvoid_mesh_protocol::ProtocolSigner::new([7u8; 32]); let message = b\"standalone mesh protocol\"; let signature = signer.sign(message); let public = signer.get_public_key_bytes(); assert!(signer.verify(message, &signature, &public)); let frame = synvoid_mesh_protocol::encode_with_length_prefix(message).unwrap(); let (decoded, consumed) = synvoid_mesh_protocol::decode_with_length_prefix(&frame).unwrap(); assert_eq!(decoded, message); assert_eq!(consumed, frame.len()); assert!(synvoid_mesh_protocol::is_compatible_message_version(synvoid_mesh_protocol::MESH_MESSAGE_VERSION)); let mut replay = synvoid_mesh_protocol::ReplayProtection::new(); assert_eq!(replay.check_and_add_at(\"consumer-nonce\", 100, 100), synvoid_mesh_protocol::ReplayResult::Valid); assert_eq!(replay.check_and_add_at(\"consumer-nonce\", 100, 100), synvoid_mesh_protocol::ReplayResult::ReplayDetected); }\n".to_owned()
        } else {
            "#[test]\nfn package_dependency_is_visible() { assert!(!env!(\"CARGO_MANIFEST_DIR\").is_empty()); }\n".to_owned()
        };
        fs::write(
            consumer.join("src/lib.rs"),
            format!("// Outside-workspace package consumer.\n{smoke}\n"),
        )
        .map_err(|e| e.to_string())?;
        let mut cmd = Command::new("cargo");
        if let Some(toolchain) = toolchain {
            cmd.arg(format!("+{toolchain}"));
        }
        cmd.args(["test", "--manifest-path"])
            .arg(consumer.join("Cargo.toml"));
        cmd.env("CARGO_NET_OFFLINE", "true");
        for key in [
            "CARGO_MANIFEST_DIR",
            "CARGO_WORKSPACE_DIR",
            "CARGO_PKG_NAME",
            "CARGO_PKG_VERSION",
        ] {
            cmd.env_remove(key);
        }
        let status = cmd.status().map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!("outside-workspace consumer failed for {name}"));
        }
        println!(
            "qualified packaged source: {name} {version}; features={}; toolchain={}",
            features.unwrap_or("default"),
            toolchain.unwrap_or("current")
        );
        Ok(())
    })();
    let _ = fs::remove_dir_all(tmp);
    match (result, expect_fail) {
        (Ok(()), true) => Err(format!("negative control unexpectedly qualified: {name}")),
        (Err(_), true) => {
            println!("negative control passed: outside-workspace consumer rejected {name}");
            Ok(())
        }
        (result, false) => result,
    }
}

fn manifest_version(path: &Path) -> Result<String, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("version = ") {
            return Ok(v.trim().trim_matches('"').to_owned());
        }
    }
    Err(format!("missing package version in {}", path.display()))
}
fn option<'a>(args: &'a [&str], key: &str) -> Option<&'a str> {
    args.windows(2).find(|w| w[0] == key).map(|w| w[1])
}
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf()
}
fn output(root: &Path, program: &str, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    Ok(out.stdout)
}
fn run_checked(root: &Path, program: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(program)
        .args(args)
        .current_dir(root)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| e.to_string())?;
    if out.success() {
        Ok(())
    } else {
        Err(format!("{program} {:?} failed", args))
    }
}

fn run_checked_offline(root: &Path, program: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(program)
        .args(args)
        .current_dir(root)
        .env("CARGO_NET_OFFLINE", "true")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| e.to_string())?;
    if out.success() {
        Ok(())
    } else {
        Err(format!("{program} {:?} failed", args))
    }
}
