use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use super::cpu_task::state::{CompressionTask, CpuWorkerState};
use synvoid_ipc::CpuTaskResult;
use synvoid_static_files::minifier;

pub(in crate::worker) fn process_minify_request(
    state: &CpuWorkerState,
    _request_id: u64,
    site_id: String,
    path: String,
    encoding: Option<String>,
) -> Result<CpuTaskResult, String> {
    let cache = {
        let caches = state
            .minifier_caches
            .read()
            .map_err(|_| "Cache lock poisoned".to_string())?;
        caches
            .get(&site_id)
            .cloned()
            .ok_or_else(|| format!("No cache for site: {}", site_id))?
    };

    let config = cache.config();
    let source_root = {
        let config_manager = state
            .config_manager
            .read()
            .map_err(|_| "Config lock poisoned".to_string())?;
        config_manager
            .sites
            .get(&site_id)
            .and_then(|s| s.r#static.locations.first())
            .map(|l| PathBuf::from(&l.root))
            .ok_or("No source root found".to_string())?
    };

    let source_path = source_root.join(path.trim_start_matches('/'));

    let original_content =
        std::fs::read(&source_path).map_err(|e| format!("Failed to read file: {}", e))?;

    let mtime = std::fs::metadata(&source_path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let key = minifier::CacheKey {
        site_id: Arc::from(site_id.as_str()),
        path: Arc::from(path.as_str()),
        encoding: minifier::Encoding::None,
    };

    let minified_content = match cache.get(&key) {
        Some(entry) if entry.mtime >= mtime => entry.content.to_vec(),
        _ => {
            let entry = cache
                .minify_and_cache(&site_id, &path, &original_content, mtime)
                .map_err(|e| format!("Minification failed: {}", e))?;
            if let Err(e) = cache.write_to_disk(&site_id, &path, &entry.content, mtime) {
                tracing::warn!("Failed to write minified cache to disk: {}", e);
            }
            entry.content.to_vec()
        }
    };

    let content_type = path
        .rsplit('.')
        .next()
        .and_then(|e| crate::mime::MIME_REGISTRY.read().get_mime_for_extension(e))
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let mut queued_encodings = Vec::new();

    let response_content = if let Some(ref enc) = encoding {
        match enc.as_str() {
            "gzip" => {
                let enc_key = minifier::CacheKey {
                    site_id: Arc::from(site_id.as_str()),
                    path: Arc::from(path.as_str()),
                    encoding: minifier::Encoding::Gzip,
                };

                match cache.get(&enc_key) {
                    Some(entry) => entry.content.to_vec(),
                    _ => {
                        let content = cache
                            .generate_compressed(
                                &site_id,
                                &path,
                                &minified_content,
                                &minifier::Encoding::Gzip,
                            )
                            .map_err(|e| format!("Gzip compression failed: {}", e))?;
                        if let Err(e) = cache.write_compressed_to_disk(
                            &site_id,
                            &path,
                            &content,
                            &minifier::Encoding::Gzip,
                        ) {
                            tracing::warn!("Failed to write gzip cache to disk: {}", e);
                        }
                        content.to_vec()
                    }
                }
            }
            "br" => {
                let enc_key = minifier::CacheKey {
                    site_id: Arc::from(site_id.as_str()),
                    path: Arc::from(path.as_str()),
                    encoding: minifier::Encoding::Br,
                };

                match cache.get(&enc_key) {
                    Some(entry) => entry.content.to_vec(),
                    _ => {
                        let content = cache
                            .generate_compressed(
                                &site_id,
                                &path,
                                &minified_content,
                                &minifier::Encoding::Br,
                            )
                            .map_err(|e| format!("Brotli compression failed: {}", e))?;
                        if let Err(e) = cache.write_compressed_to_disk(
                            &site_id,
                            &path,
                            &content,
                            &minifier::Encoding::Br,
                        ) {
                            tracing::warn!("Failed to write brotli cache to disk: {}", e);
                        }
                        content.to_vec()
                    }
                }
            }
            _ => minified_content,
        }
    } else {
        minified_content
    };

    if config.enable_gzip && encoding.as_ref().map(|e| e != "gzip").unwrap_or(true) {
        queued_encodings.push("gzip".to_string());
    }
    if config.enable_brotli && encoding.as_ref().map(|e| e != "br").unwrap_or(true) {
        queued_encodings.push("br".to_string());
    }

    for enc in &queued_encodings {
        let compression_task = CompressionTask {
            site_id: site_id.clone(),
            path: path.clone(),
            encoding: enc.clone(),
            queued_at: Instant::now(),
        };
        if let Ok(mut queue) = state.compression_queue.write() {
            queue.push(compression_task);
        }
    }

    Ok(CpuTaskResult::Minify {
        site_id,
        path,
        content: response_content,
        content_type,
        encoding,
        queued_encodings,
    })
}

pub(in crate::worker) fn process_compressed_request(
    state: &CpuWorkerState,
    _request_id: u64,
    site_id: String,
    path: String,
    encoding: String,
) -> Result<CpuTaskResult, String> {
    let cache = {
        let caches = state
            .minifier_caches
            .read()
            .map_err(|_| "Cache lock poisoned".to_string())?;
        caches
            .get(&site_id)
            .cloned()
            .ok_or_else(|| format!("No cache for site: {}", site_id))?
    };

    let enc = match encoding.as_str() {
        "gzip" => minifier::Encoding::Gzip,
        "br" => minifier::Encoding::Br,
        _ => return Err(format!("Unknown encoding: {}", encoding)),
    };

    let enc_key = minifier::CacheKey {
        site_id: Arc::from(site_id.as_str()),
        path: Arc::from(path.as_str()),
        encoding: enc,
    };

    let content = cache
        .get(&enc_key)
        .ok_or("Compressed version not cached".to_string())?
        .content
        .to_vec();

    Ok(CpuTaskResult::GetCompressed { content })
}

pub(in crate::worker) fn init_minifier_caches(
    state: &CpuWorkerState,
    _main_config: &crate::config::MainConfig,
) {
    let config = match state.config_manager.read() {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut caches = match state.minifier_caches.write() {
        Ok(c) => c,
        Err(_) => return,
    };

    for (site_id, site) in config.sites.iter() {
        if !caches.contains_key(site_id) && site.r#static.enable_minification.unwrap_or(true) {
            let min_config = minifier::MinifierConfig::from_site_config(site_id, &site.r#static);
            caches.insert(
                site_id.clone(),
                Arc::new(minifier::MinifierCache::new(min_config)),
            );
            tracing::info!("Initialized minifier cache for site: {}", site_id);
        }
    }
}

pub(in crate::worker) fn check_and_invalidate_cache(
    state: &CpuWorkerState,
    site_id: &str,
    root: &PathBuf,
) {
    if let Ok(caches) = state.minifier_caches.read() {
        if let Some(cache) = caches.get(site_id) {
            if let Ok(entries) = std::fs::read_dir(root) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Ok(metadata) = entry.metadata() {
                        if metadata.is_file() {
                            let relative = path
                                .strip_prefix(root)
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default();
                            let full_path = format!("/{}", relative);

                            if cache.check_and_invalidate(site_id, &full_path) {
                                tracing::debug!("Invalidated cache for {}: {}", site_id, full_path);
                            }
                        }
                    }
                }
            }
        }
    }
}

pub(in crate::worker) async fn handle_minify_request(
    state: &CpuWorkerState,
    request_id: u64,
    site_id: String,
    path: String,
    encoding: Option<String>,
) {
    let cache_result: Result<Arc<minifier::MinifierCache>, String> = {
        let guard = state.minifier_caches.read();
        match guard {
            Ok(ref c) => match c.get(&site_id).cloned() {
                Some(val) => Ok(val),
                None => Err(format!("No cache for site: {}", site_id)),
            },
            Err(_) => Err("Cache lock poisoned".to_string()),
        }
    };
    let cache = match cache_result {
        Ok(c) => c,
        Err(e) => {
            send_error(state, request_id, e).await;
            return;
        }
    };

    let config = cache.config();
    let source_root_result: Result<Option<PathBuf>, String> = {
        let guard = state.config_manager.read();
        match guard {
            Ok(ref cm) => Ok(cm
                .sites
                .get(&site_id)
                .and_then(|s| s.r#static.locations.first().map(|l| PathBuf::from(&l.root)))),
            Err(_) => Err("Config lock poisoned".to_string()),
        }
    };
    let source_root = match source_root_result {
        Ok(Some(r)) => r,
        Ok(None) => {
            send_error(state, request_id, "No source root found".to_string()).await;
            return;
        }
        Err(e) => {
            send_error(state, request_id, e).await;
            return;
        }
    };

    let source_path = source_root.join(path.trim_start_matches('/'));

    // Use spawn_blocking to run blocking file I/O in the blocking thread pool
    // (M-02) — avoids stalling the Tokio worker.
    let source_path_clone = source_path.clone();
    let file_result = tokio::task::spawn_blocking(move || {
        let read_result = std::fs::read(&source_path_clone);
        let mtime = std::fs::metadata(&source_path_clone)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        (read_result, mtime)
    })
    .await
    .unwrap_or((
        Err(std::io::Error::other("spawn_blocking failed")),
        SystemTime::UNIX_EPOCH,
    ));

    let (original_content, mtime) = match file_result {
        (Ok(content), mtime) => (content, mtime),
        (Err(e), _) => {
            send_error(state, request_id, format!("Failed to read file: {}", e)).await;
            return;
        }
    };

    let key = minifier::CacheKey {
        site_id: Arc::from(site_id.as_str()),
        path: Arc::from(path.as_str()),
        encoding: minifier::Encoding::None,
    };

    let minified_content = match cache.get(&key) {
        Some(entry) if entry.mtime >= mtime => entry.content.to_vec(),
        _ => match cache.minify_and_cache(&site_id, &path, &original_content, mtime) {
            Ok(entry) => {
                let cache_clone = cache.clone();
                let site_id_clone = site_id.clone();
                let path_clone = path.clone();
                let content = entry.content.clone();
                let write_result = tokio::task::spawn_blocking(move || {
                    cache_clone.write_to_disk(&site_id_clone, &path_clone, &content, mtime)
                })
                .await
                .unwrap_or_else(|e| {
                    Err(synvoid_static_files::minifier::MinifierError::Io(
                        std::io::Error::other(e.to_string()),
                    ))
                });
                if let Err(e) = write_result {
                    tracing::warn!("Failed to write minified file: {}", e);
                }
                entry.content.to_vec()
            }
            Err(e) => {
                send_error(state, request_id, format!("Minification failed: {}", e)).await;
                return;
            }
        },
    };

    let content_type = path
        .rsplit('.')
        .next()
        .and_then(|e| crate::mime::MIME_REGISTRY.read().get_mime_for_extension(e))
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let mut queued_encodings = Vec::new();

    let response_content = if let Some(ref enc) = encoding {
        match enc.as_str() {
            "gzip" => {
                let enc_key = minifier::CacheKey {
                    site_id: Arc::from(site_id.as_str()),
                    path: Arc::from(path.as_str()),
                    encoding: minifier::Encoding::Gzip,
                };

                match cache.get(&enc_key) {
                    Some(entry) => entry.content.to_vec(),
                    _ => {
                        match cache.generate_compressed(
                            &site_id,
                            &path,
                            &minified_content,
                            &minifier::Encoding::Gzip,
                        ) {
                            Ok(content) => {
                                let cache_clone = cache.clone();
                                let site_id_clone = site_id.clone();
                                let path_clone = path.clone();
                                let content_clone = content.clone();
                                let write_result = tokio::task::spawn_blocking(move || {
                                    cache_clone.write_compressed_to_disk(
                                        &site_id_clone,
                                        &path_clone,
                                        &content_clone,
                                        &minifier::Encoding::Gzip,
                                    )
                                })
                                .await
                                .unwrap_or_else(|e| {
                                    Err(synvoid_static_files::minifier::MinifierError::Io(
                                        std::io::Error::other(e.to_string()),
                                    ))
                                });
                                if let Err(e) = write_result {
                                    tracing::warn!("Failed to write gzip file: {}", e);
                                }
                                content.to_vec()
                            }
                            Err(e) => {
                                send_error(
                                    state,
                                    request_id,
                                    format!("Gzip compression failed: {}", e),
                                )
                                .await;
                                return;
                            }
                        }
                    }
                }
            }
            "br" => {
                let enc_key = minifier::CacheKey {
                    site_id: Arc::from(site_id.as_str()),
                    path: Arc::from(path.as_str()),
                    encoding: minifier::Encoding::Br,
                };

                match cache.get(&enc_key) {
                    Some(entry) => entry.content.to_vec(),
                    _ => {
                        match cache.generate_compressed(
                            &site_id,
                            &path,
                            &minified_content,
                            &minifier::Encoding::Br,
                        ) {
                            Ok(content) => {
                                let cache_clone = cache.clone();
                                let site_id_clone = site_id.clone();
                                let path_clone = path.clone();
                                let content_clone = content.clone();
                                let write_result = tokio::task::spawn_blocking(move || {
                                    cache_clone.write_compressed_to_disk(
                                        &site_id_clone,
                                        &path_clone,
                                        &content_clone,
                                        &minifier::Encoding::Br,
                                    )
                                })
                                .await
                                .unwrap_or_else(|e| {
                                    Err(synvoid_static_files::minifier::MinifierError::Io(
                                        std::io::Error::other(e.to_string()),
                                    ))
                                });
                                if let Err(e) = write_result {
                                    tracing::warn!("Failed to write brotli file: {}", e);
                                }
                                content.to_vec()
                            }
                            Err(e) => {
                                send_error(
                                    state,
                                    request_id,
                                    format!("Brotli compression failed: {}", e),
                                )
                                .await;
                                return;
                            }
                        }
                    }
                }
            }
            _ => minified_content,
        }
    } else {
        minified_content
    };

    if config.enable_gzip && encoding.as_ref().map(|e| e != "gzip").unwrap_or(true) {
        queued_encodings.push("gzip".to_string());
    }
    if config.enable_brotli && encoding.as_ref().map(|e| e != "br").unwrap_or(true) {
        queued_encodings.push("br".to_string());
    }

    for enc in &queued_encodings {
        let compression_task = CompressionTask {
            site_id: site_id.clone(),
            path: path.clone(),
            encoding: enc.clone(),
            queued_at: Instant::now(),
        };
        if let Ok(mut queue) = state.compression_queue.write() {
            queue.push(compression_task);
        }
    }

    let mut ipc = state.ipc.lock().await;
    let _ = ipc
        .send(&crate::process::Message::MinifyResponse {
            request_id,
            site_id,
            path,
            content: response_content,
            content_type,
            encoding,
            queued_encodings,
        })
        .await;
}

pub(super) async fn send_error(state: &CpuWorkerState, request_id: u64, error: String) {
    let mut ipc = state.ipc.lock().await;
    let _ = ipc
        .send(&crate::process::Message::MinifyError { request_id, error })
        .await;
}

pub(in crate::worker) async fn handle_compressed_request(
    state: &CpuWorkerState,
    request_id: u64,
    site_id: String,
    path: String,
    encoding: String,
) {
    let cache_result: Result<Arc<minifier::MinifierCache>, String> = {
        let guard = state.minifier_caches.read();
        match guard {
            Ok(ref c) => match c.get(&site_id).cloned() {
                Some(val) => Ok(val),
                None => Err(format!("No cache for site: {}", site_id)),
            },
            Err(_) => Err("Cache lock poisoned".to_string()),
        }
    };
    let cache = match cache_result {
        Ok(c) => c,
        Err(e) => {
            send_error(state, request_id, e).await;
            return;
        }
    };

    let enc = match encoding.as_str() {
        "gzip" => minifier::Encoding::Gzip,
        "br" => minifier::Encoding::Br,
        _ => {
            send_error(state, request_id, format!("Unknown encoding: {}", encoding)).await;
            return;
        }
    };

    let enc_key = minifier::CacheKey {
        site_id: Arc::from(site_id.as_str()),
        path: Arc::from(path.as_str()),
        encoding: enc,
    };

    let content = match cache.get(&enc_key) {
        Some(entry) => entry.content.to_vec(),
        None => {
            send_error(
                state,
                request_id,
                "Compressed version not cached".to_string(),
            )
            .await;
            return;
        }
    };

    let mut ipc = state.ipc.lock().await;
    let _ = ipc
        .send(&crate::process::Message::GetCompressedResponse {
            request_id,
            content,
        })
        .await;
}

pub(in crate::worker) fn process_compression_queue(state: &CpuWorkerState) {
    let tasks: Vec<CompressionTask> = match state.compression_queue.write() {
        Ok(mut queue) => queue.drain(..).collect(),
        Err(_) => return,
    };

    for task in tasks {
        if !state.running.is_running() {
            break;
        }

        let caches = match state.minifier_caches.read() {
            Ok(c) => c,
            Err(_) => continue,
        };

        if let Some(cache) = caches.get(&task.site_id) {
            let minified_key = minifier::CacheKey {
                site_id: Arc::from(task.site_id.as_str()),
                path: Arc::from(task.path.as_str()),
                encoding: minifier::Encoding::None,
            };

            let minified_content = match cache.get(&minified_key) {
                Some(e) => e.content.to_vec(),
                None => continue,
            };

            let enc = match task.encoding.as_str() {
                "gzip" => minifier::Encoding::Gzip,
                "br" => minifier::Encoding::Br,
                _ => continue,
            };

            match cache.generate_compressed(&task.site_id, &task.path, &minified_content, &enc) {
                Ok(content) => {
                    // Background compression queue runs off the hot request path;
                    // direct write is okay, but prefer blocking-pool when inside a
                    // runtime to keep the fix consistent with M-02. For the sync
                    // CPU-worker thread we can call directly; if we are inside a
                    // Tokio runtime we fire-and-forget via spawn_blocking.
                    let write_result = if tokio::runtime::Handle::try_current().is_ok() {
                        let cache_clone = Arc::clone(cache);
                        let site_id_clone = task.site_id.clone();
                        let path_clone = task.path.clone();
                        let content_clone = content.clone();
                        let enc_clone = enc.clone();
                        // Fire-and-forget on the blocking pool (M-02 optimization note)
                        tokio::task::spawn_blocking(move || {
                            let _ = cache_clone.write_compressed_to_disk(
                                &site_id_clone,
                                &path_clone,
                                &content_clone,
                                &enc_clone,
                            );
                        });
                        Ok::<_, synvoid_static_files::minifier::MinifierError>(
                            std::path::PathBuf::new(),
                        )
                    } else {
                        cache.write_compressed_to_disk(&task.site_id, &task.path, &content, &enc)
                    };
                    if let Err(e) = write_result {
                        tracing::warn!("Failed to write {} file: {}", task.encoding, e);
                    } else if tokio::runtime::Handle::try_current().is_err() {
                        tracing::debug!(
                            "Generated {} for {}/{}",
                            task.encoding,
                            task.site_id,
                            task.path
                        );
                    } else {
                        tracing::debug!(
                            "Queued {} generation for {}/{} on blocking pool",
                            task.encoding,
                            task.site_id,
                            task.path
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to generate {}: {}", task.encoding, e);
                }
            }
        }
    }
}
