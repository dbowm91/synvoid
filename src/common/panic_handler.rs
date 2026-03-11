pub fn setup_panic_handler(process_name: &str, log_file: Option<&str>) {
    let name = process_name.to_string();
    let log = log_file.map(|s| s.to_string());

    std::panic::set_hook(Box::new(move |panic_info| {
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };

        tracing::error!("{} PANIC at {}: {}", name, location, message);
        eprintln!(
            "\n=== {} PANIC ===\nLocation: {}\nMessage: {}\n",
            name, location, message
        );

        let panic_content = format!("{}: {}", location, message);
        if let Some(ref log_path) = log {
            let _ = std::fs::write(log_path, &panic_content);
            let _ = std::fs::set_permissions(
                log_path,
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            );
        }
        if let Some(temp_dir) = std::env::temp_dir().to_str() {
            let default_panic_path = format!(
                "{}/maluwaf-{}-panic.log",
                temp_dir,
                name.to_lowercase().replace(' ', "-")
            );
            let _ = std::fs::write(&default_panic_path, &panic_content);
            let _ = std::fs::set_permissions(
                &default_panic_path,
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            );
        }
    }));
}

pub fn setup_default_panic_handler() {
    setup_panic_handler("maluwaf", None);
}
