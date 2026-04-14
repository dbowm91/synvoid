#[cfg(windows)]
pub mod wintun {
    use std::io;
    use std::io::Write;
    use std::path::PathBuf;

    const WINTUN_DLL_NAME: &str = "wintun.dll";
    const WINTUN_DLL_URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";

    pub struct WintunLoader {
        dll_path: Option<PathBuf>,
    }

    impl WintunLoader {
        pub fn new() -> Self {
            Self { dll_path: None }
        }

        pub fn find_dll() -> Option<PathBuf> {
            let possible_paths = vec![
                std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|p| p.join(WINTUN_DLL_NAME))),
                std::env::current_dir()
                    .ok()
                    .map(|p| p.join(WINTUN_DLL_NAME)),
                std::env::var_os("WINTUN_DLL_PATH").map(PathBuf::from),
            ];

            for path in possible_paths.into_iter().flatten() {
                if path.exists() {
                    tracing::info!("Found wintun.dll at: {}", path.display());
                    return Some(path);
                }
            }

            None
        }

        pub fn ensure_loaded() -> Result<libloading::Library, WintunError> {
            if let Some(path) = Self::find_dll() {
                // SAFETY: Loading a DLL via libloading is unsafe; we handle errors gracefully.
                unsafe {
                    match libloading::Library::new(&path) {
                        Ok(lib) => {
                            tracing::info!("Loaded wintun.dll from: {}", path.display());
                            return Ok(lib);
                        }
                        Err(e) => {
                            tracing::error!("Failed to load wintun.dll: {}", e);
                            return Err(WintunError::LoadFailed(e.to_string()));
                        }
                    }
                }
            }

            Err(WintunError::NotFound)
        }

        pub fn download_and_extract() -> Result<PathBuf, WintunError> {
            let temp_dir = std::env::temp_dir();
            let zip_path = temp_dir.join("wintun.zip");
            let extract_dir = temp_dir.join("wintun");

            tracing::info!("Downloading wintun.dll from: {}", WINTUN_DLL_URL);

            let url = WINTUN_DLL_URL;
            let host = url.split('/').nth(2).unwrap_or("www.wintun.net");
            let path = url
                .split(host)
                .last()
                .unwrap_or("/builds/wintun-0.14.1.zip");

            let mut stream = std::net::TcpStream::connect(format!("{}:80", host))
                .map_err(|e| WintunError::DownloadFailed(e.to_string()))?;

            stream
                .write_all(
                    format!(
                        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                        path, host
                    )
                    .as_bytes(),
                )
                .map_err(|e| WintunError::DownloadFailed(e.to_string()))?;

            let mut response = Vec::new();
            let mut buffer = [0u8; 8192];
            use std::io::Read;
            let mut stream = std::io::BufReader::new(stream);
            stream
                .read_to_end(&mut response)
                .map_err(|e| WintunError::DownloadFailed(e.to_string()))?;

            let body_start = response
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .unwrap_or(0);

            let status_line = String::from_utf8_lossy(&response[..body_start.min(100)]);
            if !status_line.contains("200") {
                return Err(WintunError::DownloadFailed(format!(
                    "HTTP error: {}",
                    status_line.lines().next().unwrap_or("unknown")
                )));
            }

            let bytes = response[body_start..].to_vec();

            std::fs::write(&zip_path, &bytes)
                .map_err(|e| WintunError::ExtractFailed(e.to_string()))?;

            if extract_dir.exists() {
                let _ = std::fs::remove_dir_all(&extract_dir);
            }
            std::fs::create_dir_all(&extract_dir)
                .map_err(|e| WintunError::ExtractFailed(e.to_string()))?;

            let file = std::fs::File::open(&zip_path)
                .map_err(|e| WintunError::ExtractFailed(e.to_string()))?;
            let mut archive = zip::ZipArchive::new(file)
                .map_err(|e| WintunError::ExtractFailed(e.to_string()))?;

            for i in 0..archive.len() {
                let mut file = archive
                    .by_index(i)
                    .map_err(|e| WintunError::ExtractFailed(e.to_string()))?;
                let outpath = extract_dir.join(file.mangled_name());

                if file.name().ends_with('/') {
                    std::fs::create_dir_all(&outpath)
                        .map_err(|e| WintunError::ExtractFailed(e.to_string()))?;
                } else {
                    if let Some(p) = outpath.parent() {
                        if !p.exists() {
                            std::fs::create_dir_all(p)
                                .map_err(|e| WintunError::ExtractFailed(e.to_string()))?;
                        }
                    }
                    let mut outfile = std::fs::File::create(&outpath)
                        .map_err(|e| WintunError::ExtractFailed(e.to_string()))?;
                    std::io::copy(&mut file, &mut outfile)
                        .map_err(|e| WintunError::ExtractFailed(e.to_string()))?;
                }
            }

            let _ = std::fs::remove_file(&zip_path);

            let arch = std::env::consts::ARCH;
            let dll_name = match arch {
                "x86_64" => "wintun.dll",
                "x86" => "wintun.dll",
                "aarch64" => "wintun.dll",
                "arm" => "wintun.dll",
                _ => return Err(WintunError::UnsupportedArch(arch.to_string())),
            };

            let dll_path = extract_dir.join(dll_name);
            if !dll_path.exists() {
                return Err(WintunError::ExtractFailed(format!(
                    "Expected wintun.dll not found at: {}",
                    dll_path.display()
                )));
            }

            let exe_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                .unwrap_or_else(|| std::env::current_dir().unwrap());

            let dest_path = exe_dir.join(WINTUN_DLL_NAME);
            std::fs::copy(&dll_path, &dest_path)
                .map_err(|e| WintunError::ExtractFailed(e.to_string()))?;

            tracing::info!("Extracted wintun.dll to: {}", dest_path.display());

            Ok(dest_path)
        }

        pub fn init() -> Result<libloading::Library, WintunError> {
            if let Some(path) = Self::find_dll() {
                // SAFETY: Loading a DLL via libloading; we check errors.
                unsafe {
                    return libloading::Library::new(&path)
                        .map_err(|e| WintunError::LoadFailed(e.to_string()));
                }
            }

            tracing::warn!("wintun.dll not found, attempting to download...");

            match Self::download_and_extract() {
                Ok(path) => unsafe {
                    // SAFETY: Loading a DLL via libloading; we check errors.
                    libloading::Library::new(&path)
                        .map_err(|e| WintunError::LoadFailed(e.to_string()))
                },
                Err(e) => {
                    tracing::error!("Failed to setup wintun: {}", e);
                    Err(e)
                }
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum WintunError {
        #[error("wintun.dll not found in any search path")]
        NotFound,

        #[error("Failed to download wintun.dll: {0}")]
        DownloadFailed(String),

        #[error("Failed to extract wintun.dll: {0}")]
        ExtractFailed(String),

        #[error("Failed to load wintun.dll: {0}")]
        LoadFailed(String),

        #[error("Unsupported architecture: {0}")]
        UnsupportedArch(String),
    }

    pub fn init() -> Result<libloading::Library, WintunError> {
        WintunLoader::init()
    }
}

#[cfg(not(windows))]
pub mod wintun {
    use std::io;

    pub struct WintunLoader;

    impl WintunLoader {
        pub fn new() -> Self {
            Self
        }

        pub fn find_dll() -> Option<std::path::PathBuf> {
            None
        }

        pub fn init() -> Result<libloading::Library, WintunError> {
            Err(WintunError::NotSupported)
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum WintunError {
        #[error("wintun is only supported on Windows")]
        NotSupported,
    }

    pub fn init() -> Result<libloading::Library, WintunError> {
        WintunLoader::init()
    }
}
