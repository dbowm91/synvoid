use std::fs::File;
use std::io::{Read, Result, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;

pub struct ZeroCopyReader {
    file: File,
    size: u64,
}

impl ZeroCopyReader {
    pub fn open(path: &std::path::Path) -> Result<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        Ok(Self { file, size })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn fd(&self) -> i32 {
        self.file.as_raw_fd()
    }

    pub fn read_to_vec(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(self.size as usize);
        let mut file = File::open(self.file.path()?)?;
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }
}

#[cfg(target_os = "linux")]
pub fn sendfile_to_socket(socket_fd: i32, file: &File, offset: u64, count: usize) -> Result<usize> {
    use std::os::unix::io::AsRawFd;

    let mut c_offset = offset as libc::off_t;
    let c_count = count as libc::size_t;

    let written = unsafe { libc::sendfile(socket_fd, file.as_raw_fd(), &mut c_offset, c_count) };

    if written < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(written as usize)
}

#[cfg(not(target_os = "linux"))]
pub fn sendfile_to_socket(
    _socket_fd: i32,
    _file: &File,
    _offset: u64,
    _count: usize,
) -> Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "sendfile not supported on this platform, use regular read/write",
    ))
}

pub trait FilePath {
    fn path(&self) -> Result<std::path::PathBuf>;
}

#[cfg(unix)]
impl FilePath for File {
    fn path(&self) -> Result<std::path::PathBuf> {
        Ok(std::path::PathBuf::from("/proc/self/fd/").join(self.as_raw_fd().to_string()))
    }
}

#[cfg(not(unix))]
impl FilePath for File {
    fn path(&self) -> Result<std::path::PathBuf> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "path() not supported on this platform",
        ))
    }
}

#[cfg(target_os = "linux")]
pub fn copy_file_range(src: &File, dst: &File, count: usize) -> Result<usize> {
    use std::os::unix::io::AsRawFd;

    let mut c_count = count as libc::size_t;

    let written = unsafe {
        libc::copy_file_range(
            src.as_raw_fd(),
            std::ptr::null_mut(),
            dst.as_raw_fd(),
            &mut c_count,
            0,
        )
    };

    if written < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(written as usize)
}

#[cfg(not(target_os = "linux"))]
pub fn copy_file_range(src: &File, dst: &File, count: usize) -> Result<usize> {
    let mut src_file = File::open(src.path()?)?;
    let mut dst_file = File::open(dst.path()?)?;

    src_file.seek(SeekFrom::Start(0))?;
    dst_file.seek(SeekFrom::Start(0))?;

    let mut buffer = vec![0u8; count];
    let read = src_file.read(&mut buffer)?;
    dst_file.write_all(&buffer[..read])?;

    Ok(read)
}
