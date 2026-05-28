# Zero Copy Architecture

## 1. Purpose and Responsibility

The Zero Copy module (`src/zero_copy.rs`) provides **platform-specific kernel-level file-to-socket and file-to-file transfer** using sendfile(2) and copy_file_range(2) syscalls for maximum throughput.

**Core Responsibilities:**
- Kernel-level file-to-socket transfer (sendfile)
- Kernel-level file-to-file copy (copy_file_range)
- Platform-specific implementations (Linux, macOS, FreeBSD)
- Fallback to userspace I/O on unsupported platforms

---

## 2. Key Data Structures

```rust
pub struct ZeroCopyReader {
    file: File,
    size: u64,
}

pub trait FilePath {
    fn path(&self) -> Result<PathBuf>;
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `ZeroCopyReader::open(path)` | Open file for reading |
| `size()` | Get file size |
| `fd()` | Get raw file descriptor |
| `read_to_vec()` | Fallback: read to Vec |
| `sendfile_to_socket(socket_fd, file, offset, count)` | Platform-specific sendfile |
| `copy_file_range(src, dst, count)` | Platform-specific file copy |

---

## 4. Platform Implementations

### `sendfile_to_socket`
| Platform | Syscall | Notes |
|----------|---------|-------|
| Linux | `sendfile(2)` | With offset support |
| macOS | `sendfile(2)` | Different signature |
| FreeBSD | `sendfile(2)` | sf_fd parameter |
| Other | Fallback | Userspace copy |

### `copy_file_range`
| Platform | Syscall | Notes |
|----------|---------|-------|
| Linux | `copy_file_range(2)` | Kernel-space copy |
| macOS | `fcopyfile(3)` | Userspace but optimized |
| Other | Fallback | Regular I/O |

---

## 5. Integration Points

- **Static Files**: High-performance file serving
- **Proxy**: Large file transfer optimization
- **Buffer Pool**: Memory-efficient operations

---

## 6. Key Implementation Details

- **Kernel-space**: Avoids copying data through userspace
- **Zero-alloc**: No intermediate buffers needed
- **Platform-aware**: Compile-time platform selection
- **Graceful Fallback**: Regular I/O when kernel support unavailable
- **Offset Support**: Supports partial file transfers
