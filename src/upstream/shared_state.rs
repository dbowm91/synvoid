use memmap2::{MmapMut, MmapOptions};
use parking_lot::RwLock;
use std::fs::OpenOptions;
use std::sync::atomic::AtomicUsize;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

pub static GLOBAL_SHARED_CONNECTION_TABLE: LazyLock<RwLock<Option<SharedConnectionTable>>> =
    LazyLock::new(|| RwLock::new(None));

pub struct SharedConnectionTable {
    mmap: Arc<MmapMut>,
    size: usize,
}

impl SharedConnectionTable {
    pub fn init_global(path: PathBuf, entries: usize) -> std::io::Result<()> {
        let table = Self::new(path, entries)?;
        let mut global = GLOBAL_SHARED_CONNECTION_TABLE.write();
        *global = Some(table);
        Ok(())
    }

    pub fn get_global() -> Option<SharedConnectionTable> {
        GLOBAL_SHARED_CONNECTION_TABLE.read().as_ref().cloned()
    }
    pub fn new(path: PathBuf, entries: usize) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;
        
        let byte_size = entries * std::mem::size_of::<AtomicUsize>();
        file.set_len(byte_size as u64)?;
        
        let mmap = unsafe { MmapOptions::new().map_mut(&file)? };
        
        Ok(Self { 
            mmap: Arc::new(mmap), 
            size: entries 
        })
    }

    pub fn get_counter(&self, index: usize) -> Option<&AtomicUsize> {
        if index >= self.size {
            return None;
        }
        // SAFETY: The mmap is alive as long as SharedConnectionTable is alive.
        // We are accessing a fixed-size table of AtomicUsize.
        let ptr = self.mmap.as_ptr() as *const AtomicUsize;
        Some(unsafe { &*ptr.add(index) })
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

impl Clone for SharedConnectionTable {
    fn clone(&self) -> Self {
        Self {
            mmap: self.mmap.clone(),
            size: self.size,
        }
    }
}
