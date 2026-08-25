use std::collections::HashMap;

pub struct DnsMessageCompressor {
    labels: HashMap<String, u16>,
    current_offset: usize,
}

impl DnsMessageCompressor {
    pub fn new() -> Self {
        Self {
            labels: HashMap::new(),
            current_offset: 12,
        }
    }

    pub fn reset(&mut self) {
        self.labels.clear();
        self.current_offset = 12;
    }

    pub fn add_label(&mut self, label: &str, offset: u16) {
        self.labels.insert(label.to_lowercase(), offset);
    }

    pub fn compress_name(&mut self, name: &str, output: &mut Vec<u8>) -> usize {
        let name = name.trim_end_matches('.');

        if name.is_empty() {
            output.push(0);
            self.current_offset += 1;
            return 1;
        }

        if let Some(&offset) = self.labels.get(&name.to_lowercase()) {
            output.push(0xC0 | (offset >> 8) as u8);
            output.push((offset & 0xFF) as u8);
            self.current_offset += 2;
            return 2;
        }

        let parts: Vec<&str> = name.split('.').collect();
        let compression_start = (0..parts.len()).find(|&i| {
            self.labels
                .contains_key(&parts[i..].join(".").to_lowercase())
        });
        let literal_end = compression_start.unwrap_or(parts.len());
        let mut written = 0;

        for i in 0..literal_end {
            let suffix = parts[i..].join(".").to_lowercase();
            self.labels
                .entry(suffix)
                .or_insert(self.current_offset as u16);
            let part = parts[i];
            output.push(part.len() as u8);
            output.extend_from_slice(part.as_bytes());
            written += 1 + part.len();
            self.current_offset += 1 + part.len();
        }

        if let Some(i) = compression_start {
            let offset = self.labels[&parts[i..].join(".").to_lowercase()];
            output.push(0xC0 | (offset >> 8) as u8);
            output.push((offset & 0xFF) as u8);
            self.current_offset += 2;
            written += 2;
        } else {
            output.push(0);
            self.current_offset += 1;
            written += 1;
        }

        written
    }

    pub fn build_compressed_name(&mut self, name: &str, output: &mut Vec<u8>) {
        let _ = self.compress_name(name, output);
    }
}

impl Default for DnsMessageCompressor {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DnsMessageDecompressor {
    max_jumps: usize,
}

impl DnsMessageDecompressor {
    pub fn new() -> Self {
        Self { max_jumps: 10 }
    }

    pub fn decompress_name(&self, data: &[u8], mut pos: usize) -> Result<String, String> {
        if pos >= data.len() {
            return Err("Position out of bounds".to_string());
        }

        let mut result = Vec::new();
        let mut jumps = 0;
        let mut jumped = false;
        let mut initial_offset = 0;

        loop {
            if jumps > self.max_jumps {
                return Err("Too many compression jumps".to_string());
            }

            if pos >= data.len() {
                return Err("End of data".to_string());
            }

            let len = data[pos] as usize;

            if len == 0 {
                break;
            }

            if (len & 0xC0) == 0xC0 {
                if pos + 1 >= data.len() {
                    return Err("Invalid compression pointer".to_string());
                }

                let offset = (len & 0x3F) << 8 | data[pos + 1] as usize;

                if !jumped {
                    jumped = true;
                    initial_offset = pos + 2;
                }

                pos = offset;
                jumps += 1;
                continue;
            }

            if pos + 1 + len > data.len() {
                return Err("Label extends beyond data".to_string());
            }

            if !result.is_empty() {
                result.push(b'.');
            }

            result.extend_from_slice(&data[pos + 1..pos + 1 + len]);
            pos += 1 + len;
        }

        let name = String::from_utf8_lossy(&result).to_string();

        if jumped {
            if initial_offset > 0 && initial_offset < data.len() && data[initial_offset] != 0 {
                let prefix = self.decompress_name(data, initial_offset)?;
                Ok(format!("{}.{}", name, prefix))
            } else {
                Ok(name)
            }
        } else {
            Ok(name)
        }
    }

    pub fn decompress_name_in_place(
        &self,
        data: &[u8],
        start_pos: usize,
    ) -> Result<(String, usize), String> {
        let mut result = Vec::new();
        let mut pos = start_pos;
        let mut jumps = 0;

        loop {
            if jumps > self.max_jumps {
                return Err("Too many jumps".to_string());
            }

            if pos >= data.len() {
                return Err("Out of bounds".to_string());
            }

            let len = data[pos] as usize;

            if len == 0 {
                if !result.is_empty() {
                    result.push(0);
                }
                pos += 1;
                break;
            }

            if (len & 0xC0) == 0xC0 {
                if pos + 1 >= data.len() {
                    return Err("Invalid pointer".to_string());
                }

                let offset = (len & 0x3F) << 8 | data[pos + 1] as usize;

                if offset >= pos {
                    return Err("Compression pointer must point backwards".to_string());
                }

                pos = offset;
                jumps += 1;
                continue;
            }

            if pos + 1 + len > data.len() {
                return Err("Invalid label".to_string());
            }

            if !result.is_empty() {
                result.push(b'.');
            }

            result.extend_from_slice(&data[pos + 1..pos + 1 + len]);
            pos += 1 + len;
        }

        Ok((String::from_utf8_lossy(&result).to_string(), pos))
    }
}

impl Default for DnsMessageDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compressor_basic() {
        let mut compressor = DnsMessageCompressor::new();

        compressor.add_label("example.com", 12);

        let mut output = Vec::new();
        compressor.compress_name("example.com", &mut output);

        assert_eq!(output, vec![0xC0, 0x0C]);
    }

    #[test]
    fn test_compressor_preserves_case_and_writes_label_length() {
        let mut compressor = DnsMessageCompressor::new();
        compressor.add_label("example.com", 12);

        let mut output = Vec::new();
        compressor.compress_name("WWW.Example.COM", &mut output);

        assert_eq!(output, vec![3, b'W', b'W', b'W', 0xC0, 0x0C]);
    }

    #[test]
    fn test_compressor_registers_correct_multi_label_suffixes() {
        let mut compressor = DnsMessageCompressor::new();
        let mut first = Vec::new();
        compressor.compress_name("a.example.com", &mut first);

        let mut second = Vec::new();
        compressor.compress_name("b.example.com", &mut second);

        assert_eq!(
            first,
            vec![1, b'a', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]
        );
        assert_eq!(second, vec![1, b'b', 0xC0, 0x0E]);
    }

    #[test]
    fn test_decompressor_basic() {
        let data = vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        ];
        let decompressor = DnsMessageDecompressor::new();

        let result = decompressor.decompress_name(&data, 0).unwrap();
        assert_eq!(result, "example.com");
    }

    #[test]
    fn test_decompressor_with_pointer() {
        let data = vec![
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
            // www.example.com - starts at position 13
            0x03, b'w', b'w', b'w', 0xC0, 0x00,
        ];
        let decompressor = DnsMessageDecompressor::new();

        // Position 13: 0x03 (len=3), 0x77,0x77,0x77 ("www"), 0xC0,0x00 (pointer to pos 0)
        let result = decompressor.decompress_name(&data, 13).unwrap();
        assert_eq!(result, "www.example.com");
    }
}
