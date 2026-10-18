use super::error::StorageError;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

const MAGIC: &[u8; 8] = b"BITPACK1";
const VERSION: u16 = 1;
const HEADER_SIZE: usize = 92;
const MAX_PAYLOAD_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct ChunkRecord {
    pub chunk_hash: [u8; 32],
    pub payload: Vec<u8>,
}

impl ChunkRecord {
    pub fn new(payload: Vec<u8>) -> Self {
        let chunk_hash: [u8; 32] = Sha256::digest(&payload).into();

        Self {
            chunk_hash,
            payload,
        }
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), StorageError> {
        let stored_len = self.payload.len() as u64;

        if stored_len > MAX_PAYLOAD_SIZE {
            return Err(StorageError::InvalidLength);
        }

        let original_len = stored_len;
        let payload_checksum: [u8; 32] = Sha256::digest(&self.payload).into();

        //reject an inconsistent in-memory record
        let actual_hash: [u8; 32] = Sha256::digest(&self.payload).into();

        if actual_hash != self.chunk_hash {
            return Err(StorageError::ChunkHashMismatch);
        }

        writer.write_all(MAGIC)?;
        writer.write_all(&VERSION.to_le_bytes())?;
        writer.write_all(&[0])?; // Raw compression
        writer.write_all(&[0])?; // Reserved
        writer.write_all(&original_len.to_le_bytes())?;
        writer.write_all(&stored_len.to_le_bytes())?;
        writer.write_all(&self.chunk_hash)?;
        writer.write_all(&payload_checksum)?;
        writer.write_all(&self.payload)?;

        Ok(())
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, StorageError> {
        let mut header = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header)?;

        if &header[0..8] != MAGIC {
            return Err(StorageError::InvalidMagic);
        }

        let version = u16::from_le_bytes([header[8], header[9]]);

        if version != VERSION {
            return Err(StorageError::UnsupportedVersion(version));
        }

        let compression = header[10];

        if compression != 0 {
            return Err(StorageError::UnsupportedCompression(compression));
        }

        if header[11] != 0 {
            return Err(StorageError::InvalidLength);
        }

        let original_len = u64::from_le_bytes(header[12..20].try_into().unwrap());

        let stored_len = u64::from_le_bytes(header[20..28].try_into().unwrap());

        if original_len != stored_len || stored_len > MAX_PAYLOAD_SIZE {
            return Err(StorageError::InvalidLength);
        }

        let chunk_hash: [u8; 32] = header[28..60].try_into().unwrap();

        let expected_checksum: [u8; 32] = header[60..92].try_into().unwrap();

        let mut payload = vec![0u8; stored_len as usize];
        reader.read_exact(&mut payload)?;

        let actual_checksum: [u8; 32] = Sha256::digest(&payload).into();

        if actual_checksum != expected_checksum {
            return Err(StorageError::PayloadChecksumMismatch);
        }

        let actual_chunk_hash: [u8; 32] = Sha256::digest(&payload).into();

        if actual_chunk_hash != chunk_hash {
            return Err(StorageError::ChunkHashMismatch);
        }

        Ok(Self {
            chunk_hash,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trip() {
        let original = ChunkRecord::new(b"Bit Backup test payload".to_vec());

        let mut encoded = Vec::new();
        original.write_to(&mut encoded).unwrap();

        let mut encoded = Vec::new();
        original.write_to(&mut encoded).unwrap();

        let mut input = encoded.as_slice();
        let decoded = ChunkRecord::read_from(&mut input).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn detects_corrupted_payload() {
        let original = ChunkRecord::new(b"tesst payload".to_vec());

        let mut encoded = Vec::new();
        original.write_to(&mut encoded).unwrap();

        //header is 92 bytes; corrupt the first payload
        encoded[HEADER_SIZE] ^= 0xFF;

        let mut input = encoded.as_slice();

        assert!(matches!(
            ChunkRecord::read_from(&mut input),
            Err(StorageError::PayloadChecksumMismatch)
        ));
    }
}
