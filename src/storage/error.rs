use std::io;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid pack record magic")]
    InvalidMagic,

    #[error("Unsupported record version: {0}")]
    UnsupportedVersion(u16),

    #[error("Unsupported compression type: {0}")]
    UnsupportedCompression(u8),

    #[error("Invalid record length")]
    InvalidLength,

    #[error("payload checksum mismatch")]
    PayloadChecksumMismatch,

    #[error("Chunk hash mismatch")]
    ChunkHashMismatch,

    #[error("Invalid repository: {0}")]
    InvalidRepository(String),

    #[error("SQLite error: {0}")]
    Database(#[from] rusqlite::Error),
}
