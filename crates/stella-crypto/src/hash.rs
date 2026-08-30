//! SHA-256 helpers for exact protocol byte segments.

use sha2::{Digest, Sha256};

/// Length of every SHA-256 output in bytes.
pub const SHA256_OUTPUT_LENGTH: usize = 32;

/// Hashes the ordered concatenation of `segments` with SHA-256.
///
/// No separators or lengths are inserted. Callers supply the exact unambiguous
/// protocol encoding and domain prefix required by the specification.
#[must_use]
pub fn sha256_segments(segments: &[&[u8]]) -> [u8; SHA256_OUTPUT_LENGTH] {
    let mut hasher = Sha256::new();
    for segment in segments {
        hasher.update(segment);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::sha256_segments;

    #[test]
    fn sha256_segments_matches_published_empty_vector() {
        assert_eq!(
            sha256_segments(&[b"", b""]),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn sha256_segments_is_exact_concatenation() {
        assert_eq!(
            sha256_segments(&[b"st", b"el", b"la"]),
            sha256_segments(&[b"stella"])
        );
    }
}
