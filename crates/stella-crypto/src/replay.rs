//! Fixed-size receive replay window for authenticated packet sequences.

use crate::CryptoError;

/// Number of protected-packet sequences tracked by one receive direction.
pub const REPLAY_WINDOW_BITS: usize = 1_024;

/// Number of 64-bit bitmap words in one replay window.
pub const REPLAY_WINDOW_WORDS: usize = REPLAY_WINDOW_BITS / u64::BITS as usize;

/// Sliding replay state for one authenticated session direction.
///
/// Bit zero represents the highest committed sequence. Larger bit distances
/// represent older accepted packets. The type deliberately does not implement
/// `Clone`, preventing accidental replay-state forks.
pub struct ReplayWindow {
    highest: u64,
    seen: [u64; REPLAY_WINDOW_WORDS],
}

impl ReplayWindow {
    /// Constructs an empty replay window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            highest: 0,
            seen: [0; REPLAY_WINDOW_WORDS],
        }
    }

    /// Returns the highest authenticated sequence, or `None` while empty.
    #[must_use]
    pub const fn highest(&self) -> Option<u64> {
        if self.highest == 0 {
            None
        } else {
            Some(self.highest)
        }
    }

    /// Classifies a candidate without changing replay state.
    ///
    /// Callers may use this before AEAD verification to reject obvious replay
    /// candidates. A successful result is provisional until [`Self::commit`]
    /// succeeds after authentication.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidSequenceNumber`] for zero,
    /// [`CryptoError::DuplicateSequenceNumber`] for an already committed
    /// sequence, or [`CryptoError::SequenceNumberTooOld`] when the sequence is
    /// outside the 1,024-packet window.
    pub fn precheck(&self, sequence_number: u64) -> Result<(), CryptoError> {
        if sequence_number == 0 {
            return Err(CryptoError::InvalidSequenceNumber);
        }
        if self.highest == 0 || sequence_number > self.highest {
            return Ok(());
        }

        let distance = self.highest - sequence_number;
        if distance >= REPLAY_WINDOW_BITS as u64 {
            return Err(CryptoError::SequenceNumberTooOld {
                sequence_number,
                minimum: self.oldest_possible_sequence(),
            });
        }
        if self.bit_is_set(distance) {
            return Err(CryptoError::DuplicateSequenceNumber { sequence_number });
        }
        Ok(())
    }

    /// Commits one successfully authenticated sequence to the window.
    ///
    /// The candidate is checked again so an intervening commit cannot silently
    /// create a duplicate. Call this only after the packet tag verifies.
    ///
    /// # Errors
    ///
    /// Returns the same typed replay errors as [`Self::precheck`] and leaves
    /// the window unchanged on error.
    pub fn commit(&mut self, sequence_number: u64) -> Result<(), CryptoError> {
        self.precheck(sequence_number)?;

        if self.highest == 0 {
            self.highest = sequence_number;
            self.seen[0] = 1;
            return Ok(());
        }

        if sequence_number > self.highest {
            let advance = sequence_number - self.highest;
            self.advance(advance);
            self.highest = sequence_number;
            self.seen[0] |= 1;
            return Ok(());
        }

        let distance = self.highest - sequence_number;
        self.set_bit(distance);
        Ok(())
    }

    const fn oldest_possible_sequence(&self) -> u64 {
        self.highest.saturating_sub(REPLAY_WINDOW_BITS as u64 - 1)
    }

    fn bit_is_set(&self, distance: u64) -> bool {
        usize::try_from(distance / u64::from(u64::BITS))
            .ok()
            .and_then(|word| self.seen.get(word))
            .is_some_and(|value| value & (1_u64 << (distance % u64::from(u64::BITS))) != 0)
    }

    fn set_bit(&mut self, distance: u64) {
        let word = usize::try_from(distance / u64::from(u64::BITS));
        if let Ok(Some(value)) = word.map(|index| self.seen.get_mut(index)) {
            *value |= 1_u64 << (distance % u64::from(u64::BITS));
        }
    }

    fn advance(&mut self, distance: u64) {
        if distance >= REPLAY_WINDOW_BITS as u64 {
            self.seen.fill(0);
            return;
        }

        let Ok(word_shift) = usize::try_from(distance / u64::from(u64::BITS)) else {
            self.seen.fill(0);
            return;
        };
        let Ok(bit_shift) = u32::try_from(distance % u64::from(u64::BITS)) else {
            self.seen.fill(0);
            return;
        };
        let mut shifted = [0_u64; REPLAY_WINDOW_WORDS];

        for (source_index, source) in self.seen.iter().copied().enumerate() {
            let destination = source_index + word_shift;
            if destination >= REPLAY_WINDOW_WORDS {
                break;
            }
            shifted[destination] |= source << bit_shift;
            if bit_shift != 0 && destination + 1 < REPLAY_WINDOW_WORDS {
                shifted[destination + 1] |= source >> (u64::BITS - bit_shift);
            }
        }

        self.seen = shifted;
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ReplayWindow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReplayWindow")
            .field("highest", &self.highest())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{ReplayWindow, REPLAY_WINDOW_BITS};
    use crate::{CryptoError, PacketProtector};

    #[test]
    fn precheck_is_non_mutating_and_zero_is_always_invalid() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.highest(), None);
        assert_eq!(window.precheck(100), Ok(()));
        assert_eq!(window.highest(), None);
        assert_eq!(window.precheck(0), Err(CryptoError::InvalidSequenceNumber));
        assert_eq!(window.commit(0), Err(CryptoError::InvalidSequenceNumber));
        assert_eq!(window.highest(), None);

        assert_eq!(window.commit(10), Ok(()));
        assert_eq!(window.highest(), Some(10));
        assert_eq!(
            window.precheck(10),
            Err(CryptoError::DuplicateSequenceNumber {
                sequence_number: 10,
            })
        );
    }

    #[test]
    fn accepts_out_of_order_packets_once_within_window() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.commit(100), Ok(()));
        assert_eq!(window.commit(98), Ok(()));
        assert_eq!(window.commit(99), Ok(()));
        assert_eq!(window.highest(), Some(100));

        for sequence_number in [98, 99, 100] {
            assert_eq!(
                window.precheck(sequence_number),
                Err(CryptoError::DuplicateSequenceNumber { sequence_number })
            );
        }
        assert_eq!(window.precheck(97), Ok(()));
    }

    #[test]
    fn enforces_the_exact_1024_packet_boundary() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.commit(REPLAY_WINDOW_BITS as u64), Ok(()));
        assert_eq!(window.precheck(1), Ok(()));
        assert_eq!(window.commit(1), Ok(()));

        assert_eq!(window.commit(REPLAY_WINDOW_BITS as u64 + 1), Ok(()));
        assert_eq!(
            window.precheck(1),
            Err(CryptoError::SequenceNumberTooOld {
                sequence_number: 1,
                minimum: 2,
            })
        );
        assert_eq!(window.precheck(2), Ok(()));
    }

    #[test]
    fn shifts_seen_bits_across_word_boundaries() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.commit(1), Ok(()));
        assert_eq!(window.commit(65), Ok(()));
        assert_eq!(
            window.precheck(1),
            Err(CryptoError::DuplicateSequenceNumber { sequence_number: 1 })
        );

        assert_eq!(window.commit(66), Ok(()));
        assert_eq!(
            window.precheck(1),
            Err(CryptoError::DuplicateSequenceNumber { sequence_number: 1 })
        );
        assert_eq!(window.commit(2), Ok(()));
        assert_eq!(
            window.precheck(2),
            Err(CryptoError::DuplicateSequenceNumber { sequence_number: 2 })
        );
    }

    #[test]
    fn a_large_forward_jump_discards_the_old_bitmap() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.commit(5), Ok(()));
        assert_eq!(window.commit(10), Ok(()));
        assert_eq!(window.commit(10 + REPLAY_WINDOW_BITS as u64), Ok(()));
        assert_eq!(window.highest(), Some(1_034));
        assert_eq!(
            window.precheck(10),
            Err(CryptoError::SequenceNumberTooOld {
                sequence_number: 10,
                minimum: 11,
            })
        );
        assert_eq!(window.precheck(11), Ok(()));
        assert_eq!(
            format!("{window:?}"),
            "ReplayWindow { highest: Some(1034), .. }"
        );
    }

    #[test]
    fn failed_authentication_does_not_advance_or_mark_the_window() {
        let protector = PacketProtector::new(Zeroizing::new([0x42; 32]), [1, 2, 3, 4]);
        let mut window = ReplayWindow::new();
        let sequence_number = 500;
        assert_eq!(window.precheck(sequence_number), Ok(()));

        let mut plaintext_output = [0x5a; 8];
        assert_eq!(
            protector.open_encrypted(
                sequence_number,
                b"header",
                b"invalid!",
                &[0; 16],
                &mut plaintext_output,
            ),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(window.highest(), None);
        assert_eq!(window.precheck(sequence_number), Ok(()));
        assert_eq!(plaintext_output, [0x5a; 8]);

        let mut ciphertext = [0_u8; 8];
        let tag = protector
            .seal_encrypted(sequence_number, b"header", b"valid!!!", &mut ciphertext)
            .expect("bounded authenticated packet");
        assert_eq!(
            protector.open_encrypted(
                sequence_number,
                b"header",
                &ciphertext,
                &tag,
                &mut plaintext_output,
            ),
            Ok(8)
        );
        assert_eq!(window.commit(sequence_number), Ok(()));
        assert_eq!(
            window.precheck(sequence_number),
            Err(CryptoError::DuplicateSequenceNumber { sequence_number })
        );
    }
}
