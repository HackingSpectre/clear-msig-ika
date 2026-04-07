use tiny_keccak::{Hasher, Keccak};

/// Compute Keccak-256 hash of input data.
///
/// Ika's `approve_message` requires the `message_hash` parameter to be
/// keccak256 of the preimage. Using any other hash would cause a PDA
/// mismatch when the network commits the signature on-chain.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}
