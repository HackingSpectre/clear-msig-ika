//! Vendored copy of the Quasar-auto-generated instruction structs.
//!
//! These are produced by `quasar build` into
//! `target/client/rust/clear-wallet-client/src/instructions/`. We can't depend
//! on that crate directly because it has the same package name as the
//! workspace's `clear-wallet-client`, so we copy the files in here. Re-run
//! `quasar build` and re-copy if the program's instruction signatures change.

use solana_address::Address;

/// Program ID — kept in sync with `clear_wallet_client::ID` so the generated
/// `From` impls (which reference `crate::ID`) resolve to the right address.
pub use clear_wallet_client::ID;

pub mod approve;
pub mod bind_dwallet;
pub mod create_wallet;
pub mod execute;
pub mod ika_sign;
pub mod propose;

#[allow(dead_code)]
fn _ensure_id_in_scope() {
    let _: Address = ID;
}
