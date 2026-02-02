#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#![allow(clippy::arithmetic_side_effects)]
// So we don't fix deprecated items here in order to be
// able to merge upstream changes.
#![allow(deprecated)]

mod access_permissions;
pub mod account_loader;
pub mod account_overrides;
pub mod escrow;
pub mod message_processor;
pub mod nonce_info;
pub mod program_loader;
pub mod rollback_accounts;
pub mod runtime_config;
pub mod transaction_account_state_info;
pub mod transaction_commit_result;
pub mod transaction_error_metrics;
pub mod transaction_execution_result;
pub mod transaction_processing_callback;
pub mod transaction_processing_result;
pub mod transaction_processor;

#[cfg_attr(feature = "frozen-abi", macro_use)]
#[cfg(feature = "frozen-abi")]
extern crate solana_frozen_abi_macro;
