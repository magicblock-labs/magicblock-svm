#![cfg(feature = "agave-unstable-api")]
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]

pub use solana_sbpf;
pub mod cpi;
pub mod deploy;
pub mod execution_budget;
pub mod invoke_context;
pub mod loaded_programs;
pub mod loading_task;
pub mod mem_pool;
pub mod memory;
pub mod memory_context;
pub mod program_cache_entry;
pub mod program_metrics;
pub mod serialization;
pub mod stable_log;
pub mod sysvar_cache;
pub mod vm;

// re-exports for macros
pub mod __private {
    pub use solana_account::ReadableAccount;
    pub use solana_hash::Hash;
    pub use solana_instruction::error::InstructionError;
    pub use solana_rent::Rent;
    pub use solana_transaction_context::transaction::TransactionContext;

    pub use crate::vm::{MEMORY_POOL, calculate_heap_cost, create_vm};
}
