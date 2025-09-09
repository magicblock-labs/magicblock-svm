use solana_pubkey::{pubkey, Pubkey};

// Delegation program ID used for deriving escrow-related PDAs
pub const DELEGATION_PROGRAM_ID: Pubkey = pubkey!("DELeGGvXpWV2fqJUhqcF5ZSYMS4JTLjteaAMARRSaeSh");

/// Derive the ephemeral balance PDA for a given payer and index, using the
/// delegation program ID.
pub fn ephemeral_balance_pda_from_payer(payer: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"balance", payer.as_ref(), &[0]], &DELEGATION_PROGRAM_ID).0
}
