use solana_account::AccountSharedData;
use solana_pubkey::Pubkey;
use solana_svm_transaction::svm_message::SVMMessage;
use solana_transaction_error::TransactionError;

use crate::account_loader::LoadedTransaction;

const MAGIC_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("Magic11111111111111111111111111111111111111");
const PRIVILEGED_MAGIC_DISCRIMINANTS: [u32; 9] = [0, 8, 9, 16, 17, 18, 19, 20, 22];

// NOTE:
// this impl is kept separately to simplify synchronization with upstream
impl LoadedTransaction {
    /// Validates that a transaction does not attempt to write to non-delegated accounts.
    ///
    /// This is a critical security check to prevent privilege escalation by ensuring
    /// account modifications are restricted to accounts explicitly delegated to the
    /// validator node.
    ///
    /// Privileged fee payers may bypass this check only for the Magic program's
    /// allowlisted control instructions.
    ///
    /// For standard, non-privileged transactions, it enforces that any account
    /// marked as writable (excluding the fee payer) must be either:
    /// 1. delegated
    /// 2. undelegating
    /// 3. ephemeral
    /// 4. confined
    ///
    /// Read-only accounts are ignored. The fee payer's writability is handled in
    /// separate validation logic.
    pub(crate) fn validate_accounts_access(
        &self,
        message: &impl SVMMessage,
    ) -> Result<(), (TransactionError, Pubkey)> {
        let payer = self.accounts.first().map(|(_, acc)| acc);
        let mut privileged = payer.is_some_and(AccountSharedData::privileged);
        if privileged {
            for i in message.instructions_iter() {
                let Some(program) = message.account_keys().get(i.program_id_index as usize) else {
                    privileged = false;
                    break;
                };
                if *program != MAGIC_PROGRAM_ID {
                    privileged = false;
                    break;
                }
                let discriminant = i
                    .data
                    .get(0..4)
                    .and_then(|b| <[u8; 4]>::try_from(b).ok())
                    .map(u32::from_le_bytes)
                    .unwrap_or(u32::MAX);
                if !PRIVILEGED_MAGIC_DISCRIMINANTS.contains(&discriminant) {
                    privileged = false;
                    break;
                }
            }
        }
        if privileged {
            return Ok(());
        }

        let mutation_allowed = |acc: &AccountSharedData| {
            acc.delegated() || acc.undelegating() || acc.ephemeral() || acc.confined()
        };

        // For non-privileged payers, validate the rest of the accounts.
        // Skip the fee payer (index 0), as its writability is validated elsewhere.
        for (i, (pk, acc)) in self.accounts.iter().enumerate().skip(1) {
            if message.is_writable(i) && !mutation_allowed(acc) {
                return Err((TransactionError::InvalidWritableAccount, *pk));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{account_loader::LoadedTransaction, rollback_accounts::RollbackAccounts},
        solana_account::{
            test_utils::{create_borrowed_account_shared_data, BorrowedAccountBufferArea},
            AccountSharedData,
        },
        solana_compute_budget::compute_budget_limits::ComputeBudgetLimits,
        solana_fee_structure::FeeDetails,
        solana_hash::Hash,
        solana_message::{
            compiled_instruction::CompiledInstruction, LegacyMessage, Message, MessageHeader,
            SanitizedMessage,
        },
        solana_rent_debits::RentDebits,
        solana_reserved_account_keys::ReservedAccountKeys,
    };

    fn privileged_account() -> (BorrowedAccountBufferArea, AccountSharedData) {
        let account = AccountSharedData::default();
        let (buffer, mut account) = create_borrowed_account_shared_data(&account, 0);
        account.as_borrowed_mut().unwrap().set_privileged(true);
        (buffer, account)
    }

    fn loaded_transaction(
        payer: Pubkey,
        payer_account: AccountSharedData,
        writable: Pubkey,
    ) -> LoadedTransaction {
        LoadedTransaction {
            accounts: vec![
                (payer, payer_account),
                (writable, AccountSharedData::default()),
                (MAGIC_PROGRAM_ID, AccountSharedData::default()),
            ],
            program_indices: vec![],
            fee_details: FeeDetails::default(),
            rollback_accounts: RollbackAccounts::default(),
            compute_budget_limits: ComputeBudgetLimits::default(),
            rent: 0,
            rent_debits: RentDebits::default(),
            loaded_accounts_data_size: 0,
        }
    }

    fn message(program: Pubkey, data: Vec<u8>) -> SanitizedMessage {
        SanitizedMessage::Legacy(LegacyMessage::new(
            Message {
                account_keys: vec![Pubkey::new_unique(), Pubkey::new_unique(), program],
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: 1,
                },
                instructions: vec![CompiledInstruction {
                    program_id_index: 2,
                    accounts: vec![1],
                    data,
                }],
                recent_blockhash: Hash::default(),
            },
            &ReservedAccountKeys::empty_key_set(),
        ))
    }

    #[test]
    fn privileged_payer_allows_magic_control_instruction() {
        let payer = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let (_buffer, payer_account) = privileged_account();
        let tx = loaded_transaction(payer, payer_account, writable);
        let message = message(MAGIC_PROGRAM_ID, 8u32.to_le_bytes().to_vec());

        assert_eq!(tx.validate_accounts_access(&message), Ok(()));
    }

    #[test]
    fn privileged_payer_rejects_non_magic_write() {
        let payer = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let (_buffer, payer_account) = privileged_account();
        let tx = loaded_transaction(payer, payer_account, writable);
        let message = message(Pubkey::new_unique(), 8u32.to_le_bytes().to_vec());

        assert_eq!(
            tx.validate_accounts_access(&message),
            Err((TransactionError::InvalidWritableAccount, writable))
        );
    }

    #[test]
    fn privileged_payer_rejects_unlisted_magic_instruction() {
        let payer = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let (_buffer, payer_account) = privileged_account();
        let tx = loaded_transaction(payer, payer_account, writable);
        let message = message(MAGIC_PROGRAM_ID, 1u32.to_le_bytes().to_vec());

        assert_eq!(
            tx.validate_accounts_access(&message),
            Err((TransactionError::InvalidWritableAccount, writable))
        );
    }
}
