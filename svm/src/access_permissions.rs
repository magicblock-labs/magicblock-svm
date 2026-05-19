use solana_account::AccountSharedData;
use solana_pubkey::Pubkey;
use solana_sdk_ids::loader_v4;
use solana_svm_transaction::svm_message::SVMMessage;
use solana_transaction_error::TransactionError;

use crate::transaction_execution_result::ExecutedTransaction;

const MAGIC_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("Magic11111111111111111111111111111111111111");
const PRIVILEGED_MAGIC_DISCRIMINANTS: [u32; 9] = [0, 8, 9, 16, 17, 18, 19, 20, 22];

// NOTE:
// this impl is kept separately to simplify synchronization with upstream
impl ExecutedTransaction {
    /// Validates that a transaction does not attempt to write to non-delegated accounts.
    ///
    /// This is a critical security check to prevent privilege escalation by ensuring
    /// account modifications are restricted to accounts explicitly delegated to the
    /// validator node.
    ///
    /// Privileged fee payers may bypass this check only for the Magic program's
    /// allowlisted control instructions.
    ///
    /// For standard, non-privileged transactions, it enforces that **any account
    /// marked as writable (excluding the fee payer) must be a delegated account.**
    ///
    /// Read-only accounts are ignored. The fee payer's writability is handled in
    /// separate validation logic.
    pub(crate) fn validate_accounts_access(&mut self, message: &impl SVMMessage) {
        if !self.was_successful() {
            return;
        }
        let accounts = &self.loaded_transaction.accounts;
        if let Some((pk, payer)) = accounts.first() {
            if payer.privileged() && has_privileged_access(message) {
                return;
            }
            if !payer.delegated() && payer.lamports_changed() {
                self.execution_details.status = Err(TransactionError::InvalidAccountForFee);
                let logs = self.execution_details.log_messages.get_or_insert_default();
                logs.push(format!(
                    "Program log: Feepayer {pk} was modified without being delegated"
                ));
                return;
            }
        }

        let mut offender = None;
        let is_mutable = |acc: &AccountSharedData| {
            acc.delegated() || acc.ephemeral() || acc.confined() || acc.undelegating()
        };
        // For non-privileged payers, validate the rest of the accounts.
        // Skip the fee payer (index 0), as its writability is validated elsewhere.
        for (i, (pk, acc)) in accounts.iter().enumerate().skip(1) {
            // Enforce that any account intended to be writable must be a delegated account.
            if message.is_writable(i) && !is_mutable(acc) {
                offender.replace((i, pk));
                break;
            }
        }
        if let Some((i, offender)) = offender {
            self.execution_details.status = Err(TransactionError::InvalidWritableAccount);
            let logs = self.execution_details.log_messages.get_or_insert_default();
            logs.push(format!(
                "Program log: Account {i}:{offender} was illegally used as writeable"
            ));
        }
    }
}

fn has_privileged_access(message: &impl SVMMessage) -> bool {
    for instruction in message.instructions_iter() {
        let Some(program) = message
            .account_keys()
            .get(instruction.program_id_index as usize)
        else {
            return false;
        };
        if *program == loader_v4::ID {
            continue;
        }
        if *program != MAGIC_PROGRAM_ID {
            return false;
        }

        let discriminant = instruction
            .data
            .get(0..4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_le_bytes)
            .unwrap_or(u32::MAX);
        if !PRIVILEGED_MAGIC_DISCRIMINANTS.contains(&discriminant) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            account_loader::LoadedTransaction, rollback_accounts::RollbackAccounts,
            transaction_execution_result::TransactionExecutionDetails,
        },
        solana_fee_structure::FeeDetails,
        solana_hash::Hash,
        solana_message::{
            compiled_instruction::CompiledInstruction, LegacyMessage, Message, MessageHeader,
            SanitizedMessage,
        },
        solana_program_runtime::execution_budget::SVMTransactionExecutionBudget,
        std::collections::{HashMap, HashSet},
    };

    fn privileged_account() -> AccountSharedData {
        let mut account = AccountSharedData::default();
        account.set_privileged(true);
        account
    }

    fn executed_transaction(payer: Pubkey, writable: Pubkey) -> ExecutedTransaction {
        ExecutedTransaction {
            loaded_transaction: LoadedTransaction {
                accounts: vec![
                    (payer, privileged_account()),
                    (writable, AccountSharedData::default()),
                    (MAGIC_PROGRAM_ID, AccountSharedData::default()),
                ],
                program_indices: vec![],
                fee_details: FeeDetails::default(),
                rollback_accounts: RollbackAccounts::default(),
                compute_budget: SVMTransactionExecutionBudget::default(),
                loaded_accounts_data_size: 0,
            },
            execution_details: TransactionExecutionDetails {
                status: Ok(()),
                log_messages: None,
                inner_instructions: None,
                return_data: None,
                executed_units: 0,
                accounts_data_len_delta: 0,
            },
            programs_modified_by_tx: HashMap::new(),
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
            &HashSet::new(),
        ))
    }

    #[test]
    fn privileged_payer_allows_magic_control_instruction() {
        let payer = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let mut tx = executed_transaction(payer, writable);
        let message = message(MAGIC_PROGRAM_ID, 8u32.to_le_bytes().to_vec());

        tx.validate_accounts_access(&message);

        assert_eq!(tx.execution_details.status, Ok(()));
    }

    #[test]
    fn privileged_payer_rejects_non_magic_write() {
        let payer = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let mut tx = executed_transaction(payer, writable);
        let message = message(Pubkey::new_unique(), 8u32.to_le_bytes().to_vec());

        tx.validate_accounts_access(&message);

        assert_eq!(
            tx.execution_details.status,
            Err(TransactionError::InvalidWritableAccount)
        );
    }

    #[test]
    fn privileged_payer_rejects_unlisted_magic_instruction() {
        let payer = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let mut tx = executed_transaction(payer, writable);
        let message = message(MAGIC_PROGRAM_ID, 1u32.to_le_bytes().to_vec());

        tx.validate_accounts_access(&message);

        assert_eq!(
            tx.execution_details.status,
            Err(TransactionError::InvalidWritableAccount)
        );
    }
}
