use solana_account::AccountSharedData;
use solana_pubkey::Pubkey;
use solana_sdk_ids::loader_v4;
use solana_svm_transaction::{instruction::SVMInstruction, svm_message::SVMMessage};
use solana_transaction_error::TransactionError;

use crate::transaction_execution_result::ExecutedTransaction;

const MAGIC_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("Magic11111111111111111111111111111111111111");
const POST_DELEGATION_ACTION_EXECUTOR_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("PostAct111111111111111111111111111111111111");
const PRIVILEGED_MAGIC_DISCRIMINANTS: [u32; 11] = [0, 8, 9, 16, 17, 18, 19, 20, 21, 22, 24];
const CLONE_ACCOUNT_DISCRIMINANT: u32 = 16;
const CLONE_ACCOUNT_CONTINUE_DISCRIMINANT: u32 = 18;
const CLONED_ACCOUNT_INSTRUCTION_ACCOUNT_INDEX: usize = 1;

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
        let mut access = PrivilegedAccess::None;
        if let Some((pk, payer)) = accounts.first() {
            if payer.privileged() {
                access = privileged_access(message);
            }
            if access == PrivilegedAccess::Full {
                return;
            }
            if !access.allows_fee_payer_write() && !payer.delegated() && payer.lamports_changed() {
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
            if message.is_writable(i) && !is_mutable(acc) && !access.allows_account_write(i) {
                offender.replace((i, pk));
                break;
            }
        }
        if let Some((i, offender)) = offender {
            self.execution_details.status = Err(TransactionError::InvalidWritableAccount);
            let logs = self.execution_details.log_messages.get_or_insert_default();
            logs.push(format!(
                "Program log: Account {i}: {offender} was illegally used as writable"
            ));
            logs.push(
                "Program Magic11111111111111111111111111111111111111 failed: InvalidWritableAccount"
                    .to_string(),
            );
        }
    }
}

#[derive(PartialEq)]
enum PrivilegedAccess {
    None,
    Full,
    CloneWithPostDelegationActionExecutor { cloned_account: usize },
}

impl PrivilegedAccess {
    fn allows_fee_payer_write(&self) -> bool {
        matches!(
            self,
            PrivilegedAccess::Full | PrivilegedAccess::CloneWithPostDelegationActionExecutor { .. }
        )
    }

    fn allows_account_write(&self, index: usize) -> bool {
        match self {
            PrivilegedAccess::CloneWithPostDelegationActionExecutor { cloned_account } => {
                *cloned_account == index
            }
            PrivilegedAccess::Full => true,
            PrivilegedAccess::None => false,
        }
    }
}

fn privileged_access(message: &impl SVMMessage) -> PrivilegedAccess {
    let is_post_action = message
        .program_instructions_iter()
        .zip(&[MAGIC_PROGRAM_ID, POST_DELEGATION_ACTION_EXECUTOR_PROGRAM_ID])
        .all(|(ix, prog)| ix.0 == prog);
    if message.num_instructions() == 2 && is_post_action {
        return clone_with_post_delegation_action_executor_access(message);
    }

    for (program, instruction) in message.program_instructions_iter() {
        if *program == loader_v4::ID {
            continue;
        }
        if *program != MAGIC_PROGRAM_ID {
            return PrivilegedAccess::None;
        }

        let discriminant = instruction_discriminant(&instruction).unwrap_or(u32::MAX);
        if !PRIVILEGED_MAGIC_DISCRIMINANTS.contains(&discriminant) {
            return PrivilegedAccess::None;
        }
    }
    PrivilegedAccess::Full
}

fn clone_with_post_delegation_action_executor_access(
    message: &impl SVMMessage,
) -> PrivilegedAccess {
    let mut instructions = message.instructions_iter();
    let Some(ix1) = instructions.next() else {
        return PrivilegedAccess::None;
    };
    let Some(ix2) = instructions.next() else {
        return PrivilegedAccess::None;
    };
    const ALLOWED_IXS: [u32; 2] = [
        CLONE_ACCOUNT_DISCRIMINANT,
        CLONE_ACCOUNT_CONTINUE_DISCRIMINANT,
    ];
    if instruction_discriminant(&ix1)
        .map(|d| !ALLOWED_IXS.contains(&d))
        .unwrap_or(true)
    {
        return PrivilegedAccess::None;
    };

    let Some(cloned_account) = ix1
        .accounts
        .get(CLONED_ACCOUNT_INSTRUCTION_ACCOUNT_INDEX)
        .copied()
    else {
        return PrivilegedAccess::None;
    };
    if ix2
        .accounts
        .get(CLONED_ACCOUNT_INSTRUCTION_ACCOUNT_INDEX)
        .map(|&acc| acc != cloned_account)
        .unwrap_or(true)
    {
        return PrivilegedAccess::None;
    }

    PrivilegedAccess::CloneWithPostDelegationActionExecutor {
        cloned_account: cloned_account as usize,
    }
}

fn instruction_discriminant(instruction: &SVMInstruction<'_>) -> Option<u32> {
    instruction
        .data
        .get(0..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
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
        executed_transaction_with_writable_accounts(payer, vec![writable])
    }

    fn executed_transaction_with_writable_accounts(
        payer: Pubkey,
        writable_accounts: Vec<Pubkey>,
    ) -> ExecutedTransaction {
        let mut accounts = vec![(payer, privileged_account())];
        accounts.extend(
            writable_accounts
                .into_iter()
                .map(|pubkey| (pubkey, AccountSharedData::default())),
        );
        accounts.push((MAGIC_PROGRAM_ID, AccountSharedData::default()));
        accounts.push((
            POST_DELEGATION_ACTION_EXECUTOR_PROGRAM_ID,
            AccountSharedData::default(),
        ));

        ExecutedTransaction {
            loaded_transaction: LoadedTransaction {
                accounts,
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

    fn message_with_programs(instructions: Vec<(Pubkey, Vec<u8>)>) -> SanitizedMessage {
        message_with_program_accounts(
            1,
            instructions
                .into_iter()
                .map(|(program, data)| (program, data, vec![0, 1]))
                .collect(),
        )
    }

    fn message_with_program_accounts(
        num_writable_accounts: u8,
        instructions: Vec<(Pubkey, Vec<u8>, Vec<u8>)>,
    ) -> SanitizedMessage {
        let mut account_keys = vec![Pubkey::new_unique()];
        account_keys.extend((0..num_writable_accounts).map(|_| Pubkey::new_unique()));
        let program_id_start = account_keys.len();
        account_keys.extend(instructions.iter().map(|(program, _, _)| *program));

        SanitizedMessage::Legacy(LegacyMessage::new(
            Message {
                account_keys,
                header: MessageHeader {
                    num_required_signatures: 1,
                    num_readonly_signed_accounts: 0,
                    num_readonly_unsigned_accounts: instructions.len() as u8,
                },
                instructions: instructions
                    .into_iter()
                    .enumerate()
                    .map(|(idx, (_, data, accounts))| CompiledInstruction {
                        program_id_index: (program_id_start + idx) as u8,
                        accounts,
                        data,
                    })
                    .collect(),
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
    fn privileged_payer_allows_clone_with_post_delegation_action_executor() {
        let payer = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let mut tx = executed_transaction(payer, writable);
        let message = message_with_programs(vec![
            (
                MAGIC_PROGRAM_ID,
                CLONE_ACCOUNT_DISCRIMINANT.to_le_bytes().to_vec(),
            ),
            (POST_DELEGATION_ACTION_EXECUTOR_PROGRAM_ID, vec![]),
        ]);

        tx.validate_accounts_access(&message);

        assert_eq!(tx.execution_details.status, Ok(()));
    }

    #[test]
    fn privileged_payer_allows_clone_continue_with_post_delegation_action_executor() {
        let payer = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let mut tx = executed_transaction(payer, writable);
        let message = message_with_programs(vec![
            (
                MAGIC_PROGRAM_ID,
                CLONE_ACCOUNT_CONTINUE_DISCRIMINANT.to_le_bytes().to_vec(),
            ),
            (POST_DELEGATION_ACTION_EXECUTOR_PROGRAM_ID, vec![]),
        ]);

        tx.validate_accounts_access(&message);

        assert_eq!(tx.execution_details.status, Ok(()));
    }

    #[test]
    fn privileged_payer_rejects_post_delegation_action_executor_without_clone() {
        let payer = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let mut tx = executed_transaction(payer, writable);
        let message = message_with_programs(vec![
            (MAGIC_PROGRAM_ID, 1u32.to_le_bytes().to_vec()),
            (POST_DELEGATION_ACTION_EXECUTOR_PROGRAM_ID, vec![]),
        ]);

        tx.validate_accounts_access(&message);

        assert_eq!(
            tx.execution_details.status,
            Err(TransactionError::InvalidWritableAccount)
        );
    }

    #[test]
    fn privileged_payer_rejects_post_delegation_action_executor_with_extra_ix() {
        let payer = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let mut tx = executed_transaction(payer, writable);
        let message = message_with_programs(vec![
            (
                MAGIC_PROGRAM_ID,
                CLONE_ACCOUNT_DISCRIMINANT.to_le_bytes().to_vec(),
            ),
            (POST_DELEGATION_ACTION_EXECUTOR_PROGRAM_ID, vec![]),
            (
                MAGIC_PROGRAM_ID,
                CLONE_ACCOUNT_DISCRIMINANT.to_le_bytes().to_vec(),
            ),
        ]);

        tx.validate_accounts_access(&message);

        assert_eq!(
            tx.execution_details.status,
            Err(TransactionError::InvalidWritableAccount)
        );
    }

    #[test]
    fn privileged_payer_rejects_post_delegation_action_executor_with_extra_clone_writable_account()
    {
        let payer = Pubkey::new_unique();
        let writable = Pubkey::new_unique();
        let extra_writable = Pubkey::new_unique();
        let mut tx =
            executed_transaction_with_writable_accounts(payer, vec![writable, extra_writable]);
        let message = message_with_program_accounts(
            2,
            vec![
                (
                    MAGIC_PROGRAM_ID,
                    CLONE_ACCOUNT_DISCRIMINANT.to_le_bytes().to_vec(),
                    vec![0, 1, 2],
                ),
                (
                    POST_DELEGATION_ACTION_EXECUTOR_PROGRAM_ID,
                    vec![],
                    vec![0, 1, 2],
                ),
            ],
        );

        tx.validate_accounts_access(&message);

        assert_eq!(
            tx.execution_details.status,
            Err(TransactionError::InvalidWritableAccount)
        );
        assert_eq!(
            tx.execution_details.log_messages.as_ref().unwrap(),
            &vec![
                format!(
                    "Program log: Account 2: {extra_writable} was illegally used as writable"
                ),
                "Program Magic11111111111111111111111111111111111111 failed: InvalidWritableAccount"
                    .to_string(),
            ]
        );
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
        assert_eq!(
            tx.execution_details.log_messages.as_ref().unwrap(),
            &vec![
                format!(
                    "Program log: Account 1: {writable} was illegally used as writable"
                ),
                "Program Magic11111111111111111111111111111111111111 failed: InvalidWritableAccount"
                    .to_string(),
            ]
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
