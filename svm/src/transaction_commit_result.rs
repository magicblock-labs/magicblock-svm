use solana_fee_structure::FeeDetails;
use solana_message::inner_instruction::InnerInstructionsList;
use solana_transaction_context::transaction::TransactionReturnData;
use solana_transaction_error::TransactionResult;

use crate::transaction_execution_result::TransactionLoadedAccountsStats;

pub type TransactionCommitResult = TransactionResult<CommittedTransaction>;

#[derive(Clone, Debug)]
#[cfg_attr(feature = "dev-context-only-utils", derive(PartialEq))]
pub struct CommittedTransaction {
    pub status: TransactionResult<()>,
    pub log_messages: Option<Vec<String>>,
    pub inner_instructions: Option<InnerInstructionsList>,
    pub return_data: Option<TransactionReturnData>,
    pub executed_units: u64,
    pub fee_details: FeeDetails,
    pub loaded_account_stats: TransactionLoadedAccountsStats,
    pub fee_payer_post_balance: u64,
}

pub trait TransactionCommitResultExtensions {
    fn was_committed(&self) -> bool;
    fn was_executed_successfully(&self) -> bool;
}

impl TransactionCommitResultExtensions for TransactionCommitResult {
    fn was_committed(&self) -> bool {
        self.is_ok()
    }

    fn was_executed_successfully(&self) -> bool {
        match self {
            Ok(committed_tx) => committed_tx.status.is_ok(),
            Err(_) => false,
        }
    }
}
