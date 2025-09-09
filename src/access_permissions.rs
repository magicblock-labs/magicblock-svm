use solana_svm_transaction::svm_message::SVMMessage;
use solana_transaction_error::{TransactionError, TransactionResult};

use crate::account_loader::LoadedTransaction;

// NOTE:
// this impl is kept separately to simplify synchoronization with upstream
impl LoadedTransaction {
    /// Validates that a transaction does not attempt to write to non-delegated accounts.
    ///
    /// This is a critical security check to prevent privilege escalation by ensuring
    /// account modifications are restricted to accounts explicitly delegated to the
    /// validator node.
    ///
    /// ## Logic
    /// This function enforces a simple rule: **any account marked as writable,
    /// excluding the fee payer, must be a delegated account.**
    ///
    /// It iterates through the transaction's accounts, skipping the fee payer (index 0),
    /// which is validated separately. For each remaining account, if it is marked
    /// as writable in the message but is not delegated, the transaction is rejected.
    /// Read-only accounts are ignored.
    pub(crate) fn validate_accounts_access(
        &self,
        message: &impl SVMMessage,
    ) -> TransactionResult<()> {
        // Skip the fee payer (index 0), as it's validated elsewhere.
        for (i, (_, acc)) in self.accounts.iter().enumerate().skip(1) {
            // Enforce that any account intended to be writable must be a delegated account.
            if message.is_writable(i) && !acc.delegated() {
                return Err(TransactionError::InvalidWritableAccount);
            }
        }
        Ok(())
    }
}
