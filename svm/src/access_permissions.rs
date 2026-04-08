use solana_account::AccountSharedData;
use solana_svm_transaction::svm_message::SVMMessage;
use solana_transaction_error::TransactionError;

use crate::transaction_execution_result::ExecutedTransaction;

// NOTE:
// this impl is kept separately to simplify synchoronization with upstream
impl ExecutedTransaction {
    /// Validates that a transaction does not attempt to write to non-delegated accounts.
    ///
    /// This is a critical security check to prevent privilege escalation by ensuring
    /// account modifications are restricted to accounts explicitly delegated to the
    /// validator node.
    ///
    /// ## Logic
    /// This function enforces a security rule with a key exception: **if the fee payer
    /// has privileged access, this check is bypassed entirely.**
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
        let payer = accounts.first().map(|(_, acc)| acc);
        if payer.map(|p| p.privileged()).unwrap_or_default() {
            // Payer has privileged access, so we can skip the validation.
            return;
        }

        let mut offender = None;
        let is_mutable =
            |acc: &AccountSharedData| acc.delegated() || acc.undelegating() || acc.ephemeral();
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
            logs.push(
                "Program Magic11111111111111111111111111111111111111 failed: InvalidWritableAccount".into()
            );
        }
    }
}
