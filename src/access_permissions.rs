use solana_account::AccountSharedData;
use solana_pubkey::Pubkey;
use solana_svm_transaction::svm_message::SVMMessage;
use solana_transaction_error::TransactionError;

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
    /// This function enforces a security rule with a key exception: **if the fee payer
    /// has privileged access, this check is bypassed entirely.**
    ///
    /// For standard, non-privileged transactions, it enforces that any account
    /// marked as writable (excluding the fee payer) must be either:
    /// 1. delegated
    /// 2. undelegating
    /// 3. ephemeral
    ///
    /// Read-only accounts are ignored. The fee payer's writability is handled in
    /// separate validation logic.
    pub(crate) fn validate_accounts_access(
        &self,
        message: &impl SVMMessage,
    ) -> Result<(), (TransactionError, Pubkey)> {
        let payer = self.accounts.first().map(|(_, acc)| acc);
        if payer.map(|p| p.privileged()).unwrap_or_default() {
            // Payer has privileged access, so we can skip the validation.
            return Ok(());
        }

        let mutation_allowed =
            |acc: &AccountSharedData| acc.delegated() || acc.undelegating() || acc.ephemeral();

        // For non-privileged payers, validate the rest of the accounts.
        // Skip the fee payer (index 0), as its writability is validated elsewhere.
        for (i, (pk, acc)) in self.accounts.iter().enumerate().skip(1) {
            if message.is_writable(i) && mutation_allowed(acc) {
                return Err((TransactionError::InvalidWritableAccount, *pk));
            }
        }
        Ok(())
    }
}
