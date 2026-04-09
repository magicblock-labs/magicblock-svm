#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
//! The Solana [`Account`] type.

use cow::{
    AccountBorrowed, AccountOwned, COMPRESSED_FLAG_INDEX, CONFINED_FLAG_INDEX,
    DELEGATED_FLAG_INDEX, EPHEMERAL_FLAG_INDEX, EXECUTABLE_FLAG_INDEX, PRIVILEGED_FLAG_INDEX,
    UNDELEGATING_FLAG_INDEX,
};
#[cfg(feature = "dev-context-only-utils")]
use qualifier_attr::qualifiers;
#[cfg(feature = "serde")]
use serde::ser::{Serialize, Serializer};
#[cfg(feature = "frozen-abi")]
use solana_frozen_abi_macro::AbiExample;
use solana_sdk_ids::{bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, loader_v4};
#[cfg(feature = "bincode")]
use solana_sysvar::SysvarSerialize;

#[cfg(any(test, feature = "dev-context-only-utils"))]
pub mod test_utils;

use crate::cow::{BitFlagsOwned, LAMPORTS_CHANGED_MARKER_INDEX, OWNER_CHANGED_MARKER_INDEX};

use {
    solana_account_info::{debug_account_data::*, AccountInfo},
    solana_clock::{Epoch, INITIAL_RENT_EPOCH},
    solana_instruction::error::LamportsError,
    solana_pubkey::Pubkey,
    std::{
        cell::{Ref, RefCell},
        fmt,
        mem::size_of,
        mem::MaybeUninit,
        ptr,
        rc::Rc,
        sync::Arc,
    },
};
#[cfg(feature = "bincode")]
pub mod state_traits;

pub mod cow;

#[cfg(test)]
mod tests;

/// An Account with data that is stored on chain
#[repr(C)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[derive(PartialEq, Eq, Clone, Default)]
pub struct Account {
    /// lamports in the account
    pub lamports: u64,
    /// data held in this account
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub data: Vec<u8>,
    /// the program that owns this account. If executable, the program that loads this account.
    pub owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    pub executable: bool,
    /// the epoch at which this account will next owe rent
    pub rent_epoch: Epoch,
}

// mod because we need 'Account' below to have the name 'Account' to match expected serialization
#[cfg(feature = "serde")]
mod account_serialize {
    use {
        crate::ReadableAccount,
        serde::{ser::Serializer, Serialize},
        solana_clock::Epoch,
        solana_pubkey::Pubkey,
    };
    #[repr(C)]
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Account<'a> {
        lamports: u64,
        #[serde(with = "serde_bytes")]
        // a slice so we don't have to make a copy just to serialize this
        data: &'a [u8],
        owner: &'a Pubkey,
        executable: bool,
        rent_epoch: Epoch,
    }

    /// allows us to implement serialize on AccountSharedData that is equivalent to Account::serialize without making a copy of the Vec<u8>
    pub fn serialize_account<S>(
        account: &impl ReadableAccount,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let temp = Account {
            lamports: account.lamports(),
            data: account.data(),
            owner: account.owner(),
            executable: account.executable(),
            rent_epoch: account.rent_epoch(),
        };
        temp.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Account {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        crate::account_serialize::serialize_account(self, serializer)
    }
}

#[cfg(feature = "serde")]
impl Serialize for AccountSharedData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        crate::account_serialize::serialize_account(self, serializer)
    }
}

/// An Account with data that is stored on chain
/// This will be the in-memory representation of the 'Account' struct data.
/// The existing 'Account' structure cannot easily change due to downstream projects.
#[cfg_attr(feature = "serde", derive(serde::Deserialize), serde(from = "Account"))]
#[derive(PartialEq, Eq, Clone)]
pub enum AccountSharedData {
    Borrowed(AccountBorrowed),
    Owned(AccountOwned),
}
/// Compares two ReadableAccounts
///
/// Returns true if accounts are essentially equivalent as in all fields are equivalent.
pub fn accounts_equal<T: ReadableAccount, U: ReadableAccount>(me: &T, other: &U) -> bool {
    me.lamports() == other.lamports()
        && me.executable() == other.executable()
        && me.rent_epoch() == other.rent_epoch()
        && me.owner() == other.owner()
        && me.data() == other.data()
}

impl From<AccountSharedData> for Account {
    fn from(other: AccountSharedData) -> Self {
        match other {
            AccountSharedData::Borrowed(acc) => unsafe {
                Self {
                    lamports: *acc.lamports(),
                    data: acc.data_as_slice().to_vec(),
                    owner: *acc.owner(),
                    executable: acc.flag_is_set(EXECUTABLE_FLAG_INDEX),
                    rent_epoch: Epoch::MAX,
                }
            },
            AccountSharedData::Owned(mut acc) => {
                let account_data = Arc::make_mut(&mut acc.data);
                Self {
                    lamports: acc.lamports,
                    data: std::mem::take(account_data),
                    owner: acc.owner,
                    executable: acc.flags.is_set(EXECUTABLE_FLAG_INDEX),
                    rent_epoch: Epoch::MAX,
                }
            }
        }
    }
}

impl From<Account> for AccountSharedData {
    fn from(other: Account) -> Self {
        let mut flags = BitFlagsOwned::default();
        flags.set(other.executable, EXECUTABLE_FLAG_INDEX);
        Self::Owned(AccountOwned {
            lamports: other.lamports,
            data: Arc::new(other.data),
            owner: other.owner,
            remote_slot: 0,
            flags,
            markers: Default::default(),
        })
    }
}

pub trait WritableAccount: ReadableAccount {
    fn set_lamports(&mut self, lamports: u64);
    fn checked_add_lamports(&mut self, lamports: u64) -> Result<(), LamportsError> {
        self.set_lamports(
            self.lamports()
                .checked_add(lamports)
                .ok_or(LamportsError::ArithmeticOverflow)?,
        );
        Ok(())
    }
    fn checked_sub_lamports(&mut self, lamports: u64) -> Result<(), LamportsError> {
        self.set_lamports(
            self.lamports()
                .checked_sub(lamports)
                .ok_or(LamportsError::ArithmeticUnderflow)?,
        );
        Ok(())
    }
    fn saturating_add_lamports(&mut self, lamports: u64) {
        self.set_lamports(self.lamports().saturating_add(lamports))
    }
    fn saturating_sub_lamports(&mut self, lamports: u64) {
        self.set_lamports(self.lamports().saturating_sub(lamports))
    }
    fn data_as_mut_slice(&mut self) -> &mut [u8];
    fn set_owner(&mut self, owner: Pubkey);
    fn copy_into_owner_from_slice(&mut self, source: &[u8]);
    fn set_executable(&mut self, executable: bool);
    fn set_rent_epoch(&mut self, epoch: Epoch);
    fn create(
        lamports: u64,
        data: Vec<u8>,
        owner: Pubkey,
        executable: bool,
        rent_epoch: Epoch,
    ) -> Self;
}

pub trait ReadableAccount: Sized {
    fn lamports(&self) -> u64;
    fn data(&self) -> &[u8];
    fn owner(&self) -> &Pubkey;
    fn executable(&self) -> bool;
    fn rent_epoch(&self) -> Epoch;
    fn to_account_shared_data(&self) -> AccountSharedData {
        AccountSharedData::create(
            self.lamports(),
            self.data().to_vec(),
            *self.owner(),
            self.executable(),
            self.rent_epoch(),
        )
    }
}

impl ReadableAccount for Account {
    fn lamports(&self) -> u64 {
        self.lamports
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn owner(&self) -> &Pubkey {
        &self.owner
    }
    fn executable(&self) -> bool {
        self.executable
    }
    fn rent_epoch(&self) -> Epoch {
        self.rent_epoch
    }
}

impl WritableAccount for Account {
    fn set_lamports(&mut self, lamports: u64) {
        self.lamports = lamports;
    }
    fn data_as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    fn set_owner(&mut self, owner: Pubkey) {
        self.owner = owner;
    }
    fn copy_into_owner_from_slice(&mut self, source: &[u8]) {
        self.owner.as_mut().copy_from_slice(source);
    }
    fn set_executable(&mut self, executable: bool) {
        self.executable = executable;
    }
    fn set_rent_epoch(&mut self, epoch: Epoch) {
        self.rent_epoch = epoch;
    }
    fn create(
        lamports: u64,
        data: Vec<u8>,
        owner: Pubkey,
        executable: bool,
        rent_epoch: Epoch,
    ) -> Self {
        Account {
            lamports,
            data,
            owner,
            executable,
            rent_epoch,
        }
    }
}

impl WritableAccount for AccountSharedData {
    fn set_lamports(&mut self, lamports: u64) {
        match self {
            Self::Borrowed(acc) => unsafe {
                if *acc.lamports() == lamports {
                    return;
                }
                acc.cow();
                acc.markers.set(true, LAMPORTS_CHANGED_MARKER_INDEX);
                *acc.lamports() = lamports;
            },
            Self::Owned(acc) => acc.lamports = lamports,
        }
    }

    fn data_as_mut_slice(&mut self) -> &mut [u8] {
        self.data_mut()
    }

    fn set_owner(&mut self, owner: Pubkey) {
        match self {
            Self::Borrowed(acc) => unsafe {
                if *acc.owner() == owner {
                    return;
                }
                acc.cow();
                acc.markers.set(true, OWNER_CHANGED_MARKER_INDEX);
                *acc.owner() = owner;
            },
            Self::Owned(acc) => acc.owner = owner,
        }
    }

    fn copy_into_owner_from_slice(&mut self, source: &[u8]) {
        match self {
            Self::Borrowed(acc) => unsafe {
                if (*acc.owner()).as_array() == source {
                    return;
                }
                acc.cow();
                (acc.owner() as *mut u8)
                    .copy_from_nonoverlapping(source.as_ptr(), size_of::<Pubkey>());
            },
            Self::Owned(acc) => acc.owner.as_mut().copy_from_slice(source),
        }
    }

    fn set_executable(&mut self, executable: bool) {
        match self {
            Self::Borrowed(acc) => {
                if acc.flag_is_set(EXECUTABLE_FLAG_INDEX) == executable {
                    return;
                }
                unsafe { acc.cow() };

                acc.set_flag(executable, EXECUTABLE_FLAG_INDEX);
            }
            Self::Owned(acc) => acc.flags.set(executable, EXECUTABLE_FLAG_INDEX),
        }
    }

    fn set_rent_epoch(&mut self, _: Epoch) {
        // noop, we just make up rent epoch out of thin air: Epoch::MAX
    }

    fn create(
        lamports: u64,
        data: Vec<u8>,
        owner: Pubkey,
        executable: bool,
        _rent_epoch: Epoch,
    ) -> Self {
        let mut flags = BitFlagsOwned::default();
        flags.set(executable, EXECUTABLE_FLAG_INDEX);
        Self::Owned(AccountOwned {
            lamports,
            data: Arc::new(data),
            owner,
            remote_slot: 0,
            flags,
            markers: Default::default(),
        })
    }
}

impl ReadableAccount for AccountSharedData {
    fn lamports(&self) -> u64 {
        match self {
            Self::Borrowed(acc) => unsafe { *acc.lamports() },
            Self::Owned(acc) => acc.lamports,
        }
    }
    fn data(&self) -> &[u8] {
        match self {
            Self::Borrowed(acc) => acc.data_as_slice(),
            Self::Owned(acc) => &acc.data,
        }
    }
    fn owner(&self) -> &Pubkey {
        match self {
            Self::Borrowed(acc) => unsafe { &*acc.owner() },
            Self::Owned(acc) => &acc.owner,
        }
    }
    fn executable(&self) -> bool {
        match self {
            Self::Borrowed(acc) => acc.flag_is_set(EXECUTABLE_FLAG_INDEX),
            Self::Owned(acc) => acc.flags.is_set(EXECUTABLE_FLAG_INDEX),
        }
    }
    fn rent_epoch(&self) -> Epoch {
        Epoch::MAX
    }
    fn to_account_shared_data(&self) -> AccountSharedData {
        self.clone()
    }
}

impl ReadableAccount for Ref<'_, AccountSharedData> {
    fn lamports(&self) -> u64 {
        (**self).lamports()
    }
    fn data(&self) -> &[u8] {
        (**self).data()
    }
    fn owner(&self) -> &Pubkey {
        (**self).owner()
    }
    fn executable(&self) -> bool {
        (**self).executable()
    }
    fn rent_epoch(&self) -> Epoch {
        (**self).rent_epoch()
    }
    fn to_account_shared_data(&self) -> AccountSharedData {
        (**self).clone()
    }
}

impl ReadableAccount for Ref<'_, Account> {
    fn lamports(&self) -> u64 {
        self.lamports
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn owner(&self) -> &Pubkey {
        &self.owner
    }
    fn executable(&self) -> bool {
        self.executable
    }
    fn rent_epoch(&self) -> Epoch {
        self.rent_epoch
    }
}

fn debug_fmt<T: ReadableAccount>(item: &T, f: &mut fmt::DebugStruct<'_, '_>) {
    f.field("lamports", &item.lamports())
        .field("data.len", &item.data().len())
        .field("owner", &item.owner())
        .field("executable", &item.executable())
        .field("rent_epoch", &item.rent_epoch());
    debug_account_data(item.data(), f);
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("Account");
        debug_fmt(self, &mut f);
        f.finish()
    }
}

impl fmt::Debug for AccountSharedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("AccountSharedData");
        debug_fmt(self, &mut f);
        f.field("remote_slot", &self.remote_slot());
        f.field("delegated", &self.delegated());
        f.field("compressed", &self.compressed());
        f.field("undelegating", &self.undelegating());
        f.field("confined", &self.confined());
        f.field("ephemeral", &self.ephemeral());
        f.field("privileged", &self.privileged());
        f.finish()
    }
}

fn shared_new<T: WritableAccount>(lamports: u64, space: usize, owner: &Pubkey) -> T {
    T::create(
        lamports,
        vec![0u8; space],
        *owner,
        bool::default(),
        Epoch::MAX,
    )
}

fn shared_new_rent_epoch<T: WritableAccount>(
    lamports: u64,
    space: usize,
    owner: &Pubkey,
    rent_epoch: Epoch,
) -> T {
    T::create(
        lamports,
        vec![0u8; space],
        *owner,
        bool::default(),
        rent_epoch,
    )
}

fn shared_new_ref<T: WritableAccount>(
    lamports: u64,
    space: usize,
    owner: &Pubkey,
) -> Rc<RefCell<T>> {
    Rc::new(RefCell::new(shared_new::<T>(lamports, space, owner)))
}

#[cfg(feature = "bincode")]
fn shared_new_data<T: serde::Serialize, U: WritableAccount>(
    lamports: u64,
    state: &T,
    owner: &Pubkey,
) -> Result<U, bincode::Error> {
    let data = bincode::serialize(state)?;
    Ok(U::create(
        lamports,
        data,
        *owner,
        bool::default(),
        Epoch::default(),
    ))
}

#[cfg(feature = "bincode")]
fn shared_new_ref_data<T: serde::Serialize, U: WritableAccount>(
    lamports: u64,
    state: &T,
    owner: &Pubkey,
) -> Result<RefCell<U>, bincode::Error> {
    Ok(RefCell::new(shared_new_data::<T, U>(
        lamports, state, owner,
    )?))
}

#[cfg(feature = "bincode")]
fn shared_new_data_with_space<T: serde::Serialize, U: WritableAccount>(
    lamports: u64,
    state: &T,
    space: usize,
    owner: &Pubkey,
) -> Result<U, bincode::Error> {
    let mut account = shared_new::<U>(lamports, space, owner);

    shared_serialize_data(&mut account, state)?;

    Ok(account)
}

#[cfg(feature = "bincode")]
fn shared_new_ref_data_with_space<T: serde::Serialize, U: WritableAccount>(
    lamports: u64,
    state: &T,
    space: usize,
    owner: &Pubkey,
) -> Result<RefCell<U>, bincode::Error> {
    Ok(RefCell::new(shared_new_data_with_space::<T, U>(
        lamports, state, space, owner,
    )?))
}

#[cfg(feature = "bincode")]
fn shared_deserialize_data<T: serde::de::DeserializeOwned, U: ReadableAccount>(
    account: &U,
) -> Result<T, bincode::Error> {
    bincode::deserialize(account.data())
}

#[cfg(feature = "bincode")]
fn shared_serialize_data<T: serde::Serialize, U: WritableAccount>(
    account: &mut U,
    state: &T,
) -> Result<(), bincode::Error> {
    if bincode::serialized_size(state)? > account.data().len() as u64 {
        return Err(Box::new(bincode::ErrorKind::SizeLimit));
    }
    bincode::serialize_into(account.data_as_mut_slice(), state)
}

impl Account {
    pub fn new(lamports: u64, space: usize, owner: &Pubkey) -> Self {
        shared_new(lamports, space, owner)
    }
    pub fn new_ref(lamports: u64, space: usize, owner: &Pubkey) -> Rc<RefCell<Self>> {
        shared_new_ref(lamports, space, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        shared_new_data(lamports, state, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_ref_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        shared_new_ref_data(lamports, state, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        shared_new_data_with_space(lamports, state, space, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_ref_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        shared_new_ref_data_with_space(lamports, state, space, owner)
    }
    pub fn new_rent_epoch(lamports: u64, space: usize, owner: &Pubkey, rent_epoch: Epoch) -> Self {
        shared_new_rent_epoch(lamports, space, owner, rent_epoch)
    }
    #[cfg(feature = "bincode")]
    pub fn deserialize_data<T: serde::de::DeserializeOwned>(&self) -> Result<T, bincode::Error> {
        shared_deserialize_data(self)
    }
    #[cfg(feature = "bincode")]
    pub fn serialize_data<T: serde::Serialize>(&mut self, state: &T) -> Result<(), bincode::Error> {
        shared_serialize_data(self, state)
    }
}

impl AccountSharedData {
    pub fn is_shared(&self) -> bool {
        match self {
            Self::Owned(acc) => Arc::strong_count(&acc.data) > 1,
            Self::Borrowed(_) => true,
        }
    }

    pub fn ensure_owned(&mut self) {
        if let Self::Borrowed(acc) = self {
            *self = unsafe {
                Self::Owned(AccountOwned {
                    lamports: *acc.lamports(),
                    data: Arc::new(acc.data_as_slice().to_vec()),
                    owner: *acc.owner(),
                    remote_slot: *acc.remote_slot(),
                    flags: acc.flags_into_owned(),
                    markers: acc.markers,
                })
            }
        }
    }

    pub fn set_delegated(&mut self, delegated: bool) {
        match self {
            Self::Owned(acc) => {
                if acc.flags.is_set(DELEGATED_FLAG_INDEX) == delegated {
                    return;
                }
                acc.flags.set(delegated, DELEGATED_FLAG_INDEX);
            }
            Self::Borrowed(acc) => {
                if acc.flag_is_set(DELEGATED_FLAG_INDEX) == delegated {
                    return;
                }
                unsafe { acc.cow() };
                acc.set_flag(delegated, DELEGATED_FLAG_INDEX);
            }
        }
    }

    /// Whether the given account is delegated or not
    pub fn delegated(&self) -> bool {
        match self {
            Self::Borrowed(acc) => acc.flag_is_set(DELEGATED_FLAG_INDEX),
            Self::Owned(acc) => acc.flags.is_set(DELEGATED_FLAG_INDEX),
        }
    }

    /// Sets the compressed flag for the account
    pub fn set_compressed(&mut self, compressed: bool) {
        match self {
            Self::Owned(acc) => {
                if acc.flags.is_set(COMPRESSED_FLAG_INDEX) == compressed {
                    return;
                }
                acc.flags.set(compressed, COMPRESSED_FLAG_INDEX);
            }
            Self::Borrowed(acc) => {
                if acc.flag_is_set(COMPRESSED_FLAG_INDEX) == compressed {
                    return;
                }
                unsafe { acc.cow() };
                acc.set_flag(compressed, COMPRESSED_FLAG_INDEX);
            }
        }
    }

    /// Whether the given account is compressed on chain
    pub fn compressed(&self) -> bool {
        match self {
            Self::Borrowed(acc) => acc.flag_is_set(COMPRESSED_FLAG_INDEX),
            Self::Owned(acc) => acc.flags.is_set(COMPRESSED_FLAG_INDEX),
        }
    }

    /// Sets the undelegating flag for the account
    pub fn set_undelegating(&mut self, undelegating: bool) {
        match self {
            Self::Owned(acc) => {
                if acc.flags.is_set(UNDELEGATING_FLAG_INDEX) == undelegating {
                    return;
                }
                acc.flags.set(undelegating, UNDELEGATING_FLAG_INDEX);
            }
            Self::Borrowed(acc) => {
                if acc.flag_is_set(UNDELEGATING_FLAG_INDEX) == undelegating {
                    return;
                }
                unsafe { acc.cow() };
                acc.set_flag(undelegating, UNDELEGATING_FLAG_INDEX);
            }
        }
    }

    /// Whether the given account is undelegating
    pub fn undelegating(&self) -> bool {
        match self {
            Self::Borrowed(acc) => acc.flag_is_set(UNDELEGATING_FLAG_INDEX),
            Self::Owned(acc) => acc.flags.is_set(UNDELEGATING_FLAG_INDEX),
        }
    }

    /// Sets the [Self::confined] flag for the account
    pub fn set_confined(&mut self, confined: bool) {
        match self {
            Self::Owned(acc) => {
                if acc.flags.is_set(CONFINED_FLAG_INDEX) == confined {
                    return;
                }
                acc.flags.set(confined, CONFINED_FLAG_INDEX);
            }
            Self::Borrowed(acc) => {
                if acc.flag_is_set(CONFINED_FLAG_INDEX) == confined {
                    return;
                }
                unsafe { acc.cow() };
                acc.set_flag(confined, CONFINED_FLAG_INDEX);
            }
        }
    }

    /// Whether the given account is confined which means its usage is limited.
    /// For instance we cannot change the lamports or data size of such an account.
    pub fn confined(&self) -> bool {
        match self {
            Self::Borrowed(acc) => acc.flag_is_set(CONFINED_FLAG_INDEX),
            Self::Owned(acc) => acc.flags.is_set(CONFINED_FLAG_INDEX),
        }
    }

    /// Sets the [Self::ephemeral] flag for the account
    pub fn set_ephemeral(&mut self, ephemeral: bool) {
        match self {
            Self::Owned(acc) => {
                if acc.flags.is_set(EPHEMERAL_FLAG_INDEX) == ephemeral {
                    return;
                }
                acc.flags.set(ephemeral, EPHEMERAL_FLAG_INDEX);
            }
            Self::Borrowed(acc) => {
                if acc.flag_is_set(EPHEMERAL_FLAG_INDEX) == ephemeral {
                    return;
                }
                unsafe { acc.cow() };
                acc.set_flag(ephemeral, EPHEMERAL_FLAG_INDEX);
            }
        }
    }

    /// Whether the given account is ephemeral
    pub fn ephemeral(&self) -> bool {
        match self {
            Self::Borrowed(acc) => acc.flag_is_set(EPHEMERAL_FLAG_INDEX),
            Self::Owned(acc) => acc.flags.is_set(EPHEMERAL_FLAG_INDEX),
        }
    }

    /// Sets the privileged flag for the account.
    pub fn set_privileged(&mut self, privileged: bool) {
        match self {
            Self::Owned(acc) => {
                if acc.flags.is_set(PRIVILEGED_FLAG_INDEX) == privileged {
                    return;
                }
                acc.flags.set(privileged, PRIVILEGED_FLAG_INDEX);
            }
            Self::Borrowed(acc) => {
                if acc.flag_is_set(PRIVILEGED_FLAG_INDEX) == privileged {
                    return;
                }
                unsafe { acc.cow() };
                acc.set_flag(privileged, PRIVILEGED_FLAG_INDEX);
            }
        }
    }

    /// Whether the given account is privileged or not.
    pub fn privileged(&self) -> bool {
        match self {
            Self::Borrowed(acc) => acc.flag_is_set(PRIVILEGED_FLAG_INDEX),
            Self::Owned(acc) => acc.flags.is_set(PRIVILEGED_FLAG_INDEX),
        }
    }

    pub fn remote_slot(&self) -> u64 {
        match self {
            Self::Borrowed(acc) => unsafe { *acc.remote_slot() },
            Self::Owned(acc) => acc.remote_slot,
        }
    }

    pub fn set_remote_slot(&mut self, remote_slot: u64) {
        match self {
            Self::Owned(acc) => acc.remote_slot = remote_slot,
            Self::Borrowed(acc) => unsafe {
                acc.cow();
                *acc.remote_slot() = remote_slot;
            },
        }
    }

    /// Whether lamports of the given account have been modified
    pub fn lamports_changed(&self) -> bool {
        match self {
            Self::Borrowed(acc) => acc.markers.is_set(LAMPORTS_CHANGED_MARKER_INDEX),
            Self::Owned(acc) => acc.markers.is_set(LAMPORTS_CHANGED_MARKER_INDEX),
        }
    }

    /// Whether owner of the given account has been modified
    pub fn owner_changed(&self) -> bool {
        match self {
            Self::Borrowed(acc) => acc.markers.is_set(OWNER_CHANGED_MARKER_INDEX),
            Self::Owned(acc) => acc.markers.is_set(OWNER_CHANGED_MARKER_INDEX),
        }
    }

    pub fn reserve(&mut self, additional: usize) {
        if let Self::Borrowed(acc) = self {
            if (acc.data_cap() as usize) < (acc.data_len() as usize + additional) {
                self.ensure_owned();
            } else {
                return;
            }
        }
        if let Self::Owned(acc) = self {
            if let Some(data) = Arc::get_mut(&mut acc.data) {
                data.reserve(additional)
            } else {
                let mut data = Vec::with_capacity(acc.data.len().saturating_add(additional));
                data.extend_from_slice(&acc.data);
                acc.data = Arc::new(data);
            }
        }
    }

    pub fn capacity(&self) -> usize {
        match self {
            Self::Owned(acc) => acc.data.capacity(),
            Self::Borrowed(acc) => acc.data_cap() as usize,
        }
    }

    pub fn data_clone(&self) -> Arc<Vec<u8>> {
        // NOTE: original implementation: Arc::clone(&self.data), but we don't have a `data` field.
        // See: https://github.com/anza-xyz/solana-sdk/blob/master/account/src/lib.rs#L600
        // This just satisfies the compiler, but due to copying is not performant.
        Arc::new(self.data().to_vec())
    }

    #[inline]
    fn data_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Owned(acc) => Arc::make_mut(&mut acc.data).as_mut_slice(),
            Self::Borrowed(acc) => {
                unsafe { acc.cow() };
                acc.data_as_slice_mut()
            }
        }
    }

    pub fn resize(&mut self, new_len: usize, value: u8) {
        if new_len > self.capacity() {
            self.ensure_owned();
        }
        match self {
            Self::Owned(acc) => Arc::make_mut(&mut acc.data).resize(new_len, value),
            Self::Borrowed(acc) => {
                // we didn't grow, which means we shrunk, truncate the data
                //
                // Safety: we made sure that new_len doesn't exceed
                // the old one and old data is already initialized
                unsafe {
                    acc.cow();
                    acc.data_slice_mut().set_len(new_len);
                }
            }
        }
    }

    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.ensure_owned();
        if let Self::Owned(acc) = self {
            Arc::make_mut(&mut acc.data).extend_from_slice(data)
        }
    }

    pub fn set_data_from_slice(&mut self, new_data: &[u8]) {
        let new_len = new_data.len();
        let new_ptr = new_data.as_ptr();
        if new_len > self.capacity() {
            self.ensure_owned();
        }
        let acc = match self {
            Self::Borrowed(acc) => {
                // SAFETY:
                // we just initialized the data and made sure that
                // new_len doesn't exceed the available capacity
                unsafe {
                    acc.cow();
                    acc.data().copy_from_nonoverlapping(new_ptr, new_len);
                    acc.data_slice_mut().set_len(new_len);
                }
                return;
            }
            Self::Owned(acc) => acc,
        };
        // If the buffer isn't shared, we're going to memcpy in place.
        let Some(data) = Arc::get_mut(&mut acc.data) else {
            // If the buffer is shared, the cheapest thing to do is to clone the
            // incoming slice and replace the buffer.
            return self.set_data(new_data.to_vec());
        };

        // Reserve additional capacity if needed. Here we make the assumption
        // that growing the current buffer is cheaper than doing a whole new
        // allocation to make `new_data` owned.
        //
        // This assumption holds true during CPI, especially when the account
        // size doesn't change but the account is only changed in place. And
        // it's also true when the account is grown by a small margin (the
        // realloc limit is quite low), in which case the allocator can just
        // update the allocation metadata without moving.
        //
        // Shrinking and copying in place is always faster than making
        // `new_data` owned, since shrinking boils down to updating the Vec's
        // length.

        data.reserve(new_len.saturating_sub(data.len()));

        // Safety:
        // We just reserved enough capacity. We set data::len to 0 to avoid
        // possible UB on panic (dropping uninitialized elements), do the copy,
        // finally set the new length once everything is initialized.
        unsafe {
            data.set_len(0);
            ptr::copy_nonoverlapping(new_ptr, data.as_mut_ptr(), new_len);
            data.set_len(new_len);
        };
    }

    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn set_data(&mut self, data: Vec<u8>) {
        if self.capacity() < data.len() {
            self.ensure_owned();
        }
        if let Self::Borrowed(acc) = self {
            // SAFETY:
            // we are initializing the data and we made sure that
            // data.len() doesn't exceed the available capacity
            unsafe {
                acc.cow();
                acc.data()
                    .copy_from_nonoverlapping(data.as_slice().as_ptr(), data.len());
                acc.data_slice_mut().set_len(data.len());
            }
            return;
        }
        let Self::Owned(acc) = self else {
            // ensure_owned transformed self to Owned, this branch will never be taken
            return;
        };
        acc.data = Arc::new(data);
    }

    pub fn spare_data_capacity_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        match self {
            Self::Borrowed(acc) => unsafe {
                acc.cow();
                let ptr = acc.data().add(acc.data_len() as usize) as *mut MaybeUninit<u8>;
                std::slice::from_raw_parts_mut(
                    ptr,
                    acc.data_cap().saturating_sub(acc.data_len()) as usize,
                )
            },
            Self::Owned(acc) => Arc::make_mut(&mut acc.data).spare_capacity_mut(),
        }
    }

    pub fn new(lamports: u64, space: usize, owner: &Pubkey) -> Self {
        shared_new(lamports, space, owner)
    }

    pub fn new_ref(lamports: u64, space: usize, owner: &Pubkey) -> Rc<RefCell<Self>> {
        shared_new_ref(lamports, space, owner)
    }

    #[cfg(feature = "bincode")]
    pub fn new_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        shared_new_data(lamports, state, owner)
    }

    #[cfg(feature = "bincode")]
    pub fn new_ref_data<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        shared_new_ref_data(lamports, state, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<Self, bincode::Error> {
        shared_new_data_with_space(lamports, state, space, owner)
    }
    #[cfg(feature = "bincode")]
    pub fn new_ref_data_with_space<T: serde::Serialize>(
        lamports: u64,
        state: &T,
        space: usize,
        owner: &Pubkey,
    ) -> Result<RefCell<Self>, bincode::Error> {
        shared_new_ref_data_with_space(lamports, state, space, owner)
    }
    pub fn new_rent_epoch(lamports: u64, space: usize, owner: &Pubkey, rent_epoch: Epoch) -> Self {
        shared_new_rent_epoch(lamports, space, owner, rent_epoch)
    }
    #[cfg(feature = "bincode")]
    pub fn deserialize_data<T: serde::de::DeserializeOwned>(&self) -> Result<T, bincode::Error> {
        shared_deserialize_data(self)
    }
    #[cfg(feature = "bincode")]
    pub fn serialize_data<T: serde::Serialize>(&mut self, state: &T) -> Result<(), bincode::Error> {
        shared_serialize_data(self, state)
    }
    pub fn create_from_existing_shared_data(
        lamports: u64,
        data: Arc<Vec<u8>>,
        owner: Pubkey,
        executable: bool,
        _rent_epoch: Epoch,
    ) -> AccountSharedData {
        let mut owned = AccountOwned {
            lamports,
            data,
            owner,
            ..Default::default()
        };
        owned.flags.set(executable, EXECUTABLE_FLAG_INDEX);
        AccountSharedData::Owned(owned)
    }
}
pub type InheritableAccountFields = (u64, Epoch);
pub const DUMMY_INHERITABLE_ACCOUNT_FIELDS: InheritableAccountFields = (1, INITIAL_RENT_EPOCH);

/// Return the information required to construct an `AccountInfo`.  Used by the
/// `AccountInfo` conversion implementations.
impl solana_account_info::Account for Account {
    fn get(&mut self) -> (&mut u64, &mut [u8], &Pubkey, bool) {
        (
            &mut self.lamports,
            &mut self.data,
            &self.owner,
            self.executable,
        )
    }
}
#[cfg(feature = "bincode")]
// Serialize a `Sysvar` into an `Account`'s data.
pub fn to_account<S: SysvarSerialize, T: WritableAccount>(
    sysvar: &S,
    account: &mut T,
) -> Option<()> {
    bincode::serialize_into(account.data_as_mut_slice(), sysvar).ok()
}

#[cfg(feature = "bincode")]
/// Create an `Account` from a `Sysvar`.
pub fn create_account_shared_data_with_fields<S: SysvarSerialize>(
    sysvar: &S,
    fields: InheritableAccountFields,
) -> AccountSharedData {
    AccountSharedData::from(create_account_with_fields(sysvar, fields))
}

#[cfg(feature = "bincode")]
/// Create a `Sysvar` from an `Account`'s data.
pub fn from_account<S: SysvarSerialize, T: ReadableAccount>(account: &T) -> Option<S> {
    bincode::deserialize(account.data()).ok()
}

#[cfg(feature = "bincode")]
pub fn create_account_with_fields<S: SysvarSerialize>(
    sysvar: &S,
    (lamports, rent_epoch): InheritableAccountFields,
) -> Account {
    let data_len = S::size_of().max(bincode::serialized_size(sysvar).unwrap() as usize);
    let sysvar_id = Pubkey::from_str_const("Sysvar1111111111111111111111111111111111111");
    let mut account = Account::new(lamports, data_len, &sysvar_id);
    to_account::<S, Account>(sysvar, &mut account).unwrap();
    account.rent_epoch = rent_epoch;
    account
}

#[cfg(feature = "bincode")]
pub fn create_account_shared_data_for_test<S: SysvarSerialize>(sysvar: &S) -> AccountSharedData {
    AccountSharedData::from(create_account_with_fields(
        sysvar,
        DUMMY_INHERITABLE_ACCOUNT_FIELDS,
    ))
}

/// Create `AccountInfo`s
pub fn create_is_signer_account_infos<'a>(
    accounts: &'a mut [(&'a Pubkey, bool, &'a mut Account)],
) -> Vec<AccountInfo<'a>> {
    accounts
        .iter_mut()
        .map(|(key, is_signer, account)| {
            AccountInfo::new(
                key,
                *is_signer,
                false,
                &mut account.lamports,
                &mut account.data,
                &account.owner,
                account.executable,
            )
        })
        .collect()
}

// // Replacement for the executable flag: An account being owned by one of these contains a program.
pub const PROGRAM_OWNERS: &[Pubkey] = &[
    bpf_loader_upgradeable::id(),
    bpf_loader::id(),
    bpf_loader_deprecated::id(),
    loader_v4::id(),
];
