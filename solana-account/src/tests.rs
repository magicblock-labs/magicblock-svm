//! Tests for the copy-on-write account implementation.

use solana_clock::Epoch;
use solana_pubkey::Pubkey;

use crate::{
    accounts_equal,
    cow::{
        IS_DIRTY_MARKER_INDEX, LAMPORTS_CHANGED_MARKER_INDEX, OWNER_CHANGED_MARKER_INDEX,
        RELATIVE_DATA_LEN_POINTER_OFFSET_TEST,
    },
    test_utils::create_borrowed_account_shared_data,
    AccountSharedData, ReadableAccount, WritableAccount,
};

const DATA_LEN: u32 = 16384;
const LAMPORTS: u64 = 2342525;
const SPACE: usize = 2525;
const OWNER: Pubkey = Pubkey::new_from_array([5; 32]);

macro_rules! setup {
    () => {{
        let owned = AccountSharedData::new_rent_epoch(LAMPORTS, SPACE, &OWNER, Epoch::MAX);
        let (buffer, borrowed) = create_borrowed_account_shared_data(&owned, DATA_LEN);
        (buffer, owned, borrowed)
    }};
}

#[test]
fn test_serialized_size() {
    for align in [128, 256, 512] {
        for s in 128..16384 {
            let size = AccountSharedData::serialized_size_aligned(s, align);
            // Verify alignment
            assert_eq!(size % align, 0);
            // Verify size is reasonable (header + 2 buffers)
            assert!(size >= s * 2);
        }
    }
}

#[test]
fn test_serde() {
    let (_buffer, owned, borrowed) = setup!();
    assert!(accounts_equal(&borrowed, &owned));
}

#[test]
fn test_shadow_switch() {
    let (buffer, _, mut borrowed) = setup!();
    let shadow_switch = buffer.ptr as *const u32;

    assert_eq!(borrowed.lamports(), LAMPORTS);
    unsafe { assert_eq!(*shadow_switch, 0) };

    borrowed.set_lamports(42);
    // Primary buffer should still have old value before commit
    assert_eq!(
        unsafe { *AccountSharedData::deserialize_from_mmap(buffer.ptr).lamports() },
        LAMPORTS
    );
    // Borrowed view should see new value
    assert_eq!(borrowed.lamports(), 42);

    if let AccountSharedData::Borrowed(bacc) = &borrowed {
        bacc.commit();
    }
    unsafe { assert_eq!(*shadow_switch, 1) }

    // After commit, deserialization should see committed value
    let new_borrowed = unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr) };
    assert_eq!(unsafe { *new_borrowed.lamports() }, 42);
}

#[test]
fn test_switch_back() {
    let (buffer, _, mut borrowed) = setup!();
    let shadow_switch = buffer.ptr as *const u32;

    // First modification: primary -> shadow
    borrowed.set_lamports(42);
    if let AccountSharedData::Borrowed(bacc) = &borrowed {
        bacc.commit();
    }
    borrowed = unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr).into() };
    assert_eq!(borrowed.lamports(), 42);
    unsafe { assert_eq!(*shadow_switch, 1) };

    // Second modification: shadow -> primary
    borrowed.set_lamports(43);
    if let AccountSharedData::Borrowed(bacc) = &borrowed {
        bacc.commit();
    }
    assert_eq!(borrowed.lamports(), 43);
    unsafe { assert_eq!(*shadow_switch, 2) };

    let new_borrowed = unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr) };
    assert_eq!(unsafe { *new_borrowed.lamports() }, 43);
}

#[test]
fn test_upgrade_to_owned() {
    let (_buffer, owned, mut borrowed) = setup!();
    let msg = vec![42; DATA_LEN as usize];
    let mut new_data = borrowed.data().to_vec();
    new_data.extend_from_slice(&msg);

    borrowed.resize(borrowed.data().len() + msg.len(), 0);
    borrowed.set_data_from_slice(&new_data);

    assert_eq!(borrowed.data(), new_data.as_slice());
    assert!(matches!(borrowed, AccountSharedData::Owned(_)));
    assert_ne!(owned, borrowed);
}

#[test]
fn test_setting_data_from_slice() {
    let (_buffer, _, mut borrowed) = setup!();
    let msg = b"hello world?";
    borrowed.set_data_from_slice(msg);

    assert_eq!(borrowed.data(), msg);

    let AccountSharedData::Borrowed(b) = borrowed else {
        panic!("should remain borrowed");
    };

    // Verify the length field in memory was updated via the relative offset hack
    assert_eq!(
        unsafe { *(b.data().offset(RELATIVE_DATA_LEN_POINTER_OFFSET_TEST) as *const u32) } as usize,
        msg.len()
    );
}

#[test]
fn test_account_shrinking() {
    let (_buffer, _, mut borrowed) = setup!();
    let original_cap = borrowed.capacity();

    borrowed.resize(0, 0);
    assert_eq!(borrowed.data().len(), 0);

    let AccountSharedData::Borrowed(b) = borrowed else {
        panic!("should remain borrowed");
    };
    // Verify length is zero via relative offset hack
    assert_eq!(
        unsafe { *(b.data().offset(RELATIVE_DATA_LEN_POINTER_OFFSET_TEST) as *const u32) },
        0
    );
    // Verify capacity wasn't corrupted
    assert_eq!(b.data_cap(), original_cap as u32);
}

#[test]
fn test_account_growth() {
    let (_buffer, _, mut borrowed) = setup!();
    let original_cap = if let AccountSharedData::Borrowed(b) = &borrowed {
        b.data_cap()
    } else {
        0
    };

    // Grow within capacity
    borrowed.resize(SPACE * 2, 0);
    assert_eq!(borrowed.data().len(), SPACE * 2);

    if let AccountSharedData::Borrowed(ref b) = borrowed {
        // Verify length in memory via relative offset hack
        assert_eq!(
            unsafe { *(b.data().offset(RELATIVE_DATA_LEN_POINTER_OFFSET_TEST) as *const u32) },
            SPACE as u32 * 2
        );
        // Verify capacity wasn't corrupted
        assert_eq!(b.data_cap(), original_cap);
    } else {
        panic!("should remain borrowed");
    }

    // Grow beyond capacity
    borrowed.resize((original_cap + 1) as usize, 0);
    let AccountSharedData::Owned(ref owned) = borrowed else {
        panic!("should have converted to owned")
    };
    assert_eq!(owned.data.len(), (original_cap + 1) as usize);
}

/// Generic helper to test flag persistence across CoW operations.
fn test_flag_persistence<Set, Get>(set: Set, get: Get)
where
    Set: Fn(&mut AccountSharedData, bool),
    Get: Fn(&AccountSharedData) -> bool,
{
    let (buffer, _, mut acc) = setup!();

    assert!(!get(&acc));
    set(&mut acc, true);
    if let AccountSharedData::Borrowed(b) = &acc {
        b.commit();
    }
    let mut acc = unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr).into() };
    assert!(get(&acc));

    set(&mut acc, false);
    if let AccountSharedData::Borrowed(b) = &acc {
        b.commit();
    }
    let acc = unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr).into() };
    assert!(!get(&acc));
}

#[test]
fn test_flag_persistence_all() {
    test_flag_persistence(|acc, val| acc.set_executable(val), |acc| acc.executable());
    test_flag_persistence(|acc, val| acc.set_delegated(val), |acc| acc.delegated());
    test_flag_persistence(|acc, val| acc.set_privileged(val), |acc| acc.privileged());
    test_flag_persistence(|acc, val| acc.set_compressed(val), |acc| acc.compressed());
    test_flag_persistence(
        |acc, val| acc.set_undelegating(val),
        |acc| acc.undelegating(),
    );
    test_flag_persistence(|acc, val| acc.set_confined(val), |acc| acc.confined());
    test_flag_persistence(|acc, val| acc.set_ephemeral(val), |acc| acc.ephemeral());
}

#[test]
fn test_markers() {
    let (_buffer, _, mut borrowed) = setup!();

    // Test is_dirty marker
    let AccountSharedData::Borrowed(b) = &mut borrowed else {
        panic!("Expected borrowed account");
    };
    assert!(!b.markers.is_set(IS_DIRTY_MARKER_INDEX));
    unsafe { b.cow() };
    assert!(b.markers.is_set(IS_DIRTY_MARKER_INDEX));

    // Test owner_changed marker
    let (_buffer, _, mut borrowed) = setup!();
    let AccountSharedData::Borrowed(b) = &borrowed else {
        panic!("Expected borrowed account");
    };
    assert!(!b.owner_changed());
    let new_owner = Pubkey::new_from_array([99; 32]);
    borrowed.set_owner(new_owner);
    let AccountSharedData::Borrowed(b) = &borrowed else {
        panic!("Expected borrowed account");
    };
    assert!(b.owner_changed());
    assert!(b.markers.is_set(OWNER_CHANGED_MARKER_INDEX));
    // Verify owner actually changed in memory
    assert_eq!(unsafe { *b.owner() }, new_owner);

    // Test lamports_changed marker
    let (_buffer, _, mut borrowed) = setup!();
    let AccountSharedData::Borrowed(b) = &borrowed else {
        panic!("Expected borrowed account");
    };
    assert!(!b.lamports_changed());
    borrowed.set_lamports(9999);
    let AccountSharedData::Borrowed(b) = &borrowed else {
        panic!("Expected borrowed account");
    };
    assert!(b.lamports_changed());
    assert!(b.markers.is_set(LAMPORTS_CHANGED_MARKER_INDEX));
}

#[test]
fn test_rollback_various_fields() {
    let (buffer, _, mut borrowed) = setup!();
    let original_lamports = borrowed.lamports();
    let original_owner = *borrowed.owner();
    let original_data = borrowed.data().to_vec();

    // Modify multiple fields
    borrowed.set_lamports(5555);
    borrowed.set_owner(Pubkey::new_from_array([77; 32]));
    borrowed.set_data_from_slice(b"modified data");
    borrowed.set_executable(true);
    borrowed.set_delegated(true);

    // Commit changes
    if let AccountSharedData::Borrowed(bacc) = &borrowed {
        bacc.commit();
    }

    // Verify changes persisted
    let intermediate: AccountSharedData =
        unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr).into() };
    assert_eq!(intermediate.lamports(), 5555);
    assert_eq!(intermediate.data(), b"modified data");
    assert!(intermediate.executable());
    assert!(intermediate.delegated());

    // Rollback to original state
    unsafe { borrowed.rollback() };
    let rolled_back: AccountSharedData =
        unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr).into() };
    assert_eq!(rolled_back.lamports(), original_lamports);
    assert_eq!(*rolled_back.owner(), original_owner);
    assert_eq!(rolled_back.data(), original_data.as_slice());
    assert!(!rolled_back.executable());
    assert!(!rolled_back.delegated());
}

#[test]
fn test_rollback_shadow_switch_mechanics() {
    let (buffer, _, mut borrowed) = setup!();
    let shadow_switch = buffer.ptr as *const u32;

    // Initial state: counter = 0 (primary buffer active)
    unsafe { assert_eq!(*shadow_switch, 0) };

    // First cycle: modify, commit, verify, rollback
    borrowed.set_lamports(1111);
    if let AccountSharedData::Borrowed(bacc) = &borrowed {
        bacc.commit();
    }
    unsafe { assert_eq!(*shadow_switch, 1) };

    let intermediate: AccountSharedData =
        unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr).into() };
    assert_eq!(intermediate.lamports(), 1111);

    unsafe { borrowed.rollback() };
    unsafe { assert_eq!(*shadow_switch, 0) };
    let rolled_back: AccountSharedData =
        unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr).into() };
    assert_eq!(rolled_back.lamports(), LAMPORTS);

    // Second cycle: reload, modify, commit, verify, rollback
    borrowed = unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr).into() };
    borrowed.set_lamports(2222);
    if let AccountSharedData::Borrowed(bacc) = &borrowed {
        bacc.commit();
    }
    unsafe { assert_eq!(*shadow_switch, 1) };

    let intermediate2: AccountSharedData =
        unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr).into() };
    assert_eq!(intermediate2.lamports(), 2222);

    unsafe { borrowed.rollback() };
    unsafe { assert_eq!(*shadow_switch, 0) };
}

// Tests for basic Account and AccountSharedData functionality

fn make_two_accounts(key: &Pubkey) -> (crate::Account, AccountSharedData) {
    let mut account1 = crate::Account::new(1, 2, key);
    account1.executable = true;
    let account2 = AccountSharedData::from(account1.clone());
    assert!(accounts_equal(&account1, &account2));
    (account1, account2)
}

#[test]
fn test_account_data_copy_as_slice() {
    let key = Pubkey::new_unique();
    let key2 = Pubkey::new_unique();
    let (mut account1, mut account2) = make_two_accounts(&key);
    account1.copy_into_owner_from_slice(key2.as_ref());
    account2.copy_into_owner_from_slice(key2.as_ref());
    assert!(accounts_equal(&account1, &account2));
    assert_eq!(account1.owner(), &key2);
}

#[test]
fn test_account_set_data_from_slice() {
    let key = Pubkey::new_unique();
    let (_, mut account) = make_two_accounts(&key);
    assert_eq!(account.data(), &vec![0, 0]);
    account.set_data_from_slice(&[1, 2]);
    assert_eq!(account.data(), &vec![1, 2]);
    account.set_data_from_slice(&[1, 2, 3]);
    assert_eq!(account.data(), &vec![1, 2, 3]);
    account.set_data_from_slice(&[4, 5, 6]);
    assert_eq!(account.data(), &vec![4, 5, 6]);
    account.set_data_from_slice(&[4, 5, 6, 0]);
    assert_eq!(account.data(), &vec![4, 5, 6, 0]);
    account.set_data_from_slice(&[]);
    assert_eq!(account.data().len(), 0);
    account.set_data_from_slice(&[44]);
    assert_eq!(account.data(), &vec![44]);
    account.set_data_from_slice(&[44]);
    assert_eq!(account.data(), &vec![44]);
}

#[test]
fn test_account_data_set_data() {
    let key = Pubkey::new_unique();
    let (_, mut account) = make_two_accounts(&key);
    assert_eq!(account.data(), &vec![0, 0]);
    account.set_data(vec![1, 2]);
    assert_eq!(account.data(), &vec![1, 2]);
    account.set_data(vec![]);
    assert_eq!(account.data().len(), 0);
}

#[test]
fn test_to_account_shared_data() {
    let key = Pubkey::new_unique();
    let (account1, account2) = make_two_accounts(&key);
    assert!(accounts_equal(&account1, &account2));
    let account3 = account1.to_account_shared_data();
    let account4 = account2.to_account_shared_data();
    assert!(accounts_equal(&account1, &account3));
    assert!(accounts_equal(&account1, &account4));
}

#[test]
fn test_account_shared_data() {
    let key = Pubkey::new_unique();
    let (account1, account2) = make_two_accounts(&key);
    assert!(accounts_equal(&account1, &account2));
    let account = account1;
    assert_eq!(account.lamports, 1);
    assert_eq!(account.lamports(), 1);
    assert_eq!(account.data.len(), 2);
    assert_eq!(account.data().len(), 2);
    assert_eq!(account.owner, key);
    assert_eq!(account.owner(), &key);
    assert!(account.executable);
    assert!(account.executable());
    let account = account2;
    assert_eq!(account.lamports(), 1);
    assert_eq!(account.data().len(), 2);
    assert_eq!(account.owner(), &key);
    assert!(account.executable());
}

#[test]
fn test_account_add_sub_lamports() {
    let key = Pubkey::new_unique();
    let (mut account1, mut account2) = make_two_accounts(&key);
    assert!(accounts_equal(&account1, &account2));
    account1.checked_add_lamports(1).unwrap();
    account2.checked_add_lamports(1).unwrap();
    assert!(accounts_equal(&account1, &account2));
    assert_eq!(account1.lamports(), 2);
    account1.checked_sub_lamports(2).unwrap();
    account2.checked_sub_lamports(2).unwrap();
    assert!(accounts_equal(&account1, &account2));
    assert_eq!(account1.lamports(), 0);
}

#[test]
#[should_panic(expected = "Overflow")]
fn test_account_checked_add_lamports_overflow() {
    let key = Pubkey::new_unique();
    let (mut account1, _account2) = make_two_accounts(&key);
    account1.checked_add_lamports(u64::MAX).unwrap();
}

#[test]
#[should_panic(expected = "Underflow")]
fn test_account_checked_sub_lamports_underflow() {
    let key = Pubkey::new_unique();
    let (mut account1, _account2) = make_two_accounts(&key);
    account1.checked_sub_lamports(u64::MAX).unwrap();
}

#[test]
#[should_panic(expected = "Overflow")]
fn test_account_checked_add_lamports_overflow2() {
    let key = Pubkey::new_unique();
    let (_account1, mut account2) = make_two_accounts(&key);
    account2.checked_add_lamports(u64::MAX).unwrap();
}

#[test]
#[should_panic(expected = "Underflow")]
fn test_account_checked_sub_lamports_underflow2() {
    let key = Pubkey::new_unique();
    let (_account1, mut account2) = make_two_accounts(&key);
    account2.checked_sub_lamports(u64::MAX).unwrap();
}

#[test]
fn test_account_saturating_add_lamports() {
    let key = Pubkey::new_unique();
    let (mut account, _) = make_two_accounts(&key);

    let remaining = 22;
    account.set_lamports(u64::MAX - remaining);
    account.saturating_add_lamports(remaining * 2);
    assert_eq!(account.lamports(), u64::MAX);
}

#[test]
fn test_account_saturating_sub_lamports() {
    let key = Pubkey::new_unique();
    let (mut account, _) = make_two_accounts(&key);

    let remaining = 33;
    account.set_lamports(remaining);
    account.saturating_sub_lamports(remaining * 2);
    assert_eq!(account.lamports(), 0);
}

#[test]
fn test_buffer_allocation_size() {
    let (buffer, _, borrowed) = setup!();

    let AccountSharedData::Borrowed(b) = &borrowed else {
        panic!("Expected borrowed account");
    };

    let buf = b.buffer();
    // Total allocation >= metadata (8) + 2 * buffer (primary + shadow)
    // May have additional padding for alignment
    let min_expected = 2 * buf.len() + 8;
    assert!(buffer.buffer_size() as usize >= min_expected);
    assert_eq!(buffer.buffer_size() % 256, 0); // properly aligned
}

#[test]
fn test_buffer_jump_to_next_account() {
    use std::alloc::{alloc, dealloc, Layout};

    let data_len: u32 = 1024;
    let alignment: u32 = 128;
    let single_size = AccountSharedData::serialized_size_aligned(data_len, alignment) as usize;

    // Allocate space for two consecutive accounts
    let layout = Layout::from_size_align(single_size * 2, alignment as usize).unwrap();
    let ptr = unsafe { alloc(layout) };
    assert!(!ptr.is_null(), "allocation failed");

    // Create first account
    let acc1 = AccountSharedData::new_rent_epoch(100, 64, &OWNER, Epoch::MAX);
    let AccountSharedData::Owned(ref owned1) = acc1 else {
        panic!("expected owned")
    };
    unsafe { AccountSharedData::serialize_to_mmap(owned1, ptr, single_size as u32) };

    // Create second account at offset single_size
    let acc2 = AccountSharedData::new_rent_epoch(200, 64, &OWNER, Epoch::MAX);
    let AccountSharedData::Owned(ref owned2) = acc2 else {
        panic!("expected owned")
    };
    unsafe {
        AccountSharedData::serialize_to_mmap(owned2, ptr.add(single_size), single_size as u32)
    };

    // Deserialize first account and get its buffer
    let b1 = unsafe { AccountSharedData::deserialize_from_mmap(ptr) };
    let buf1 = b1.buffer();

    // Jump to second account: buf1.as_ptr() is already 8 bytes past the original allocation
    // (it points past account1's metadata to account1's buffer start). Adding single_size
    // lands at account2's buffer start (ptr + 8 + single_size = ptr + single_size + 8).
    let acc2_buf_ptr = unsafe { buf1.as_ptr().add(single_size) };

    // Read lamports from account 2's buffer (at offset 0)
    let acc2_lamports = unsafe { *(acc2_buf_ptr as *const u64) };
    assert_eq!(acc2_lamports, 200);

    unsafe { dealloc(ptr, layout) };
}

#[test]
fn test_slack_space_and_shadow_zeroed() {
    let small_data_size = 32;
    let data_len: u32 = 256;

    // Create account and get a buffer for it
    let acc = AccountSharedData::new(LAMPORTS, small_data_size, &OWNER);
    let (buffer, _) = create_borrowed_account_shared_data(&acc, data_len);

    // Fill entire buffer with non-zero bytes to test zeroing
    unsafe { buffer.ptr.write_bytes(0xFF, buffer.buffer_size() as usize) };

    // Re-serialize (this should zero slack and shadow)
    let AccountSharedData::Owned(ref owned) = acc else {
        panic!("expected owned")
    };
    unsafe { AccountSharedData::serialize_to_mmap(owned, buffer.ptr, buffer.buffer_size()) };

    // Deserialize to get buffer info
    let b = unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr) };
    let buf = b.buffer();

    // Verify slack space is zeroed (data starts at buffer offset 60)
    let data_end = 60 + small_data_size;
    let slack = &buf[data_end..];
    assert!(
        slack.iter().all(|&b| b == 0),
        "slack space should be zeroed"
    );

    // Verify shadow buffer is zeroed
    let shadow_start = unsafe { buffer.ptr.add(8 + buf.len()) };
    let shadow_buf = unsafe { std::slice::from_raw_parts(shadow_start, buf.len()) };
    assert!(
        shadow_buf.iter().all(|&b| b == 0),
        "shadow buffer should be zeroed"
    );
}
