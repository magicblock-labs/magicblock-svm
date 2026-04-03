//! A memory-optimized, zero-copy account representation for Solana.
//!
//! This module provides `AccountSharedData`, an enum that manages Solana accounts either
//! in a memory-mapped region (`AccountBorrowed`) or on the heap (`AccountOwned`). The primary
//! goal is to maximize performance by directly manipulating account data in memory-mapped
//! files, avoiding deserialization overhead.
//!
//! ## Core Concepts
//!
//! - **`AccountBorrowed`**: A lightweight view into an account's data stored in a memory-mapped
//!   file. It uses raw pointers for direct field access and modification. This is the "zero-copy"
//!   part of the implementation.
//!
//! - **Copy-on-Write (CoW)**: To handle modifications safely (e.g., during a transaction that
//!   might fail), `AccountBorrowed` uses a shadow buffer. The first time a borrowed account is
//!   modified, its data is copied to an adjacent "shadow" memory region. All subsequent changes
//!   are applied to this shadow copy.
//!
//! - **`ShadowSwitch`**: An atomic counter that acts as a sequence lock. It tracks which buffer
//!   (primary or shadow) holds the most recent version of the account data. An even count
//!   points to the primary buffer, and an odd count points to the shadow buffer. This allows for
//!   safe, optimistic reads.
//!
//! - **`AccountOwned`**: A standard, heap-allocated representation of an account.
//!   An `AccountBorrowed` is promoted to `AccountOwned` if its data needs to grow
//!   beyond the capacity of its memory-mapped buffer.
//!
//! ## Memory Layout
//!
//! The efficiency of this module hinges on a precise and stable memory layout for serialized
//! accounts. Each account record consists of a small header, a primary data buffer, and an
//! identical shadow buffer for CoW operations.
//!
//! ```text
//! +---------------------------------------------------------------------------------------------+
//! | Section      | Field               | Size (bytes) | Offset | Description                    |
//! |--------------|---------------------|--------------|--------|--------------------------------|
//! |              | 1. Shadow Switch    | 4            | 0      | Atomic counter for CoW buffer. |
//! |     Meta     | 2. Shadow Offset    | 4            | 4      | Byte offset to the shadow copy.|
//! |--------------|---------------------|--------------|--------|--------------------------------|
//! |              | 3. Lamports         | 8            | 8      | Account balance.               |
//! |              | 4. Owner            | 32           | 16     | Public key of the owner.       |
//! |              | 5. Remote Slot      | 8            | 48     | Remote slot number.            |
//! |   Primary    | 6. Flags            | 4            | 56     | Bit-packed flags (e.g., exec). |
//! |    Buffer    | 7. Data Capacity    | 4            | 60     | Max capacity of account data.  |
//! |              | 8. Data Length      | 4            | 64     | Current length of data.        |
//! |              | 9. Data             | Variable     | 68     | Account data payload.          |
//! |              | 10. Padding         | Variable     | -      | Aligns buffer to 8 bytes.      |
//! |--------------|---------------------|--------------|--------|--------------------------------|
//! | Shadow Buf   | Fields 3-10 cloned  | eq primary   | -      | Shadow copy for modifications. |
//! +---------------------------------------------------------------------------------------------+
//! ```
//!
use std::{
    mem::{align_of, size_of},
    ops::{Deref, DerefMut, Div, Mul},
    ptr::NonNull,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use solana_pubkey::Pubkey;

use crate::AccountSharedData;

// --- Memory Layout Offsets ---
// NOTE: These constants define the memory layout of a serialized account and must
// be kept in sync with the `serialize_to_mmap` function.
const LAMPORTS_OFFSET: usize = 0;
const OWNER_OFFSET: usize = LAMPORTS_OFFSET + size_of::<u64>();
const REMOTE_SLOT_OFFSET: usize = OWNER_OFFSET + size_of::<Pubkey>();
const FLAGS_OFFSET: usize = REMOTE_SLOT_OFFSET + size_of::<u64>();
const DATA_CAPACITY_OFFSET: usize = FLAGS_OFFSET + size_of::<u32>();
const DATA_LEN_OFFSET: usize = DATA_CAPACITY_OFFSET + size_of::<u32>();
const DATA_START_OFFSET: usize = DATA_LEN_OFFSET + size_of::<u32>();

/// The byte offset to find the data length (`u32`) relative to the data pointer.
/// This is a performance optimization that relies on the fixed memory layout
/// where `data_len` is stored immediately before `data`.
///
/// NOTE: Any changes to the memory layout must be reflected here.
const RELATIVE_DATA_LEN_OFFSET: isize = -4;
#[cfg(test)]
pub(crate) const RELATIVE_DATA_LEN_POINTER_OFFSET_TEST: isize = RELATIVE_DATA_LEN_OFFSET;

// --- Flag bit indices (stored in u32 at FLAGS_OFFSET) ---
pub(crate) const EXECUTABLE_FLAG_INDEX: u32 = 0;
pub(crate) const DELEGATED_FLAG_INDEX: u32 = 1;
pub(crate) const PRIVILEGED_FLAG_INDEX: u32 = 2;
pub(crate) const COMPRESSED_FLAG_INDEX: u32 = 3;
pub(crate) const UNDELEGATING_FLAG_INDEX: u32 = 4;
pub(crate) const CONFINED_FLAG_INDEX: u32 = 5;
pub(crate) const EPHEMERAL_FLAG_INDEX: u32 = 6;

// Static assertion: all flag indices fit in u8 (BitFlagsOwned truncates u32 -> u8).
const _: () = assert!(EPHEMERAL_FLAG_INDEX < 8);

// --- Marker bit indices (runtime state, not persisted) ---
pub(crate) const IS_DIRTY_MARKER_INDEX: u32 = 0;
pub(crate) const OWNER_CHANGED_MARKER_INDEX: u32 = 1;
pub(crate) const LAMPORTS_CHANGED_MARKER_INDEX: u32 = 2;

/// A memory-optimized, "borrowed" view of a Solana account residing in a memory-mapped region.
///
/// This struct uses a single pointer to directly access and manipulate the serialized account data,
/// avoiding deserialization costs. It implements a Copy-on-Write (CoW) mechanism to handle
/// modifications: changes are written to a separate "shadow" buffer, ensuring the original
/// data remains untouched until the changes are committed.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountBorrowed {
    /// An atomic counter that determines which buffer (primary or shadow) is active.
    /// Even values indicate the primary buffer, odd values indicate the shadow buffer.
    shadow_switch: ShadowSwitch,
    /// The byte offset to the shadow buffer. A positive value means the primary buffer is active,
    /// and a negative value means the shadow buffer is active. A value of `0` indicates
    /// that a CoW has already occurred and no further copies are needed.
    shadow_offset: isize,
    /// Pointer to the start of the active buffer (lamports field).
    buffer: NonNull<u8>,
    /// Runtime markers (not persisted to disk):
    /// - bit 0: `is_dirty` - account has been modified
    /// - bit 1: `owner_changed` - owner field was modified
    /// - bit 2: `lamports_changed` - lamports field was modified
    pub(crate) markers: BitFlagsOwned,
}

/// Bit-packed flags stored inline (u8).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct BitFlagsOwned(u8);

impl From<AccountBorrowed> for AccountSharedData {
    fn from(value: AccountBorrowed) -> Self {
        Self::Borrowed(value)
    }
}

// SAFETY: `AccountBorrowed` is safe to send across threads because the underlying
// data is in a shared memory map. Synchronization for writes is handled by the CoW
// mechanism and the atomic `ShadowSwitch`. Concurrent writes to the same account
// are undefined behavior and must be prevented by higher-level locking.
unsafe impl Send for AccountBorrowed {}
// SAFETY: See `Send`. Access is synchronized via atomics for the switch, and writes
// are isolated via CoW. Concurrent writes are UB.
unsafe impl Sync for AccountBorrowed {}

impl AccountBorrowed {
    // --- Field accessors ---

    /// Returns a pointer to the lamports field.
    pub(crate) fn lamports(&self) -> *mut u64 {
        self.buffer.as_ptr() as *mut u64
    }

    /// Returns a pointer to the owner field.
    pub(crate) fn owner(&self) -> *mut Pubkey {
        // SAFETY: buffer is guaranteed to be valid and OWNER_OFFSET is within bounds.
        unsafe { self.buffer.as_ptr().add(OWNER_OFFSET) as *mut Pubkey }
    }

    /// Returns a pointer to the remote_slot field.
    pub(crate) fn remote_slot(&self) -> *mut u64 {
        // SAFETY: buffer is guaranteed to be valid and REMOTE_SLOT_OFFSET is within bounds.
        unsafe { self.buffer.as_ptr().add(REMOTE_SLOT_OFFSET) as *mut u64 }
    }

    /// Returns a pointer to the start of the data payload.
    pub(crate) fn data(&self) -> *mut u8 {
        // SAFETY: buffer is guaranteed to be valid and DATA_START_OFFSET is within bounds.
        unsafe { self.buffer.as_ptr().add(DATA_START_OFFSET) }
    }

    /// Returns the data length.
    pub(crate) fn data_len(&self) -> u32 {
        // SAFETY: buffer is guaranteed to be valid and DATA_LEN_OFFSET is within bounds.
        unsafe { *(self.buffer.as_ptr().add(DATA_LEN_OFFSET) as *const u32) }
    }

    /// Returns the data capacity.
    pub(crate) fn data_cap(&self) -> u32 {
        // SAFETY: buffer is guaranteed to be valid and DATA_CAPACITY_OFFSET is within bounds.
        unsafe { *(self.buffer.as_ptr().add(DATA_CAPACITY_OFFSET) as *const u32) }
    }

    /// Returns a reference to the account's data as a slice.
    pub(crate) fn data_as_slice(&self) -> &[u8] {
        // SAFETY: data() and data_len() are guaranteed to be valid.
        unsafe { std::slice::from_raw_parts(self.data(), self.data_len() as usize) }
    }

    /// Returns a mutable reference to the account's data as a slice.
    pub(crate) fn data_as_slice_mut(&mut self) -> &mut [u8] {
        // SAFETY: data() and data_len() are guaranteed to be valid.
        unsafe { std::slice::from_raw_parts_mut(self.data(), self.data_len() as usize) }
    }

    /// Returns a DataSlice for modifying the data length in memory.
    pub(crate) fn data_slice_mut(&mut self) -> DataSlice {
        DataSlice {
            ptr: self.data(),
            len: self.data_len(),
            cap: self.data_cap(),
        }
    }

    // --- Flag accessors ---

    /// Checks if the flag at `index` is set.
    pub(crate) fn flag_is_set(&self, index: u32) -> bool {
        // SAFETY: buffer is valid and FLAGS_OFFSET is within bounds.
        unsafe { (*(self.buffer.as_ptr().add(FLAGS_OFFSET) as *const u32) >> index) & 1 == 1 }
    }

    /// Sets or clears the flag at `index`.
    pub(crate) fn set_flag(&mut self, val: bool, index: u32) {
        // SAFETY: buffer is valid, FLAGS_OFFSET is within bounds.
        // Modifications only occur after CoW, so we write to a private shadow buffer.
        unsafe {
            let flags = self.buffer.as_ptr().add(FLAGS_OFFSET) as *mut u32;
            if val {
                *flags |= 1 << index;
            } else {
                *flags &= !(1 << index);
            }
        }
    }

    /// Copies flags to an owned BitFlagsOwned.
    pub(crate) fn flags_into_owned(&self) -> BitFlagsOwned {
        // SAFETY: buffer is valid and FLAGS_OFFSET is within bounds.
        BitFlagsOwned(unsafe { *(self.buffer.as_ptr().add(FLAGS_OFFSET) as *const u32) } as u8)
    }

    // --- CoW operations ---

    /// Performs a Copy-on-Write (CoW) by copying the active buffer to its shadow buffer.
    ///
    /// After the copy, the buffer pointer is updated to point to the shadow buffer.
    /// This function is idempotent; it does nothing if CoW has already occurred.
    ///
    /// # Safety
    ///
    /// The `AccountBorrowed` instance must be properly initialized with a valid shadow buffer.
    pub unsafe fn cow(&mut self) {
        if self.shadow_offset == 0 {
            return;
        }
        self.markers.set(true, IS_DIRTY_MARKER_INDEX);

        let src = self.buffer.as_ptr();
        let dst = src.offset(self.shadow_offset);
        dst.copy_from_nonoverlapping(src, self.shadow_offset.unsigned_abs());

        self.buffer = NonNull::new_unchecked(dst);
        self.shadow_offset = 0;
    }

    /// Commits changes by incrementing the `shadow_switch` counter.
    ///
    /// This atomically makes the shadow buffer the new primary buffer.
    /// No-op if no CoW occurred.
    ///
    /// Note: calling this method multiple times after a single `cow()` will increment the
    /// counter each time, corrupting the shadow switch state. The caller must ensure
    /// `commit()` is called at most once after each `cow()`.
    pub fn commit(&self) {
        if self.shadow_offset == 0 {
            self.shadow_switch.increment();
        }
    }

    /// Rolls back to the previous buffer by decrementing the shadow switch.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that a prior `commit()` was called (not just `cow()`).
    /// `commit()` increments the counter via `ShadowSwitch::increment`, while `cow()` does not.
    /// Calling `rollback` without a prior `commit` might cause `fetch_sub` to underflow
    /// the atomic `u32` counter (e.g., 0 -> u32::MAX), corrupting the `shadow_switch` state.
    pub unsafe fn rollback(&self) {
        (*self.shadow_switch.0).fetch_sub(1, Ordering::Release);
    }

    // --- Utility methods ---

    /// Checks if the owner matches any in the provided slice.
    ///
    /// Returns `None` if the account has zero lamports (non-existent).
    ///
    /// # Safety
    ///
    /// `memptr` must point to a valid, initialized account record including metadata header.
    pub unsafe fn any_owner_matches(memptr: *mut u8, others: &[Pubkey]) -> Option<usize> {
        let buffer = AccountSharedData::init_deserialization(memptr).buffer;

        if *(buffer as *const u64) == 0 {
            return None;
        }

        let owner = buffer.add(OWNER_OFFSET) as *const Pubkey;
        others.iter().position(|o| *o == *owner)
    }

    /// Creates a sequence lock guard for optimistic reads.
    pub fn lock(&self) -> AccountSeqLock {
        AccountSeqLock {
            counter: self.shadow_switch.clone(),
            current: self.shadow_switch.counter(),
        }
    }

    /// Re-deserializes from the original memory location.
    pub fn reinit(&self) -> AccountSharedData {
        // SAFETY: shadow_switch points to valid memory allocation.
        unsafe { AccountSharedData::deserialize_from_mmap(self.shadow_switch.inner()).into() }
    }

    /// Sets the privileged flag for the account.
    pub fn set_privileged(&mut self, privileged: bool) {
        unsafe { self.cow() };
        self.set_flag(privileged, PRIVILEGED_FLAG_INDEX);
    }

    /// Returns whether the account has privileged runtime access.
    pub fn privileged(&self) -> bool {
        self.flag_is_set(PRIVILEGED_FLAG_INDEX)
    }

    /// Returns whether the account's owner has been modified.
    pub fn owner_changed(&self) -> bool {
        self.markers.is_set(OWNER_CHANGED_MARKER_INDEX)
    }

    /// Returns whether the account's balance has been modified.
    pub fn lamports_changed(&self) -> bool {
        self.markers.is_set(LAMPORTS_CHANGED_MARKER_INDEX)
    }

    /// Returns the entire active buffer as a static slice.
    ///
    /// The buffer contains all serialized fields (lamports, owner, remote_slot, flags,
    /// data_capacity, data_length) plus the data payload and slack space.
    pub fn buffer(&self) -> &'static [u8] {
        let size = AccountSharedData::ACCOUNT_STATIC_SIZE as usize + self.data_cap() as usize;
        // SAFETY: buffer points to valid memory-mapped data with 'static lifetime.
        unsafe { std::slice::from_raw_parts(self.buffer.as_ptr(), size) }
    }
}

/// A standard, heap-allocated representation of a Solana account.
///
/// This is the "owned" variant of `AccountSharedData`, used when an account's data
/// needs to grow beyond its memory-mapped capacity or when a non-mmap-backed
/// account is needed.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct AccountOwned {
    /// Lamports in the account.
    pub(crate) lamports: u64,
    /// Data held in this account, wrapped in an `Arc` for cheap cloning.
    pub(crate) data: Arc<Vec<u8>>,
    /// The program that owns this account.
    pub(crate) owner: Pubkey,
    /// Remote slot number.
    pub(crate) remote_slot: u64,
    /// Various boolean flags (bit packed):
    /// - bit 0: executable
    /// - bit 1: delegated
    /// - bit 2: privileged (unused in Owned variant)
    /// - bit 3: compressed
    /// - bit 4: undelegating
    /// - bit 5: confined
    /// - bit 6: ephemeral
    pub(crate) flags: BitFlagsOwned,
}

impl Default for AccountSharedData {
    fn default() -> Self {
        Self::Owned(AccountOwned::default())
    }
}

/// Helper for deserialization.
struct Deserialization {
    buffer: *mut u8,
    shadow_switch: ShadowSwitch,
    shadow_offset: isize,
}

/// A helper for serializing/deserializing data from a raw byte pointer.
/// It acts as a cursor over the memory region.
struct BytesSerDe {
    ptr: *mut u8,
}

impl BytesSerDe {
    fn new(ptr: *mut u8) -> Self {
        Self { ptr }
    }

    /// Writes a value of type `T` to the current position and advances the pointer.
    unsafe fn write<T: Sized>(&mut self, val: T) {
        (self.ptr as *mut T).write_unaligned(val);
        self.ptr = self.ptr.add(size_of::<T>());
    }

    /// Writes a slice's length (`u32`) followed by its data, and advances the pointer.
    unsafe fn write_slice(&mut self, slice: &[u8]) {
        self.write(slice.len() as u32);
        self.ptr
            .copy_from_nonoverlapping(slice.as_ptr(), slice.len());
        self.ptr = self.ptr.add(slice.len());
    }
}

impl AccountSharedData {
    /// Size of the metadata header (shadow switch and offset).
    const SERIALIZED_META_SIZE: u32 = (size_of::<u32>() * 2) as u32;
    /// The required memory alignment for the account buffers.
    const SERIALIZATION_ALIGNMENT: u32 = align_of::<u64>() as u32;
    /// Total size of the fixed-size fields in a serialized account buffer.
    pub const ACCOUNT_STATIC_SIZE: u32 = (DATA_LEN_OFFSET + size_of::<u32>()) as u32;

    /// Calculates the total serialized size for an account, including its shadow buffer
    /// and metadata, aligned to a specified boundary.
    pub const fn serialized_size_aligned(data_len: u32, alignment: u32) -> u32 {
        const fn align_up(size: u32, align: u32) -> u32 {
            // Equivalent to `(size + align - 1) / align * align`
            size.div_ceil(align).wrapping_mul(align)
        }
        // Size of one buffer (static fields + data).
        let base_size = Self::ACCOUNT_STATIC_SIZE + data_len;

        // Align the buffer size up to ensure 8-byte alignment for fields.
        let aligned_buffer_size = align_up(base_size, Self::SERIALIZATION_ALIGNMENT);

        // Total size is metadata + two aligned buffers (primary and shadow).
        let total_size = Self::SERIALIZED_META_SIZE + aligned_buffer_size * 2;

        // Align the final total size to the user-requested alignment.
        align_up(total_size, alignment)
    }

    /// Calculates the optimal data capacity for a single buffer given a total allocation size.
    /// This function derives the usable space per buffer from the total size provided
    /// by `serialized_size_aligned`.
    #[inline]
    fn calculate_capacity(total_capacity: u32) -> u32 {
        total_capacity
            // 1. Subtract metadata size
            .saturating_sub(Self::SERIALIZED_META_SIZE)
            // 2. Halve it for one buffer (primary or shadow)
            .div(2)
            // 3. Floor to the nearest alignment boundary (integer division trick)
            .div(Self::SERIALIZATION_ALIGNMENT)
            .mul(Self::SERIALIZATION_ALIGNMENT)
    }

    /// Serializes an `AccountOwned` into a memory-mapped region.
    ///
    /// **NOTE**: since the privileged flag is only supported in [AccountBorrowed], it is
    /// set to the default value of `false` here.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// 1. `memptr` points to a valid, exclusively owned memory region.
    /// 2. The memory region is aligned to at least 8 bytes (`SERIALIZATION_ALIGNMENT`).
    /// 3. The region has sufficient `capacity`, which must be a value returned from
    ///    `serialized_size_aligned` to ensure the correct layout and space for the shadow buffer.
    ///    Mismatching capacity can lead to buffer overflows and undefined behavior.
    pub unsafe fn serialize_to_mmap(acc: &AccountOwned, memptr: *mut u8, capacity: u32) {
        // Calculate the actual size of a single buffer based on the total allocation size.
        let single_buffer_capacity = Self::calculate_capacity(capacity);

        let mut serializer = BytesSerDe::new(memptr);

        // --- Write Metadata Header ---
        // 1. Shadow Switch: Starts at 0, pointing to the first (primary) buffer.
        serializer.write(0u32);
        // 2. Shadow Offset: The size of a single buffer, which is the distance to the shadow copy.
        serializer.write(single_buffer_capacity);

        // --- Write Primary Buffer ---
        // 3. Lamports
        serializer.write(acc.lamports);
        // 4. Owner
        serializer.write(acc.owner);
        // 5. Remote Slot
        serializer.write(acc.remote_slot);
        // 6. Flags (bit-packed)
        let flags = acc.flags.0 as u32;
        serializer.write(flags);
        // 7. Data Capacity
        let data_capacity = single_buffer_capacity.saturating_sub(Self::ACCOUNT_STATIC_SIZE);
        serializer.write(data_capacity);
        // 8. Data Length and Payload
        serializer.write_slice(&acc.data);

        // 9. Zero out slack space (between data end and buffer end)
        let slack_size = data_capacity as usize - acc.data.len();
        serializer.ptr.write_bytes(0, slack_size);

        // 10. Zero out the shadow buffer
        let shadow_start =
            memptr.add(Self::SERIALIZED_META_SIZE as usize + single_buffer_capacity as usize);
        shadow_start.write_bytes(0, single_buffer_capacity as usize);
    }

    /// Deserializes an `AccountBorrowed` from a memory-mapped region.
    ///
    /// # Safety
    ///
    /// `memptr` must be aligned to 8 bytes and point to a memory region containing a
    /// correctly serialized account, including metadata and a shadow buffer. The layout
    /// must match the one produced by `serialize_to_mmap`.
    pub unsafe fn deserialize_from_mmap(memptr: *mut u8) -> AccountBorrowed {
        let Deserialization {
            buffer,
            shadow_switch,
            shadow_offset,
        } = Self::init_deserialization(memptr);

        AccountBorrowed {
            buffer: NonNull::new_unchecked(buffer),
            shadow_offset,
            shadow_switch,
            markers: BitFlagsOwned::default(),
        }
    }

    /// Reads metadata header and computes pointer to active buffer.
    unsafe fn init_deserialization(memptr: *mut u8) -> Deserialization {
        let shadow_switch = ShadowSwitch::from(memptr as *mut AtomicU32);
        let shadow_offset = *(memptr.add(size_of::<u32>()) as *const u32) as isize;

        // Check if the shadow switch is odd. An odd value means the shadow buffer is active.
        let is_shadow_active = shadow_switch.counter() % 2 == 1;

        // Skip the metadata header to get to the start of the primary buffer.
        let buffer = memptr.add(Self::SERIALIZED_META_SIZE as usize);

        let (buffer, shadow_offset) = if is_shadow_active {
            // The shadow buffer is active. Jump to the start of it.
            // Invert the offset. Now, a CoW will copy from the shadow buffer *back*
            // to the primary buffer.
            (buffer.offset(shadow_offset), -shadow_offset)
        } else {
            (buffer, shadow_offset)
        };

        Deserialization {
            buffer,
            shadow_offset,
            shadow_switch,
        }
    }

    /// Returns `true` if the account has been modified.
    pub fn is_dirty(&self) -> bool {
        match self {
            Self::Borrowed(acc) => acc.markers.is_set(IS_DIRTY_MARKER_INDEX),
            // Owned accounts are heap-allocated copies, so they are always considered "dirty".
            Self::Owned(_) => true,
        }
    }

    /// Rolls back a Borrowed account to its previous buffer state.
    /// Note: Does nothing if the account is Owned.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that if this is a `Borrowed` variant, the account has
    /// previously initialized a valid buffer to rollback to. This requires a prior `commit()`
    /// call (not just `cow()`). `commit()` increments the counter via `ShadowSwitch::increment`,
    /// while `cow()` does not. If the account is `Owned`, this function has no effect and is always safe.
    pub unsafe fn rollback(&self) {
        if let Self::Borrowed(acc) = self {
            acc.rollback();
        }
    }
}

impl BitFlagsOwned {
    /// Checks if the bit at `index` is set.
    pub(crate) fn is_set(&self, index: u32) -> bool {
        (self.0 >> index) & 1 == 1
    }

    /// Sets or clears the bit at `index`.
    pub(crate) fn set(&mut self, val: bool, index: u32) {
        if val {
            self.0 |= 1 << index;
        } else {
            self.0 &= !(1 << index);
        }
    }
}

/// An atomic counter used as a sequence lock to select the active account buffer.
///
/// This struct wraps a pointer to an `AtomicU32`. Even counter values indicate the
/// primary buffer is active, while odd values indicate the shadow buffer is active.
/// This allows readers to optimistically read from a buffer and later check if a
/// write occurred concurrently.
#[repr(transparent)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ShadowSwitch(*const AtomicU32);

impl From<*mut AtomicU32> for ShadowSwitch {
    fn from(value: *mut AtomicU32) -> Self {
        Self(value)
    }
}

impl ShadowSwitch {
    /// Atomically loads the current value of the counter.
    pub(crate) fn counter(&self) -> u32 {
        // SAFETY: `self.0` points to a valid `AtomicU32` within the mmap region.
        // Atomic operations ensure thread safety. `Acquire` ordering ensures that
        // any writes made before the counter was incremented are visible to this thread.
        unsafe { (*self.0).load(Ordering::Acquire) }
    }

    /// Atomically increments the counter.
    fn increment(&self) {
        // SAFETY: `self.0` points to a valid `AtomicU32`.
        // `Release` ordering ensures that all writes to the shadow buffer are completed
        // before the counter is incremented, making them visible to other threads
        // that see the new counter value.
        unsafe { (*self.0).fetch_add(1, Ordering::Release) };
    }

    /// Returns the raw pointer to the start of the account's memory allocation.
    fn inner(&self) -> *mut u8 {
        self.0 as *mut u8
    }
}

/// A "fat pointer" representing a view into the account's data in the mmap region.
#[derive(Clone, PartialEq, Eq)]
pub struct DataSlice {
    pub(crate) ptr: *mut u8,
    pub(crate) len: u32,
    pub(crate) cap: u32,
}

impl Deref for DataSlice {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        // SAFETY: `ptr` and `len` are initialized from the serialized account data.
        // The lifetime is tied to the parent `AccountBorrowed`, which holds the mmap view.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len as usize) }
    }
}

impl DerefMut for DataSlice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: Similar to `Deref`. Mutable access is safe because modifications
        // only happen after a CoW, on a private shadow buffer.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len as usize) }
    }
}

impl DataSlice {
    /// Updates the length of the data slice, both in this struct and in the underlying memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `len` is less than or equal to the capacity (`self.cap`)
    /// and that the bytes from `0..len` in the backing store are properly initialized.
    pub(crate) unsafe fn set_len(&mut self, len: usize) {
        self.len = len as u32;
        // This is a performance hack that directly writes the new length to its known
        // location in memory, which is `RELATIVE_DATA_LEN_OFFSET` bytes
        // before the data pointer itself. This avoids needing a separate pointer.
        (self.ptr.offset(RELATIVE_DATA_LEN_OFFSET) as *mut u32).write_unaligned(len as u32);
    }
}

/// A guard used for optimistic reads, implementing a sequence lock pattern.
///
/// A reader creates this lock, reads data, and then calls `changed()` to see if
/// a writer modified the data during the read.
#[derive(Clone)]
pub struct AccountSeqLock {
    counter: ShadowSwitch,
    current: u32,
}

impl AccountSeqLock {
    /// Re-reads the current value of the atomic counter.
    pub fn relock(&mut self) {
        self.current = self.counter.counter();
    }

    /// Checks if the atomic counter has changed since the lock was created or last relocked.
    ///
    /// A change indicates a concurrent write occurred, and the data read may be inconsistent.
    pub fn changed(&self) -> bool {
        self.counter.counter() != self.current
    }
}

// SAFETY: `AccountSeqLock` is safe to send and sync across threads because it only
// contains a `ShadowSwitch`, which internally uses atomic operations for thread safety.
unsafe impl Send for AccountSeqLock {}
unsafe impl Sync for AccountSeqLock {}
