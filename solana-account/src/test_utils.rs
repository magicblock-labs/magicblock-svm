use std::alloc::Layout;

use crate::AccountSharedData;

const ALIGNMENT: u32 = 256;

pub struct BorrowedAccountBufferArea {
    pub ptr: *mut u8,
    pub layout: Layout,
    buffer_size: u32,
}

impl BorrowedAccountBufferArea {
    fn new(data_len: u32) -> Self {
        let buffer_size = AccountSharedData::serialized_size_aligned(data_len, ALIGNMENT);
        let layout = Layout::from_size_align(buffer_size as usize, ALIGNMENT as usize).unwrap();
        let ptr = unsafe { std::alloc::alloc(layout) };
        assert!(!ptr.is_null(), "Allocation failed");

        Self {
            ptr,
            layout,
            buffer_size,
        }
    }

    pub fn buffer_size(&self) -> u32 {
        self.buffer_size
    }
}
impl Drop for BorrowedAccountBufferArea {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

pub fn create_borrowed_account_shared_data(
    owned: &AccountSharedData,
    data_len: u32,
) -> (BorrowedAccountBufferArea, AccountSharedData) {
    let buffer_size: u32 = AccountSharedData::serialized_size_aligned(data_len, ALIGNMENT);
    let buffer = BorrowedAccountBufferArea::new(data_len);
    let AccountSharedData::Owned(ref acc) = owned else {
        panic!("invalid AccountSharedData initialization");
    };
    unsafe { AccountSharedData::serialize_to_mmap(acc, buffer.ptr, buffer_size) };

    let borrowed = unsafe { AccountSharedData::deserialize_from_mmap(buffer.ptr) };
    (buffer, AccountSharedData::Borrowed(borrowed))
}
