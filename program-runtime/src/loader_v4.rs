//! Loader-v4 account headers retain their wire layout even in unaligned mmap data.

use solana_instruction::error::InstructionError;
use solana_loader_v4_interface::state::{LoaderV4State, LoaderV4Status};
use solana_pubkey::Pubkey;
use std::mem::{offset_of, size_of};

const _: () = {
    assert!(size_of::<LoaderV4State>() == 48);
    assert!(offset_of!(LoaderV4State, slot) == 0);
    assert!(offset_of!(LoaderV4State, authority_address_or_next_version) == 8);
    assert!(offset_of!(LoaderV4State, status) == 40);
    assert!(LoaderV4Status::Retracted as u64 == 0);
    assert!(LoaderV4Status::Deployed as u64 == 1);
    assert!(LoaderV4Status::Finalized as u64 == 2);
};

/// Reads a header without creating an aligned reference or an invalid enum.
pub fn get_state(data: &[u8]) -> Result<LoaderV4State, InstructionError> {
    let data: &[u8; 48] = data
        .get(..LoaderV4State::program_data_offset())
        .ok_or(InstructionError::AccountDataTooSmall)?
        .try_into()
        .unwrap();
    let status = match u64::from_le_bytes(data[40..48].try_into().unwrap()) {
        0 => LoaderV4Status::Retracted,
        1 => LoaderV4Status::Deployed,
        2 => LoaderV4Status::Finalized,
        _ => return Err(InstructionError::InvalidAccountData),
    };
    Ok(LoaderV4State {
        slot: u64::from_le_bytes(data[..8].try_into().unwrap()),
        authority_address_or_next_version: Pubkey::new_from_array(data[8..40].try_into().unwrap()),
        status,
    })
}

/// Writes only the header; the program payload and account layout are unchanged.
pub fn set_state(data: &mut [u8], state: LoaderV4State) -> Result<(), InstructionError> {
    let data: &mut [u8; 48] = data
        .get_mut(..LoaderV4State::program_data_offset())
        .ok_or(InstructionError::AccountDataTooSmall)?
        .try_into()
        .unwrap();
    data[..8].copy_from_slice(&state.slot.to_le_bytes());
    data[8..40].copy_from_slice(state.authority_address_or_next_version.as_ref());
    data[40..48].copy_from_slice(&(state.status as u64).to_le_bytes());
    Ok(())
}
