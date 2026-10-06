#![cfg(feature = "agave-unstable-api")]
//! Loader-v4 management from Agave 4.0.0, retained for MagicBlock's cloned program
//! accounts and adapted to the Agave 4.2.2 execution and deployment runtime.
use {
    solana_bincode::limited_deserialize,
    solana_instruction::error::InstructionError,
    solana_loader_v3_interface::state::UpgradeableLoaderState,
    solana_loader_v4_interface::{
        DEPLOYMENT_COOLDOWN_IN_SLOTS,
        instruction::LoaderV4Instruction,
        state::{LoaderV4State, LoaderV4Status},
    },
    solana_program_runtime::{
        deploy_program,
        invoke_context::InvokeContext,
        program_cache_entry::{ProgramCacheEntry, ProgramCacheEntryOwner, ProgramCacheEntryType},
        vm::execute,
    },
    solana_pubkey::Pubkey,
    solana_sbpf::declare_builtin_function,
    solana_sdk_ids::{bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, loader_v4},
    solana_svm_log_collector::{LogCollector, ic_logger_msg},
    solana_svm_measure::measure::Measure,
    solana_svm_type_overrides::sync::Arc,
    solana_transaction_context::{
        instruction::InstructionContext, instruction_accounts::BorrowedInstructionAccount,
    },
    std::{
        cell::RefCell,
        cmp::Ordering,
        error::Error,
        mem::{align_of, offset_of},
        rc::Rc,
    },
};

pub const DEFAULT_COMPUTE_UNITS: u64 = 2_000;

pub fn get_state(data: &[u8]) -> Result<&LoaderV4State, InstructionError> {
    let header = data
        .get(..LoaderV4State::program_data_offset())
        .ok_or(InstructionError::AccountDataTooSmall)?;
    let status = u64::from_ne_bytes(
        header[offset_of!(LoaderV4State, status)..]
            .try_into()
            .unwrap(),
    );
    if !(header.as_ptr() as usize).is_multiple_of(align_of::<LoaderV4State>())
        || status > LoaderV4Status::Finalized as u64
    {
        return Err(InstructionError::InvalidAccountData);
    }
    // SAFETY: The complete header is aligned and its enum discriminant is valid.
    // Slot and Pubkey accept every bit pattern; the reference cannot outlive data.
    Ok(unsafe { &*header.as_ptr().cast::<LoaderV4State>() })
}

fn get_state_mut(data: &mut [u8]) -> Result<&mut LoaderV4State, InstructionError> {
    get_state(data)?;
    // SAFETY: get_state validated the layout, alignment and discriminant, and
    // the mutable slice gives this reference exclusive access to the header.
    Ok(unsafe { &mut *data.as_mut_ptr().cast::<LoaderV4State>() })
}

fn check_program_account(
    log_collector: &Option<Rc<RefCell<LogCollector>>>,
    instruction_context: &InstructionContext,
    program: &BorrowedInstructionAccount,
    authority_address: &Pubkey,
) -> Result<LoaderV4State, InstructionError> {
    if !loader_v4::check_id(program.get_owner()) {
        ic_logger_msg!(log_collector, "Program not owned by loader");
        return Err(InstructionError::InvalidAccountOwner);
    }
    let state = get_state(program.get_data())?;
    if !program.is_writable() {
        ic_logger_msg!(log_collector, "Program is not writeable");
        return Err(InstructionError::InvalidArgument);
    }
    if !instruction_context.is_instruction_account_signer(1)? {
        ic_logger_msg!(log_collector, "Authority did not sign");
        return Err(InstructionError::MissingRequiredSignature);
    }
    if state.authority_address_or_next_version != *authority_address {
        ic_logger_msg!(log_collector, "Incorrect authority provided");
        return Err(InstructionError::IncorrectAuthority);
    }
    if matches!(state.status, LoaderV4Status::Finalized) {
        ic_logger_msg!(log_collector, "Program is finalized");
        return Err(InstructionError::Immutable);
    }
    Ok(*state)
}

fn process_instruction_write(
    invoke_context: &mut InvokeContext,
    offset: u32,
    bytes: Vec<u8>,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(0)?;
    let authority_address = instruction_context.get_key_of_instruction_account(1)?;
    let state = check_program_account(
        &log_collector,
        &instruction_context,
        &program,
        authority_address,
    )?;
    if !matches!(state.status, LoaderV4Status::Retracted) {
        ic_logger_msg!(log_collector, "Program is not retracted");
        return Err(InstructionError::InvalidArgument);
    }
    let destination_offset = (offset as usize).saturating_add(LoaderV4State::program_data_offset());
    program
        .get_data_mut()?
        .get_mut(destination_offset..destination_offset.saturating_add(bytes.len()))
        .ok_or_else(|| {
            ic_logger_msg!(log_collector, "Write out of bounds");
            InstructionError::AccountDataTooSmall
        })?
        .copy_from_slice(&bytes);
    Ok(())
}

fn process_instruction_copy(
    invoke_context: &mut InvokeContext,
    destination_offset: u32,
    source_offset: u32,
    length: u32,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(0)?;
    let authority_address = instruction_context.get_key_of_instruction_account(1)?;
    let source_program = instruction_context.try_borrow_instruction_account(2)?;
    let state = check_program_account(
        &log_collector,
        &instruction_context,
        &program,
        authority_address,
    )?;
    if !matches!(state.status, LoaderV4Status::Retracted) {
        ic_logger_msg!(log_collector, "Program is not retracted");
        return Err(InstructionError::InvalidArgument);
    }
    let source_owner = &source_program.get_owner();
    let source_offset =
        (source_offset as usize).saturating_add(if loader_v4::check_id(source_owner) {
            LoaderV4State::program_data_offset()
        } else if bpf_loader_upgradeable::check_id(source_owner) {
            UpgradeableLoaderState::size_of_programdata_metadata()
        } else if bpf_loader_deprecated::check_id(source_owner)
            || bpf_loader::check_id(source_owner)
        {
            0
        } else {
            ic_logger_msg!(log_collector, "Source is not a program");
            return Err(InstructionError::InvalidArgument);
        });
    let data = source_program
        .get_data()
        .get(source_offset..source_offset.saturating_add(length as usize))
        .ok_or_else(|| {
            ic_logger_msg!(log_collector, "Read out of bounds");
            InstructionError::AccountDataTooSmall
        })?;
    let destination_offset =
        (destination_offset as usize).saturating_add(LoaderV4State::program_data_offset());
    program
        .get_data_mut()?
        .get_mut(destination_offset..destination_offset.saturating_add(length as usize))
        .ok_or_else(|| {
            ic_logger_msg!(log_collector, "Write out of bounds");
            InstructionError::AccountDataTooSmall
        })?
        .copy_from_slice(data);
    Ok(())
}

fn process_instruction_set_program_length(
    invoke_context: &mut InvokeContext,
    new_size: u32,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(0)?;
    let authority_address = instruction_context.get_key_of_instruction_account(1)?;
    let is_initialization = program.get_data().len() < LoaderV4State::program_data_offset();
    if is_initialization {
        if !loader_v4::check_id(program.get_owner()) {
            ic_logger_msg!(log_collector, "Program not owned by loader");
            return Err(InstructionError::InvalidAccountOwner);
        }
        if !program.is_writable() {
            ic_logger_msg!(log_collector, "Program is not writeable");
            return Err(InstructionError::InvalidArgument);
        }
        if !instruction_context.is_instruction_account_signer(1)? {
            ic_logger_msg!(log_collector, "Authority did not sign");
            return Err(InstructionError::MissingRequiredSignature);
        }
    } else {
        let state = check_program_account(
            &log_collector,
            &instruction_context,
            &program,
            authority_address,
        )?;
        if !matches!(state.status, LoaderV4Status::Retracted) {
            ic_logger_msg!(log_collector, "Program is not retracted");
            return Err(InstructionError::InvalidArgument);
        }
    }
    let required_lamports = if new_size == 0 {
        0
    } else {
        let rent = invoke_context
            .environment_config
            .sysvar_cache()
            .get_rent()?;
        rent.minimum_balance(LoaderV4State::program_data_offset().saturating_add(new_size as usize))
            .max(1)
    };
    match program.get_lamports().cmp(&required_lamports) {
        Ordering::Less => {
            ic_logger_msg!(
                log_collector,
                "Insufficient lamports, {} are required",
                required_lamports
            );
            return Err(InstructionError::InsufficientFunds);
        }
        Ordering::Greater => {
            let recipient = instruction_context.try_borrow_instruction_account(2).ok();
            if let Some(mut recipient) = recipient {
                if !instruction_context.is_instruction_account_writable(2)? {
                    ic_logger_msg!(log_collector, "Recipient is not writeable");
                    return Err(InstructionError::InvalidArgument);
                }
                let lamports_to_receive = program.get_lamports().saturating_sub(required_lamports);
                program.checked_sub_lamports(lamports_to_receive)?;
                recipient.checked_add_lamports(lamports_to_receive)?;
            } else if new_size == 0 {
                ic_logger_msg!(
                    log_collector,
                    "Closing a program requires a recipient account"
                );
                return Err(InstructionError::InvalidArgument);
            }
        }
        Ordering::Equal => {}
    }
    if new_size == 0 {
        program.set_data_length(0)?;
    } else {
        program.set_data_length(
            LoaderV4State::program_data_offset().saturating_add(new_size as usize),
        )?;
        if is_initialization {
            program.set_executable(true)?;
            let state = get_state_mut(program.get_data_mut()?)?;
            state.slot = 0;
            state.status = LoaderV4Status::Retracted;
            state.authority_address_or_next_version = *authority_address;
        }
    }
    Ok(())
}

fn process_instruction_deploy(invoke_context: &mut InvokeContext) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(0)?;
    let authority_address = instruction_context.get_key_of_instruction_account(1)?;
    let state = check_program_account(
        &log_collector,
        &instruction_context,
        &program,
        authority_address,
    )?;
    let current_slot = invoke_context
        .environment_config
        .sysvar_cache()
        .get_clock()?
        .slot;

    // Slot = 0 indicates that the program hasn't been deployed yet. So no need to check for the cooldown slots.
    // (Without this check, the program deployment is failing in freshly started test validators. That's
    //  because at startup current_slot is 0, which is < DEPLOYMENT_COOLDOWN_IN_SLOTS).
    if state.slot != 0 && state.slot.saturating_add(DEPLOYMENT_COOLDOWN_IN_SLOTS) > current_slot {
        ic_logger_msg!(
            log_collector,
            "Program was deployed recently, cooldown still in effect"
        );
        return Err(InstructionError::InvalidArgument);
    }
    if !matches!(state.status, LoaderV4Status::Retracted) {
        ic_logger_msg!(log_collector, "Destination program is not retracted");
        return Err(InstructionError::InvalidArgument);
    }

    let programdata = program
        .get_data()
        .get(LoaderV4State::program_data_offset()..)
        .ok_or(InstructionError::AccountDataTooSmall)?;
    deploy_program!(
        invoke_context,
        program.get_key(),
        &loader_v4::id(),
        program.get_data().len(),
        programdata,
        current_slot,
        invoke_context
            .get_feature_set()
            .disable_sbpf_v0_v1_v2_deployment,
    );

    let state = get_state_mut(program.get_data_mut()?)?;
    state.slot = current_slot;
    state.status = LoaderV4Status::Deployed;
    Ok(())
}

fn process_instruction_retract(invoke_context: &mut InvokeContext) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(0)?;

    let authority_address = instruction_context.get_key_of_instruction_account(1)?;
    let state = check_program_account(
        &log_collector,
        &instruction_context,
        &program,
        authority_address,
    )?;
    let current_slot = invoke_context
        .environment_config
        .sysvar_cache()
        .get_clock()?
        .slot;
    if state.slot.saturating_add(DEPLOYMENT_COOLDOWN_IN_SLOTS) > current_slot {
        ic_logger_msg!(
            log_collector,
            "Program was deployed recently, cooldown still in effect"
        );
        return Err(InstructionError::InvalidArgument);
    }
    if !matches!(state.status, LoaderV4Status::Deployed) {
        ic_logger_msg!(log_collector, "Program is not deployed");
        return Err(InstructionError::InvalidArgument);
    }
    let state = get_state_mut(program.get_data_mut()?)?;
    state.status = LoaderV4Status::Retracted;
    invoke_context
        .program_cache_for_tx_batch
        .store_modified_entry(
            *program.get_key(),
            Arc::new(ProgramCacheEntry::new_tombstone(
                current_slot,
                ProgramCacheEntryOwner::LoaderV4,
                ProgramCacheEntryType::Closed,
            )),
        );
    Ok(())
}

fn process_instruction_transfer_authority(
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(0)?;
    let authority_address = instruction_context.get_key_of_instruction_account(1)?;
    let new_authority_address = instruction_context.get_key_of_instruction_account(2)?;
    let state = check_program_account(
        &log_collector,
        &instruction_context,
        &program,
        authority_address,
    )?;
    if !instruction_context.is_instruction_account_signer(2)? {
        ic_logger_msg!(log_collector, "New authority did not sign");
        return Err(InstructionError::MissingRequiredSignature);
    }
    if state.authority_address_or_next_version == *new_authority_address {
        ic_logger_msg!(log_collector, "No change");
        return Err(InstructionError::InvalidArgument);
    }
    let state = get_state_mut(program.get_data_mut()?)?;
    state.authority_address_or_next_version = *new_authority_address;
    Ok(())
}

fn process_instruction_finalize(
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let program = instruction_context.try_borrow_instruction_account(0)?;
    let authority_address = instruction_context.get_key_of_instruction_account(1)?;
    let state = check_program_account(
        &log_collector,
        &instruction_context,
        &program,
        authority_address,
    )?;
    if !matches!(state.status, LoaderV4Status::Deployed) {
        ic_logger_msg!(log_collector, "Program must be deployed to be finalized");
        return Err(InstructionError::InvalidArgument);
    }
    drop(program);
    let next_version = instruction_context.try_borrow_instruction_account(2)?;
    if !loader_v4::check_id(next_version.get_owner()) {
        ic_logger_msg!(log_collector, "Next version is not owned by loader");
        return Err(InstructionError::InvalidAccountOwner);
    }
    let state_of_next_version = get_state(next_version.get_data())?;
    if state_of_next_version.authority_address_or_next_version != *authority_address {
        ic_logger_msg!(log_collector, "Next version has a different authority");
        return Err(InstructionError::IncorrectAuthority);
    }
    if matches!(state_of_next_version.status, LoaderV4Status::Finalized) {
        ic_logger_msg!(log_collector, "Next version is finalized");
        return Err(InstructionError::Immutable);
    }
    let address_of_next_version = *next_version.get_key();
    drop(next_version);
    let mut program = instruction_context.try_borrow_instruction_account(0)?;
    let state = get_state_mut(program.get_data_mut()?)?;
    state.authority_address_or_next_version = address_of_next_version;
    state.status = LoaderV4Status::Finalized;
    Ok(())
}

declare_builtin_function!(
    Entrypoint,
    fn rust(
        invoke_context: &mut InvokeContext<'static, 'static>,
        _arg0: u64,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
    ) -> Result<u64, Box<dyn Error>> {
        process_instruction_inner(invoke_context)
    }
);

fn process_instruction_inner<'a>(
    invoke_context: &mut InvokeContext<'a, 'a>,
) -> Result<u64, Box<dyn Error>> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let instruction_data = instruction_context.get_instruction_data();
    let program_id = instruction_context.get_program_key()?;
    if loader_v4::check_id(program_id) {
        invoke_context
            .compute_meter
            .consume_checked(DEFAULT_COMPUTE_UNITS)?;
        match limited_deserialize(instruction_data, solana_packet::PACKET_DATA_SIZE as u64)? {
            LoaderV4Instruction::Write { offset, bytes } => {
                process_instruction_write(invoke_context, offset, bytes)
            }
            LoaderV4Instruction::Copy {
                destination_offset,
                source_offset,
                length,
            } => {
                process_instruction_copy(invoke_context, destination_offset, source_offset, length)
            }
            LoaderV4Instruction::SetProgramLength { new_size } => {
                process_instruction_set_program_length(invoke_context, new_size)
            }
            LoaderV4Instruction::Deploy => process_instruction_deploy(invoke_context),
            LoaderV4Instruction::Retract => process_instruction_retract(invoke_context),
            LoaderV4Instruction::TransferAuthority => {
                process_instruction_transfer_authority(invoke_context)
            }
            LoaderV4Instruction::Finalize => process_instruction_finalize(invoke_context),
        }
        .map_err(|err| Box::new(err) as Box<dyn Error>)
    } else {
        let mut get_or_create_executor_time = Measure::start("get_or_create_executor_time");
        let loaded_program = invoke_context
            .program_cache_for_tx_batch
            .find(program_id)
            .ok_or_else(|| {
                ic_logger_msg!(log_collector, "Program is not cached");
                InstructionError::UnsupportedProgramId
            })?;
        get_or_create_executor_time.stop();
        invoke_context.timings.get_or_create_executor_us += get_or_create_executor_time.as_us();
        match &loaded_program.program {
            ProgramCacheEntryType::FailedVerification(_)
            | ProgramCacheEntryType::Closed
            | ProgramCacheEntryType::DelayVisibility => {
                ic_logger_msg!(log_collector, "Program is not deployed");
                Err(Box::new(InstructionError::UnsupportedProgramId) as Box<dyn Error>)
            }
            ProgramCacheEntryType::Loaded(executable) => {
                execute(executable, invoke_context, &loaded_program)
            }
            _ => Err(Box::new(InstructionError::UnsupportedProgramId) as Box<dyn Error>),
        }
    }
    .map(|_| 0)
}
