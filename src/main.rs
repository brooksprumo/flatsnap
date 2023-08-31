mod errors;
#[allow(dead_code, unused_imports)]
#[path = "../target/schema/snapshot_generated.rs"]
mod schema;
use {
    anyhow,
    clap::Parser,
    errors::de,
    flatbuffers::{self, ForwardsUOffset},
    im::HashMap as ImHashMap,
    itertools::Itertools,
    log::*,
    schema::solana::snapshot as fb,
    solana_runtime::{
        account_storage::{
            meta::StoredMetaWriteVersion, AccountStorageMap, AccountStorageReference,
        },
        accounts_db::{
            AccountShrinkThreshold, AccountStorageEntry, AtomicAppendVecId, BankHashStats,
            CalcAccountsHashDataSource,
        },
        accounts_file::AccountsFile,
        accounts_hash::{AccountsDeltaHash, AccountsHash},
        accounts_index::AccountSecondaryIndexes,
        ancestors::AncestorsForSerialization,
        bank::{Bank, EpochRewardStatus},
        blockhash_queue::{BlockhashQueue, HashAge},
        epoch_stakes::{EpochStakes, NodeVoteAccounts},
        hardened_unpack::open_genesis_config,
        rent_collector::RentCollector,
        runtime_config::RuntimeConfig,
        serde_snapshot::{
            self,
            storage::SerializableAccountStorageEntry,
            types::{SerdeAccountsHash, SerdeIncrementalAccountsHash},
            AccountsDbFields, BankIncrementalSnapshotPersistence, SnapshotAccountsDbFields,
        },
        snapshot_utils::{self, StorageAndNextAppendVecId},
        stake_history::StakeHistory,
        stakes::{Stakes, StakesCache, StakesEnum},
        vote_account::{VoteAccounts, VoteAccountsHashMap},
    },
    solana_sdk::{
        account::{Account, AccountSharedData, ReadableAccount},
        clock::Slot,
        epoch_schedule::{Epoch, EpochSchedule},
        fee_calculator::{FeeCalculator, FeeRateGovernor},
        genesis_config::GenesisConfig,
        hard_forks::HardForks,
        hash::Hash,
        inflation::Inflation,
        pubkey::Pubkey,
        rent::Rent,
        stake::state::Delegation,
        stake_history::StakeHistoryEntry,
    },
    std::{collections::HashMap, path::PathBuf, sync::Arc, time::Instant},
    tempfile::TempDir,
};

#[derive(Debug, Parser)]
struct Cli {
    /// Path to the ledger directory
    ledger_dir: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    debug!("{cli:?}");

    info!("Loading bank...");
    let temp_accounts_dir = TempDir::new()?;
    let timer = Instant::now();
    let (bank, genesis_config, account_paths) = {
        if let Some(ledger_dir) = &cli.ledger_dir {
            let bank_snapshots_dir = ledger_dir.join("snapshot");
            let accounts_dir = ledger_dir.join("accounts");
            let account_paths = [accounts_dir];
            let genesis_config = open_genesis_config(ledger_dir, u64::MAX);

            /* NOTE: Fastboot is broken in v1.16
             * snapshot_utils::bank_from_latest_snapshot_dir(
             *     bank_snapshots_dir,
             *     &genesis_config,
             *     &RuntimeConfig::default(),
             *     &[accounts_dir],
             *     None,
             *     None,
             *     AccountSecondaryIndexes::default(),
             *     None,
             *     AccountShrinkThreshold::default(),
             *     false,
             *     None,
             *     None,
             *     &Arc::default(),
             * )?
             */

            let (bank, ..) = snapshot_utils::bank_from_latest_snapshot_archives(
                bank_snapshots_dir,
                ledger_dir,
                ledger_dir,
                &account_paths,
                &genesis_config,
                &RuntimeConfig::default(),
                None,
                None,
                AccountSecondaryIndexes::default(),
                None,
                AccountShrinkThreshold::default(),
                false,
                true,
                false,
                None,
                None,
                &Arc::default(),
            )?;
            (bank, genesis_config, account_paths)
        } else {
            let account_paths = [temp_accounts_dir.path().to_path_buf()];
            let genesis_config = GenesisConfig::default();
            let mut bank = Arc::new(Bank::new_with_paths_for_tests(
                &genesis_config,
                RuntimeConfig::default().into(),
                account_paths.to_vec(),
                AccountSecondaryIndexes::default(),
                AccountShrinkThreshold::default(),
            ));
            for _ in 0..21 {
                bank = Arc::new(Bank::new_from_parent(
                    &bank,
                    &Pubkey::new_unique(),
                    bank.slot() + 1,
                ));
                bank.fill_bank_with_ticks_for_tests();
            }
            let bank = Arc::into_inner(bank).unwrap();
            bank.squash();
            bank.force_flush_accounts_cache();
            bank.update_accounts_hash(CalcAccountsHashDataSource::Storages, false, false);
            (bank, genesis_config, account_paths)
        }
    };
    info!("Loading bank... Done, and took {:?}", timer.elapsed());

    let snapshot_storages = bank.get_snapshot_storages(None);

    info!("Taking snapshot...");
    let timer = Instant::now();
    let serialized_snapshot = snapshot_bank(&bank, &snapshot_storages)?;
    info!("Taking snapshot... Done, and took {:?}", timer.elapsed());

    info!("Rebuilding from snapshot...");
    let timer = Instant::now();
    let deserialized_bank = rebuild_bank(
        serialized_snapshot,
        &genesis_config,
        &account_paths,
        &snapshot_storages,
    )?;
    info!(
        "Rebuilding from snapshot... Done, and took {:?}",
        timer.elapsed()
    );

    assert_eq!(deserialized_bank.slot(), bank.slot());
    assert_eq!(deserialized_bank.hash(), bank.hash());

    info!("Success!");
    Ok(())
}

fn snapshot_bank(
    bank: &Bank,
    snapshot_storages: &[Arc<AccountStorageEntry>],
) -> anyhow::Result<Box<[u8]>> {
    let ancestors_for_bank_fields = &bank.ancestors;
    let ancestors_for_bank_fields = ancestors_for_bank_fields.into();
    let bank_fields = bank.get_fields_to_serialize(&ancestors_for_bank_fields);

    let mut fb_builder = flatbuffers::FlatBufferBuilder::with_capacity(/* 1 GiB */ 1 << 30);

    // TODO: change to use start_vector + push + end_vector ?
    let ancestors: Vec<_> = bank_fields
        .ancestors
        .keys()
        .map(|ancestor| {
            fb::AncestorsEntry::create(&mut fb_builder, &fb::AncestorsEntryArgs { slot: *ancestor })
        })
        .collect();
    let fb_ancestors = fb_builder.create_vector(&ancestors);

    let hard_forks: Vec<_> = bank_fields
        .hard_forks
        .read()
        .unwrap()
        .iter()
        .map(|hard_fork| {
            fb::HardForksEntry::create(
                &mut fb_builder,
                &fb::HardForksEntryArgs {
                    slot: hard_fork.0,
                    count: hard_fork.1 as u64,
                },
            )
        })
        .collect();
    let fb_hard_forks = fb_builder.create_vector_from_iter(hard_forks.into_iter());

    #[allow(deprecated)]
    let fee_rate_governor = bank_fields.fee_rate_governor;
    let fb_fee_rate_governor = fb::FeeRateGovernor::create(
        &mut fb_builder,
        &fb::FeeRateGovernorArgs {
            lamports_per_signature: fee_rate_governor.lamports_per_signature,
            target_lamports_per_signature: fee_rate_governor.target_lamports_per_signature,
            target_signatures_per_slot: fee_rate_governor.target_signatures_per_slot,
            min_lamports_per_signature: fee_rate_governor.min_lamports_per_signature,
            max_lamports_per_signature: fee_rate_governor.max_lamports_per_signature,
            burn_percent: fee_rate_governor.burn_percent,
        },
    );

    let rent_collector = bank_fields.rent_collector;
    let rent = rent_collector.rent;
    let fb_rent = fb::Rent::create(
        &mut fb_builder,
        &fb::RentArgs {
            lamports_per_byte_year: rent.lamports_per_byte_year,
            exemption_threshold: rent.exemption_threshold,
            burn_percent: rent.burn_percent,
        },
    );
    let fb_epoch_schedule_from_rent_collector = fb::EpochSchedule::create(
        &mut fb_builder,
        &fb::EpochScheduleArgs {
            slots_per_epoch: rent_collector.epoch_schedule.slots_per_epoch,
            leader_schedule_slot_offset: rent_collector.epoch_schedule.leader_schedule_slot_offset,
            warmup: rent_collector.epoch_schedule.warmup,
            first_normal_epoch: rent_collector.epoch_schedule.first_normal_epoch,
            first_normal_slot: rent_collector.epoch_schedule.first_normal_slot,
        },
    );
    let fb_rent_collector = fb::RentCollector::create(
        &mut fb_builder,
        &fb::RentCollectorArgs {
            epoch: rent_collector.epoch,
            epoch_schedule: Some(fb_epoch_schedule_from_rent_collector),
            slots_per_year: rent_collector.slots_per_year,
            rent: Some(fb_rent),
        },
    );

    let epoch_schedule = bank_fields.epoch_schedule;
    let fb_epoch_schedule = fb::EpochSchedule::create(
        &mut fb_builder,
        &fb::EpochScheduleArgs {
            slots_per_epoch: epoch_schedule.slots_per_epoch,
            leader_schedule_slot_offset: epoch_schedule.leader_schedule_slot_offset,
            warmup: epoch_schedule.warmup,
            first_normal_epoch: epoch_schedule.first_normal_epoch,
            first_normal_slot: epoch_schedule.first_normal_slot,
        },
    );

    let inflation = bank_fields.inflation;
    let fb_inflation = fb::Inflation::create(
        &mut fb_builder,
        &fb::InflationArgs {
            initial: inflation.initial,
            terminal: inflation.terminal,
            taper: inflation.taper,
            foundation: inflation.foundation,
            foundation_term: inflation.foundation_term,
        },
    );

    let fb_incremental_snapshot_persistence =
        bank.incremental_snapshot_persistence
            .as_ref()
            .map(|incremental_snapshot_persistence| {
                fb::IncrementalSnapshotPersistence::create(
                    &mut fb_builder,
                    &fb::IncrementalSnapshotPersistenceArgs {
                        full_slot: incremental_snapshot_persistence.full_slot,
                        full_hash: Some(bytemuck::cast_ref(
                            &incremental_snapshot_persistence.full_hash.0,
                        )),
                        full_capitalization: incremental_snapshot_persistence.full_capitalization,
                        incremental_hash: Some(bytemuck::cast_ref(
                            &incremental_snapshot_persistence.incremental_hash.0,
                        )),
                        incremental_capitalization: incremental_snapshot_persistence
                            .incremental_capitalization,
                    },
                )
            });

    let fb_blockhash_queue = create_fb_blockhash_queue(
        &mut fb_builder,
        &bank_fields.blockhash_queue.read().unwrap(),
    );
    let fb_stakes = create_fb_stakes_from_cache(&mut fb_builder, bank_fields.stakes);
    let fb_epoch_stakes = create_fb_epoch_stakes(&mut fb_builder, bank_fields.epoch_stakes);

    let fb_bank = fb::Bank::create(
        &mut fb_builder,
        &fb::BankArgs {
            epoch: bank_fields.epoch,
            block_height: bank_fields.block_height,
            slot: bank_fields.slot,
            hash: Some(bytemuck::cast_ref(&bank_fields.hash)),
            epoch_accounts_hash: bank
                .get_epoch_accounts_hash_to_serialize()
                .map(|epoch_accounts_hash| fb::Hash(epoch_accounts_hash.as_ref().to_bytes()))
                .as_ref(),
            parent_slot: bank_fields.parent_slot,
            parent_hash: Some(bytemuck::cast_ref(&bank_fields.parent_hash)),
            transaction_count: bank_fields.transaction_count,
            tick_height: bank_fields.tick_height,
            max_tick_height: bank_fields.max_tick_height,
            hashes_per_tick: bank_fields.hashes_per_tick,
            ticks_per_slot: bank_fields.ticks_per_slot,
            ns_per_slot: bank_fields.ns_per_slot.try_into().unwrap(),
            slots_per_year: bank_fields.slots_per_year,
            signature_count: bank_fields.signature_count,
            capitalization: bank_fields.capitalization,
            collector_id: Some(bytemuck::cast_ref(&bank_fields.collector_id)),
            collector_fees: bank_fields.collector_fees,
            collected_rent: bank_fields.collected_rent,
            accounts_data_size: bank_fields.accounts_data_len,
            is_delta: bank_fields.is_delta,
            ancestors: Some(fb_ancestors),
            hard_forks: Some(fb_hard_forks),
            genesis_creation_time: bank_fields.genesis_creation_time,
            //fee_calculator:FeeCalculator (deprecated);
            fee_rate_governor: Some(fb_fee_rate_governor),
            rent_collector: Some(fb_rent_collector),
            epoch_schedule: Some(fb_epoch_schedule),
            inflation: Some(fb_inflation),
            incremental_snapshot_persistence: fb_incremental_snapshot_persistence,
            blockhash_queue: Some(fb_blockhash_queue),
            stakes: Some(fb_stakes),
            epoch_stakes: Some(fb_epoch_stakes),
            epoch_rewards: None, // partitioned epoch rewards is not in v1.16
        },
    );

    let slot = bank.slot();
    let accounts_db = &bank.rc.accounts.accounts_db;

    let account_storages = create_fb_account_storages(&mut fb_builder, snapshot_storages);
    let fb_snapshot = fb::Snapshot::create(
        &mut fb_builder,
        &fb::SnapshotArgs {
            bank: Some(fb_bank),
            accounts_delta_hash: Some(bytemuck::cast_ref(
                &accounts_db.get_accounts_delta_hash(slot).unwrap().0, // TODO: unwrap -> Result
            )),
            accounts_hash: Some(bytemuck::cast_ref(
                &accounts_db.get_accounts_hash(slot).unwrap().0 .0, // TODO: unwrap -> Result
            )),
            account_storages: Some(account_storages),
        },
    );

    fb_builder.finish_minimal(fb_snapshot);
    info!("Snapshot size: {} bytes", fb_builder.finished_data().len());
    Ok(fb_builder.finished_data().into())
}

fn rebuild_bank(
    serialized_snapshot: Box<[u8]>,
    genesis_config: &GenesisConfig,
    account_paths: &[PathBuf],
    snapshot_storages: &[Arc<AccountStorageEntry>],
) -> anyhow::Result<Bank> {
    let fb_opts = flatbuffers::VerifierOptions {
        //max_depth: 64,
        max_tables: 100_000_000, // default: 1_000_000
        //max_apparent_size: 1 << 31,
        ..flatbuffers::VerifierOptions::default()
    };
    info!("Loading snapshot...");
    let timer = Instant::now();
    let fb_snapshot = fb::root_as_snapshot_with_opts(&fb_opts, &serialized_snapshot).unwrap();
    info!("Loading snapshot... Done, and took {:?}", timer.elapsed());
    trace!("deserialized snapshot: {fb_snapshot:#?}");

    info!("Getting fields from snapshot...");
    let timer = Instant::now();
    let fb_bank = fb_snapshot.bank().unwrap();
    let bank_fields = solana_runtime::bank::BankFieldsToDeserialize {
        blockhash_queue: new_blockhash_queue_from_fb(
            fb_bank
                .blockhash_queue()
                .ok_or(de::BankError::MissingBlockhashQueue)?,
        )?,
        ancestors: new_ancestors_from_fb(
            fb_bank.ancestors().ok_or(de::BankError::MissingAncestors)?,
        ),
        hash: fb_bank.hash().copied().unwrap().into(),
        parent_hash: fb_bank.parent_hash().copied().unwrap().into(),
        parent_slot: fb_bank.parent_slot(),
        hard_forks: new_hard_forks_from_fb(
            fb_bank
                .hard_forks()
                .ok_or(de::BankError::MissingHardForks)?,
        ),
        transaction_count: fb_bank.transaction_count(),
        tick_height: fb_bank.tick_height(),
        signature_count: fb_bank.signature_count(),
        capitalization: fb_bank.capitalization(),
        max_tick_height: fb_bank.max_tick_height(),
        hashes_per_tick: fb_bank.hashes_per_tick(),
        ticks_per_slot: fb_bank.ticks_per_slot(),
        ns_per_slot: fb_bank.ns_per_slot().into(),
        genesis_creation_time: fb_bank.genesis_creation_time(),
        slots_per_year: fb_bank.slots_per_year(),
        slot: fb_bank.slot(),
        epoch: fb_bank.epoch(),
        block_height: fb_bank.block_height(),
        collector_id: fb_bank.collector_id().copied().unwrap().into(),
        collector_fees: fb_bank.collector_fees(),
        fee_calculator: FeeCalculator::default(), // unused, I believe
        fee_rate_governor: new_fee_rate_governor_from_fb(
            fb_bank
                .fee_rate_governor()
                .ok_or(de::BankError::MissingFeeRateGovernor)?,
        ),
        collected_rent: fb_bank.collected_rent(),
        rent_collector: new_rent_collector_from_fb(
            fb_bank
                .rent_collector()
                .ok_or(de::BankError::MissingRentCollector)?,
        )?,
        epoch_schedule: new_epoch_schedule_from_fb(
            fb_bank
                .epoch_schedule()
                .ok_or(de::BankError::MissingEpochSchedule)?,
        ),
        inflation: new_inflation_from_fb(
            fb_bank.inflation().ok_or(de::BankError::MissingInflation)?,
        ),
        stakes: new_stakes_from_fb(fb_bank.stakes().ok_or(de::BankError::MissingStakes)?)?,
        epoch_stakes: new_epoch_stakes_from_fb(
            fb_bank
                .epoch_stakes()
                .ok_or(de::BankError::MissingEpochStakes)?,
        )?,
        is_delta: fb_bank.is_delta(),
        accounts_data_len: fb_bank.accounts_data_size(),
        incremental_snapshot_persistence: fb_bank
            .incremental_snapshot_persistence()
            .map(|fb| new_incremental_snapshot_persistence_from_fb(fb).unwrap()), // TODO: unwrap -> Result
        epoch_accounts_hash: fb_bank.epoch_accounts_hash().copied().map(Into::into),
        epoch_reward_status: EpochRewardStatus::Inactive, // partitioned epoch rewards is not in v1.16
    };
    let bank_fields = serde_snapshot::SnapshotBankFields {
        full: bank_fields,
        incremental: None,
    };

    let storages_map = new_account_storages_map_from_fb(fb_snapshot.account_storages().unwrap()); // TODO: unwrap -> Result
    let accounts_delta_hash =
        AccountsDeltaHash(fb_snapshot.accounts_delta_hash().copied().unwrap().into()); // TODO: unwrap -> Result
    let accounts_hash = AccountsHash(fb_snapshot.accounts_hash().copied().unwrap().into()); // TODO: unwrap -> Result
    let accounts_db_fields = AccountsDbFields(
        storages_map,
        StoredMetaWriteVersion::default(), // value shouldn't matter
        fb_bank.slot(),
        serde_snapshot::BankHashInfo {
            accounts_delta_hash: accounts_delta_hash.into(),
            accounts_hash: accounts_hash.into(),
            stats: BankHashStats::default(), // value shouldn't matter
        },
        Vec::default(), // unused: was for historical roots
        Vec::default(), // unused: was for historical roots with hash
    );
    let accounts_db_fields = SnapshotAccountsDbFields {
        full_snapshot_accounts_db_fields: accounts_db_fields,
        incremental_snapshot_accounts_db_fields: None,
    };
    let storages = AccountStorageMap::with_capacity(snapshot_storages.len());
    for snapshot_storage in snapshot_storages {
        let slot = snapshot_storage.slot();
        let append_vec_id = snapshot_storage.append_vec_id();

        let (accounts_file, num_accounts) = AccountsFile::new_from_file(
            &snapshot_storage.get_path(),
            snapshot_storage.written_bytes() as usize,
        )?;
        let account_storage_entry =
            AccountStorageEntry::new_existing(slot, append_vec_id, accounts_file, num_accounts);

        let key = slot;
        let value = AccountStorageReference {
            storage: account_storage_entry.into(),
            id: append_vec_id,
        };
        let old_value = storages.insert(key, value);
        assert!(
            old_value.is_none(),
            "key: {key:?}, old value: {old_value:?}"
        );
    }
    let storage_and_next_append_vec_id = StorageAndNextAppendVecId {
        storage: storages,
        next_append_vec_id: AtomicAppendVecId::new((snapshot_storages.len() + 1).try_into()?),
    };
    info!(
        "Getting fields from snapshot... Done, and took {:?}",
        timer.elapsed()
    );

    info!("Reconstructing bank from fields...");
    let timer = Instant::now();
    let bank = serde_snapshot::reconstruct_bank_from_fields(
        bank_fields,
        accounts_db_fields,
        genesis_config,
        &RuntimeConfig::default(),
        account_paths,
        storage_and_next_append_vec_id,
        None,
        None,
        AccountSecondaryIndexes::default(),
        None,
        AccountShrinkThreshold::default(),
        false,
        None,
        None,
        &Arc::new(false.into()),
    )?;
    info!(
        "Reconstructing bank from fields... Done, and took {:?}",
        timer.elapsed()
    );

    Ok(bank)
}

impl From<Hash> for fb::Hash {
    fn from(hash: Hash) -> fb::Hash {
        fb::Hash(hash.to_bytes())
    }
}
impl From<fb::Hash> for Hash {
    fn from(fb_hash: fb::Hash) -> Hash {
        fb_hash.0.into()
    }
}
unsafe impl bytemuck::Pod for fb::Hash {}
unsafe impl bytemuck::Zeroable for fb::Hash {}

impl From<Pubkey> for fb::Pubkey {
    fn from(pubkey: Pubkey) -> fb::Pubkey {
        fb::Pubkey(pubkey.to_bytes())
    }
}
impl From<fb::Pubkey> for Pubkey {
    fn from(fb_pubkey: fb::Pubkey) -> Pubkey {
        fb_pubkey.0.into()
    }
}
unsafe impl bytemuck::Pod for fb::Pubkey {}
unsafe impl bytemuck::Zeroable for fb::Pubkey {}

fn create_fb_account<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    account: &impl ReadableAccount,
) -> flatbuffers::WIPOffset<fb::Account<'bldr>> {
    let fb_account_data = fbb.create_vector(account.data());
    fb::Account::create(
        fbb,
        &fb::AccountArgs {
            lamports: account.lamports(),
            data: Some(fb_account_data),
            owner: Some(bytemuck::cast_ref(account.owner())),
            executable: account.executable(),
            rent_epoch: account.rent_epoch(),
        },
    )
}
fn new_account_from_fb(fb: fb::Account<'_>) -> Result<Account, de::AccountError> {
    Ok(Account {
        lamports: fb.lamports(),
        data: fb
            .data()
            .ok_or(de::AccountError::MissingData)?
            .iter()
            .collect(),
        owner: fb
            .owner()
            .copied()
            .ok_or(de::AccountError::MissingOwner)?
            .into(),
        executable: fb.executable(),
        rent_epoch: fb.rent_epoch(),
    })
}

fn create_fb_fee_calculator<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    fee_calculator: &FeeCalculator,
) -> flatbuffers::WIPOffset<fb::FeeCalculator<'bldr>> {
    fb::FeeCalculator::create(
        fbb,
        &fb::FeeCalculatorArgs {
            lamports_per_signature: fee_calculator.lamports_per_signature,
        },
    )
}
fn new_fee_calculator_from_fb(fb: fb::FeeCalculator<'_>) -> FeeCalculator {
    FeeCalculator {
        lamports_per_signature: fb.lamports_per_signature(),
    }
}

fn create_fb_blockhash_queue_ages_entry<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    hash: &Hash,
    hash_age: &HashAge,
) -> flatbuffers::WIPOffset<fb::BlockhashAgesEntry<'bldr>> {
    let fb_fee_calculator = create_fb_fee_calculator(fbb, &hash_age.fee_calculator);
    fb::BlockhashAgesEntry::create(
        fbb,
        &fb::BlockhashAgesEntryArgs {
            hash_index: hash_age.hash_index,
            hash: Some(bytemuck::cast_ref(hash)),
            timestamp: hash_age.timestamp,
            fee_calculator: Some(fb_fee_calculator),
        },
    )
}
fn new_hash_age_from_fb(fb: fb::BlockhashAgesEntry<'_>) -> Result<HashAge, de::Error> {
    Ok(HashAge {
        fee_calculator: new_fee_calculator_from_fb(
            fb.fee_calculator()
                .ok_or_else(|| de::Error::MissingField("fee calculator".to_string()))?,
        ),
        hash_index: fb.hash_index(),
        timestamp: fb.timestamp(),
    })
}

fn create_fb_blockhash_queue_ages<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    ages: &HashMap<Hash, HashAge>,
) -> flatbuffers::WIPOffset<
    flatbuffers::Vector<'bldr, ForwardsUOffset<fb::BlockhashAgesEntry<'bldr>>>,
> {
    let fb_ages: Vec<_> = ages
        .iter()
        .map(|(hash, hash_age)| create_fb_blockhash_queue_ages_entry(fbb, hash, hash_age))
        .collect();
    fbb.create_vector(&fb_ages)
}
fn new_hash_ages_from_fb<'fb>(
    fb: flatbuffers::Vector<'fb, ForwardsUOffset<fb::BlockhashAgesEntry<'fb>>>,
) -> anyhow::Result<HashMap<Hash, HashAge>> {
    let mut ages = HashMap::with_capacity(fb.len());
    for fb_blockhash_ages_entry in fb.iter() {
        let hash = fb_blockhash_ages_entry.hash().copied().unwrap().into(); // TODO: unwrap -> Result
        let hash_age = new_hash_age_from_fb(fb_blockhash_ages_entry)?;
        let old_value = ages.insert(hash, hash_age);
        assert!(
            old_value.is_none(),
            "key already exists! key: {hash}, old value: {old_value:?}"
        );
    }
    Ok(ages)
}

fn create_fb_blockhash_queue<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    blockhash_queue: &BlockhashQueue,
) -> flatbuffers::WIPOffset<fb::BlockhashQueue<'bldr>> {
    let fb_ages = create_fb_blockhash_queue_ages(fbb, &blockhash_queue.ages);
    fb::BlockhashQueue::create(
        fbb,
        &fb::BlockhashQueueArgs {
            last_hash_index: blockhash_queue.last_hash_index,
            last_hash: blockhash_queue.last_hash.map(Into::into).as_ref(),
            max_age: blockhash_queue.max_age as u64,
            ages: Some(fb_ages),
        },
    )
}
fn new_blockhash_queue_from_fb(fb: fb::BlockhashQueue<'_>) -> anyhow::Result<BlockhashQueue> {
    Ok(BlockhashQueue {
        last_hash_index: fb.last_hash_index(),
        last_hash: fb.last_hash().copied().map(Into::into),
        max_age: fb.max_age().try_into()?,
        ages: new_hash_ages_from_fb(fb.ages().unwrap())?,
    })
}

fn new_ancestors_from_fb<'fb>(
    fb: flatbuffers::Vector<'fb, ForwardsUOffset<fb::AncestorsEntry<'fb>>>,
) -> AncestorsForSerialization {
    AncestorsForSerialization::from_iter(fb.iter().map(|ancestor_entry| {
        (
            ancestor_entry.slot(),
            usize::default(), // unused - value does not matter
        )
    }))
}

fn new_hard_forks_from_fb<'fb>(
    fb: flatbuffers::Vector<'fb, ForwardsUOffset<fb::HardForksEntry<'fb>>>,
) -> HardForks {
    HardForks {
        hard_forks: fb
            .iter()
            .map(|hard_forks_entry| (hard_forks_entry.slot(), hard_forks_entry.count() as usize)) // TODO: cast -> conversion
            .sorted_unstable()
            .collect(),
    }
}

fn new_fee_rate_governor_from_fb(fb: fb::FeeRateGovernor<'_>) -> FeeRateGovernor {
    FeeRateGovernor {
        lamports_per_signature: fb.lamports_per_signature(),
        target_lamports_per_signature: fb.target_lamports_per_signature(),
        target_signatures_per_slot: fb.target_signatures_per_slot(),
        min_lamports_per_signature: fb.min_lamports_per_signature(),
        max_lamports_per_signature: fb.max_lamports_per_signature(),
        burn_percent: fb.burn_percent(),
    }
}

fn new_rent_from_fb(fb: fb::Rent<'_>) -> Rent {
    Rent {
        lamports_per_byte_year: fb.lamports_per_byte_year(),
        exemption_threshold: fb.exemption_threshold(),
        burn_percent: fb.burn_percent(),
    }
}

fn new_epoch_schedule_from_fb(fb: fb::EpochSchedule<'_>) -> EpochSchedule {
    EpochSchedule {
        slots_per_epoch: fb.slots_per_epoch(),
        leader_schedule_slot_offset: fb.leader_schedule_slot_offset(),
        warmup: fb.warmup(),
        first_normal_epoch: fb.first_normal_epoch(),
        first_normal_slot: fb.first_normal_slot(),
    }
}

fn new_rent_collector_from_fb(
    fb: fb::RentCollector<'_>,
) -> Result<RentCollector, de::RentCollectorError> {
    Ok(RentCollector {
        epoch: fb.epoch(),
        epoch_schedule: new_epoch_schedule_from_fb(
            fb.epoch_schedule()
                .ok_or(de::RentCollectorError::MissingEpochSchedule)?,
        ),
        slots_per_year: fb.slots_per_year(),
        rent: new_rent_from_fb(fb.rent().ok_or(de::RentCollectorError::MissingRent)?),
    })
}

fn new_inflation_from_fb(fb: fb::Inflation<'_>) -> Inflation {
    Inflation {
        initial: fb.initial(),
        terminal: fb.terminal(),
        taper: fb.taper(),
        foundation: fb.foundation(),
        foundation_term: fb.foundation_term(),
        __unused: Default::default(),
    }
}

fn new_incremental_snapshot_persistence_from_fb(
    fb: fb::IncrementalSnapshotPersistence<'_>,
) -> Result<BankIncrementalSnapshotPersistence, de::IncrementalSnapshotPersistenceError> {
    Ok(BankIncrementalSnapshotPersistence {
        full_slot: fb.full_slot(),
        full_hash: SerdeAccountsHash(
            fb.full_hash()
                .copied()
                .ok_or(de::IncrementalSnapshotPersistenceError::MissingFullHash)?
                .into(),
        ),
        full_capitalization: fb.full_capitalization(),
        incremental_hash: SerdeIncrementalAccountsHash(
            fb.incremental_hash()
                .copied()
                .ok_or(de::IncrementalSnapshotPersistenceError::MissingIncrementalHash)?
                .into(),
        ),
        incremental_capitalization: fb.incremental_capitalization(),
    })
}

fn create_fb_vote_accounts_entry<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    pubkey: &Pubkey,
    stake: u64,
    vote_account: &impl ReadableAccount,
) -> flatbuffers::WIPOffset<fb::VoteAccountsEntry<'bldr>> {
    let fb_account = create_fb_account(fbb, vote_account);
    fb::VoteAccountsEntry::create(
        fbb,
        &fb::VoteAccountsEntryArgs {
            pubkey: Some(bytemuck::cast_ref(pubkey)),
            stake,
            account: Some(fb_account),
        },
    )
}

fn create_fb_vote_accounts<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    vote_accounts: &VoteAccountsHashMap,
) -> flatbuffers::WIPOffset<flatbuffers::Vector<'bldr, ForwardsUOffset<fb::VoteAccountsEntry<'bldr>>>>
{
    let fb_vote_accounts_entries: Vec<_> = vote_accounts
        .iter()
        .map(|(pubkey, (stake, vote_account))| {
            create_fb_vote_accounts_entry(fbb, pubkey, *stake, vote_account.account())
        })
        .collect();
    fbb.create_vector(&fb_vote_accounts_entries)
}
fn new_vote_accounts_from_fb<'fb>(
    fb: flatbuffers::Vector<'fb, ForwardsUOffset<fb::VoteAccountsEntry<'fb>>>,
) -> Result<VoteAccounts, de::VoteAccountError> {
    let mut vote_accounts = VoteAccountsHashMap::with_capacity(fb.len());
    for fb_vote_accounts_entry in fb.iter() {
        let pubkey = fb_vote_accounts_entry
            .pubkey()
            .copied()
            .ok_or(de::VoteAccountError::MissingPubkey)?
            .into();
        let stake = fb_vote_accounts_entry.stake();
        let account: AccountSharedData = new_account_from_fb(
            fb_vote_accounts_entry
                .account()
                .ok_or(de::VoteAccountError::MissingAccount)?,
        )?
        .into();
        let old_value = vote_accounts.insert(pubkey, (stake, account.try_into()?));
        assert!(
            old_value.is_none(),
            "key already exists! key: {pubkey}, old value: {old_value:?}"
        );
    }
    Ok(Arc::new(vote_accounts).into())
}

fn create_fb_stake_history_entry<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    epoch: Epoch,
    stake_history_entry: &StakeHistoryEntry,
) -> flatbuffers::WIPOffset<fb::StakeHistoryEntry<'bldr>> {
    fb::StakeHistoryEntry::create(
        fbb,
        &fb::StakeHistoryEntryArgs {
            epoch,
            effective: stake_history_entry.effective,
            activating: stake_history_entry.activating,
            deactivating: stake_history_entry.deactivating,
        },
    )
}

fn create_fb_stake_history<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    stake_history: &StakeHistory,
) -> flatbuffers::WIPOffset<flatbuffers::Vector<'bldr, ForwardsUOffset<fb::StakeHistoryEntry<'bldr>>>>
{
    let fb_stake_history_entries: Vec<_> = stake_history
        .iter()
        .map(|(epoch, stake_history_entry)| {
            create_fb_stake_history_entry(fbb, *epoch, stake_history_entry)
        })
        .collect();
    fbb.create_vector(&fb_stake_history_entries)
}
fn new_stake_history_from_fb<'fb>(
    fb: flatbuffers::Vector<'fb, ForwardsUOffset<fb::StakeHistoryEntry<'fb>>>,
) -> StakeHistory {
    let mut stake_history = StakeHistory::default();
    for fb_stake_history_entry in fb.iter() {
        let epoch = fb_stake_history_entry.epoch();
        let stake_history_entry = StakeHistoryEntry {
            effective: fb_stake_history_entry.effective(),
            activating: fb_stake_history_entry.activating(),
            deactivating: fb_stake_history_entry.deactivating(),
        };
        stake_history.add(epoch, stake_history_entry);
    }
    stake_history
}

fn create_fb_stake_delegations_entry<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    stake_pubkey: &Pubkey,
    delegation: &Delegation,
) -> flatbuffers::WIPOffset<fb::StakeDelegationsEntry<'bldr>> {
    fb::StakeDelegationsEntry::create(
        fbb,
        &fb::StakeDelegationsEntryArgs {
            stake_pubkey: Some(bytemuck::cast_ref(stake_pubkey)),
            voter_pubkey: Some(bytemuck::cast_ref(&delegation.voter_pubkey)),
            stake: delegation.stake,
            activation_epoch: delegation.activation_epoch,
            deactivation_epoch: delegation.deactivation_epoch,
            warmup_cooldown_rate: delegation.warmup_cooldown_rate,
        },
    )
}
fn new_stake_delegation_from_fb(
    fb: fb::StakeDelegationsEntry<'_>,
) -> Result<Delegation, de::StakeDelegationError> {
    Ok(Delegation {
        voter_pubkey: fb
            .voter_pubkey()
            .copied()
            .ok_or(de::StakeDelegationError::MissingVoterPubkey)?
            .into(),
        stake: fb.stake(),
        activation_epoch: fb.activation_epoch(),
        deactivation_epoch: fb.deactivation_epoch(),
        warmup_cooldown_rate: fb.warmup_cooldown_rate(),
    })
}

fn create_fb_stake_delegations<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    stake_delegations: &ImHashMap<Pubkey, Delegation>,
) -> flatbuffers::WIPOffset<
    flatbuffers::Vector<'bldr, ForwardsUOffset<fb::StakeDelegationsEntry<'bldr>>>,
> {
    let fb_stake_delegations_entries: Vec<_> = stake_delegations
        .iter()
        .map(|(stake_pubkey, delegation)| {
            create_fb_stake_delegations_entry(fbb, stake_pubkey, delegation)
        })
        .collect();
    fbb.create_vector(&fb_stake_delegations_entries)
}
fn new_stake_delegations_from_fb<'fb>(
    fb: flatbuffers::Vector<'fb, ForwardsUOffset<fb::StakeDelegationsEntry<'fb>>>,
) -> Result<ImHashMap<Pubkey, Delegation>, de::StakeDelegationError> {
    let mut stake_delegations = ImHashMap::new();
    for fb_stake_delegations_entry in fb.iter() {
        let stake_pubkey = fb_stake_delegations_entry
            .stake_pubkey()
            .copied()
            .ok_or(de::StakeDelegationError::MissingStakePubkey)?
            .into();
        let stake_delegation = new_stake_delegation_from_fb(fb_stake_delegations_entry)?;
        let old_value = stake_delegations.insert(stake_pubkey, stake_delegation);
        assert!(
            old_value.is_none(),
            "key already exists! key: {stake_pubkey}, old value: {old_value:?}"
        );
    }
    Ok(stake_delegations)
}

fn create_fb_stakes_from_delegations<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    stakes: &Stakes<Delegation>,
) -> flatbuffers::WIPOffset<fb::Stakes<'bldr>> {
    let vote_accounts: Arc<VoteAccountsHashMap> = (&stakes.vote_accounts).into();
    let fb_vote_accounts = create_fb_vote_accounts(fbb, &vote_accounts);
    let fb_stake_delegations = create_fb_stake_delegations(fbb, &stakes.stake_delegations);
    let fb_stake_history = create_fb_stake_history(fbb, &stakes.stake_history);
    fb::Stakes::create(
        fbb,
        &fb::StakesArgs {
            epoch: stakes.epoch,
            vote_accounts: Some(fb_vote_accounts),
            stake_delegations: Some(fb_stake_delegations),
            stake_history: Some(fb_stake_history),
        },
    )
}
fn new_stakes_from_fb(fb: fb::Stakes<'_>) -> Result<Stakes<Delegation>, de::StakesError> {
    Ok(Stakes::<Delegation> {
        unused: Default::default(),
        epoch: fb.epoch(),
        vote_accounts: new_vote_accounts_from_fb(
            fb.vote_accounts()
                .ok_or(de::StakesError::MissingVoteAccounts)?,
        )?,
        stake_delegations: new_stake_delegations_from_fb(
            fb.stake_delegations()
                .ok_or(de::StakesError::MissingStakeDelegations)?,
        )?,
        stake_history: new_stake_history_from_fb(
            fb.stake_history()
                .ok_or(de::StakesError::MissingStakeHistory)?,
        ),
    })
}

fn create_fb_stakes_from_cache<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    stakes: &StakesCache,
) -> flatbuffers::WIPOffset<fb::Stakes<'bldr>> {
    let stakes = Stakes::<Delegation>::from(stakes.0.read().unwrap().clone());
    create_fb_stakes_from_delegations(fbb, &stakes)
}

fn create_fb_stakes_from_enum<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    stakes: &StakesEnum,
) -> flatbuffers::WIPOffset<fb::Stakes<'bldr>> {
    let stakes = match stakes {
        StakesEnum::Accounts(stakes) => stakes.clone().into(),
        StakesEnum::Delegations(stakes) => stakes.clone(),
    };
    create_fb_stakes_from_delegations(fbb, &stakes)
}

fn create_fb_node_id_to_vote_accounts_entry<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    node_id: &Pubkey,
    node_vote_accounts: &NodeVoteAccounts,
) -> flatbuffers::WIPOffset<fb::NodeIdToVoteAccountsEntry<'bldr>> {
    let fb_pubkeys: Vec<_> = node_vote_accounts
        .vote_accounts
        .iter()
        .map(|vote_account| fb::Pubkey(vote_account.to_bytes()))
        .collect();
    let fb_vote_accounts = fbb.create_vector(&fb_pubkeys);

    fb::NodeIdToVoteAccountsEntry::create(
        fbb,
        &fb::NodeIdToVoteAccountsEntryArgs {
            node_id: Some(bytemuck::cast_ref(node_id)),
            vote_accounts: Some(fb_vote_accounts),
            total_stake: node_vote_accounts.total_stake,
        },
    )
}

fn create_fb_node_id_to_vote_accounts<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    node_id_to_vote_accounts: &HashMap<Pubkey, NodeVoteAccounts>,
) -> flatbuffers::WIPOffset<
    flatbuffers::Vector<'bldr, ForwardsUOffset<fb::NodeIdToVoteAccountsEntry<'bldr>>>,
> {
    let fb_node_id_to_vote_accounts_entries: Vec<_> = node_id_to_vote_accounts
        .iter()
        .map(|(node_id, node_vote_accounts)| {
            create_fb_node_id_to_vote_accounts_entry(fbb, node_id, node_vote_accounts)
        })
        .collect();
    fbb.create_vector(&fb_node_id_to_vote_accounts_entries)
}
fn new_node_id_to_vote_accounts_from_fb<'fb>(
    fb: flatbuffers::Vector<'fb, ForwardsUOffset<fb::NodeIdToVoteAccountsEntry<'fb>>>,
) -> Result<HashMap<Pubkey, NodeVoteAccounts>, de::NodeIdToVoteAccountsError> {
    let mut node_id_to_vote_accounts = HashMap::with_capacity(fb.len());
    for fb_entry in fb.iter() {
        let node_id = fb_entry
            .node_id()
            .copied()
            .ok_or(de::NodeIdToVoteAccountsError::MissingNodeId)?
            .into();
        let total_stake = fb_entry.total_stake();
        let vote_accounts = fb_entry
            .vote_accounts()
            .ok_or(de::NodeIdToVoteAccountsError::MissingVoteAccounts)?
            .iter()
            .copied()
            .map(Into::into)
            .collect();
        let node_vote_accounts = NodeVoteAccounts {
            total_stake,
            vote_accounts,
        };
        let old_value = node_id_to_vote_accounts.insert(node_id, node_vote_accounts);
        assert!(
            old_value.is_none(),
            "key: {node_id}, old value: {old_value:?}"
        );
    }
    Ok(node_id_to_vote_accounts)
}

fn create_fb_epoch_authorized_voters_entry<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    vote_account: &Pubkey,
    authorized_voter: &Pubkey,
) -> flatbuffers::WIPOffset<fb::EpochAuthorizedVotersEntry<'bldr>> {
    fb::EpochAuthorizedVotersEntry::create(
        fbb,
        &fb::EpochAuthorizedVotersEntryArgs {
            vote_account: Some(bytemuck::cast_ref(vote_account)),
            authorized_voter: Some(bytemuck::cast_ref(authorized_voter)),
        },
    )
}

fn create_fb_epoch_authorized_voters<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    epoch_authorized_voters: &HashMap<Pubkey, Pubkey>,
) -> flatbuffers::WIPOffset<
    flatbuffers::Vector<'bldr, ForwardsUOffset<fb::EpochAuthorizedVotersEntry<'bldr>>>,
> {
    let fb_epoch_authorized_voters_entries: Vec<_> = epoch_authorized_voters
        .iter()
        .map(|(vote_account, authorized_voter)| {
            create_fb_epoch_authorized_voters_entry(fbb, vote_account, authorized_voter)
        })
        .collect();
    fbb.create_vector(&fb_epoch_authorized_voters_entries)
}
fn new_epoch_authorized_voters_from_fb<'fb>(
    fb: flatbuffers::Vector<'fb, ForwardsUOffset<fb::EpochAuthorizedVotersEntry<'fb>>>,
) -> Result<HashMap<Pubkey, Pubkey>, de::EpochAuthorizedVoterError> {
    let mut epoch_authorized_voters = HashMap::with_capacity(fb.len());
    for fb_entry in fb.iter() {
        let vote_account = fb_entry
            .vote_account()
            .copied()
            .ok_or(de::EpochAuthorizedVoterError::MissingVoteAccount)?
            .into();
        let authorized_voter = fb_entry
            .authorized_voter()
            .copied()
            .ok_or(de::EpochAuthorizedVoterError::MissingAuthorizedVoter)?
            .into();
        let old_value = epoch_authorized_voters.insert(vote_account, authorized_voter);
        assert!(
            old_value.is_none(),
            "key: {vote_account}, old value: {old_value:?}"
        );
    }
    Ok(epoch_authorized_voters)
}

fn create_fb_epoch_stakes_entry<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    epoch: Epoch,
    epoch_stakes: &EpochStakes,
) -> flatbuffers::WIPOffset<fb::EpochStakesEntry<'bldr>> {
    let fb_stakes = create_fb_stakes_from_enum(fbb, epoch_stakes.stakes());
    let fb_node_id_to_vote_accounts =
        create_fb_node_id_to_vote_accounts(fbb, epoch_stakes.node_id_to_vote_accounts());
    let fb_epoch_authorized_voters =
        create_fb_epoch_authorized_voters(fbb, epoch_stakes.epoch_authorized_voters());
    fb::EpochStakesEntry::create(
        fbb,
        &fb::EpochStakesEntryArgs {
            epoch,
            total_stake: epoch_stakes.total_stake(),
            stakes: Some(fb_stakes),
            node_id_to_vote_accounts: Some(fb_node_id_to_vote_accounts),
            epoch_authorized_voters: Some(fb_epoch_authorized_voters),
        },
    )
}

fn create_fb_epoch_stakes<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    epoch_stakes: &HashMap<Epoch, EpochStakes>,
) -> flatbuffers::WIPOffset<flatbuffers::Vector<'bldr, ForwardsUOffset<fb::EpochStakesEntry<'bldr>>>>
{
    let fb_epoch_stakes_entries: Vec<_> = epoch_stakes
        .iter()
        .map(|(epoch, epoch_stakes)| create_fb_epoch_stakes_entry(fbb, *epoch, epoch_stakes))
        .collect();
    fbb.create_vector(&fb_epoch_stakes_entries)
}
fn new_epoch_stakes_from_fb<'fb>(
    fb: flatbuffers::Vector<'fb, ForwardsUOffset<fb::EpochStakesEntry<'fb>>>,
) -> Result<HashMap<Epoch, EpochStakes>, de::EpochStakesError> {
    let mut epoch_stakes = HashMap::with_capacity(fb.len());
    for fb_epoch_stakes_entry in fb.iter() {
        let epoch = fb_epoch_stakes_entry.epoch();
        let total_stake = fb_epoch_stakes_entry.total_stake();
        let stakes = new_stakes_from_fb(
            fb_epoch_stakes_entry
                .stakes()
                .ok_or(de::EpochStakesError::MissingStakes)?,
        )?;
        let node_id_to_vote_accounts = new_node_id_to_vote_accounts_from_fb(
            fb_epoch_stakes_entry
                .node_id_to_vote_accounts()
                .ok_or(de::EpochStakesError::MissingNodeIdToVoteAccounts)?,
        )?;
        let epoch_authorized_voters = new_epoch_authorized_voters_from_fb(
            fb_epoch_stakes_entry
                .epoch_authorized_voters()
                .ok_or(de::EpochStakesError::MissingEpochAuthorizedVoters)?,
        )?;
        let epoch_stake = EpochStakes {
            total_stake,
            stakes: Arc::new(stakes.into()),
            node_id_to_vote_accounts: node_id_to_vote_accounts.into(),
            epoch_authorized_voters: epoch_authorized_voters.into(),
        };
        let old_value = epoch_stakes.insert(epoch, epoch_stake);
        assert!(
            old_value.is_none(),
            "key: {epoch}, old value: {old_value:?}"
        );
    }
    Ok(epoch_stakes)
}

fn create_fb_account_storages<'bldr>(
    fbb: &mut flatbuffers::FlatBufferBuilder<'bldr>,
    account_storages: &[Arc<AccountStorageEntry>], // TODO: remove Arc
) -> flatbuffers::WIPOffset<flatbuffers::Vector<'bldr, ForwardsUOffset<fb::AccountStorage<'bldr>>>>
{
    let fb_account_storages: Vec<_> = account_storages
        .iter()
        .map(|account_storage| {
            fb::AccountStorage::create(
                fbb,
                &fb::AccountStorageArgs {
                    id: account_storage.append_vec_id(),
                    slot: account_storage.slot(),
                    count: account_storage.count() as u64, // TODO: try_into?
                },
            )
        })
        .collect();
    fbb.create_vector(&fb_account_storages)
}
fn new_account_storages_map_from_fb<'fb>(
    fb: flatbuffers::Vector<'fb, ForwardsUOffset<fb::AccountStorage<'fb>>>,
) -> HashMap<Slot, Vec<SerializableAccountStorageEntry>> {
    let mut account_storages_map = HashMap::with_capacity(fb.len());
    for fb_entry in fb.iter() {
        let slot = fb_entry.slot();
        let account_storage_entry = SerializableAccountStorageEntry {
            id: fb_entry.id() as usize,                      // TODO: try_into?
            accounts_current_len: fb_entry.count() as usize, // TODO: try_into?
        };
        let old_value = account_storages_map.insert(slot, vec![account_storage_entry]);
        assert!(old_value.is_none(), "key: {slot}, old value: {old_value:?}");
    }
    account_storages_map
}
