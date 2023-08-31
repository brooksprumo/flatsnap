/// Serialization errors
pub mod se {}

/// Deserialization errors
pub mod de {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("field is missing: {0}")]
        MissingField(String),
        #[error("deserializing Bank: {0}")]
        Bank(#[from] BankError),
        #[error("deserializing Account: {0}")]
        Account(#[from] AccountError),
        #[error("deserializing RentCollector: {0}")]
        RentCollector(#[from] RentCollectorError),
        #[error("deserializing IncrementalSnapshotPersistence: {0}")]
        IncrementalSnapshotPersistence(#[from] IncrementalSnapshotPersistenceError),
        #[error("deserializing Stakes: {0}")]
        Stakes(#[from] StakesError),
        #[error("deserializing EpochStakes: {0}")]
        EpochStakes(#[from] EpochStakesError),
    }

    #[derive(Error, Debug)]
    pub enum BankError {
        #[error("the 'blockhash queue' field is missing")]
        MissingBlockhashQueue,
        #[error("the 'ancestors' field is missing")]
        MissingAncestors,
        #[error("the 'hard forks' field is missing")]
        MissingHardForks,
        #[error("the 'fee rate governor' field is missing")]
        MissingFeeRateGovernor,
        #[error("the 'rent collector' field is missing")]
        MissingRentCollector,
        #[error("the 'epoch schedule' field is missing")]
        MissingEpochSchedule,
        #[error("the 'inflation' field is missing")]
        MissingInflation,
        #[error("the 'stakes' field is missing")]
        MissingStakes,
        #[error("the 'epoch stakes' field is missing")]
        MissingEpochStakes,
    }

    #[derive(Error, Debug)]
    pub enum AccountError {
        #[error("the 'data' field is missing")]
        MissingData,
        #[error("the 'owner' field is missing")]
        MissingOwner,
    }

    #[derive(Error, Debug)]
    pub enum RentCollectorError {
        #[error("the 'epoch schedule' field is missing")]
        MissingEpochSchedule,
        #[error("the 'rent' field is missing")]
        MissingRent,
    }

    #[derive(Error, Debug)]
    pub enum IncrementalSnapshotPersistenceError {
        #[error("the 'full hash' field is missing")]
        MissingFullHash,
        #[error("the 'incremental hash' field is missing")]
        MissingIncrementalHash,
    }

    #[derive(Error, Debug)]
    pub enum VoteAccountError {
        #[error("the 'pubkey' field is missing")]
        MissingPubkey,
        #[error("the 'account' field is missing")]
        MissingAccount,
        #[error("deserializing Account: {0}")]
        Account(#[from] AccountError),
        #[error("deserializing solana_runtime::VoteAccount: {0}")]
        SolanaRuntimeVoteAccount(#[from] solana_runtime::vote_account::Error),
    }

    #[derive(Error, Debug)]
    pub enum StakeDelegationError {
        #[error("the 'stake pubkey' field is missing")]
        MissingStakePubkey,
        #[error("the 'voter pubkey' field is missing")]
        MissingVoterPubkey,
    }

    #[derive(Error, Debug)]
    pub enum StakesError {
        #[error("the 'vote accouns' field is missing")]
        MissingVoteAccounts,
        #[error("the 'stake delegations' field is missing")]
        MissingStakeDelegations,
        #[error("the 'stake history' field is missing")]
        MissingStakeHistory,
        #[error("deserializing VoteAccount: {0}")]
        VoteAccount(#[from] VoteAccountError),
        #[error("deserializing StakeDelegation: {0}")]
        StakeDelegation(#[from] StakeDelegationError),
    }

    #[derive(Error, Debug)]
    pub enum NodeIdToVoteAccountsError {
        #[error("the 'node id' field is missing")]
        MissingNodeId,
        #[error("the 'vote accounts' field is missing")]
        MissingVoteAccounts,
    }

    #[derive(Error, Debug)]
    pub enum EpochAuthorizedVoterError {
        #[error("the 'vote account' field is missing")]
        MissingVoteAccount,
        #[error("the 'authorized voter' field is missing")]
        MissingAuthorizedVoter,
    }

    #[derive(Error, Debug)]
    pub enum EpochStakesError {
        #[error("the 'stakes' field is missing")]
        MissingStakes,
        #[error("the 'node id to vote accounts' field is missing")]
        MissingNodeIdToVoteAccounts,
        #[error("the 'epoch authorized voters' field is missing")]
        MissingEpochAuthorizedVoters,
        #[error("deserializing Stakes: {0}")]
        Stakes(#[from] StakesError),
        #[error("deserializing NodeIdToVoteAccounts: {0}")]
        NodeIdToVoteAccounts(#[from] NodeIdToVoteAccountsError),
        #[error("deserializing EpochAuthorizedVoter: {0}")]
        EpochAuthorizedVoter(#[from] EpochAuthorizedVoterError),
    }
}
