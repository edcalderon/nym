// Copyright 2022-2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: GPL-3.0-only

use crate::node_status_api::models::NymApiStorageError;
use nym_coconut_dkg_common::types::{ChunkIndex, DealingIndex, EpochId};
use nym_crypto::asymmetric::{
    encryption::KeyRecoveryError,
    identity::{Ed25519RecoveryError, SignatureError},
};
use nym_dkg::error::DkgError;
use nym_ecash_contract_common::deposit::DepositId;
use nym_validator_client::coconut::CoconutApiError;
use nym_validator_client::nyxd::error::NyxdError;
use rocket::http::{ContentType, Status};
use rocket::response::Responder;
use rocket::{response, Request, Response};
use std::io::Cursor;
use std::num::ParseIntError;
use thiserror::Error;
use time::error::ComponentRange;

pub type Result<T> = std::result::Result<T, CoconutError>;

#[derive(Debug, Error)]
pub enum CoconutError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error("the address of the bandwidth contract hasn't been set")]
    MissingBandwidthContractAddress,

    #[error("the current bandwidth contract does not have any admin address set")]
    MissingBandwidthContractAdmin,

    #[error("failed to derive the admin account from the provided public key: {formatted_source}")]
    AdminAccountDerivationFailure { formatted_source: String },

    #[error("only secp256k1 keys are supported for free pass issuance")]
    UnsupportedNonSecp256k1Key,

    #[error("failed to parse the free pass expiry date: {source}")]
    ExpiryDateParsingFailure {
        #[source]
        source: ParseIntError,
    },

    #[error("the provided expiration date is too late")]
    ExpirationDateTooLate,

    #[error("failed to parse expiry timestamp into proper datetime: {source}")]
    InvalidExpiryDate {
        unix_timestamp: i64,
        #[source]
        source: ComponentRange,
    },

    #[error("explicit free passes can no longer be issued")]
    DisabledFreePass,

    #[error("the received bandwidth voucher did not contain deposit value")]
    MissingBandwidthValue,

    #[error("failed to parse the bandwidth voucher value: {source}")]
    VoucherValueParsingFailure {
        #[source]
        source: ParseIntError,
    },

    #[error("coconut api query failure: {0}")]
    CoconutApiError(#[from] CoconutApiError),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),

    #[error("could not parse Ed25519 data: {0}")]
    Ed25519ParseError(#[from] Ed25519RecoveryError),

    #[error("could not parse X25519 data: {0}")]
    X25519ParseError(#[from] KeyRecoveryError),

    #[error("could not get transaction details for '{tx_hash}': {source}")]
    TxRetrievalFailure {
        tx_hash: String,
        #[source]
        source: NyxdError,
    },

    #[error("nyxd error: {0}")]
    NyxdError(#[from] NyxdError),

    #[error("validator client error: {0}")]
    ValidatorClientError(#[from] nym_validator_client::ValidatorClientError),

    #[error("coconut internal error: {0}")]
    CoconutInternalError(#[from] nym_coconut::CoconutError),

    #[error("Compact ecash internal error - {0}")]
    CompactEcashInternalError(#[from] nym_compact_ecash::error::CompactEcashError),

    #[error("Account linked to this public key has been blacklisted")]
    BlacklistedAccount,

    #[error("could not find a deposit event in the transaction provided")]
    DepositEventNotFound,

    #[error("could not find the deposit info in the event")]
    DepositInfoNotFound,

    #[error("signature didn't verify correctly")]
    SignatureVerificationError(#[from] SignatureError),

    #[error("storage error: {0}")]
    StorageError(#[from] NymApiStorageError),

    #[error("credentials error: {0}")]
    CredentialsError(#[from] nym_credentials::error::Error),

    #[error("incorrect credential proposal description: {reason}")]
    IncorrectProposal { reason: String },

    #[error("DKG error: {0}")]
    DkgError(#[from] DkgError),

    #[error("failed to recover assigned node index: {reason}")]
    NodeIndexRecoveryError { reason: String },

    #[error("unrecoverable state: {reason}")]
    UnrecoverableState { reason: String },

    #[error("DKG has not finished yet in order to derive the coconut key")]
    KeyPairNotDerivedYet,

    #[error("the coconut keypair is corrupted")]
    CorruptedCoconutKeyPair,

    #[error("there was a problem with the proposal id: {reason}")]
    ProposalIdError { reason: String },

    // I guess we should make this one a bit more detailed
    #[error("the provided query arguments were invalid")]
    InvalidQueryArguments,

    #[error("the internal dkg state for epoch {epoch_id} is missing - we might have joined mid exchange")]
    MissingDkgState { epoch_id: EpochId },

    #[error(
        "the node index value for epoch {epoch_id} is not available - are you sure we are a dealer?"
    )]
    UnavailableAssignedIndex { epoch_id: EpochId },

    #[error("the receiver index value for epoch {epoch_id} is not available - are you sure we are a receiver?")]
    UnavailableReceiverIndex { epoch_id: EpochId },

    #[error("the threshold value for epoch {epoch_id} is not available")]
    UnavailableThreshold { epoch_id: EpochId },

    #[error("the proposal id value for epoch {epoch_id} is not available")]
    UnavailableProposalId { epoch_id: EpochId },

    #[error("could not find dealing chunk {chunk_index} for dealing {dealing_index} from dealer {dealer} for epoch {epoch_id} on the chain!")]
    MissingDealingChunk {
        epoch_id: EpochId,
        dealer: String,
        dealing_index: DealingIndex,
        chunk_index: ChunkIndex,
    },

    #[error("could not find ecash deposit associated with id {deposit_id}")]
    NonExistentDeposit { deposit_id: DepositId },
}

impl<'r, 'o: 'r> Responder<'r, 'o> for CoconutError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'o> {
        let err_msg = self.to_string();
        Response::build()
            .header(ContentType::Plain)
            .sized_body(err_msg.len(), Cursor::new(err_msg))
            .status(Status::BadRequest)
            .ok()
    }
}
