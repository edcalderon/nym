// Copyright 2024 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use crate::coconut::bandwidth::CredentialSigningData;
use crate::error::Error;
use nym_api_requests::coconut::BlindSignRequestBody;
use nym_credentials_interface::{BlindedSignature, WithdrawalRequest};
use nym_crypto::asymmetric::identity;
use nym_ecash_contract_common::events::TICKET_BOOK_VALUE;
use nym_validator_client::nyxd::Hash;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct BandwidthVoucherIssuedData {
    /// the plain value (e.g., bandwidth) encoded in this voucher
    // note: for legacy reasons we're only using the value of the coin and ignoring the denom
    #[zeroize(skip)]
    value: u128,
}

impl<'a> From<&'a BandwidthVoucherIssuanceData> for BandwidthVoucherIssuedData {
    fn from(value: &'a BandwidthVoucherIssuanceData) -> Self {
        BandwidthVoucherIssuedData {
            value: value.value(),
        }
    }
}

impl BandwidthVoucherIssuedData {
    pub fn value(&self) -> u128 {
        self.value
    }

    pub fn value_plain(&self) -> String {
        self.value.to_string()
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct BandwidthVoucherIssuanceData {
    /// the plain value (e.g., bandwidth) encoded in this voucher
    // note: for legacy reasons we're only using the value of the coin and ignoring the denom
    #[zeroize(skip)]
    value: u128,

    /// the hash of the deposit transaction
    #[zeroize(skip)]
    deposit_tx_hash: Hash,

    /// base58 encoded private key ensuring the depositer requested these attributes
    signing_key: identity::PrivateKey,
}

impl BandwidthVoucherIssuanceData {
    pub fn new(deposit_tx_hash: Hash, signing_key: identity::PrivateKey) -> Self {
        let value = TICKET_BOOK_VALUE;

        BandwidthVoucherIssuanceData {
            value,
            deposit_tx_hash,
            signing_key,
        }
    }

    pub fn request_plaintext(request: &WithdrawalRequest, tx_hash: Hash) -> Vec<u8> {
        let mut message = request.to_bytes();
        message.extend_from_slice(tx_hash.as_bytes());
        message
    }

    fn request_signature(&self, signing_request: &CredentialSigningData) -> identity::Signature {
        let message =
            Self::request_plaintext(&signing_request.withdrawal_request, self.deposit_tx_hash);
        self.signing_key.sign(message)
    }

    pub fn create_blind_sign_request_body(
        &self,
        signing_request: &CredentialSigningData,
    ) -> BlindSignRequestBody {
        let request_signature = self.request_signature(signing_request);

        BlindSignRequestBody::new(
            signing_request.withdrawal_request.clone(),
            self.deposit_tx_hash,
            request_signature,
            signing_request.ecash_pub_key.clone(),
            signing_request.expiration_date,
        )
    }

    pub async fn obtain_blinded_credential(
        &self,
        client: &nym_validator_client::client::NymApiClient,
        request_body: &BlindSignRequestBody,
    ) -> Result<BlindedSignature, Error> {
        let server_response = client.blind_sign(request_body).await?;
        Ok(server_response.blinded_signature)
    }

    pub fn value(&self) -> u128 {
        self.value
    }

    pub fn tx_hash(&self) -> Hash {
        self.deposit_tx_hash
    }

    pub fn identity_key(&self) -> &identity::PrivateKey {
        &self.signing_key
    }
}
