use super::{BeaconBlockHeader, BeaconState, EthSpec, FixedVector, Hash256, SyncCommittee};
use crate::{light_client_update::*, test_utils::TestRandom};
use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use test_random_derive::TestRandom;
use tree_hash::TreeHash;

/// A LightClientBootstrap is the initializer we send over to lightclient nodes
/// that are trying to generate their basic storage when booting up.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TestRandom,
    arbitrary::Arbitrary,
)]
#[serde(bound = "T: EthSpec")]
#[arbitrary(bound = "T: EthSpec")]
pub struct LightClientBootstrap<T: EthSpec> {
    /// Requested beacon block header.
    pub header: BeaconBlockHeader,
    /// The `SyncCommittee` used in the requested period.
    pub current_sync_committee: Arc<SyncCommittee<T>>,
    /// Merkle proof for sync committee
    pub current_sync_committee_branch: FixedVector<Hash256, CurrentSyncCommitteeProofLen>,
}

// TODO Removed after https://github.com/sigp/lighthouse/pull/3886 merged.
#[derive(Serialize, Deserialize)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
}

// TODO Removed after https://github.com/sigp/lighthouse/pull/3886 merged.
#[derive(Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct PatchedLightClientBootstrap<T: EthSpec> {
    pub header: LightClientHeader,
    pub current_sync_committee: Arc<SyncCommittee<T>>,
    pub current_sync_committee_branch: FixedVector<Hash256, CurrentSyncCommitteeProofLen>,
}

// TODO Removed after https://github.com/sigp/lighthouse/pull/3886 merged.
impl<T: EthSpec> core::convert::From<PatchedLightClientBootstrap<T>> for LightClientBootstrap<T> {
    fn from(patched: PatchedLightClientBootstrap<T>) -> Self {
        Self {
            header: patched.header.beacon,
            current_sync_committee: patched.current_sync_committee,
            current_sync_committee_branch: patched.current_sync_committee_branch,
        }
    }
}

impl<T: EthSpec> LightClientBootstrap<T> {
    pub fn from_beacon_state(beacon_state: &mut BeaconState<T>) -> Result<Self, Error> {
        let mut header = beacon_state.latest_block_header().clone();
        header.state_root = beacon_state.tree_hash_root();
        let current_sync_committee_branch =
            beacon_state.compute_merkle_proof(CURRENT_SYNC_COMMITTEE_INDEX)?;
        Ok(LightClientBootstrap {
            header,
            current_sync_committee: beacon_state.current_sync_committee()?.clone(),
            current_sync_committee_branch: FixedVector::new(current_sync_committee_branch)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MainnetEthSpec;

    ssz_tests!(LightClientBootstrap<MainnetEthSpec>);
}
