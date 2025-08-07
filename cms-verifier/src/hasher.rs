use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
};
use core::iter::Iterator;

use der::oid::{AssociatedOid, ObjectIdentifier};
use digest::{
    crypto_common::hazmat::{SerializableState, SerializedState},
    Digest,
};
use x509_cert::spki::AlgorithmIdentifierOwned;

/// [`Hasher`] holds a cache of the digest for the payload
pub(crate) struct Hasher<'payload> {
    payload: &'payload [u8],
    digests: BTreeSet<ObjectIdentifier>,
    state: BTreeMap<ObjectIdentifier, Box<[u8]>>,
}

impl<'payload> Hasher<'payload> {
    pub(crate) fn new<'a, D>(payload: &'payload [u8], digests: D) -> Self
    where
        D: Iterator<Item = &'a AlgorithmIdentifierOwned>,
    {
        let digests = digests.map(|d| d.oid).collect();
        Self {
            payload,
            digests,
            state: BTreeMap::new(),
        }
    }

    pub(crate) fn get(&mut self, oid: ObjectIdentifier) -> Option<Box<[u8]>> {
        match oid {
            sha2::Sha224::OID => self.get_digest_output::<sha2::Sha224>(),
            sha2::Sha256::OID => self.get_digest_output::<sha2::Sha256>(),
            sha2::Sha384::OID => self.get_digest_output::<sha2::Sha384>(),
            sha2::Sha512::OID => self.get_digest_output::<sha2::Sha512>(),

            _ => None,
        }
    }

    pub(crate) fn get_digest_output<D>(&mut self) -> Option<Box<[u8]>>
    where
        D: Digest + AssociatedOid + SerializableState,
    {
        self.get_digest::<D>()
            .map(|d| d.finalize().as_slice().to_vec().into())
    }

    pub(crate) fn get_digest<D>(&mut self) -> Option<D>
    where
        D: Digest + AssociatedOid + SerializableState,
    {
        if !self.digests.contains(&D::OID) {
            return None;
        }

        if let Some(state) = self.state.get(&D::OID) {
            let state = SerializedState::<D>::try_from(state.as_ref())
                .expect("state stored in the hasher doesn't match the expected serialization");

            Some(
                D::deserialize(&state)
                    .expect("Unable to restore the digest from its serialized state"),
            )
        } else {
            let mut hash = D::new();
            hash.update(self.payload);

            let hash_state = hash.serialize();
            self.state.insert(D::OID, hash_state.to_vec().into());

            Some(hash)
        }
    }
}
