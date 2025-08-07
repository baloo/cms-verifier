#![no_std]

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeSet, format, string::String, vec::Vec};

use certval::{
    environment::{pki_environment::PkiEnvironment, pki_environment_traits::CertVector},
    source::{
        cert_source::{CertFile, CertSource},
        ta_source::TaSource,
    },
    util::{crypto::verify_signature_message_rust_crypto, time_of_interest::TimeOfInterest},
    validator::{
        cert_path::CertificationPath, path_results::CertificationPathResults,
        path_settings::CertificationPathSettings, pdv_certificate::PDVCertificate,
    },
};
use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{CertificateSet, SignedData, SignerInfo},
};
use der::{
    asn1::OctetStringRef,
    oid::{
        db::{rfc3161, rfc5280, rfc5911, rfc6268},
        AssociatedOid, ObjectIdentifier,
    },
    DateTime, Encode,
};
use digest::Digest;
use error_set::{error_set, ErrContext};
use log::{error, trace};
use x509_cert::{spki::AlgorithmIdentifierOwned, time::Time, Certificate};
use x509_tsp::TstInfo;

mod hasher;
mod utils;

use self::{
    hasher::Hasher,
    utils::{FindCertificate, GetAttribute},
};

pub struct Context {
    trust_anchors: Vec<Certificate>,
    timestamp_trust_anchors: Vec<Certificate>,
    trust_signer_datetime: bool,
}

impl Context {
    pub fn builder() -> ContextBuilder {
        ContextBuilder {
            context: Context {
                trust_anchors: Vec::new(),
                timestamp_trust_anchors: Vec::new(),
                trust_signer_datetime: false,
            },
        }
    }
}

pub struct ContextBuilder {
    context: Context,
}

impl ContextBuilder {
    pub fn with_time_trust_anchors(mut self, anchors: &[Certificate]) -> Self {
        self.context.timestamp_trust_anchors = anchors.to_vec();
        self
    }

    pub fn with_sign_trust_anchors(mut self, anchors: &[Certificate]) -> Self {
        self.context.trust_anchors = anchors.to_vec();
        self
    }

    pub fn trust_signer_datetime(mut self) -> Self {
        self.context.trust_signer_datetime = true;
        self
    }

    pub fn build(self) -> Context {
        self.context
    }
}

impl Context {
    pub fn verify(&self, signature: &ContentInfo, payload: &[u8]) -> Result<(), Error> {
        if signature.content_type != rfc5911::ID_SIGNED_DATA {
            return Err(SignerInfoVerificationError::UnexpectedContentType {
                expected: rfc5911::ID_SIGNED_DATA,
                got: signature.content_type,
            }
            .into());
        }

        let signed_data = signature
            .content
            .decode_as::<SignedData>()
            .map_err(|inner| SignerInfoVerificationError::SignedDataParsing { inner })?;

        // TODO: Check ID_DATA in the EncapsulatedContentInfo
        let mut digests = Hasher::new(payload, signed_data.digest_algorithms.iter());

        let mut cps = CertificationPathSettings::new();
        cps.set_extended_key_usage_from_oid_set(BTreeSet::from([rfc5280::ID_KP_CODE_SIGNING]));
        cps.set_extended_key_usage_path(true);
        cps.set_enforce_trust_anchor_constraints(true);

        self.verify_signer_infos(
            &signed_data,
            &mut digests,
            TimeAuthenticationMode::UseCountersigner,
            &self.trust_anchors,
            cps,
        )?;

        Ok(())
    }

    fn verify_signer_infos(
        &self,
        signed_data: &SignedData,
        digests: &mut Hasher,
        time_authentication_mode: TimeAuthenticationMode,
        trust_anchors: &[Certificate],
        cps: CertificationPathSettings,
    ) -> Result<(), SignerInfoVerificationError> {
        let certificates = signed_data
            .certificates
            .as_ref()
            .ok_or(SignerInfoVerificationError::NoCertificatesAttached)?;

        for (idx, signer_info) in signed_data.signer_infos.0.iter().enumerate() {
            if let Ok(_) = self
                .verify_signer_info(
                    signer_info,
                    digests,
                    certificates,
                    time_authentication_mode,
                    trust_anchors,
                    cps.clone(),
                )
                .info_context(format!("Error while checking signer info {idx}"))
            {
                return Ok(());
            } else {
                // Verification failed, check next signer info
                continue;
            }
        }

        Err(SignerInfoVerificationError::NoSuitableSignerFound)
    }

    fn verify_signer_info(
        &self,
        signer_info: &SignerInfo,
        digests: &mut Hasher,
        certificates: &CertificateSet,
        time_authentication_mode: TimeAuthenticationMode,
        trust_anchors: &[Certificate],
        cps: CertificationPathSettings,
    ) -> Result<(), SignerInfoVerificationError> {
        // First, we'll extract the message digest from the SignerInfo
        // and compare that with the payload's digest.
        let signed_attrs = signer_info
            .signed_attrs
            .as_ref()
            .ok_or(SignerInfoVerificationError::NoSignedAttributesFound)
            .trace_context("no signed attributes in signer info")?;

        let message_digest = signed_attrs
            .get_attr(rfc6268::ID_MESSAGE_DIGEST)
            .ok_or(SignerInfoVerificationError::NoMessageDigest)
            .trace_context("no message digest found in signer info")?;

        if message_digest.len() != 1 {
            return Err(SignerInfoVerificationError::MessageDigestInvalid {
                len: message_digest.len(),
            })
            .trace_context("message digest is invalid, only one value should be present");
        }
        let message_digest = message_digest
            .get(0)
            .expect("Invariant violation, only one value is present in the attribute");

        let message_digest = message_digest
            .decode_as::<OctetStringRef>()
            .map_err(SignerInfoVerificationError::MessageDigestSerialization)
            .trace_context("message digest not serialized as OctetString in signer info")?;

        let matching_digest = digests
            .get(signer_info.digest_alg.oid)
            .ok_or_else(|| SignerInfoVerificationError::NoMatchingDigest {
                oid: signer_info.digest_alg.oid,
            })
            .trace_context("digest algorithm either not specified, or not supported")?;

        if message_digest.as_bytes() != matching_digest.as_ref() {
            return Err(SignerInfoVerificationError::DigestMismatch).warn_context(
                "digest mismatch between what signer signed and the payload's digest",
            );
        }

        let trusted_datetime: DateTime = match time_authentication_mode {
            TimeAuthenticationMode::UseCountersigner => {
                // Now that we've got the message digest and that it matches the message.
                // We'll get the signature bytes.
                //
                // The signature bytes are what are signed by the counter-signature.
                //
                // ```
                //    The countersignature attribute type specifies one or more signatures
                //    on the contents octets of the signature OCTET STRING in a SignerInfo
                //    value of the signed-data.  That is, the message digest is computed
                //    over the octets comprising the value of the OCTET STRING, neither the
                //    tag nor length octets are included.
                // ```
                let signature_bytes = signer_info.signature.as_bytes();

                let trusted_datetime = self
                    .verify_countersignatures(signer_info, signature_bytes)
                    .info_context("Error while checking counter signer info")?;

                trusted_datetime
            }
            TimeAuthenticationMode::TrustSignerClaim => {
                let signing_time = signed_attrs
                    .get_attr(rfc5911::ID_SIGNING_TIME)
                    .ok_or(SignerInfoVerificationError::NoMessageDigest)
                    .trace_context("no message digest found in signer info")?;

                if signing_time.len() != 1 {
                    return Err(SignerInfoVerificationError::SigningTimeInvalid {
                        len: signing_time.len(),
                    })
                    .trace_context("Signing time is invalid, only one value should be present");
                }
                let signing_time = signing_time
                    .get(0)
                    .expect("Invariant violation, only one value is present in the attribute");

                // TODO: Check the serialization, is this supposed to be Time or GeneralizedTime
                let signing_time = signing_time
                    .decode_as::<Time>()
                    .map_err(SignerInfoVerificationError::SigningTimeSerialization)
                    .trace_context("Signing time not serialized as Time in signer info")?;

                signing_time.to_date_time()
            }
        };

        let leaf = certificates.find(&signer_info.sid).unwrap();

        let time_of_interest = TimeOfInterest(trusted_datetime);

        self.check_x509_path(
            trust_anchors,
            &leaf,
            certificates,
            time_of_interest,
            cps.clone(),
        )
        .warn_context("Error while building path to a trust anchor")?;

        let payload = signed_attrs.to_der().unwrap();

        self.check_signature(
            &leaf,
            &payload,
            signer_info.signature.as_bytes(),
            &signer_info.signature_algorithm,
        )
        .warn_context("Failed to check signature")?;

        Ok(())
    }

    fn check_x509_path(
        &self,
        trust_anchors: &[Certificate],
        signer_identity: &Certificate,
        certificates: &CertificateSet,
        time_of_interest: TimeOfInterest,
        cps: CertificationPathSettings,
    ) -> Result<(), PathBuildingError> {
        // TODO TryFrom<Certificate<P>>
        let leaf = PDVCertificate::try_from(signer_identity.to_der()?.as_slice()).unwrap();

        let mut pe = PkiEnvironment::new();
        pe.populate_5280_pki_environment();

        {
            let mut trusted = TaSource::new();
            for c in trust_anchors {
                trusted.push(CertFile {
                    filename: String::new(),
                    bytes: c.to_der().unwrap(),
                })
            }
            trusted.initialize().unwrap();
            pe.add_trust_anchor_source(Box::new(trusted));
        }

        {
            let mut cert_store = CertSource::new();
            for cert in certificates.0.iter() {
                match cert {
                    CertificateChoices::Certificate(cert) => cert_store.push(CertFile {
                        filename: String::new(),
                        bytes: cert.to_der().unwrap(),
                    }),
                    _ => {}
                }
            }

            cert_store.initialize(&cps).unwrap();
            cert_store.find_all_partial_paths(&pe, &cps);
            pe.add_certificate_source(Box::new(cert_store));
        }

        let mut paths: Vec<CertificationPath> = Vec::new();
        pe.get_paths_for_target(&leaf, &mut paths, 0, time_of_interest)
            .unwrap();
        for path in &mut paths {
            let mut cpr = CertificationPathResults::new();
            match pe.validate_path(&pe, &cps, path, &mut cpr) {
                Ok(()) => match cpr.get_validation_status() {
                    Some(certval::PathValidationStatus::Valid) => return Ok(()),
                    _ => {
                        todo!()
                        // Invalid path, maybe next path?
                    }
                },
                Err(e) => {
                    // TODO: log attempted path
                    error!("Invalid path attempted: {e}")
                    // Invalid path, maybe next path?
                }
            }
        }

        Err(PathBuildingError::NoValidPathFound)
    }

    fn check_signature(
        &self,
        signer_identity: &Certificate,
        payload: &[u8],
        signature: &[u8],
        signature_alg: &AlgorithmIdentifierOwned,
    ) -> Result<(), SignerInfoVerificationError> {
        let tbs = signer_identity.tbs_certificate();
        let spki = tbs.subject_public_key_info();

        let pe = PkiEnvironment::new();
        verify_signature_message_rust_crypto(&pe, payload, signature, signature_alg, spki).unwrap();

        Ok(())
    }

    fn verify_countersignatures(
        &self,
        signer_info: &SignerInfo,
        signature_bytes: &[u8],
    ) -> Result<DateTime, SignerInfoVerificationError> {
        let unsigned_attrs = signer_info
            .unsigned_attrs
            .as_ref()
            .ok_or(SignerInfoVerificationError::NoUnsignedAttributesFound)
            .trace_context("no unsigned attributes in signer info")?;

        for (idx, counter_value) in unsigned_attrs
            .iter_values(rfc3161::ID_AA_TIME_STAMP_TOKEN)
            .enumerate()
        {
            let Ok(countersignature) = counter_value
                .decode_as::<ContentInfo>()
                .map_err(CountersignerVerificationError::ContentInfoDeserialization)
                .warn_context("counter signer expected to be a ContentInfo, could not deserialize")
            else {
                continue;
            };

            match self
                .verify_countersignature(&countersignature, signature_bytes)
                .info_context(format!("Unable to verify countersignature ({idx})"))
            {
                Ok(authenticated_date) => return Ok(authenticated_date),
                Err(_) => continue,
            }
        }

        Err(SignerInfoVerificationError::NoSuitableCountersignerFound)
    }

    fn verify_countersignature(
        &self,
        countersigner_info: &ContentInfo,
        signature_bytes: &[u8],
    ) -> Result<DateTime, CountersignerVerificationError> {
        if countersigner_info.content_type != rfc5911::ID_SIGNED_DATA {
            return Err(SignerInfoVerificationError::UnexpectedContentType {
                expected: rfc5911::ID_SIGNED_DATA,
                got: countersigner_info.content_type,
            }
            .into());
        }

        let signed_data = countersigner_info
            .content
            .decode_as::<SignedData>()
            .map_err(|inner| SignerInfoVerificationError::SignedDataParsing { inner })?;

        if signed_data.encap_content_info.econtent_type != rfc3161::ID_CT_TST_INFO {
            return Err(CountersignerVerificationError::ContentTypeMismatch {
                expected: rfc3161::ID_CT_TST_INFO,
                got: signed_data.encap_content_info.econtent_type,
            });
        }

        let econtent = signed_data
            .encap_content_info
            .econtent
            .as_ref()
            .ok_or(CountersignerVerificationError::NoContentFound)
            .warn_context("TstInfo expected, none found")?;

        let tstinfo = econtent
            .decode_as::<TstInfo>()
            .map_err(CountersignerVerificationError::TstInfoDeserialization)
            .debug_context("Error when trying to read the countersignature content as TstInfo")?;

        let expected_digest = match tstinfo.message_imprint.hash_algorithm.oid {
            sha2::Sha256::OID => sha2::Sha256::digest(signature_bytes),
            unsupported => {
                return Err(CountersignerVerificationError::UnsupportedDigest { unsupported })
            }
        };

        if expected_digest.as_slice() != tstinfo.message_imprint.hashed_message.as_bytes() {
            return Err(CountersignerVerificationError::DigestMismatch).warn_context("hash mismatch when checking the TstInfo message imprint against the signature bytes");
        }

        let mut digests = Hasher::new(econtent.value(), signed_data.digest_algorithms.iter());

        let mut cps = CertificationPathSettings::new();
        cps.set_extended_key_usage_from_oid_set(BTreeSet::from([rfc5280::ID_KP_TIME_STAMPING]));
        cps.set_extended_key_usage_path(true);
        cps.set_enforce_trust_anchor_constraints(true);

        self.verify_signer_infos(
            &signed_data,
            &mut digests,
            TimeAuthenticationMode::TrustSignerClaim,
            &self.timestamp_trust_anchors,
            cps,
        )?;

        let trusted_time = tstinfo.gen_time.to_date_time();
        trace!("Countersignature time: {trusted_time}");

        Ok(trusted_time)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum TimeAuthenticationMode {
    /// We will seek to check the signature date with a counter signer
    UseCountersigner,
    /// We will trust signer's signature date placed in a signed attribute
    TrustSignerClaim,
}

error_set! {
    Error = {

        SignerInfo(SignerInfoVerificationError),
    };

    SignerInfoVerificationError = {
        #[display("Invalid document found, expected {expected}, but got {got}")]
        UnexpectedContentType {
            expected: ObjectIdentifier,
            got: ObjectIdentifier,
        },
        #[display("Unable to parse content as SignedData: {inner}")]
        SignedDataParsing { inner: der::Error },

        #[display("No suitable verifier were found to verify the signature of the payload")]
        NoSuitableSignerFound,

        #[display("No signed attributes were found in the SignerInfo")]
        NoSignedAttributesFound,

        #[display("No id-message-digest attribute in the signed attributes of the signer info")]
        NoMessageDigest,

        #[display("Message digest should carry one value, got {len} values")]
        MessageDigestInvalid {
            len: usize
        },

        #[display("Unable to deserialize message digest: {0}")]
        MessageDigestSerialization(der::Error),

        #[display("No matching digest found, or missing support (oid: {oid})")]
        NoMatchingDigest {
            oid: ObjectIdentifier,
        },

        #[display("Digest in the signer info does not match the expected hash")]
        DigestMismatch,

        #[display("Signing time should carry one value, got {len} values")]
        SigningTimeInvalid {
            len: usize
        },

        #[display("Unable to deserialize signing time: {0}")]
        SigningTimeSerialization(der::Error),

        #[display("No unsigned attributes were found in the SignerInfo")]
        NoUnsignedAttributesFound,

        #[display("No suitable countersignature found for this signer info")]
        NoSuitableCountersignerFound,

        #[display("No certificates were attached to the SignedData")]
        NoCertificatesAttached,

        PathBuilding(PathBuildingError),
    };

    CountersignerVerificationError = {
        SignerInfoVerificationError(SignerInfoVerificationError),

        #[display("countersignature could not be deserialized as a SignedData: {0}")]
        ContentInfoDeserialization(der::Error),

        #[display("no countersignature could be found")]
        NoSuitableCountersignerFound,

        #[display("Countersignature are expected to have TstInfo inline, no content was found")]
        NoContentFound,

        #[display("Unsupported digest used in the TstInfo: unsupported={unsupported}")]
        UnsupportedDigest {
            unsupported: ObjectIdentifier,
        },

        #[display("TstInfo digest does not match the expected digest of the signature")]
        DigestMismatch,

        #[display("content of the countersignature could not be read as a TstInfo: {0}")]
        TstInfoDeserialization(der::Error),

        #[display("Content-Type of the countersignature expected to be `{expected}`, got `{got}`")]
        ContentTypeMismatch {
            expected: ObjectIdentifier,
            got: ObjectIdentifier,
        },
    };

    PathBuildingError = {
        #[display("Unable to parse certificate from source: {0}")]
        CertificateParsingError(der::Error),

        #[display("No valid path were found")]
        NoValidPathFound,
    };
}
