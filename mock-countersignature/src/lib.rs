use cms::{
    attr::MessageDigest,
    builder::{create_content_type_attribute, SignedDataBuilder, SignerInfoBuilder},
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{EncapsulatedContentInfo, SignerIdentifier},
};
use der::{
    asn1::{Any, GeneralizedTime, Int, OctetString, SetOfVec},
    oid::{
        db::{rfc3161, rfc5280, rfc5911},
        AssociatedOid, ObjectIdentifier,
    },
    DateTime, Decode, Encode,
};
use digest::Digest;
use error_set::{error_set, ErrContext};
use p256::ecdsa::{DerSignature, SigningKey};
use rand::Rng;
use sha2::Sha256;
use std::ops::RangeInclusive;
use x509_cert::{
    attr::{Attribute, AttributeValue},
    builder::{self, profile, Builder, CertificateBuilder},
    ext::{
        pkix::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages},
        AsExtension, Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{self, AlgorithmIdentifierOwned, SubjectPublicKeyInfo, SubjectPublicKeyInfoRef},
    time::{Time, Validity},
    Certificate, TbsCertificate,
};
use x509_tsp::{MessageImprint, TspVersion, TstInfo};

const DIGICERT_TIMESTAMP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.114412.7.1");

pub struct MockTsa {
    root_cert: Certificate,
    signer_cert: Certificate,
    signer_key: p256::ecdsa::SigningKey,
}

impl MockTsa {
    pub fn new(
        root_subject: Name,
        signer_subject: Name,
        root_lifetime: RangeInclusive<DateTime>,
        signer_lifetime: RangeInclusive<DateTime>,
    ) -> Result<Self, Error> {
        let mut rng = rand::rng();
        let root = SigningKey::random(&mut rng);
        let signer_key = SigningKey::random(&mut rng);

        let root_cert = {
            let serial_number = SerialNumber::generate(&mut rng);

            let validity = Validity::new(
                Time::from(root_lifetime.start().clone()),
                Time::from(root_lifetime.end().clone()),
            );
            let profile = profile::cabf::Root::new(false, root_subject.clone())
                .map_err(PkiCreation::CreateProfile)
                .info_context("create root profile")?;

            let pub_key = SubjectPublicKeyInfo::from_key(root.verifying_key())
                .map_err(PkiCreation::ConvertPublicKey)
                .info_context("create spki for root public key")?;

            let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
                .map_err(PkiCreation::CreateCertificateBuilder)
                .info_context("crate root certificate builder")?;

            builder
                .build::<_, DerSignature>(&root)
                .map_err(PkiCreation::SignCertificate)
                .info_context("Sign root certificate")?
        };

        let signer_cert = {
            let serial_number = SerialNumber::generate(&mut rng);

            let validity = Validity::new(
                Time::from(signer_lifetime.start().clone()),
                Time::from(signer_lifetime.end().clone()),
            );
            let profile = TimestampAuthority {
                issuer: root_subject,
                subject: signer_subject,
            };

            let pub_key = SubjectPublicKeyInfo::from_key(signer_key.verifying_key())
                .map_err(PkiCreation::ConvertPublicKey)
                .info_context("create spki for signer public key")?;

            let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
                .map_err(PkiCreation::CreateCertificateBuilder)
                .info_context("crate signer certificate builder")?;

            builder
                .build::<_, DerSignature>(&root)
                .map_err(PkiCreation::SignCertificate)
                .info_context("Sign TSA certificate")?
        };

        Ok(Self {
            root_cert,
            signer_cert,
            signer_key,
        })
    }

    pub fn root(&self) -> Certificate {
        self.root_cert.clone()
    }
}

impl MockTsa {
    pub fn sign_timestamp<D>(
        &self,
        timestamp: DateTime,
        imprint: D,
    ) -> Result<ContentInfo, SigningError>
    where
        D: Digest + AssociatedOid,
    {
        let mut rng = rand::rng();
        let message_imprint = MessageImprint {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: D::OID,
                parameters: None,
            },
            hashed_message: OctetString::new(imprint.finalize().to_vec())
                .map_err(SigningError::SerializeImprint)?,
        };

        let serial_number =
            Int::try_from(rng.random::<i64>()).map_err(SigningError::GenerateSerialNumber)?;

        let tstinfo = TstInfo {
            version: TspVersion::V1,
            policy: DIGICERT_TIMESTAMP,
            message_imprint,
            serial_number,
            gen_time: GeneralizedTime::from(timestamp),
            accuracy: None,
            ordering: false,
            nonce: None,
            tsa: None,
            extensions: None,
        };

        let econtent = Any::encode_from(&tstinfo).map_err(SigningError::TstInfoSerialization)?;
        let mut digest = Sha256::new();
        digest.update(econtent.value());

        let signed_data = EncapsulatedContentInfo {
            econtent_type: rfc3161::ID_CT_TST_INFO,
            econtent: Some(econtent),
        };

        let digest_algorithm = AlgorithmIdentifierOwned {
            oid: Sha256::OID,
            parameters: None,
        };
        let mut message_digest_values: SetOfVec<AttributeValue> = Default::default();
        let message_digest_value = MessageDigest::from_digest(digest)
            .map_err(SigningError::SerializeDigest)
            .info_context("Serializing MessageDigest")?;
        message_digest_values
            .insert(Any::from(message_digest_value.as_octet_string_ref()))
            .map_err(SigningError::SerializeDigest)
            .info_context("Adding MessageDigest to the set")?;

        let mut signer_info_builder = SignerInfoBuilder::new(
            SignerIdentifier::from(&self.signer_cert),
            digest_algorithm.clone(),
            &signed_data,
            None,
        )
        .map_err(SigningError::SignerInfoBuilder)
        .info_context("Could not create SignerInfoBuilder")?;
        signer_info_builder
            .add_signed_attribute(
                create_content_type_attribute(rfc3161::ID_CT_TST_INFO)
                    .map_err(SigningError::CreateAttribute)
                    .info_context("Creating content type attribute")?,
            )
            .map_err(SigningError::AddAttribute)
            .info_context("Adding content-type attribute")?;
        signer_info_builder
            .add_signed_attribute(
                Self::create_signing_time_attribute(timestamp)
                    .map_err(SigningError::CreateAttribute)
                    .info_context("Creating time attribute")?,
            )
            .map_err(SigningError::AddAttribute)
            .info_context("Adding time attribute")?;
        // Missing id-smime-aa-signingCertificate

        //signer_info_builder
        //    .add_signed_attribute(Attribute {
        //        oid: rfc6268::ID_MESSAGE_DIGEST,
        //        values: message_digest_values,
        //    })
        //    .map_err(SigningError::AddAttribute)
        //    .info_context("Adding message digest attribute")?;

        let mut builder = SignedDataBuilder::new(&signed_data);

        let signed_data = builder
            .add_digest_algorithm(digest_algorithm)
            .map_err(SigningError::SignedDataBuilder)
            .info_context("could not add a digest algorithm")?
            .add_signer_info::<_, DerSignature>(signer_info_builder, &self.signer_key)
            .map_err(SigningError::SignedDataBuilder)
            .info_context("could not sign document")?
            .add_certificate(CertificateChoices::Certificate(self.signer_cert.clone()))
            .map_err(SigningError::SignedDataBuilder)
            .info_context("could not add signer's certificate")?
            .build()
            .map_err(SigningError::SignedDataBuilder)
            .info_context("Assemble SignedData document")?;

        Ok(signed_data)
    }

    fn create_signing_time_attribute(time: DateTime) -> Result<Attribute, cms::builder::Error> {
        let time_der = Time::from(time).to_der()?;
        let signing_time_attribute_value = AttributeValue::from_der(&time_der)?;
        let mut values = SetOfVec::<AttributeValue>::new();
        values.insert(signing_time_attribute_value)?;
        let attribute = Attribute {
            oid: rfc5911::ID_SIGNING_TIME,
            values,
        };

        Ok(attribute)
    }
}

error_set! {
    Error = PkiCreation;

    PkiCreation = {
        #[display("Error when converting a public key to SPKI: {0}")]
        ConvertPublicKey(spki::Error),
        #[display("Error when creating certificate profile: {0}")]
        CreateProfile(builder::Error),
        #[display("Error when creating certificate builder: {0}")]
        CreateCertificateBuilder(builder::Error),
        #[display("Error when signing certificate: {0}")]
        SignCertificate(builder::Error),
    };

    SigningError = {
        #[display("Error when signing SignedData: {0}")]
        SignCms(builder::Error),
        #[display("Error when serializing digest: {0}")]
        SerializeImprint(der::Error),
        #[display("Error when generating a serial number: {0}")]
        GenerateSerialNumber(der::Error),
        #[display("Error when serializing the tstinfo: {0}")]
        TstInfoSerialization(der::Error),
        #[display("Error when creating an attribute for the signer info: {0}")]
        CreateAttribute(cms::builder::Error),
        #[display("Error when adding an attribute to the signer info: {0}")]
        AddAttribute(cms::builder::Error),
        #[display("Error when serializing digest: {0}")]
        SerializeDigest(der::Error),
        #[display("Error when creating the SignerInfoBuilder: {0}")]
        SignerInfoBuilder(cms::builder::Error),
        #[display("Error when building SignedData: {0}")]
        SignedDataBuilder(cms::builder::Error),
    };
}

struct TimestampAuthority {
    issuer: Name,
    subject: Name,
}

impl profile::BuilderProfile for TimestampAuthority {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> Result<Vec<Extension>, builder::Error> {
        let mut extensions: Vec<Extension> = Vec::new();

        extensions.push(
            AuthorityKeyIdentifier::try_from(issuer_spk.clone())?
                .to_extension(tbs.subject(), &extensions)?,
        );

        let eku = ExtendedKeyUsage(vec![rfc5280::ID_KP_TIME_STAMPING]);
        extensions.push(eku.to_extension(tbs.subject(), &extensions)?);

        extensions.push(
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_extension(tbs.subject(), &extensions)?,
        );

        let key_usage = KeyUsages::DigitalSignature.into();
        extensions.push(KeyUsage(key_usage).to_extension(tbs.subject(), &extensions)?);

        Ok(extensions)
    }
}
