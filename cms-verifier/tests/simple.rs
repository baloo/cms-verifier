use cms::{
    attr::MessageDigest,
    builder::{
        create_content_type_attribute, /*create_signing_time_attribute,*/ SignedDataBuilder,
        SignerInfoBuilder,
    },
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{EncapsulatedContentInfo, SignerIdentifier},
};
use cms_verifier::Context;
use der::{
    asn1::{Any, SetOfVec},
    oid::db::{rfc3161, rfc5280, rfc5911, rfc5912, rfc6268},
    pem::PemLabel,
    DateTime, Decode, Encode, EncodePem, Length, Writer,
};
use mock_countersignature::MockTsa;
use p256::{
    ecdsa::{DerSignature, SigningKey},
    pkcs8::EncodePrivateKey,
};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use x509_cert::{
    attr::{Attribute, AttributeValue},
    builder::{self, profile, profile::BuilderProfile, Builder, CertificateBuilder},
    ext::{
        pkix::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages},
        AsExtension, Extension,
    },
    name::Name,
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef},
    time::{Time, Validity},
    Certificate, SubjectPublicKeyInfo, TbsCertificate,
};

struct CodeSign {
    issuer: Name,
    subject: Name,
}

impl BuilderProfile for CodeSign {
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

        let eku = ExtendedKeyUsage(vec![rfc5280::ID_KP_CODE_SIGNING]);
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

pub struct MockDocument {
    sign_trust_anchors: Vec<Certificate>,
    timestamp_trust_anchors: Vec<Certificate>,
    document: ContentInfo,
    payload: &'static [u8],
}

fn make_signer_identity() -> (Certificate, (Certificate, SigningKey)) {
    let mut rng = rand::rng();
    let root = SigningKey::random(&mut rng);
    let leaf = SigningKey::random(&mut rng);

    let root_subject = Name::from_str("CN=CA service,O=World domination Inc,C=US").unwrap();
    let root_cert = {
        let serial_number = SerialNumber::generate(&mut rng);

        let validity = Validity::new(
            Time::from_str("2020-01-01T00:00:00Z").unwrap(),
            Time::from_str("2024-12-31T23:59:59Z").unwrap(),
        );
        let profile =
            profile::cabf::Root::new(false, root_subject.clone()).expect("Create root profile");

        let pub_key =
            SubjectPublicKeyInfo::from_key(root.verifying_key()).expect("get public from root key");

        let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
            .expect("Create certificate builder");

        builder
            .build::<_, DerSignature>(&root)
            .expect("Create certificate")
    };

    let signer_cert = {
        let serial_number = SerialNumber::generate(&mut rng);

        let validity = Validity::new(
            Time::from_str("2021-01-01T00:00:00Z").unwrap(),
            Time::from_str("2021-12-31T23:59:59Z").unwrap(),
        );
        let subject = Name::from_str("CN=code.signer,O=World domination Inc,C=US").unwrap();
        let profile = CodeSign {
            issuer: root_subject,
            subject,
        };

        let pub_key =
            SubjectPublicKeyInfo::from_key(leaf.verifying_key()).expect("get public from root key");

        let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
            .expect("Create certificate builder");

        builder
            .build::<_, DerSignature>(&root)
            .expect("Create certificate")
    };

    (root_cert, (signer_cert, leaf))
}

pub fn create_signing_time_attribute() -> der::Result<Attribute> {
    let time_der = Time::from_str("2021-06-30T23:59:59Z")?.to_der()?;
    let signing_time_attribute_value = AttributeValue::from_der(&time_der)?;
    let mut values = SetOfVec::<AttributeValue>::new();
    values.insert(signing_time_attribute_value)?;
    let attribute = Attribute {
        oid: rfc5911::ID_SIGNING_TIME,
        values,
    };
    Ok(attribute)
}

fn sign_payload(payload: &[u8]) -> (Certificate, Certificate, ContentInfo) {
    let mock_tsa = MockTsa::new(
        Name::from_str("CN=TSA CA service,O=World domination Inc,C=US").unwrap(),
        Name::from_str("CN=TSA CA signer,O=World domination Inc,C=US").unwrap(),
        DateTime::from_str("2010-01-01T00:00:00Z").unwrap()
            ..=DateTime::from_str("2030-01-01T00:00:00Z").unwrap(),
        DateTime::from_str("2010-01-01T00:00:00Z").unwrap()
            ..=DateTime::from_str("2030-01-01T00:00:00Z").unwrap(),
    )
    .unwrap();

    let (root_cert, (signer_cert, signer)) = make_signer_identity();
    std::fs::write(
        "/tmp/time-root.pem",
        mock_tsa.root().to_pem(Default::default()).unwrap(),
    );
    std::fs::write(
        "/tmp/root.pem",
        root_cert.to_pem(Default::default()).unwrap(),
    );
    std::fs::write(
        "/tmp/leaf.pem",
        signer_cert.to_pem(Default::default()).unwrap(),
    );
    std::fs::write(
        "/tmp/leaf.key",
        signer.to_pkcs8_pem(Default::default()).unwrap(),
    );

    let signed_data = EncapsulatedContentInfo {
        econtent_type: rfc5911::ID_DATA,
        econtent: None,
    };

    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: rfc5912::ID_SHA_256,
        parameters: None,
    };
    let mut message_digest_values: SetOfVec<AttributeValue> = Default::default();
    let mut digest = Sha256::new();
    digest.update("foo");
    let message_digest_value = MessageDigest::from_digest(digest).unwrap();
    message_digest_values
        .insert(Any::from(message_digest_value.as_octet_string_ref()))
        .unwrap();

    let external_message_digest = None;
    let mut signer_info_builder = SignerInfoBuilder::new(
        SignerIdentifier::from(&signer_cert),
        digest_algorithm.clone(),
        &signed_data,
        external_message_digest,
    )
    .expect("Could not create RSA SignerInfoBuilder");
    signer_info_builder
        .add_signed_attribute(create_content_type_attribute(rfc5911::ID_DATA).unwrap())
        .unwrap();
    signer_info_builder
        .add_signed_attribute(create_signing_time_attribute().unwrap())
        .unwrap();
    signer_info_builder
        .add_signed_attribute(Attribute {
            oid: rfc6268::ID_MESSAGE_DIGEST,
            values: message_digest_values,
        })
        .unwrap();

    let mut builder = SignedDataBuilder::new(&signed_data);

    let signed_data_pkcs7 = builder
        .add_digest_algorithm(digest_algorithm)
        .expect("could not add a digest algorithm")
        .add_signer_info_cb::<_, DerSignature, _>(signer_info_builder, &signer, |signer_info| {
            let mut hash = Sha256::new();
            hash.update(signer_info.signature.as_bytes());
            let ts = mock_tsa
                .sign_timestamp(DateTime::from_str("2021-06-30T23:59:59Z").unwrap(), hash)
                .unwrap();
            let mut unsigned_attrs = signer_info.unsigned_attrs.get_or_insert_default();
            // TODO: there might be more than one value
            unsigned_attrs.insert(Attribute {
                oid: rfc3161::ID_AA_TIME_STAMP_TOKEN,
                values: SetOfVec::from_iter([Any::encode_from(&ts).unwrap()]).unwrap(),
            });
            Ok(())
        })
        .expect("add signer info")
        .add_certificate(CertificateChoices::Certificate(signer_cert.clone()))
        .expect("add signer certificate")
        .build()
        .expect("sign document");

    let signed_data_pkcs7_der = signed_data_pkcs7
        .to_der()
        .expect("conversion of signed data to DER failed.");

    struct ContentInfoPem<'a>(&'a ContentInfo);

    impl<'a> Encode for ContentInfoPem<'a> {
        fn encoded_len(&self) -> der::Result<Length> {
            self.0.encoded_len()
        }
        fn encode(&self, encoder: &mut impl Writer) -> der::Result<()> {
            self.0.encode(encoder)
        }
    }

    impl PemLabel for ContentInfoPem<'_> {
        const PEM_LABEL: &'static str = "CMS";
    }

    println!(
        "{}",
        ContentInfoPem(&signed_data_pkcs7)
            .to_pem(Default::default())
            .unwrap()
    );
    std::fs::write(
        "/tmp/cms.pem",
        ContentInfoPem(&signed_data_pkcs7)
            .to_pem(Default::default())
            .unwrap(),
    );

    (mock_tsa.root(), root_cert, signed_data_pkcs7)
}

#[test]
fn verify_signed() {
    let _ = tracing_subscriber::fmt::try_init();

    let payload = b"foo";
    let (timestamp_root_cert, root_cert, signed_data) = sign_payload(payload);

    let mock = MockDocument {
        sign_trust_anchors: vec![root_cert],
        timestamp_trust_anchors: vec![timestamp_root_cert],
        document: signed_data,
        payload,
    };

    let context = Context::builder()
        .with_sign_trust_anchors(&mock.sign_trust_anchors)
        .with_time_trust_anchors(&mock.timestamp_trust_anchors)
        .build();
    context
        .verify(&mock.document, &mock.payload)
        .expect("document should verify");
}
