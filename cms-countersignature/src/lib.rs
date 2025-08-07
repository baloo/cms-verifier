use cms::content_info::ContentInfo;
use der::{
    asn1::OctetString,
    oid::{db::rfc6268, AssociatedOid},
    Decode, Encode,
};
use digest::Digest;
use error_set::error_set;
use reqwest::{header, Url};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_tsp::{cmpv2::status::PkiStatus, MessageImprint, TimeStampReq, TimeStampResp, TspVersion};

pub struct CounterSignature {}

impl CounterSignature {
    pub async fn request<D>(server: Url, imprint: D) -> Result<ContentInfo, Error>
    where
        D: Digest + AssociatedOid,
    {
        let request = TimeStampReq {
            version: TspVersion::V1,
            message_imprint: MessageImprint {
                hash_algorithm: AlgorithmIdentifierOwned {
                    oid: D::OID,
                    parameters: None,
                },
                hashed_message: OctetString::new(imprint.finalize().to_vec())
                    .map_err(RequestError::HashSerialization)?,
            },
            cert_req: true,
            extensions: Default::default(),
            nonce: Default::default(),
            req_policy: Default::default(),
        };

        let client = reqwest::Client::new();
        let res = client
            .post(server)
            .header(header::CONTENT_TYPE, "application/timestamp-query")
            .body(
                request
                    .to_der()
                    .map_err(RequestError::TimestampSerialization)?,
            )
            .send()
            .await
            .map_err(RequestError::Http)?;

        let content_type = res
            .headers()
            .get(header::CONTENT_TYPE)
            .ok_or(ResponseError::NoContentType)?;
        let content_type = content_type.to_str().map_err(ResponseError::from)?;

        const EXPECTED: &str = "application/timestamp-reply";
        if content_type != EXPECTED {
            return Err(ResponseError::UnexpectedContentType {
                expected: EXPECTED.to_string(),
                found: content_type.to_string(),
            }
            .into());
        }

        let response = res.bytes().await.map_err(ResponseError::ParsingBody)?;

        let response = TimeStampResp::from_der(&response)
            .map_err(ResponseError::TimeStampRespDeserializing)?;

        if response.status.status != PkiStatus::Accepted {
            return Err(ContentError::TsaRejectedSignature {
                status: response.status.status,
            }
            .into());
        }

        let out = response
            .time_stamp_token
            .ok_or(ContentError::SignedInfoExpected)?;
        if out.content_type != rfc6268::ID_SIGNED_DATA {
            return Err(ContentError::SignedInfoExpected.into());
        }

        Ok(out)
    }
}

error_set! {
    /// The errors returned by [`cms-countersignature`]
    Error = RequestError || ResponseError || ContentError;

    /// Error returned when sending a request for countersignature
    #[disable(From)]
    RequestError = {
        #[display("Error when serialization a digest to OctetString: {0}")]
        HashSerialization(der::Error),

        #[display("TimeStampReq failed to serialize: {0}")]
        TimestampSerialization(der::Error),

        #[display("Error when sending request to server")]
        Http(reqwest::Error)
    };

    /// Error returned when parsing the response from the TSA
    ResponseError = {
        #[display("No `Content-Type` header found in the response")]
        NoContentType,

        #[display("Non utf-8 characters found in the `Content-Type` header")]
        NonUtfHeader(header::ToStrError),

        #[display("Unexpected `Content-Type` found (expected={expected}, found={found})")]
        UnexpectedContentType {expected:String, found:String},

        #[display("Error while parsing body: {0}")]
        ParsingBody(reqwest::Error),

        #[display("Error while deserializing TimeStampResp")]
        TimeStampRespDeserializing(der::Error),
    };

    ContentError = {
        #[display("TSA rejected the signature: {status:?}")]
        TsaRejectedSignature{
            status:PkiStatus
        },

        #[display("SignedInfo expected in the `time_stamp_token`, none found")]
        SignedInfoExpected,
    };
}

//#[derive(Debug, Error)]
//pub enum Error {
//    #[error("hash serialization problem: {inner}")]
//    HashSerialization { inner: der::Error },
//    #[error("timestamp request serialization: {inner}")]
//    TimestampSerialization { inner: der::Error },
//    #[error("Content-Type expected in the response, but none received")]
//    ContentTypeExpected,
//    #[error("Non utf characters found in the header value")]
//    NonUtfHeader,
//    #[error("Unexpected content type (expected={expected}, got={got})")]
//    UnexpectedContentType { expected: String, got: String },
//    #[error("error parsing the response")]
//    ResponseParsing { inner: der::Error },
//    #[error(transparent)]
//    Http {
//        #[from]
//        inner: reqwest::Error,
//    },
//
//    #[error("TSA rejected the signature: {status:?}")]
//    TsaRejectedSignature { status: PkiStatus },
//    #[error("Signed info expected in the response")]
//    SignedInfoExpected,
//}
//
//impl Error {
//    fn hash_serialization(inner: der::Error) -> Self {
//        Self::HashSerialization { inner }
//    }
//    fn timestamp_serialization(inner: der::Error) -> Self {
//        Self::TimestampSerialization { inner }
//    }
//
//    fn response_parsing(inner: der::Error) -> Self {
//        Self::ResponseParsing { inner }
//    }
//}
