use cms::{
    cert::{CertificateChoices, IssuerAndSerialNumber},
    signed_data::{CertificateSet, SignerIdentifier},
};
use der::{asn1::SetOfVec, oid::ObjectIdentifier};
use x509_cert::{
    attr::{AttributeValue, Attributes},
    ext::pkix::SubjectKeyIdentifier,
    Certificate,
};

pub(crate) trait GetAttribute<'a> {
    fn get_attr(&self, oid: ObjectIdentifier) -> Option<&SetOfVec<AttributeValue>>;

    fn iter_values(&'a self, oid: ObjectIdentifier) -> Self::Iter;

    type Iter: Iterator<Item = &'a AttributeValue>;
}

impl<'a> GetAttribute<'a> for Attributes {
    fn get_attr(&self, oid: ObjectIdentifier) -> Option<&SetOfVec<AttributeValue>> {
        for attr in self.iter() {
            if attr.oid == oid {
                return Some(&attr.values);
            }
        }

        None
    }

    type Iter = Iter<'a>;

    fn iter_values(&'a self, oid: ObjectIdentifier) -> Iter<'a> {
        Iter::new(self, oid)
    }
}

pub(crate) struct Iter<'a> {
    attrs: &'a Attributes,
    oid: ObjectIdentifier,
    outer_pos: usize,
    inner_pos: usize,
}

impl<'a> Iter<'a> {
    fn new(attrs: &'a Attributes, oid: ObjectIdentifier) -> Self {
        Self {
            attrs,
            oid,
            outer_pos: 0,
            inner_pos: 0,
        }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a AttributeValue;

    fn next(&mut self) -> Option<&'a AttributeValue> {
        loop {
            let Some(attr) = self.attrs.get(self.outer_pos) else {
                return None;
            };

            if attr.oid != self.oid {
                self.inner_pos = 0;
                self.outer_pos += 1;
                continue;
            }

            let Some(inner) = attr.values.get(self.inner_pos) else {
                self.inner_pos = 0;
                self.outer_pos += 1;
                continue;
            };
            self.inner_pos += 1;

            return Some(inner);
        }
    }
}

pub(crate) trait FindCertificate {
    fn find(&self, sid: &SignerIdentifier) -> Option<Certificate>;
}

impl FindCertificate for CertificateSet {
    fn find(&self, sid: &SignerIdentifier) -> Option<Certificate> {
        for cert in self.0.iter() {
            match cert {
                CertificateChoices::Certificate(cert) => match sid {
                    SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                        issuer,
                        serial_number,
                    }) => {
                        if cert.tbs_certificate().issuer() == issuer
                            && cert.tbs_certificate().serial_number() == serial_number
                        {
                            return Some(cert.clone());
                        }
                    }
                    SignerIdentifier::SubjectKeyIdentifier(ski) => {
                        let Ok(Some((_critical, cert_ski))) =
                            cert.tbs_certificate()
                                .get_extension::<SubjectKeyIdentifier>()
                        else {
                            continue;
                        };

                        if ski == &cert_ski {
                            return Some(cert.clone());
                        }
                    }
                },
                _ => {}
            }
        }

        None
    }
}
