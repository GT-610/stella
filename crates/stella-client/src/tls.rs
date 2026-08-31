//! TLS 1.3 controller trust with explicit SPKI pinning.

use std::{fmt, str::FromStr, sync::Arc};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use stella_crypto::sha256_segments;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio_rustls::{
    rustls::{
        self,
        client::{
            danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
            WebPkiServerVerifier,
        },
        crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms},
        pki_types::{CertificateDer, ServerName, UnixTime},
        version::TLS13,
        CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    },
    TlsConnector,
};
use x509_parser::parse_x509_certificate;

use crate::ClientError;

const SPKI_PIN_PREFIX: &str = "sha256/";
const SPKI_SHA256_LENGTH: usize = 32;

/// SHA-256 digest of one complete DER `SubjectPublicKeyInfo` object.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SpkiPin([u8; SPKI_SHA256_LENGTH]);

impl SpkiPin {
    /// Constructs a pin from its exact SHA-256 digest bytes.
    #[must_use]
    pub const fn from_digest(digest: [u8; SPKI_SHA256_LENGTH]) -> Self {
        Self(digest)
    }

    /// Returns the exact SHA-256 digest bytes.
    #[must_use]
    pub const fn digest(self) -> [u8; SPKI_SHA256_LENGTH] {
        self.0
    }

    fn matches(self, digest: &[u8; SPKI_SHA256_LENGTH]) -> bool {
        bool::from(self.0.ct_eq(digest))
    }
}

impl fmt::Display for SpkiPin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{SPKI_PIN_PREFIX}{}", STANDARD.encode(self.0))
    }
}

impl fmt::Debug for SpkiPin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SpkiPin({self})")
    }
}

impl FromStr for SpkiPin {
    type Err = SpkiPinParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let encoded = text
            .strip_prefix(SPKI_PIN_PREFIX)
            .ok_or(SpkiPinParseError::Prefix)?;
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| SpkiPinParseError::Base64)?;
        let digest = decoded
            .try_into()
            .map_err(|decoded: Vec<u8>| SpkiPinParseError::Length {
                actual: decoded.len(),
            })?;
        Ok(Self(digest))
    }
}

/// Failure while parsing a `sha256/` SPKI pin.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SpkiPinParseError {
    /// The algorithm prefix was absent or unsupported.
    #[error("SPKI pin must begin with sha256/")]
    Prefix,
    /// The digest was not canonical standard base64.
    #[error("SPKI pin digest is not valid standard base64")]
    Base64,
    /// The decoded SHA-256 digest had the wrong length.
    #[error("SPKI pin digest must contain 32 bytes, got {actual}")]
    Length {
        /// Decoded digest length.
        actual: usize,
    },
}

#[derive(Debug)]
struct PinnedServerVerifier {
    pins: Vec<SpkiPin>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (remaining, certificate) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if !remaining.is_empty() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::BadEncoding,
            ));
        }
        let digest = sha256_segments(&[certificate.public_key().raw]);
        if !self.pins.iter().any(|pin| pin.matches(&digest)) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }

        let mut roots = RootCertStore::empty();
        roots.add(end_entity.clone())?;
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&self.provider),
        )
        .build()
        .map_err(|_| {
            rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
        })?;
        verifier.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

pub(crate) fn connector(pins: &[SpkiPin]) -> Result<TlsConnector, ClientError> {
    if pins.is_empty() {
        return Err(ClientError::NoSpkiPins);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = PinnedServerVerifier {
        pins: pins.to_vec(),
        supported: provider.signature_verification_algorithms,
        provider: Arc::clone(&provider),
    };
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|source| ClientError::Tls(std::io::Error::other(source)))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{SpkiPin, SpkiPinParseError};

    #[test]
    fn spki_pin_round_trips_canonical_text() {
        let pin = SpkiPin::from_digest([0x5a; 32]);
        let text = pin.to_string();

        assert!(text.starts_with("sha256/"));
        assert_eq!(SpkiPin::from_str(&text), Ok(pin));
        assert_eq!(format!("{pin:?}"), format!("SpkiPin({text})"));
        assert_eq!(pin.digest(), [0x5a; 32]);
    }

    #[test]
    fn spki_pin_rejects_prefix_encoding_and_length() {
        assert_eq!(SpkiPin::from_str("AAAA"), Err(SpkiPinParseError::Prefix));
        assert_eq!(
            SpkiPin::from_str("sha256/not base64"),
            Err(SpkiPinParseError::Base64)
        );
        assert_eq!(
            SpkiPin::from_str("sha256/AA=="),
            Err(SpkiPinParseError::Length { actual: 1 })
        );
    }
}
