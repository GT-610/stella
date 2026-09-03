//! TLS-exporter-bound controller and node proof transcripts.

use std::fmt;

use stella_common::{ControllerId, NodeId};
use stella_crypto::{CryptoError, IdentityPublicKey, IdentitySigningKey, ED25519_SIGNATURE_LENGTH};
use stella_proto::VersionEntry;
use zeroize::Zeroizing;

/// TLS exporter label used by Stella version 0.1 control authentication.
pub const CONTROL_EXPORTER_LABEL: &[u8] = b"EXPORTER-Stella-Control-v1";

/// Exact number of bytes requested from the TLS exporter.
pub const CONTROL_EXPORTER_LENGTH: usize = 32;

/// Exact controller and client nonce length.
pub const CONTROL_NONCE_LENGTH: usize = 32;

/// Domain prefix for the controller proof signature.
pub const CONTROLLER_PROOF_DOMAIN: &[u8] = b"stella controller proof v1";

/// Domain prefix for the node proof signature.
pub const NODE_PROOF_DOMAIN: &[u8] = b"stella node proof v1";

/// Typed connection values bound into a controller proof.
#[derive(Clone, Copy)]
pub struct ControllerProofContext<'a> {
    /// TLS exporter bytes for this exact connection.
    pub control_exporter: &'a [u8; CONTROL_EXPORTER_LENGTH],
    /// Fresh nonce sent in `SERVER_HELLO`.
    pub server_nonce: &'a [u8; CONTROL_NONCE_LENGTH],
    /// Negotiated protocol version and cryptographic suite.
    pub selected: VersionEntry,
    /// Expected Stella controller identity.
    pub controller_id: ControllerId,
}

impl<'a> ControllerProofContext<'a> {
    /// Groups the fixed controller proof inputs for signing or verification.
    #[must_use]
    pub const fn new(
        control_exporter: &'a [u8; CONTROL_EXPORTER_LENGTH],
        server_nonce: &'a [u8; CONTROL_NONCE_LENGTH],
        selected: VersionEntry,
        controller_id: ControllerId,
    ) -> Self {
        Self {
            control_exporter,
            server_nonce,
            selected,
            controller_id,
        }
    }
}

/// Typed connection and identity values bound into a node proof.
#[derive(Clone, Copy)]
pub struct NodeProofContext<'a> {
    /// TLS exporter bytes for this exact connection.
    pub control_exporter: &'a [u8; CONTROL_EXPORTER_LENGTH],
    /// Fresh nonce sent in `SERVER_HELLO`.
    pub server_nonce: &'a [u8; CONTROL_NONCE_LENGTH],
    /// Fresh nonce sent in `CLIENT_HELLO`.
    pub client_nonce: &'a [u8; CONTROL_NONCE_LENGTH],
    /// Negotiated protocol version and cryptographic suite.
    pub selected: VersionEntry,
    /// Authenticated controller identity for this connection.
    pub controller_id: ControllerId,
    /// Claimed node identity derived from the node public key.
    pub node_id: NodeId,
}

impl<'a> NodeProofContext<'a> {
    /// Groups the fixed node proof inputs for signing or verification.
    #[must_use]
    pub const fn new(
        control_exporter: &'a [u8; CONTROL_EXPORTER_LENGTH],
        server_nonce: &'a [u8; CONTROL_NONCE_LENGTH],
        client_nonce: &'a [u8; CONTROL_NONCE_LENGTH],
        selected: VersionEntry,
        controller_id: ControllerId,
        node_id: NodeId,
    ) -> Self {
        Self {
            control_exporter,
            server_nonce,
            client_nonce,
            selected,
            controller_id,
            node_id,
        }
    }
}

/// Owned proof input whose diagnostics do not expose TLS exporter material.
#[derive(Eq, PartialEq)]
pub struct ProofTranscript(Zeroizing<Vec<u8>>);

impl ProofTranscript {
    /// Borrows the exact bytes that are signed or verified.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ProofTranscript {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofTranscript")
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Builds the canonical controller proof input from typed fixed-size values.
#[must_use]
pub fn controller_proof_transcript(
    context: ControllerProofContext<'_>,
    controller_public_key: IdentityPublicKey,
) -> ProofTranscript {
    let mut transcript = Vec::with_capacity(
        CONTROLLER_PROOF_DOMAIN.len()
            + CONTROL_EXPORTER_LENGTH
            + CONTROL_NONCE_LENGTH
            + 4
            + ControllerId::LENGTH
            + stella_crypto::ED25519_PUBLIC_KEY_LENGTH,
    );
    transcript.extend_from_slice(CONTROLLER_PROOF_DOMAIN);
    transcript.extend_from_slice(context.control_exporter);
    transcript.extend_from_slice(context.server_nonce);
    append_version(&mut transcript, context.selected);
    transcript.extend_from_slice(context.controller_id.as_bytes());
    transcript.extend_from_slice(controller_public_key.as_bytes());
    ProofTranscript(Zeroizing::new(transcript))
}

/// Builds the canonical node proof input from typed fixed-size values.
#[must_use]
pub fn node_proof_transcript(
    context: NodeProofContext<'_>,
    node_public_key: IdentityPublicKey,
) -> ProofTranscript {
    let mut transcript = Vec::with_capacity(
        NODE_PROOF_DOMAIN.len()
            + CONTROL_EXPORTER_LENGTH
            + (2 * CONTROL_NONCE_LENGTH)
            + 4
            + ControllerId::LENGTH
            + NodeId::LENGTH
            + stella_crypto::ED25519_PUBLIC_KEY_LENGTH,
    );
    transcript.extend_from_slice(NODE_PROOF_DOMAIN);
    transcript.extend_from_slice(context.control_exporter);
    transcript.extend_from_slice(context.server_nonce);
    transcript.extend_from_slice(context.client_nonce);
    append_version(&mut transcript, context.selected);
    transcript.extend_from_slice(context.controller_id.as_bytes());
    transcript.extend_from_slice(context.node_id.as_bytes());
    transcript.extend_from_slice(node_public_key.as_bytes());
    ProofTranscript(Zeroizing::new(transcript))
}

/// Signs the exact controller proof transcript with the controller identity.
#[must_use]
pub fn sign_controller_proof(
    signing_key: &IdentitySigningKey,
    context: ControllerProofContext<'_>,
) -> [u8; ED25519_SIGNATURE_LENGTH] {
    let public_key = signing_key.public_key();
    signing_key.sign(controller_proof_transcript(context, public_key).as_bytes())
}

/// Verifies an exact controller proof transcript.
///
/// # Errors
///
/// Returns [`CryptoError`] when the Ed25519 signature is invalid.
pub fn verify_controller_proof(
    public_key: IdentityPublicKey,
    context: ControllerProofContext<'_>,
    signature: &[u8; ED25519_SIGNATURE_LENGTH],
) -> Result<(), CryptoError> {
    public_key.verify(
        controller_proof_transcript(context, public_key).as_bytes(),
        signature,
    )
}

/// Signs the exact node proof transcript with the node identity.
#[must_use]
pub fn sign_node_proof(
    signing_key: &IdentitySigningKey,
    context: NodeProofContext<'_>,
) -> [u8; ED25519_SIGNATURE_LENGTH] {
    let public_key = signing_key.public_key();
    signing_key.sign(node_proof_transcript(context, public_key).as_bytes())
}

/// Verifies an exact node proof transcript.
///
/// # Errors
///
/// Returns [`CryptoError`] when the Ed25519 signature is invalid.
pub fn verify_node_proof(
    public_key: IdentityPublicKey,
    context: NodeProofContext<'_>,
    signature: &[u8; ED25519_SIGNATURE_LENGTH],
) -> Result<(), CryptoError> {
    public_key.verify(
        node_proof_transcript(context, public_key).as_bytes(),
        signature,
    )
}

fn append_version(output: &mut Vec<u8>, selected: VersionEntry) {
    output.push(selected.major);
    output.push(selected.minor);
    output.extend_from_slice(&selected.suite_id.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use stella_common::{ControllerId, NodeId};
    use stella_crypto::{derive_controller_id, derive_node_id, IdentitySeed, IdentitySigningKey};
    use stella_proto::VersionEntry;

    use super::{
        controller_proof_transcript, node_proof_transcript, sign_controller_proof, sign_node_proof,
        verify_controller_proof, verify_node_proof, ControllerProofContext, NodeProofContext,
        CONTROLLER_PROOF_DOMAIN, NODE_PROOF_DOMAIN,
    };

    fn signing_key(seed: u8) -> IdentitySigningKey {
        IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([seed; 32]))
    }

    #[test]
    fn transcripts_match_the_normative_concatenation() {
        let controller_key = signing_key(1);
        let node_key = signing_key(2);
        let controller_id = derive_controller_id(controller_key.public_key());
        let node_id = derive_node_id(node_key.public_key());
        let exporter = [3; 32];
        let server_nonce = [4; 32];
        let client_nonce = [5; 32];

        let controller_context = ControllerProofContext::new(
            &exporter,
            &server_nonce,
            VersionEntry::V0_1_SUITE_1,
            controller_id,
        );
        let controller =
            controller_proof_transcript(controller_context, controller_key.public_key());
        let mut expected = CONTROLLER_PROOF_DOMAIN.to_vec();
        expected.extend_from_slice(&exporter);
        expected.extend_from_slice(&server_nonce);
        expected.extend_from_slice(&[0, 1, 0, 1]);
        expected.extend_from_slice(controller_id.as_bytes());
        expected.extend_from_slice(controller_key.public_key().as_bytes());
        assert_eq!(controller.as_bytes(), expected);

        let node_context = NodeProofContext::new(
            &exporter,
            &server_nonce,
            &client_nonce,
            VersionEntry::V0_1_SUITE_1,
            controller_id,
            node_id,
        );
        let node = node_proof_transcript(node_context, node_key.public_key());
        let mut expected = NODE_PROOF_DOMAIN.to_vec();
        expected.extend_from_slice(&exporter);
        expected.extend_from_slice(&server_nonce);
        expected.extend_from_slice(&client_nonce);
        expected.extend_from_slice(&[0, 1, 0, 1]);
        expected.extend_from_slice(controller_id.as_bytes());
        expected.extend_from_slice(node_id.as_bytes());
        expected.extend_from_slice(node_key.public_key().as_bytes());
        assert_eq!(node.as_bytes(), expected);
        assert_eq!(format!("{node:?}"), "ProofTranscript { length: 184, .. }");
    }

    #[test]
    fn sign_and_verify_helpers_bind_every_identity() {
        let controller_key = signing_key(9);
        let node_key = signing_key(10);
        let controller_id = derive_controller_id(controller_key.public_key());
        let node_id = derive_node_id(node_key.public_key());
        let exporter = [11; 32];
        let server_nonce = [12; 32];
        let client_nonce = [13; 32];

        let controller_context = ControllerProofContext::new(
            &exporter,
            &server_nonce,
            VersionEntry::V0_1_SUITE_1,
            controller_id,
        );
        let controller_signature = sign_controller_proof(&controller_key, controller_context);
        assert_eq!(
            verify_controller_proof(
                controller_key.public_key(),
                controller_context,
                &controller_signature,
            ),
            Ok(())
        );
        let wrong_controller_context = ControllerProofContext::new(
            &exporter,
            &[99; 32],
            VersionEntry::V0_1_SUITE_1,
            controller_id,
        );
        assert!(verify_controller_proof(
            controller_key.public_key(),
            wrong_controller_context,
            &controller_signature,
        )
        .is_err());

        let node_context = NodeProofContext::new(
            &exporter,
            &server_nonce,
            &client_nonce,
            VersionEntry::V0_1_SUITE_1,
            controller_id,
            node_id,
        );
        let node_signature = sign_node_proof(&node_key, node_context);
        assert_eq!(
            verify_node_proof(node_key.public_key(), node_context, &node_signature,),
            Ok(())
        );
        let wrong_node_context = NodeProofContext::new(
            &exporter,
            &server_nonce,
            &client_nonce,
            VersionEntry::V0_1_SUITE_1,
            ControllerId::from_bytes([0; 16]),
            NodeId::from_bytes([0; 16]),
        );
        assert!(
            verify_node_proof(node_key.public_key(), wrong_node_context, &node_signature,).is_err()
        );
    }
}
