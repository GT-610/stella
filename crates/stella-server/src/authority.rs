//! Bounded asynchronous access to the blocking controller authority store.

use std::{io, num::NonZeroUsize, thread};

use stella_common::{NetworkId, NodeId};
use stella_crypto::IdentityPublicKey;
use tokio::sync::{mpsc, oneshot};

use crate::store::{
    AuthorityRevision, AuthorityStore, BearerToken, MembershipRecord, MembershipStatus,
    NetworkRecord, NodeRecord, StoreError,
};

type StoreReply<T> = oneshot::Sender<Result<T, StoreError>>;

/// Cloneable asynchronous command handle for the controller authority thread.
#[derive(Clone)]
pub struct AuthorityHandle {
    sender: mpsc::Sender<Command>,
}

impl AuthorityHandle {
    /// Returns the fixed maximum number of queued authority commands.
    #[must_use]
    pub fn max_queue_capacity(&self) -> usize {
        self.sender.max_capacity()
    }

    /// Returns the number of commands that can currently enter without waiting.
    #[must_use]
    pub fn remaining_queue_capacity(&self) -> usize {
        self.sender.capacity()
    }

    /// Verifies every persisted authority invariant.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] when the queue or reply channel closes, or
    /// when the underlying store fails verification.
    pub async fn verify(&self) -> Result<(), AuthorityError> {
        self.request(|reply| Command::Verify { reply }).await
    }

    /// Creates a node record.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, or store failure.
    pub async fn create_node(&self, record: NodeRecord) -> Result<(), AuthorityError> {
        self.request(|reply| Command::CreateNode { record, reply })
            .await
    }

    /// Returns one node by stable ID.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, or store failure.
    pub async fn get_node(&self, node_id: NodeId) -> Result<Option<NodeRecord>, AuthorityError> {
        self.request(|reply| Command::GetNode { node_id, reply })
            .await
    }

    /// Lists all nodes in stable ID order.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, or store failure.
    pub async fn list_nodes(&self) -> Result<Vec<NodeRecord>, AuthorityError> {
        self.request(|reply| Command::ListNodes { reply }).await
    }

    /// Changes a node's enabled state and atomically invalidates its grants.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, or store failure.
    pub async fn set_node_enabled(
        &self,
        node_id: NodeId,
        enabled: bool,
    ) -> Result<bool, AuthorityError> {
        self.request(|reply| Command::SetNodeEnabled {
            node_id,
            enabled,
            reply,
        })
        .await
    }

    /// Creates a virtual network record.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, or store failure.
    pub async fn create_network(&self, record: NetworkRecord) -> Result<(), AuthorityError> {
        self.request(|reply| Command::CreateNetwork { record, reply })
            .await
    }

    /// Returns one virtual network by stable ID.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, or store failure.
    pub async fn get_network(
        &self,
        network_id: NetworkId,
    ) -> Result<Option<NetworkRecord>, AuthorityError> {
        self.request(|reply| Command::GetNetwork { network_id, reply })
            .await
    }

    /// Lists all virtual networks in stable ID order.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, or store failure.
    pub async fn list_networks(&self) -> Result<Vec<NetworkRecord>, AuthorityError> {
        self.request(|reply| Command::ListNetworks { reply }).await
    }

    /// Issues one single-use enrollment token.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, randomness, validation, or
    /// store failure.
    pub async fn issue_enrollment_token(
        &self,
        created_at: u64,
        expires_at: u64,
    ) -> Result<BearerToken, AuthorityError> {
        self.request(|reply| Command::IssueEnrollmentToken {
            created_at,
            expires_at,
            reply,
        })
        .await
    }

    /// Consumes an enrollment token and creates a node in one transaction.
    ///
    /// The queued command owns a zeroizing token copy, so cancellation never
    /// borrows secret memory from the caller.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, token, validation, or store
    /// failure.
    pub async fn enroll_node(
        &self,
        token: &BearerToken,
        public_key: IdentityPublicKey,
        display_name: String,
        now: u64,
    ) -> Result<NodeRecord, AuthorityError> {
        let token = token.duplicate();
        self.request(|reply| Command::EnrollNode {
            token,
            public_key,
            display_name,
            now,
            reply,
        })
        .await
    }

    /// Issues one single-use token scoped to a virtual network.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, randomness, validation, or
    /// store failure.
    pub async fn issue_join_token(
        &self,
        network_id: NetworkId,
        created_at: u64,
        expires_at: u64,
    ) -> Result<BearerToken, AuthorityError> {
        self.request(|reply| Command::IssueJoinToken {
            network_id,
            created_at,
            expires_at,
            reply,
        })
        .await
    }

    /// Consumes a token and joins a node to its scoped network atomically.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, authorization, or store
    /// failure.
    pub async fn join_with_token(
        &self,
        token: &BearerToken,
        node_id: NodeId,
        network_id: NetworkId,
        now: u64,
    ) -> Result<AuthorityRevision, AuthorityError> {
        let token = token.duplicate();
        self.request(|reply| Command::JoinWithToken {
            token,
            node_id,
            network_id,
            now,
            reply,
        })
        .await
    }

    /// Administratively adds an active network member.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, authorization, or store
    /// failure.
    pub async fn add_member(
        &self,
        node_id: NodeId,
        network_id: NetworkId,
        now: u64,
    ) -> Result<AuthorityRevision, AuthorityError> {
        self.request(|reply| Command::AddMember {
            node_id,
            network_id,
            now,
            reply,
        })
        .await
    }

    /// Removes a member and its endpoint state atomically.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, authorization, or store
    /// failure.
    pub async fn leave_network(
        &self,
        node_id: NodeId,
        network_id: NetworkId,
    ) -> Result<AuthorityRevision, AuthorityError> {
        self.request(|reply| Command::LeaveNetwork {
            node_id,
            network_id,
            reply,
        })
        .await
    }

    /// Suspends or resumes an existing membership.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, authorization, or store
    /// failure.
    pub async fn set_membership_status(
        &self,
        node_id: NodeId,
        network_id: NetworkId,
        status: MembershipStatus,
    ) -> Result<AuthorityRevision, AuthorityError> {
        self.request(|reply| Command::SetMembershipStatus {
            node_id,
            network_id,
            status,
            reply,
        })
        .await
    }

    /// Returns one network membership.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, or store failure.
    pub async fn get_membership(
        &self,
        node_id: NodeId,
        network_id: NetworkId,
    ) -> Result<Option<MembershipRecord>, AuthorityError> {
        self.request(|reply| Command::GetMembership {
            node_id,
            network_id,
            reply,
        })
        .await
    }

    /// Lists every membership in one virtual network.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] for queue, reply, or store failure.
    pub async fn list_memberships(
        &self,
        network_id: NetworkId,
    ) -> Result<Vec<MembershipRecord>, AuthorityError> {
        self.request(|reply| Command::ListMemberships { network_id, reply })
            .await
    }

    async fn request<T>(
        &self,
        build: impl FnOnce(StoreReply<T>) -> Command,
    ) -> Result<T, AuthorityError>
    where
        T: Send + 'static,
    {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(build(reply))
            .await
            .map_err(|_| AuthorityError::QueueClosed)?;
        response
            .await
            .map_err(|_| AuthorityError::ReplyDropped)?
            .map_err(|source| AuthorityError::Store(Box::new(source)))
    }
}

impl std::fmt::Debug for AuthorityHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorityHandle")
            .field("max_queue_capacity", &self.sender.max_capacity())
            .field("remaining_queue_capacity", &self.sender.capacity())
            .finish_non_exhaustive()
    }
}

/// Running dedicated authority thread and its ordered shutdown capability.
pub struct AuthorityThread {
    handle: AuthorityHandle,
    thread: thread::JoinHandle<()>,
}

impl AuthorityThread {
    /// Starts a named blocking thread that takes exclusive ownership of a store.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::Spawn`] when the operating system cannot
    /// create the thread.
    pub fn spawn(
        store: AuthorityStore,
        queue_capacity: NonZeroUsize,
    ) -> Result<Self, AuthorityError> {
        let (sender, receiver) = mpsc::channel(queue_capacity.get());
        let thread = thread::Builder::new()
            .name("stella-authority".to_owned())
            .spawn(move || run_authority(&store, receiver))
            .map_err(|source| AuthorityError::Spawn { source })?;
        Ok(Self {
            handle: AuthorityHandle { sender },
            thread,
        })
    }

    /// Returns a cloneable asynchronous handle to the authority queue.
    #[must_use]
    pub fn handle(&self) -> AuthorityHandle {
        self.handle.clone()
    }

    /// Drains all earlier commands, stops the worker, and joins its thread.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError`] when the worker already stopped, drops the
    /// shutdown acknowledgement, or panics.
    pub async fn shutdown(self) -> Result<(), AuthorityError> {
        let (reply, response) = oneshot::channel();
        self.handle
            .sender
            .send(Command::Shutdown { reply })
            .await
            .map_err(|_| AuthorityError::QueueClosed)?;
        response.await.map_err(|_| AuthorityError::ReplyDropped)?;
        self.thread
            .join()
            .map_err(|_| AuthorityError::ThreadPanicked)
    }
}

impl std::fmt::Debug for AuthorityThread {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorityThread")
            .field("handle", &self.handle)
            .field("thread", &self.thread.thread().name())
            .finish_non_exhaustive()
    }
}

/// Authority queue, persistence, or worker lifecycle failure.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    /// The bounded command receiver is no longer available.
    #[error("authority command queue is closed")]
    QueueClosed,
    /// The worker stopped without sending a typed response.
    #[error("authority worker dropped a command response")]
    ReplyDropped,
    /// The operating system could not start the dedicated worker thread.
    #[error("unable to spawn authority worker thread")]
    Spawn {
        /// Underlying thread creation failure.
        #[source]
        source: io::Error,
    },
    /// The dedicated authority worker panicked.
    #[error("authority worker thread panicked")]
    ThreadPanicked,
    /// The authority store rejected or failed a command.
    #[error(transparent)]
    Store(Box<StoreError>),
}

enum Command {
    Verify {
        reply: StoreReply<()>,
    },
    CreateNode {
        record: NodeRecord,
        reply: StoreReply<()>,
    },
    GetNode {
        node_id: NodeId,
        reply: StoreReply<Option<NodeRecord>>,
    },
    ListNodes {
        reply: StoreReply<Vec<NodeRecord>>,
    },
    SetNodeEnabled {
        node_id: NodeId,
        enabled: bool,
        reply: StoreReply<bool>,
    },
    CreateNetwork {
        record: NetworkRecord,
        reply: StoreReply<()>,
    },
    GetNetwork {
        network_id: NetworkId,
        reply: StoreReply<Option<NetworkRecord>>,
    },
    ListNetworks {
        reply: StoreReply<Vec<NetworkRecord>>,
    },
    IssueEnrollmentToken {
        created_at: u64,
        expires_at: u64,
        reply: StoreReply<BearerToken>,
    },
    EnrollNode {
        token: BearerToken,
        public_key: IdentityPublicKey,
        display_name: String,
        now: u64,
        reply: StoreReply<NodeRecord>,
    },
    IssueJoinToken {
        network_id: NetworkId,
        created_at: u64,
        expires_at: u64,
        reply: StoreReply<BearerToken>,
    },
    JoinWithToken {
        token: BearerToken,
        node_id: NodeId,
        network_id: NetworkId,
        now: u64,
        reply: StoreReply<AuthorityRevision>,
    },
    AddMember {
        node_id: NodeId,
        network_id: NetworkId,
        now: u64,
        reply: StoreReply<AuthorityRevision>,
    },
    LeaveNetwork {
        node_id: NodeId,
        network_id: NetworkId,
        reply: StoreReply<AuthorityRevision>,
    },
    SetMembershipStatus {
        node_id: NodeId,
        network_id: NetworkId,
        status: MembershipStatus,
        reply: StoreReply<AuthorityRevision>,
    },
    GetMembership {
        node_id: NodeId,
        network_id: NetworkId,
        reply: StoreReply<Option<MembershipRecord>>,
    },
    ListMemberships {
        network_id: NetworkId,
        reply: StoreReply<Vec<MembershipRecord>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

impl Command {
    fn execute(self, store: &AuthorityStore) -> bool {
        match self {
            Self::Verify { reply } => respond(reply, store.verify()),
            Self::CreateNode { record, reply } => respond(reply, store.create_node(&record)),
            Self::GetNode { node_id, reply } => respond(reply, store.get_node(node_id)),
            Self::ListNodes { reply } => respond(reply, store.list_nodes()),
            Self::SetNodeEnabled {
                node_id,
                enabled,
                reply,
            } => respond(reply, store.set_node_enabled(node_id, enabled)),
            Self::CreateNetwork { record, reply } => {
                respond(reply, store.create_network(&record));
            }
            Self::GetNetwork { network_id, reply } => {
                respond(reply, store.get_network(network_id));
            }
            Self::ListNetworks { reply } => respond(reply, store.list_networks()),
            Self::IssueEnrollmentToken {
                created_at,
                expires_at,
                reply,
            } => respond(reply, store.issue_enrollment_token(created_at, expires_at)),
            Self::EnrollNode {
                token,
                public_key,
                display_name,
                now,
                reply,
            } => respond(
                reply,
                store.enroll_node(&token, public_key, &display_name, now),
            ),
            Self::IssueJoinToken {
                network_id,
                created_at,
                expires_at,
                reply,
            } => respond(
                reply,
                store.issue_join_token(network_id, created_at, expires_at),
            ),
            Self::JoinWithToken {
                token,
                node_id,
                network_id,
                now,
                reply,
            } => respond(
                reply,
                store.join_with_token(&token, node_id, network_id, now),
            ),
            Self::AddMember {
                node_id,
                network_id,
                now,
                reply,
            } => respond(reply, store.add_member(node_id, network_id, now)),
            Self::LeaveNetwork {
                node_id,
                network_id,
                reply,
            } => respond(reply, store.leave_network(node_id, network_id)),
            Self::SetMembershipStatus {
                node_id,
                network_id,
                status,
                reply,
            } => respond(
                reply,
                store.set_membership_status(node_id, network_id, status),
            ),
            Self::GetMembership {
                node_id,
                network_id,
                reply,
            } => respond(reply, store.get_membership(node_id, network_id)),
            Self::ListMemberships { network_id, reply } => {
                respond(reply, store.list_memberships(network_id));
            }
            Self::Shutdown { reply } => {
                let _reply_result = reply.send(());
                return false;
            }
        }
        true
    }
}

fn run_authority(store: &AuthorityStore, mut receiver: mpsc::Receiver<Command>) {
    while let Some(command) = receiver.blocking_recv() {
        if !command.execute(store) {
            receiver.close();
            break;
        }
    }
}

fn respond<T>(reply: StoreReply<T>, result: Result<T, StoreError>) {
    drop(reply.send(result));
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroUsize,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use stella_common::{ControllerId, NetworkId};
    use stella_crypto::{IdentitySeed, IdentitySigningKey};
    use stella_proto::{ConfidentialityPolicy, NetworkPolicy};

    use super::{AuthorityError, AuthorityThread};
    use crate::store::{AuthorityStore, MembershipStatus, NetworkRecord, NodeRecord};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_directory() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "stella-authority-thread-{}-{sequence}",
            std::process::id()
        ))
    }

    fn signing_key(seed: u8) -> IdentitySigningKey {
        IdentitySigningKey::from_seed(&IdentitySeed::from_bytes([seed; 32]))
    }

    fn policy(network_id: NetworkId) -> NetworkPolicy {
        NetworkPolicy {
            confidentiality: ConfidentialityPolicy::Encrypt,
            max_frame_size: 1_514,
            max_flood_peers: 32,
            flood_rate: 1_000,
            flood_burst: 2_000,
            mac_age_seconds: 300,
            heartbeat_seconds: 10,
            peer_lease_seconds: 30,
            session_lifetime_seconds: 900,
            reassembly_timeout_ms: 3_000,
            network_id,
            policy_revision: 1,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn typed_commands_preserve_transaction_order() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.redb");
        let store = AuthorityStore::initialize(&path, ControllerId::from_bytes([31; 16]))
            .expect("initialize store");
        let worker = AuthorityThread::spawn(
            store,
            NonZeroUsize::new(2).expect("non-zero queue capacity"),
        )
        .expect("spawn authority thread");
        let authority = worker.handle();
        assert_eq!(authority.max_queue_capacity(), 2);

        let node =
            NodeRecord::new(signing_key(32).public_key(), "Async node", 100).expect("valid node");
        let node_id = node.node_id();
        authority.create_node(node).await.expect("create node");
        let network_id = NetworkId::from_bytes([33; 16]);
        let network =
            NetworkRecord::new(policy(network_id), "Async LAN", 100).expect("valid network");
        authority
            .create_network(network)
            .await
            .expect("create network");
        let joined = authority
            .add_member(node_id, network_id, 110)
            .await
            .expect("add member");
        assert_eq!(joined.controller_epoch, 2);
        let suspended = authority
            .set_membership_status(node_id, network_id, MembershipStatus::Suspended)
            .await
            .expect("suspend member");
        assert_eq!(suspended.controller_epoch, 3);
        assert_eq!(
            authority
                .get_membership(node_id, network_id)
                .await
                .expect("get membership")
                .expect("membership exists")
                .status(),
            MembershipStatus::Suspended
        );
        authority.verify().await.expect("verify authority state");

        let stale = worker.handle();
        worker.shutdown().await.expect("shutdown worker");
        assert!(matches!(
            stale.verify().await,
            Err(AuthorityError::QueueClosed)
        ));
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn token_commands_own_zeroizing_secret_copies() {
        let directory = temp_directory();
        std::fs::create_dir(&directory).expect("create test directory");
        let path = directory.join("controller.redb");
        let store = AuthorityStore::initialize(&path, ControllerId::from_bytes([34; 16]))
            .expect("initialize store");
        let worker = AuthorityThread::spawn(
            store,
            NonZeroUsize::new(1).expect("non-zero queue capacity"),
        )
        .expect("spawn authority thread");
        let authority = worker.handle();
        let token = authority
            .issue_enrollment_token(100, 200)
            .await
            .expect("issue enrollment token");
        let node = authority
            .enroll_node(
                &token,
                signing_key(35).public_key(),
                "Enrolled async node".to_owned(),
                150,
            )
            .await
            .expect("enroll node");
        assert_eq!(
            authority.get_node(node.node_id()).await.expect("get node"),
            Some(node)
        );
        worker.shutdown().await.expect("shutdown worker");
        std::fs::remove_dir_all(&directory).expect("remove test directory");
    }
}
