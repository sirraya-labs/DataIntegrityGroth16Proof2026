//! # ZK Credential W3C
//!
//! W3C-compliant Verifiable Credentials with Zero-Knowledge Proofs.
//!
//! This library provides a complete implementation of the
//! `poseidon-groth16-2026` cryptosuite for creating privacy-preserving
//! verifiable credentials.
//!
//! ## Quick Start
//!
//! ```rust
//! use zk_credential_w3c::prelude::*;
//!
//! // 1. Setup (do once)
//! let config = DisclosureConfig {
//!     mask: { let mut m = [false; 16]; m[3] = true; m },
//!     age_index: Some(2),
//!     age_threshold: Some(18),
//!     ..Default::default()
//! };
//! let setup = TrustedSetup::new(&config).unwrap();
//!
//! // 2. Create credential
//! let credential = CredentialBuilder::new()
//!     .subject("did:example:alice")
//!     .add_age(2, 25)
//!     .add_attribute(3, "isOver18", "true")
//!     .reveal(3)
//!     .require_min_age(18)
//!     .build(&setup)
//!     .unwrap();
//!
//! // 3. Verify
//! let result = verify_credential(&credential, &setup, None).unwrap();
//! assert!(result.valid);
//! ```
//!
//! ## Modules
//!
//! - `core`: Low-level cryptographic primitives (Poseidon hash, Groth16)
//! - `credential`: High-level API for building and verifying credentials
//! - `cryptosuite`: W3C Data Integrity cryptosuite implementation
//! - `error`: Error types

pub mod core;
pub mod credential;
pub mod cryptosuite;
pub mod error;

/// Prelude with commonly used types
pub mod prelude {
    pub use crate::core::{
        DisclosureConfig, TrustedSetup, generate_master_secret,
        hash_attribute, fr_to_string, fr_from_string,
    };
    pub use crate::credential::{
        CredentialBuilder, W3CCredential, verify_credential,
        VerificationResult, AttributeInfo,
    };
    pub use crate::cryptosuite::{
        Cryptosuite, Issuer, Verifier,
        ProofOptions, ProofConfig, SelectiveDisclosureProof,
        CRYPTOSUITE_ID, PROOF_TYPE,
    };
    pub use crate::error::CredentialError;
}

/// Re-export for convenience
pub use credential::W3CCredential;
pub use core::TrustedSetup;