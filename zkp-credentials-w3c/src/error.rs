//! Error types for the library

use thiserror::Error;

/// Main error type for zk-credential-w3c
#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Setup failed: {0}")]
    SetupFailed(String),
    
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Invalid credential format: {0}")]
    InvalidCredential(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Constraint not satisfied: {0}")]
    ConstraintUnsatisfied(String),
}

pub type Result<T> = std::result::Result<T, CredentialError>;