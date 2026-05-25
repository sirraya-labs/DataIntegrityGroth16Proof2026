use thiserror::Error;

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Setup failed: {0}")]
    SetupFailed(String),
    
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Constraint not satisfied: {0}")]
    ConstraintUnsatisfied(String),
    
    #[error("Unknown attribute: {0}")]
    UnknownAttribute(String),
    
    #[error("Invalid predicate: {0}")]
    InvalidPredicate(String),
    
    #[error("Too many predicates: max {0}, got {1}")]
    TooManyPredicates(usize, usize),
    
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),
    
    #[error("Proof expired at {0}")]
    ProofExpired(u64),
    
    #[error("Proof not yet valid until {0}")]
    ProofNotYetValid(u64),
}