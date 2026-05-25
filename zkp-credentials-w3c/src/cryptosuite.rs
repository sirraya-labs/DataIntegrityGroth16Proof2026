//! W3C Data Integrity Cryptosuite: poseidon-groth16-2026

use serde::{Deserialize, Serialize};
use crate::core::*;
use crate::credential::*;
use crate::error::CredentialError;

pub const CRYPTOSUITE_ID: &str = "poseidon-groth16-2026";
pub const CRYPTOSUITE_VERSION: &str = "1.0";
pub const PROOF_TYPE: &str = "DataIntegrityProof";

#[derive(Debug, Clone)]
pub struct ProofOptions {
    pub verification_method: String,
    pub proof_purpose: String,
    pub domain: Option<String>,
    pub challenge: Option<String>,
    pub created: Option<String>,
}

impl Default for ProofOptions {
    fn default() -> Self {
        Self {
            verification_method: "did:example:government#poseidon-groth16-key-1".into(),
            proof_purpose: "assertionMethod".into(),
            domain: None,
            challenge: None,
            created: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectiveDisclosureProof {
    pub cryptosuite: String,
    pub config: ProofConfig,
    pub proof_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofConfig {
    pub num_attributes: usize,
    pub revealed_indices: Vec<usize>,
    pub age_verification: Option<AgeVerification>,
    pub commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgeVerification {
    pub age_index: usize,
    pub threshold: u64,
}

pub struct Cryptosuite {
    setup: TrustedSetup,
    #[allow(dead_code)]
    config: DisclosureConfig,
}

impl Cryptosuite {
    pub fn new(config: DisclosureConfig) -> std::result::Result<Self, CredentialError> {
        let setup = TrustedSetup::new(&config)?;
        Ok(Self { setup, config })
    }
    
    pub fn load(keys_dir: &std::path::Path, config: DisclosureConfig) -> std::result::Result<Self, CredentialError> {
        let setup = TrustedSetup::load(keys_dir)?;
        Ok(Self { setup, config })
    }
    
    pub fn save_keys(&self, dir: &std::path::Path) -> std::result::Result<(), CredentialError> {
        self.setup.save(dir)
    }
    
    pub fn verify(
        &self,
        credential: &W3CCredential,
        expected_domain: Option<&str>,
        _expected_challenge: Option<&str>,
        attribute_mapping: &[(usize, &str)],
        age_threshold: Option<u64>,
    ) -> std::result::Result<VerificationResult, CredentialError> {
        if credential.proof.cryptosuite != CRYPTOSUITE_ID {
            return Ok(VerificationResult {
                valid: false,
                reason: Some(format!("Unsupported cryptosuite: {}", credential.proof.cryptosuite)),
                revealed_attributes: vec![],
            });
        }
        
        if credential.proof.proof_type != PROOF_TYPE {
            return Ok(VerificationResult {
                valid: false,
                reason: Some("Invalid proof type".into()),
                revealed_attributes: vec![],
            });
        }
        
        verify_credential(credential, &self.setup, expected_domain, attribute_mapping, age_threshold)
    }
}

pub struct Issuer {
    cryptosuite: Cryptosuite,
    issuer_did: String,
    master_secret: [u8; 32],
}

impl Issuer {
    pub fn new(config: DisclosureConfig, issuer_did: &str) -> std::result::Result<Self, CredentialError> {
        let cryptosuite = Cryptosuite::new(config)?;
        let master_secret = generate_master_secret();
        Ok(Self { cryptosuite, issuer_did: issuer_did.to_string(), master_secret })
    }
    
    pub fn save_keys(&self, dir: &std::path::Path) -> std::result::Result<(), CredentialError> {
        self.cryptosuite.save_keys(dir)
    }
    
    pub fn issue_credential(
        &self,
        subject_id: &str,
        attributes: &[(&str, &str)],
        age: Option<u64>,
        revealed_attribute_names: &[&str],
    ) -> std::result::Result<W3CCredential, CredentialError> {
        let mut builder = CredentialBuilder::new()
            .subject(subject_id)
            .issuer(&self.issuer_did)
            .master_secret(self.master_secret);
        
        for (i, (name, value)) in attributes.iter().enumerate() {
            builder = builder.add_attribute(i, name, value);
        }
        
        if let Some(age_value) = age {
            let age_index = attributes.len();
            builder = builder.add_age(age_index, age_value);
            builder = builder.require_min_age(18);
        }
        
        for (i, (name, _)) in attributes.iter().enumerate() {
            if revealed_attribute_names.contains(name) {
                builder = builder.reveal(i);
            }
        }
        
        builder.build(&self.cryptosuite.setup)
    }
}

pub struct Verifier {
    cryptosuite: Cryptosuite,
}

impl Verifier {
    pub fn new(keys_dir: &std::path::Path, config: DisclosureConfig) -> std::result::Result<Self, CredentialError> {
        let cryptosuite = Cryptosuite::load(keys_dir, config)?;
        Ok(Self { cryptosuite })
    }
    
    pub fn verify_credential(
        &self,
        credential: &W3CCredential,
        expected_domain: Option<&str>,
        attribute_mapping: &[(usize, &str)],
        age_threshold: Option<u64>,
    ) -> std::result::Result<VerificationResult, CredentialError> {
        self.cryptosuite.verify(credential, expected_domain, None, attribute_mapping, age_threshold)
    }
}