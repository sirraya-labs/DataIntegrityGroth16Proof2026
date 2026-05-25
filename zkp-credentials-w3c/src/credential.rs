//! W3C Verifiable Credential creation and verification

use ark_bn254::Fr;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::core::*;
use crate::error::CredentialError;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// W3C JSON Types
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    pub id: String,
    pub commitment: String,
    #[serde(rename = "revealedAttributes")]
    pub revealed_attributes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub cryptosuite: String,
    pub created: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct W3CCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    pub proof: CredentialProof,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Credential Builder
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub struct AttributeInfo {
    pub index: usize,
    pub name: String,
    pub value: String,
    pub is_age: bool,
}

pub struct CredentialBuilder {
    credential_id: String,
    subject_id: String,
    issuer: String,
    domain: String,
    attributes: [Option<String>; NUM_ATTRIBUTES],
    attribute_infos: Vec<AttributeInfo>,
    revealed: Vec<String>,
    config: DisclosureConfig,
    master_secret: Option<[u8; 32]>,
}

impl CredentialBuilder {
    pub fn new() -> Self {
        Self {
            credential_id: format!("urn:uuid:{}", uuid_simple()),
            subject_id: String::new(),
            issuer: "did:example:government".to_string(),
            domain: "https://verifier.example".to_string(),
            attributes: [const { None }; NUM_ATTRIBUTES],
            attribute_infos: Vec::new(),
            revealed: Vec::new(),
            config: DisclosureConfig::default(),
            master_secret: None,
        }
    }

    pub fn id(mut self, id: &str) -> Self {
        self.credential_id = id.to_string();
        self
    }

    pub fn subject(mut self, id: &str) -> Self {
        self.subject_id = id.to_string();
        self
    }

    pub fn issuer(mut self, issuer: &str) -> Self {
        self.issuer = issuer.to_string();
        self
    }

    pub fn domain(mut self, domain: &str) -> Self {
        self.domain = domain.to_string();
        self
    }

    pub fn add_attribute(mut self, index: usize, name: &str, value: &str) -> Self {
        if index < NUM_ATTRIBUTES {
            self.attributes[index] = Some(value.to_string());
            self.attribute_infos.push(AttributeInfo {
                index,
                name: name.to_string(),
                value: value.to_string(),
                is_age: false,
            });
        }
        self
    }

    pub fn add_age(mut self, index: usize, age: u64) -> Self {
        if index < NUM_ATTRIBUTES {
            let age_str = age.to_string();
            self.attributes[index] = Some(age_str.clone());
            self.config.age_index = Some(index);
            self.attribute_infos.push(AttributeInfo {
                index,
                name: "age".to_string(),
                value: age_str,
                is_age: true,
            });
        }
        self
    }

    pub fn require_min_age(mut self, threshold: u64) -> Self {
        self.config.age_threshold = Some(threshold);
        self
    }

    pub fn reveal(mut self, index: usize) -> Self {
        if index < NUM_ATTRIBUTES {
            self.config.mask[index] = true;
            if let Some(ref attr) = self.attributes[index] {
                self.revealed.push(attr.clone());
            }
        }
        self
    }

    pub fn master_secret(mut self, secret: [u8; 32]) -> Self {
        self.master_secret = Some(secret);
        self
    }

    pub fn build(self, setup: &TrustedSetup) -> std::result::Result<W3CCredential, CredentialError> {
        if self.subject_id.is_empty() {
            return Err(CredentialError::InvalidCredential("Subject ID is required".into()));
        }

        let master_secret = self.master_secret.unwrap_or_else(generate_master_secret);
        let blinding = derive_blinding(&master_secret, &self.credential_id);

        let mut attr_fr = [Fr::from(0u64); NUM_ATTRIBUTES];
        for info in &self.attribute_infos {
            if info.is_age {
                if let Ok(age) = info.value.parse::<u64>() {
                    attr_fr[info.index] = Fr::from(age);
                }
            } else {
                attr_fr[info.index] = hash_attribute(&info.value);
            }
        }

        let commitment = create_commitment(&attr_fr, &blinding);
        let proof = generate_proof(setup, &attr_fr, blinding, commitment, &self.config)?;
        let proof_bytes = proof_to_bytes(&proof)?;
        let proof_value = base64url_encode(&proof_bytes);
        let verification_method = format!("{}#poseidon-groth16-key-1", self.issuer);

        Ok(W3CCredential {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".into(),
                "https://w3id.org/security/data-integrity/v2".into(),
            ],
            id: self.credential_id,
            credential_type: vec!["VerifiableCredential".into(), "AgeCredential".into()],
            issuer: self.issuer,
            issuance_date: current_timestamp(),
            credential_subject: CredentialSubject {
                id: self.subject_id,
                commitment: commitment.to_string(),
                revealed_attributes: self.revealed,
            },
            proof: CredentialProof {
                proof_type: "DataIntegrityProof".into(),
                cryptosuite: "poseidon-groth16-2026".into(),
                created: current_timestamp(),
                verification_method,
                proof_purpose: "assertionMethod".into(),
                proof_value,
                domain: self.domain,
            },
        })
    }
}

impl Default for CredentialBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Verification
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub fn verify_credential(
    credential: &W3CCredential,
    setup: &TrustedSetup,
    expected_domain: Option<&str>,
    attribute_mapping: &[(usize, &str)],
    age_threshold: Option<u64>,
) -> std::result::Result<VerificationResult, CredentialError> {
    if let Some(domain) = expected_domain {
        if credential.proof.domain != domain {
            return Ok(VerificationResult {
                valid: false,
                reason: Some(format!("Domain mismatch: expected '{}', got '{}'", domain, credential.proof.domain)),
                revealed_attributes: vec![],
            });
        }
    }

    let commitment = match fr_from_string(&credential.credential_subject.commitment) {
        Ok(c) => c,
        Err(_) => return Ok(VerificationResult {
            valid: false,
            reason: Some("Invalid commitment format".into()),
            revealed_attributes: vec![],
        }),
    };

    let proof_bytes = match base64url_decode(&credential.proof.proof_value) {
        Some(b) => b,
        None => return Ok(VerificationResult {
            valid: false,
            reason: Some("Invalid proof encoding".into()),
            revealed_attributes: vec![],
        }),
    };

    let proof = match proof_from_bytes(&proof_bytes) {
        Ok(p) => p,
        Err(_) => return Ok(VerificationResult {
            valid: false,
            reason: Some("Invalid proof format".into()),
            revealed_attributes: vec![],
        }),
    };

    let mut revealed = [None; NUM_ATTRIBUTES];
    for (index, value) in attribute_mapping {
        if *index < NUM_ATTRIBUTES {
            revealed[*index] = if value.parse::<u64>().is_ok() {
                Some(Fr::from(value.parse::<u64>().unwrap()))
            } else {
                Some(hash_attribute(value))
            };
        }
    }

    match verify_proof(setup, &proof, &revealed, commitment, age_threshold) {
        Ok(valid) => Ok(VerificationResult {
            valid,
            reason: if valid { None } else { Some("Proof verification failed".into()) },
            revealed_attributes: credential.credential_subject.revealed_attributes.clone(),
        }),
        Err(e) => Ok(VerificationResult {
            valid: false,
            reason: Some(format!("Verification error: {}", e)),
            revealed_attributes: vec![],
        }),
    }
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub reason: Option<String>,
    pub revealed_attributes: Vec<String>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Serialization
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl W3CCredential {
    pub fn to_json(&self) -> std::result::Result<String, CredentialError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CredentialError::SerializationError(e.to_string()))
    }

    pub fn from_json(json: &str) -> std::result::Result<Self, CredentialError> {
        serde_json::from_str(json)
            .map_err(|e| CredentialError::InvalidCredential(e.to_string()))
    }

    pub fn save(&self, path: &Path) -> std::result::Result<(), CredentialError> {
        let json = self.to_json()?;
        fs::write(path, json).map_err(CredentialError::IoError)
    }

    pub fn load(path: &Path) -> std::result::Result<Self, CredentialError> {
        let json = fs::read_to_string(path).map_err(CredentialError::IoError)?;
        Self::from_json(&json)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn base64url_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[(triple >> 18) as usize & 0x3F] as char);
        result.push(CHARS[(triple >> 12) as usize & 0x3F] as char);
        if chunk.len() > 1 { result.push(CHARS[(triple >> 6) as usize & 0x3F] as char); }
        if chunk.len() > 2 { result.push(CHARS[(triple >> 0) as usize & 0x3F] as char); }
    }
    result
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    const DECODE: [u8; 128] = {
        let mut table = [0xFFu8; 128];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut i = 0u8;
        while (i as usize) < chars.len() {
            table[chars[i as usize] as usize] = i;
            i += 1;
        }
        table
    };

    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    
    for chunk in bytes.chunks(4) {
        if chunk.len() == 4 {
            let vals = [DECODE[chunk[0] as usize], DECODE[chunk[1] as usize], DECODE[chunk[2] as usize], DECODE[chunk[3] as usize]];
            if vals.iter().any(|&v| v == 0xFF) { return None; }
            let triple = ((vals[0] as u32) << 18) | ((vals[1] as u32) << 12) | ((vals[2] as u32) << 6) | (vals[3] as u32);
            result.push((triple >> 16) as u8);
            result.push((triple >> 8) as u8);
            result.push(triple as u8);
        } else {
            let chunk_len = chunk.len();
            let padding = 4 - chunk_len;
            let mut padded = chunk.to_vec();
            for _ in 0..padding { padded.push(b'A'); }
            let vals = [DECODE[padded[0] as usize], DECODE[padded[1] as usize], DECODE[padded[2] as usize], DECODE[padded[3] as usize]];
            if vals[0] == 0xFF || vals[1] == 0xFF { return None; }
            let triple = ((vals[0] as u32) << 18) | ((vals[1] as u32) << 12) | ((vals[2] as u32) << 6) | (vals[3] as u32);
            result.push((triple >> 16) as u8);
            if chunk_len > 2 { result.push((triple >> 8) as u8); }
            if chunk_len > 3 { result.push(triple as u8); }
        }
    }
    Some(result)
}

fn current_timestamp() -> String {
    "2026-05-21T00:00:00Z".to_string()
}

fn uuid_simple() -> String {
    let bytes: Vec<u8> = (0..16).map(|_| rand::Rng::gen(&mut rand::thread_rng())).collect();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}