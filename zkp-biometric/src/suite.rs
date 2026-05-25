use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ark_bn254::Fr;
use ark_ff::Zero;

use crate::crypto::*;
use crate::error::CredentialError;
use crate::types::*;

pub struct PoseidonGroth16Suite {
    pub holder_secret: [u8; 32],
    pub setup: TrustedSetup,
    pub domain_element: Fr,
    pub attribute_map: HashMap<String, usize>,
    pub next_index: usize,
}

impl PoseidonGroth16Suite {
    pub fn new() -> Result<Self, CredentialError> {
        Ok(Self {
            holder_secret: generate_holder_secret(),
            setup: TrustedSetup::new()?,
            domain_element: get_commitment_domain(),
            attribute_map: HashMap::new(),
            next_index: 0,
        })
    }

    pub fn register_attribute(&mut self, label: &str) {
        let idx = self.next_index;
        self.attribute_map.insert(label.to_string(), idx);
        self.next_index += 1;
    }

    pub fn register_biometric_attributes(&mut self) {
        self.register_attribute("biometric_face_match");
        self.register_attribute("biometric_depth_variance");
        self.register_attribute("biometric_liveness");
        self.register_attribute("biometric_timestamp");
    }

    pub fn issue_credential(
        &self,
        credential_id: &str,
        issuer_did: &str,
        claims: &[Claim],
    ) -> Result<VerifiableCredential, CredentialError> {
        let mut attrs = [Fr::zero(); NUM_ATTRIBUTES];
        let mut presence = [false; NUM_ATTRIBUTES];
        
        for claim in claims {
            let idx = *self.attribute_map.get(&claim.label)
                .ok_or_else(|| CredentialError::UnknownAttribute(claim.label.clone()))?;
            attrs[idx] = claim.value.to_fr();
            presence[idx] = true;
        }

        let nonce = derive_nonce(credential_id, &self.holder_secret);
        let blinding = derive_blinding(&self.holder_secret, &nonce);
        let commitment = create_commitment(&attrs,  &blinding);

        Ok(VerifiableCredential {
            credential_id: credential_id.to_string(),
            issuer_did: issuer_did.to_string(),
            claims: claims.to_vec(),
            commitment: commitment.to_string(),
            proof_value: String::new(),
            revealed_labels: vec![],
            predicates_described: vec![],
            cryptosuite: "poseidon-groth16-bn254-2026".to_string(),
            window_start: 0,
            window_expires: 0,
        })
    }

    pub fn derive_proof_with_timestamp(
        &self,
        credential: &VerifiableCredential,
        reveal: &RevealRequest,
        predicates: &[PredicateType],
        window_start: u64,
        window_expires: u64,
    ) -> Result<VerifiableCredential, CredentialError> {
        if predicates.len() > MAX_PREDICATES {
            return Err(CredentialError::TooManyPredicates(MAX_PREDICATES, predicates.len()));
        }

        // Build attributes from claims
        let mut attrs = [Fr::zero(); NUM_ATTRIBUTES];
        let mut presence = [false; NUM_ATTRIBUTES];
        for claim in &credential.claims {
            let idx = *self.attribute_map.get(&claim.label)
                .ok_or_else(|| CredentialError::UnknownAttribute(claim.label.clone()))?;
            attrs[idx] = claim.value.to_fr();
            presence[idx] = true;
        }

        // Deterministic nonce and blinding
        let nonce = derive_nonce(&credential.credential_id, &self.holder_secret);
        let blinding = derive_blinding(&self.holder_secret, &nonce);
        
        // Parse stored commitment
        let commitment: Fr = credential.commitment.parse().unwrap_or(Fr::zero());
        
        // DEBUG: Recompute and compare commitment
        let recomputed = create_commitment(&attrs,  &blinding);
        if commitment != recomputed {
            return Err(CredentialError::ConstraintUnsatisfied(format!(
                "COMMITMENT MISMATCH: stored={} recomputed={}", commitment, recomputed
            )));
        }

        // Build mask
        let mut mask = [false; NUM_ATTRIBUTES];
        for label in &reveal.reveal_labels {
            let idx = *self.attribute_map.get(label)
                .ok_or_else(|| CredentialError::UnknownAttribute(label.clone()))?;
            mask[idx] = true;
        }

        // Build predicate slots
        let mut slots = [PredicateSlot::default(); MAX_PREDICATES];
        for (i, pred) in predicates.iter().enumerate() {
            slots[i] = self.build_slot(pred)?;
        }

        // Generate proof
        let proof_bytes = generate_proof(
            &self.setup, &attrs, blinding, commitment, &slots, &mask,
            window_start as u32, window_expires as u32,
        )?;

        let proof_value = base64_url::encode(&proof_bytes);
        let described: Vec<String> = predicates.iter().map(|p| p.describe()).collect();

        Ok(VerifiableCredential {
            credential_id: credential.credential_id.clone(),
            issuer_did: credential.issuer_did.clone(),
            claims: credential.claims.clone(),
            commitment: commitment.to_string(),
            proof_value,
            revealed_labels: reveal.reveal_labels.clone(),
            predicates_described: described,
            cryptosuite: "poseidon-groth16-bn254-2026".to_string(),
            window_start,
            window_expires,
        })
    }

    fn build_slot(&self, pred: &PredicateType) -> Result<PredicateSlot, CredentialError> {
        let idx = |l: &str| -> Result<usize, CredentialError> {
            self.attribute_map.get(l).copied()
                .ok_or_else(|| CredentialError::UnknownAttribute(l.to_string()))
        };

        match pred {
            PredicateType::GreaterThanOrEqual { attribute, threshold } => Ok(PredicateSlot {
                active: true, pred_type: 1, attr_index: idx(attribute)?,
                val1: Fr::from(*threshold), val2: Fr::zero(), ..Default::default()
            }),
            PredicateType::GreaterThan { attribute, threshold } => Ok(PredicateSlot {
                active: true, pred_type: 2, attr_index: idx(attribute)?,
                val1: Fr::from(*threshold), val2: Fr::zero(), ..Default::default()
            }),
            PredicateType::LessThan { attribute, threshold } => Ok(PredicateSlot {
                active: true, pred_type: 3, attr_index: idx(attribute)?,
                val1: Fr::from(*threshold), val2: Fr::zero(), ..Default::default()
            }),
            PredicateType::LessThanOrEqual { attribute, threshold } => Ok(PredicateSlot {
                active: true, pred_type: 4, attr_index: idx(attribute)?,
                val1: Fr::from(*threshold), val2: Fr::zero(), ..Default::default()
            }),
            PredicateType::Equality { attribute, value } => Ok(PredicateSlot {
                active: true, pred_type: 5, attr_index: idx(attribute)?,
                val1: hash_attribute(value), val2: Fr::zero(), ..Default::default()
            }),
            PredicateType::NotEqual { attribute, value } => Ok(PredicateSlot {
                active: true, pred_type: 6, attr_index: idx(attribute)?,
                val1: hash_attribute(value), val2: Fr::zero(), ..Default::default()
            }),
            PredicateType::Range { attribute, min, max } => {
                if min > max {
                    return Err(CredentialError::InvalidPredicate("min > max".into()));
                }
                Ok(PredicateSlot {
                    active: true, pred_type: 7, attr_index: idx(attribute)?,
                    val1: Fr::from(*min), val2: Fr::from(*max), ..Default::default()
                })
            }
            PredicateType::InSet { attribute, allowed_values } => {
                let mut sorted = allowed_values.clone();
                sorted.sort();
                sorted.dedup();
                let mut inset_values = [Fr::zero(); MAX_INSET_VALUES];
                let count = sorted.len().min(MAX_INSET_VALUES);
                for i in 0..count { inset_values[i] = hash_attribute(&sorted[i]); }
                Ok(PredicateSlot {
                    active: true, pred_type: 8, attr_index: idx(attribute)?,
                    val1: Fr::zero(), val2: Fr::zero(), inset_values, inset_count: count,
                })
            }
            PredicateType::FaceMatch { min_similarity } => {
                let idx = self.attribute_map.get("biometric_face_match").copied()
                    .ok_or_else(|| CredentialError::UnknownAttribute("biometric_face_match".into()))?;
                Ok(PredicateSlot {
                    active: true, pred_type: 9, attr_index: idx,
                    val1: Fr::from(*min_similarity), val2: Fr::zero(), ..Default::default()
                })
            }
            PredicateType::DepthCheck { min_depth_variance } => {
                let idx = self.attribute_map.get("biometric_depth_variance").copied()
                    .ok_or_else(|| CredentialError::UnknownAttribute("biometric_depth_variance".into()))?;
                Ok(PredicateSlot {
                    active: true, pred_type: 10, attr_index: idx,
                    val1: Fr::from(*min_depth_variance), val2: Fr::zero(), ..Default::default()
                })
            }
            PredicateType::LivenessCheck { min_confidence } => {
                let idx = self.attribute_map.get("biometric_liveness").copied()
                    .ok_or_else(|| CredentialError::UnknownAttribute("biometric_liveness".into()))?;
                Ok(PredicateSlot {
                    active: true, pred_type: 11, attr_index: idx,
                    val1: Fr::from(*min_confidence), val2: Fr::zero(), ..Default::default()
                })
            }
        }
    }

    pub fn verify_proof_with_time(&self, credential: &VerifiableCredential) -> VerificationResult {
        let mut errors = Vec::new();
        let proof_bytes = match base64_url::decode(&credential.proof_value) {
            Ok(b) => b,
            Err(e) => {
                errors.push(e.to_string());
                return VerificationResult { valid: false, revealed_claims: vec![], predicates_verified: vec![], errors };
            }
        };

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if now < credential.window_start {
            errors.push(format!("Not yet valid until {}", credential.window_start));
            return VerificationResult { valid: false, revealed_claims: vec![], predicates_verified: vec![], errors };
        }
        if now >= credential.window_expires {
            errors.push(format!("Expired at {}", credential.window_expires));
            return VerificationResult { valid: false, revealed_claims: vec![], predicates_verified: vec![], errors };
        }

        let mut public_inputs = [Fr::zero(); PUBLIC_INPUT_SIZE];
        let mut revealed_claims = Vec::new();
        for claim in &credential.claims {
            if credential.revealed_labels.contains(&claim.label) {
                if let Some(&idx) = self.attribute_map.get(&claim.label) {
                    public_inputs[idx] = claim.value.to_fr();
                    revealed_claims.push(claim.clone());
                }
            }
        }
        public_inputs[NUM_ATTRIBUTES] = credential.commitment.parse::<Fr>().unwrap_or(Fr::zero());
        public_inputs[NUM_ATTRIBUTES + 1] = Fr::from(credential.window_start);
        public_inputs[NUM_ATTRIBUTES + 2] = Fr::from(credential.window_expires);

        match verify_proof(&self.setup, &proof_bytes, &public_inputs) {
            Ok(true) => VerificationResult {
                valid: true, revealed_claims,
                predicates_verified: credential.predicates_described.clone(), errors: vec![],
            },
            Ok(false) => VerificationResult {
                valid: false, revealed_claims, predicates_verified: vec![],
                errors: vec!["Invalid proof".to_string()],
            },
            Err(e) => VerificationResult {
                valid: false, revealed_claims, predicates_verified: vec![],
                errors: vec![e.to_string()],
            },
        }
    }

    pub fn export_w3c_json(&self, credential: &VerifiableCredential) -> String {
        let claims_json: Vec<String> = credential.claims.iter().map(|c| {
            let v = match &c.value {
                ClaimValue::Text(s) => format!("\"{}\"", s),
                ClaimValue::Number(n) => n.to_string(),
                ClaimValue::Boolean(b) => b.to_string(),
            };
            format!("      {{\"label\": \"{}\", \"value\": {}}}", c.label, v)
        }).collect();

        format!(r#"{{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/security/data-integrity/v2",
    "https://w3id.org/security/poseidon-groth16-bn254-2026/v1"
  ],
  "id": "{id}",
  "type": ["VerifiableCredential"],
  "issuer": "{issuer}",
  "credentialSubject": {{
    "claims": [
{claims}
    ],
    "commitment": "{comm}"
  }},
  "proof": {{
    "type": "DataIntegrityProof",
    "cryptosuite": "poseidon-groth16-bn254-2026",
    "proofValue": "{pv}",
    "windowStart": {ws},
    "windowExpires": {we},
    "revealedAttributes": [{revealed}],
    "predicates": [{preds}]
  }}
}}"#,
            id = credential.credential_id,
            issuer = credential.issuer_did,
            claims = claims_json.join(",\n"),
            comm = credential.commitment,
            pv = credential.proof_value,
            ws = credential.window_start,
            we = credential.window_expires,
            revealed = credential.revealed_labels.iter().map(|l| format!("\"{}\"", l)).collect::<Vec<_>>().join(", "),
            preds = credential.predicates_described.iter().map(|p| format!("\"{}\"", p)).collect::<Vec<_>>().join(", "),
        )
    }

    pub fn save_keys(&self, dir: &std::path::Path) -> Result<(), CredentialError> {
        self.setup.save(dir)
    }
}