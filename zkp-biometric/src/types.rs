use serde::{Deserialize, Serialize};
use ark_bn254::Fr;
use ark_ff::{Zero, PrimeField};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claim {
    pub label: String,
    pub value: ClaimValue,
}

impl Claim {
    pub fn new(label: &str, value: ClaimValue) -> Self {
        Self { label: label.to_string(), value }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimValue {
    Text(String),
    Number(u64),
    Boolean(bool),
}

impl ClaimValue {
    pub fn to_fr(&self) -> Fr {
        match self {
            Self::Text(s) => crate::crypto::hash_attribute(s),
            Self::Number(n) => Fr::from(*n),
            Self::Boolean(b) => {
                crate::crypto::hash_attribute(if *b { "true" } else { "false" })
            }
        }
    }
}

#[derive(Clone, Debug)]
pub enum PredicateType {
    GreaterThanOrEqual { attribute: String, threshold: u64 },
    GreaterThan { attribute: String, threshold: u64 },
    LessThan { attribute: String, threshold: u64 },
    LessThanOrEqual { attribute: String, threshold: u64 },
    Equality { attribute: String, value: String },
    NotEqual { attribute: String, value: String },
    Range { attribute: String, min: u64, max: u64 },
    InSet { attribute: String, allowed_values: Vec<String> },
    FaceMatch { min_similarity: u64 },
    DepthCheck { min_depth_variance: u64 },
    LivenessCheck { min_confidence: u64 },
}

impl PredicateType {
    pub fn describe(&self) -> String {
        match self {
            Self::GreaterThanOrEqual { attribute, threshold } => format!("{} >= {}", attribute, threshold),
            Self::GreaterThan { attribute, threshold } => format!("{} > {}", attribute, threshold),
            Self::LessThan { attribute, threshold } => format!("{} < {}", attribute, threshold),
            Self::LessThanOrEqual { attribute, threshold } => format!("{} <= {}", attribute, threshold),
            Self::Equality { attribute, value } => format!("{} = \"{}\"", attribute, value),
            Self::NotEqual { attribute, value } => format!("{} != \"{}\"", attribute, value),
            Self::Range { attribute, min, max } => format!("{} BETWEEN {} AND {}", attribute, min, max),
            Self::InSet { attribute, allowed_values } => {
                let mut v = allowed_values.clone();
                v.sort();
                format!("{} IN {:?}", attribute, v)
            }
            Self::FaceMatch { min_similarity } => format!("face_match >= {}", min_similarity),
            Self::DepthCheck { min_depth_variance } => format!("depth_variance >= {}", min_depth_variance),
            Self::LivenessCheck { min_confidence } => format!("liveness >= {}", min_confidence),
        }
    }

    pub fn to_opcode(&self) -> u8 {
        match self {
            Self::GreaterThanOrEqual { .. } => 1,
            Self::GreaterThan { .. } => 2,
            Self::LessThan { .. } => 3,
            Self::LessThanOrEqual { .. } => 4,
            Self::Equality { .. } => 5,
            Self::NotEqual { .. } => 6,
            Self::Range { .. } => 7,
            Self::InSet { .. } => 8,
            Self::FaceMatch { .. } => 9,
            Self::DepthCheck { .. } => 10,
            Self::LivenessCheck { .. } => 11,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RevealRequest {
    pub reveal_labels: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiableCredential {
    pub credential_id: String,
    pub issuer_did: String,
    pub claims: Vec<Claim>,
    pub commitment: String,
    pub proof_value: String,
    pub revealed_labels: Vec<String>,
    pub predicates_described: Vec<String>,
    pub cryptosuite: String,
    pub window_start: u64,
    pub window_expires: u64,
}

#[derive(Debug)]
pub struct VerificationResult {
    pub valid: bool,
    pub revealed_claims: Vec<Claim>,
    pub predicates_verified: Vec<String>,
    pub errors: Vec<String>,
}

pub const MAX_PREDICATES: usize = 8;
pub const MAX_INSET_VALUES: usize = 6;

#[derive(Clone, Copy)]
pub struct PredicateSlot {
    pub active: bool,
    pub pred_type: u8,
    pub attr_index: usize,
    pub val1: Fr,
    pub val2: Fr,
    pub inset_values: [Fr; MAX_INSET_VALUES],
    pub inset_count: usize,
}

impl Default for PredicateSlot {
    fn default() -> Self {
        Self {
            active: false,
            pred_type: 0,
            attr_index: 0,
            val1: Fr::zero(),
            val2: Fr::zero(),
            inset_values: [Fr::zero(); MAX_INSET_VALUES],
            inset_count: 0,
        }
    }
}

pub fn fr_to_u64(f: &Fr) -> u64 {
    f.into_bigint().0[0]
}

pub fn u64_to_fr(n: u64) -> Fr {
    Fr::from(n)
}