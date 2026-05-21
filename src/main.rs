use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, PrimeField, Zero};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_snark::SNARK;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::Instant;

const DOMAIN_SEP: &[u8] = b"DataIntegrityGroth16Proof2026::v1.0::";
const COMMITMENT_DOMAIN: &[u8] = b"Commitment";
const ATTRIBUTE_HASH_DOMAIN: &[u8] = b"AttributeHash";

const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 56;
const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;
const STATE_WIDTH: usize = 3;
const RATE: usize = 2;

struct PoseidonParams {
    constants: Vec<Vec<Fr>>,
    mds: Vec<Vec<Fr>>,
}

fn get_params() -> &'static PoseidonParams {
    static PARAMS: OnceLock<PoseidonParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let mut constants = Vec::with_capacity(TOTAL_ROUNDS);
        let mut hasher = Sha256::new();
        hasher.update(b"PoseidonBN254Constants");
        let mut seed = hasher.finalize();
        for _ in 0..TOTAL_ROUNDS {
            let mut round = Vec::with_capacity(STATE_WIDTH);
            for _ in 0..STATE_WIDTH {
                let mut inner = Sha256::new();
                inner.update(&seed);
                seed = inner.finalize();
                round.push(Fr::from_be_bytes_mod_order(&seed));
            }
            constants.push(round);
        }
        let mds = vec![
            vec![Fr::from(2u64), Fr::from(3u64), Fr::from(1u64)],
            vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
            vec![Fr::from(3u64), Fr::from(1u64), Fr::from(2u64)],
        ];
        PoseidonParams { constants, mds }
    })
}

fn sbox(x: &Fr) -> Fr { let x2 = x.square(); let x4 = x2.square(); *x * x4 }

fn full_round(state: &mut [Fr; STATE_WIDTH], round_idx: usize, params: &PoseidonParams) {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH { state[i] += rc[i]; }
    for i in 0..STATE_WIDTH { state[i] = sbox(&state[i]); }
    let old = *state;
    for i in 0..STATE_WIDTH {
        state[i] = Fr::zero();
        for j in 0..STATE_WIDTH { state[i] += params.mds[i][j] * old[j]; }
    }
}

fn partial_round(state: &mut [Fr; STATE_WIDTH], round_idx: usize, params: &PoseidonParams) {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH { state[i] += rc[i]; }
    state[0] = sbox(&state[0]);
    let old = *state;
    for i in 0..STATE_WIDTH {
        state[i] = Fr::zero();
        for j in 0..STATE_WIDTH { state[i] += params.mds[i][j] * old[j]; }
    }
}

fn poseidon_permutation(state: &mut [Fr; STATE_WIDTH]) {
    let params = get_params();
    for i in 0..FULL_ROUNDS / 2 { full_round(state, i, params); }
    for i in 0..PARTIAL_ROUNDS { partial_round(state, FULL_ROUNDS / 2 + i, params); }
    for i in 0..FULL_ROUNDS / 2 { full_round(state, FULL_ROUNDS / 2 + PARTIAL_ROUNDS + i, params); }
}

fn poseidon_sponge_hash(inputs: &[Fr]) -> Fr {
    let mut state = [Fr::zero(); STATE_WIDTH];
    let mut i = 0;
    while i < inputs.len() {
        for j in 0..RATE { if i < inputs.len() { state[j] += inputs[i]; i += 1; } }
        poseidon_permutation(&mut state);
    }
    state[0]
}

fn poseidon_hash(inputs: &[Fr], domain_tag: &[u8]) -> Fr {
    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(domain_tag);
    let domain_fr = Fr::from_be_bytes_mod_order(&sha.finalize());
    let mut all = Vec::with_capacity(1 + inputs.len());
    all.push(domain_fr);
    all.extend_from_slice(inputs);
    poseidon_sponge_hash(&all)
}

fn hash_attribute(value: &str) -> Fr {
    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(ATTRIBUTE_HASH_DOMAIN);
    sha.update(value.as_bytes());
    Fr::from_be_bytes_mod_order(&sha.finalize())
}

fn create_commitment(attrs: &[Fr; 16], blinding: &Fr) -> Fr {
    let mut inputs = Vec::with_capacity(17);
    inputs.extend_from_slice(attrs);
    inputs.push(*blinding);
    poseidon_hash(&inputs, COMMITMENT_DOMAIN)
}

fn random_fr() -> Fr {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    Fr::from_le_bytes_mod_order(&bytes)
}

fn sbox_circuit(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x.square()?; let x4 = x2.square()?; Ok(&x4 * x)
}

fn full_round_circuit(state: &mut [FpVar<Fr>; STATE_WIDTH], round_idx: usize, params: &PoseidonParams) -> Result<(), SynthesisError> {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH { state[i] = &state[i] + FpVar::Constant(rc[i]); }
    for i in 0..STATE_WIDTH { state[i] = sbox_circuit(&state[i])?; }
    let old = state.clone();
    for i in 0..STATE_WIDTH {
        state[i] = FpVar::zero();
        for j in 0..STATE_WIDTH { state[i] = &state[i] + FpVar::Constant(params.mds[i][j]) * &old[j]; }
    }
    Ok(())
}

fn partial_round_circuit(state: &mut [FpVar<Fr>; STATE_WIDTH], round_idx: usize, params: &PoseidonParams) -> Result<(), SynthesisError> {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH { state[i] = &state[i] + FpVar::Constant(rc[i]); }
    state[0] = sbox_circuit(&state[0])?;
    let old = state.clone();
    for i in 0..STATE_WIDTH {
        state[i] = FpVar::zero();
        for j in 0..STATE_WIDTH { state[i] = &state[i] + FpVar::Constant(params.mds[i][j]) * &old[j]; }
    }
    Ok(())
}

fn poseidon_permutation_circuit(state: &mut [FpVar<Fr>; STATE_WIDTH]) -> Result<(), SynthesisError> {
    let params = get_params();
    for i in 0..FULL_ROUNDS / 2 { full_round_circuit(state, i, params)?; }
    for i in 0..PARTIAL_ROUNDS { partial_round_circuit(state, FULL_ROUNDS / 2 + i, params)?; }
    for i in 0..FULL_ROUNDS / 2 { full_round_circuit(state, FULL_ROUNDS / 2 + PARTIAL_ROUNDS + i, params)?; }
    Ok(())
}

fn poseidon_sponge_hash_circuit(inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut state = [FpVar::zero(), FpVar::zero(), FpVar::zero()];
    let mut i = 0;
    while i < inputs.len() {
        for j in 0..RATE { if i < inputs.len() { state[j] = &state[j] + &inputs[i]; i += 1; } }
        poseidon_permutation_circuit(&mut state)?;
    }
    Ok(state[0].clone())
}

struct SelectiveDisclosureCircuit {
    pub attributes: [Option<Fr>; 16],
    pub mask: [bool; 16],
    pub blinding: Option<Fr>,
    pub expected_commitment: Option<Fr>,
    pub age_threshold: Option<Fr>,
    pub age_index: usize,
    pub domain_element: Fr,
}

impl ConstraintSynthesizer<Fr> for SelectiveDisclosureCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let domain_var = FpVar::Constant(self.domain_element);

        // Public inputs allocation alignment
        let mut revealed_vars = Vec::with_capacity(16);
        for i in 0..16 {
            let val = if self.mask[i] {
                self.attributes[i]
            } else {
                Some(Fr::zero())
            };
            revealed_vars.push(FpVar::new_input(
                cs.clone(),
                || val.ok_or(SynthesisError::AssignmentMissing),
            )?);
        }

        let expected_commitment_var = FpVar::new_input(
            cs.clone(),
            || self.expected_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let age_threshold_var = FpVar::new_input(
            cs.clone(),
            || self.age_threshold.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Witness allocations
        let mut hidden_vars = Vec::new();
        for i in 0..16 {
            if !self.mask[i] {
                hidden_vars.push(FpVar::new_witness(
                    cs.clone(),
                    || self.attributes[i].ok_or(SynthesisError::AssignmentMissing),
                )?);
            }
        }

        let blinding_var = FpVar::new_witness(
            cs.clone(),
            || self.blinding.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let mut hash_inputs: Vec<FpVar<Fr>> = vec![domain_var];
        let mut hidden_idx = 0;
        let mut age_var: Option<FpVar<Fr>> = None;

        for i in 0..16 {
            let attr_var = if self.mask[i] {
                let v = revealed_vars[i].clone();
                if i == self.age_index { age_var = Some(v.clone()); }
                v
            } else {
                let v = hidden_vars[hidden_idx].clone();
                hidden_idx += 1;
                if i == self.age_index { age_var = Some(v.clone()); }
                v
            };
            hash_inputs.push(attr_var);
        }
        hash_inputs.push(blinding_var);

        // Constraint 1: Poseidon identity validation 
        let computed = poseidon_sponge_hash_circuit(&hash_inputs)?;
        computed.enforce_equal(&expected_commitment_var)?;

        // Constraint 2: Secure age >= threshold validation
        if let Some(age) = age_var {
            let delta = FpVar::new_witness(cs.clone(), || {
                let a = self.attributes[self.age_index].ok_or(SynthesisError::AssignmentMissing)?;
                let t = self.age_threshold.ok_or(SynthesisError::AssignmentMissing)?;
                // Prevent underflow during tracking value assignment
                Ok(if a >= t { a - t } else { Fr::zero() })
            })?;

            // age = threshold + delta
            age.enforce_equal(&(&age_threshold_var + &delta))?;

            // Range check restriction: Enforce that delta fits comfortably in 32 bits
            // This effectively cuts off field wrapping space, rendering exploits impossible.
            let delta_bits = delta.to_bits_le()?;
            for bit in delta_bits.iter().skip(32) {
                bit.enforce_equal(&Boolean::constant(false))?;
            }
        }

        Ok(())
    }
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  DataIntegrityGroth16Proof2026 — Secure Fix              ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let alice   = hash_attribute("Alice");
    let chen    = hash_attribute("Chen");
    
    // FIX 1: Numeric comparisons require actual raw number injection
    let age_val = Fr::from(25u64); 
    let over18  = hash_attribute("true");
    let address = hash_attribute("123 Main St");

    let mut attrs = [Fr::zero(); 16];
    attrs[0] = alice;
    attrs[1] = chen;
    attrs[2] = age_val;
    attrs[3] = over18;
    attrs[4] = address;

    let blinding   = random_fr();
    let commitment = create_commitment(&attrs, &blinding);

    println!("━━━ CREDENTIAL ISSUED ━━━\n");
    println!("Commitment: {}", commitment);

    // Mask: Keep age completely hidden from public visibility, prove predicate dynamically
    let mut mask = [false; 16];
    mask[3] = true; // only explicitly release the 'over18' metadata token

    println!("\n━━━ SELECTIVE DISCLOSURE ━━━\n");
    println!("Revealing: isOver18");
    println!("Hidden:    givenName, familyName, age, address\n");

    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(COMMITMENT_DOMAIN);
    let domain_element = Fr::from_be_bytes_mod_order(&sha.finalize());

    let circuit = SelectiveDisclosureCircuit {
        attributes: attrs.map(Some),
        mask,
        blinding: Some(blinding),
        expected_commitment: Some(commitment),
        age_threshold: Some(Fr::from(18u64)),
        age_index: 2,
        domain_element,
    };

    let blank = SelectiveDisclosureCircuit {
        attributes: [None; 16],
        mask,
        blinding: None,
        expected_commitment: None,
        age_threshold: None,
        age_index: 2,
        domain_element,
    };

    let mut rng = ark_std::rand::thread_rng();

    println!("Trusted setup...");
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, &mut rng)
        .expect("Setup failed");
    println!("  Setup: {:?}", t.elapsed());

    println!("Generating proof...");
    let t = Instant::now();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .expect("Proof generation failed");
    println!("  Prove: {:?}", t.elapsed());

    let mut public_inputs = vec![Fr::zero(); 16];
    public_inputs[3] = attrs[3]; 
    public_inputs.push(commitment);
    public_inputs.push(Fr::from(18u64));

    println!("Verifying proof...");
    let t = Instant::now();
    let is_valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)
        .expect("Verification error");
    println!("  Verify: {:?}", t.elapsed());

    if is_valid {
        println!("\n✓ Proof VALID");
        println!("  Predicate execution successfully authenticated target parameter >= 18 safely.");
    } else {
        println!("\n✗ Proof INVALID");
    }
}