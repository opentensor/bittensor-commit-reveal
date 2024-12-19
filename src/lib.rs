use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use codec::Encode;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand_core::OsRng;
use sha2::Digest;
use std::time::{SystemTime, UNIX_EPOCH};
use tle::{
    curves::drand::TinyBLS381, ibe::fullident::Identity,
    stream_ciphers::AESGCMStreamCipherProvider, tlock::tle,
};
use tokio;
use w3f_bls::EngineBLS;

pub const SUBTENSOR_PULSE_DELAY: u64 = 24;

#[derive(Encode)]
pub struct WeightsTlockPayload {
    pub uids: Vec<u16>,
    pub values: Vec<u16>,
    pub version_key: u64,
}

async fn generate_commit(
    uids: Vec<u16>,
    values: Vec<u16>,
    version_key: u64,
    tempo: u64,
    current_block: u64,
    netuid: u16,
    subnet_reveal_period_epochs: u64,
    block_time: u64,
) -> Result<(Vec<u8>, u64), (std::io::Error, String)> {
    // Steps comes from here https://github.com/opentensor/subtensor/pull/982/files#diff-7261bf1c7f19fc66a74c1c644ec2b4b277a341609710132fb9cd5f622350a6f5R120-R131
    // Instantiate payload
    let payload = WeightsTlockPayload {
        uids,
        values,
        version_key,
    };
    let serialized_payload = payload.encode();

    let period = 3;
    let genesis_time = 1692803367;
    let public_key = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let tempo_plus_one = tempo + 1;
    let netuid_plus_one = (netuid as u64) + 1;
    let block_with_offset = current_block + netuid_plus_one;
    let current_epoch = block_with_offset / tempo_plus_one;

    // Calculate reveal epoch and ensure enough time for SUBTENSOR_PULSE_DELAY pulses
    let mut reveal_epoch = current_epoch + subnet_reveal_period_epochs;
    let mut reveal_block_number = reveal_epoch * tempo_plus_one - netuid_plus_one;
    let mut blocks_until_reveal = reveal_block_number - current_block;
    let mut time_until_reveal = blocks_until_reveal * block_time;

    // Ensure at least SUBTENSOR_PULSE_DELAY * period seconds lead time
    while time_until_reveal < SUBTENSOR_PULSE_DELAY * period {

        if blocks_until_reveal > 1 {
            break;
        }

        reveal_epoch += 1;
        reveal_block_number = reveal_epoch * tempo_plus_one - netuid_plus_one;
        blocks_until_reveal = reveal_block_number - current_block;
        time_until_reveal = blocks_until_reveal * block_time;
    }

    let reveal_time = now + time_until_reveal;
    let reveal_round = ((reveal_time - genesis_time + period - 1) / period) - SUBTENSOR_PULSE_DELAY;

    // Deserialize public key
    let pub_key_bytes = hex::decode(public_key).map_err(|e| {
        (
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)),
            "Decoding public key failed.".to_string(),
        )
    })?;
    let pub_key =
        <TinyBLS381 as EngineBLS>::PublicKeyGroup::deserialize_compressed(&*pub_key_bytes)
            .map_err(|e| {
                (
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{:?}", e)),
                    "Deserializing public key failed.".to_string(),
                )
            })?;

    // Create identity from reveal_round
    let message = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(reveal_round.to_be_bytes());
        hasher.finalize().to_vec()
    };
    let identity = Identity::new(b"", vec![message]);

    // Encrypt payload
    let esk = [2; 32];
    let ct = tle::<TinyBLS381, AESGCMStreamCipherProvider, OsRng>(
        pub_key,
        esk,
        &serialized_payload,
        identity,
        OsRng,
    )
    .map_err(|e| {
        (
            std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)),
            "Encryption failed.".to_string(),
        )
    })?;

    // Compress ciphertext
    let mut ct_bytes: Vec<u8> = Vec::new();
    ct.serialize_compressed(&mut ct_bytes).map_err(|e| {
        (
            std::io::Error::new(std::io::ErrorKind::Other, format!("{:?}", e)),
            "Ciphertext serialization failed.".to_string(),
        )
    })?;

    Ok((ct_bytes, reveal_round))
}

#[pyfunction]
#[pyo3(signature = (uids, weights, version_key, tempo, current_block, netuid, subnet_reveal_period_epochs, block_time=12))]
fn get_encrypted_commit(
    py: Python,
    uids: Vec<u16>,
    weights: Vec<u16>,
    version_key: u64,
    tempo: u64,
    current_block: u64,
    netuid: u16,
    subnet_reveal_period_epochs: u64,
    block_time: u64,
) -> PyResult<(Py<PyBytes>, u64)> {
    // create runtime to make async call
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| PyValueError::new_err(e.to_string()))?;
    let result = runtime.block_on(generate_commit(
        uids,
        weights,
        version_key,
        tempo,
        current_block,
        netuid,
        subnet_reveal_period_epochs,
        block_time,
    ));
    // matching the result
    match result {
        Ok((ciphertext, target_round)) => {
            let py_bytes = PyBytes::new_bound(py, &ciphertext).into();
            Ok((py_bytes, target_round))
        }
        Err(e) => Err(PyValueError::new_err(format!("{:?}", e))),
    }
}

#[pymodule]
fn bittensor_commit_reveal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_encrypted_commit, m)?)?;
    Ok(())
}
