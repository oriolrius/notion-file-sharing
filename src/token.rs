//! Link tokens.
//!
//! * **v1** (legacy, frozen): `/<sig>/<customer_id>/<expire_ts>/<cipher_b64>`
//!   - `cipher_b64` = standard base64 of `nonce(24) || crypto_secretbox_easy(block_id)` (libsodium layout,
//!     produced by the Lua rock `symmetric`).
//!   - `sig` = `sha1_hex(customer_id || expire_ts || cipher_b64 || base64(key) || seed)`.
//!   - Byte compatible with the Lua server and with every client that still generates v1 links (mm-a2a).
//! * **v2**: `/v2/<token>`, token = base64url(nonce(24) || secretbox(json payload)) with a sub-key
//!   derived from the main key. Used for password protected links. Authenticity comes from the
//!   secretbox MAC, so there is no separate signature.

use base64::Engine;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{
    GeneralPurpose, GeneralPurposeConfig, STANDARD, URL_SAFE_NO_PAD,
};
use crypto_secretbox::aead::{Aead, KeyInit as _};
use crypto_secretbox::{Nonce, XSalsa20Poly1305};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use subtle::ConstantTimeEq;

const NONCE_LEN: usize = 24;
const MAC_LEN: usize = 16;

/// Lenient standard base64 decoder: the Lua decoder ignored padding and unknown characters.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LinkError {
    #[error("malformed link")]
    Malformed,
    #[error("invalid signature")]
    BadSignature,
    #[error("link expired")]
    Expired,
}

/// Secret material shared by every link.
pub struct Keys {
    key: [u8; 32],
    key_b64: String,
    seed: String,
    v2_key: [u8; 32],
}

impl Keys {
    pub fn new(key: &[u8], seed: String) -> anyhow::Result<Self> {
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("key must be exactly 32 bytes, got {}", key.len()))?;
        if seed.is_empty() {
            anyhow::bail!("seed must not be empty");
        }
        Ok(Self {
            key_b64: STANDARD.encode(key),
            v2_key: derive(&key, b"nfs/v2/token"),
            key,
            seed,
        })
    }

    /// Derive a 64-byte key for a given purpose (cookies, ...).
    pub fn derive64(&self, purpose: &[u8]) -> [u8; 64] {
        let a = derive(&self.key, &[purpose, b"/a"].concat());
        let b = derive(&self.key, &[purpose, b"/b"].concat());
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&a);
        out[32..].copy_from_slice(&b);
        out
    }
}

fn derive(key: &[u8; 32], purpose: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(purpose);
    mac.finalize().into_bytes().into()
}

fn random<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("OS random generator");
    buf
}

fn seal(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let nonce: [u8; NONCE_LEN] = random();
    let cipher = XSalsa20Poly1305::new_from_slice(key).expect("32-byte key");
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("secretbox encryption cannot fail");
    [nonce.as_slice(), &ct].concat()
}

fn open(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < NONCE_LEN + MAC_LEN {
        return None;
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);
    let cipher = XSalsa20Poly1305::new_from_slice(key).ok()?;
    cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
}

pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

// ---------------------------------------------------------------- v1

/// A parsed v1 link. Fields keep the raw strings from the URL: the signature covers them verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V1Link {
    pub sig: String,
    pub customer_id: String,
    pub expire: String,
    pub cipher_b64: String,
}

impl V1Link {
    /// Parse a (percent-decoded) request path: `/<sig>/<cid>/<exp>/<cipher...>`.
    /// The cipher can contain `/`, so everything after the third segment belongs to it.
    pub fn parse(path: &str) -> Option<Self> {
        let mut parts = path.strip_prefix('/')?.splitn(4, '/');
        let sig = parts.next()?;
        let customer_id = parts.next()?;
        let expire = parts.next()?;
        let cipher_b64 = parts.next()?;
        if sig.len() != 40 || !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        if customer_id.is_empty() || expire.is_empty() || cipher_b64.is_empty() {
            return None;
        }
        Some(Self {
            sig: sig.to_ascii_lowercase(),
            customer_id: customer_id.to_string(),
            expire: expire.to_string(),
            cipher_b64: cipher_b64.to_string(),
        })
    }

    pub fn path(&self) -> String {
        format!(
            "/{}/{}/{}/{}",
            self.sig, self.customer_id, self.expire, self.cipher_b64
        )
    }
}

fn v1_signature(keys: &Keys, customer_id: &str, expire: &str, cipher_b64: &str) -> String {
    let mut h = Sha1::new();
    h.update(customer_id.as_bytes());
    h.update(expire.as_bytes());
    h.update(cipher_b64.as_bytes());
    h.update(keys.key_b64.as_bytes());
    h.update(keys.seed.as_bytes());
    hex::encode(h.finalize())
}

/// Build a v1 link for `block_id`, valid until `expire` (unix seconds).
pub fn v1_encode(keys: &Keys, customer_id: &str, expire: i64, block_id: &str) -> V1Link {
    let cipher_b64 = STANDARD.encode(seal(&keys.key, block_id.as_bytes()));
    let expire = expire.to_string();
    let sig = v1_signature(keys, customer_id, &expire, &cipher_b64);
    V1Link {
        sig,
        customer_id: customer_id.to_string(),
        expire,
        cipher_b64,
    }
}

/// Verify signature and expiry, then return the block id.
pub fn v1_decode(keys: &Keys, link: &V1Link, now: i64) -> Result<String, LinkError> {
    let expected = v1_signature(keys, &link.customer_id, &link.expire, &link.cipher_b64);
    if !bool::from(expected.as_bytes().ct_eq(link.sig.as_bytes())) {
        return Err(LinkError::BadSignature);
    }
    let expire: i64 = link.expire.parse().map_err(|_| LinkError::Malformed)?;
    if now >= expire {
        return Err(LinkError::Expired);
    }
    let cleaned: String = link
        .cipher_b64
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect();
    let raw = LENIENT
        .decode(cleaned.trim_end_matches('='))
        .map_err(|_| LinkError::Malformed)?;
    let plain = open(&keys.key, &raw).ok_or(LinkError::Malformed)?;
    String::from_utf8(plain).map_err(|_| LinkError::Malformed)
}

// ---------------------------------------------------------------- v2

/// Password hash stored inside the encrypted v2 payload: argon2id (default params) salt + hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordHash {
    /// base64url salt (16 bytes)
    pub s: String,
    /// base64url argon2id output (32 bytes)
    pub h: String,
}

impl PasswordHash {
    pub fn new(password: &str) -> Self {
        let salt: [u8; 16] = random();
        let hash = argon2_hash(password, &salt);
        Self {
            s: URL_SAFE_NO_PAD.encode(salt),
            h: URL_SAFE_NO_PAD.encode(hash),
        }
    }

    /// CPU heavy (~20 ms): call from a blocking task.
    pub fn verify(&self, password: &str) -> bool {
        let (Ok(salt), Ok(expected)) = (
            URL_SAFE_NO_PAD.decode(&self.s),
            URL_SAFE_NO_PAD.decode(&self.h),
        ) else {
            return false;
        };
        let hash = argon2_hash(password, &salt);
        bool::from(hash.as_slice().ct_eq(&expected))
    }
}

fn argon2_hash(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .expect("valid argon2 parameters");
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2Payload {
    /// Notion block id
    pub b: String,
    /// customer id
    pub c: String,
    /// expiry, unix seconds
    pub e: i64,
    /// optional password
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p: Option<PasswordHash>,
}

pub fn v2_encode(keys: &Keys, payload: &V2Payload) -> String {
    let json = serde_json::to_vec(payload).expect("payload serializes");
    URL_SAFE_NO_PAD.encode(seal(&keys.v2_key, &json))
}

/// Decrypt a v2 token. Expiry is checked; the password (if any) is the caller's job.
pub fn v2_decode(keys: &Keys, token: &str, now: i64) -> Result<V2Payload, LinkError> {
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| LinkError::Malformed)?;
    let plain = open(&keys.v2_key, &raw).ok_or(LinkError::BadSignature)?;
    let payload: V2Payload = serde_json::from_slice(&plain).map_err(|_| LinkError::Malformed)?;
    if now >= payload.e {
        return Err(LinkError::Expired);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> Keys {
        let key: Vec<u8> = (1u8..=32).collect();
        Keys::new(&key, "test-seed-!\"#$%&'()*+,-./:;<=>?@[]^_`{|}~".into()).unwrap()
    }

    /// Generated by the original Lua implementation (modules/lib.lua + rock `symmetric` 1.1-4)
    /// with the test key 0x01..0x20 and the seed above.
    const LUA_VECTORS: &[(&str, &str, &str, &str, &str)] = &[
        (
            "2db24fc0fb49734b2bfeb31c542ffb4d0662c7c0",
            "1",
            "4102444800",
            "2C4FsLzmyRA9Cb2aRt0FUSSQtJBbNVFvX6gWmMLGgFZzIFcSTBcih6F2RK9KVDzJ8kuUaKDPqy58HeTXCUUR12WeOhVZskTm",
            "416c413b2a6881ba87eaebad1f979d66",
        ),
        (
            "2c323734b318f1feabe246edbb0daa031896265e",
            "1",
            "4102444800",
            "aGfDrMfRTPlzdP0I1bTgMt2HgMVb2qSZqqoMRu/enyqLC0C4AEKf3kJ4f1fp3woq+WhTDQOeW9lnfeVxw8AJ7ZjpDzwANLe8hJK4Vg==",
            "1c2d3e4f-5a6b-7c8d-9e0f-a1b2c3d4e5f6",
        ),
    ];
    const LUA_EXPIRED: (&str, &str, &str, &str) = (
        "28c5bd5774835ff36e9fd1c499d688b152060648",
        "1",
        "1000000000",
        "61XqFU70AhonxnnWSZRmFoSbPSRdYmYhVRTgC1r6xiu3hJQ3ykh33RsMOJaGJU2ZSsQRIvR446EzcLIhymNjiAe/a10Yfacl",
    );

    #[test]
    fn decodes_links_made_by_lua() {
        let keys = test_keys();
        for (sig, cid, exp, cipher, block) in LUA_VECTORS {
            let path = format!("/{sig}/{cid}/{exp}/{cipher}");
            let link = V1Link::parse(&path).expect("parses");
            assert_eq!(link.cipher_b64, *cipher);
            assert_eq!(v1_decode(&keys, &link, 1_800_000_000).unwrap(), *block);
        }
    }

    #[test]
    fn lua_expired_link_is_expired() {
        let (sig, cid, exp, cipher) = LUA_EXPIRED;
        let link = V1Link::parse(&format!("/{sig}/{cid}/{exp}/{cipher}")).unwrap();
        assert_eq!(
            v1_decode(&test_keys(), &link, 1_800_000_000),
            Err(LinkError::Expired)
        );
    }

    #[test]
    fn tampering_breaks_signature() {
        let (sig, cid, exp, cipher, _) = LUA_VECTORS[0];
        let keys = test_keys();
        for path in [
            format!("/{sig}/{cid}/4102444801/{cipher}"),
            format!("/{sig}/2/{exp}/{cipher}"),
            format!("/{sig}/{cid}/{exp}/A{}", &cipher[1..]),
        ] {
            let link = V1Link::parse(&path).unwrap();
            assert_eq!(
                v1_decode(&keys, &link, 0),
                Err(LinkError::BadSignature),
                "{path}"
            );
        }
        let other = Keys::new(&[7u8; 32], "x".into()).unwrap();
        let link = V1Link::parse(&format!("/{sig}/{cid}/{exp}/{cipher}")).unwrap();
        assert_eq!(v1_decode(&other, &link, 0), Err(LinkError::BadSignature));
    }

    #[test]
    fn v1_roundtrip_and_lua_signature_format() {
        let keys = test_keys();
        let link = v1_encode(&keys, "1", 4102444800, "416c413b2a6881ba87eaebad1f979d66");
        assert_eq!(link.sig.len(), 40);
        // 24 nonce + 16 mac + 32 id = 72 bytes -> 96 base64 chars, standard alphabet, no padding needed
        assert_eq!(link.cipher_b64.len(), 96);
        let parsed = V1Link::parse(&link.path()).unwrap();
        assert_eq!(
            v1_decode(&keys, &parsed, 0).unwrap(),
            "416c413b2a6881ba87eaebad1f979d66"
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        for p in [
            "/",
            "/robots.txt",
            "/abc/1/2/x",
            "/_/links",
            "/v2/abc",
            "/2db24fc0fb49734b2bfeb31c542ffb4d0662c7c0/1/2",
        ] {
            assert!(V1Link::parse(p).is_none(), "{p}");
        }
    }

    #[test]
    fn v2_roundtrip_with_password() {
        let keys = test_keys();
        let payload = V2Payload {
            b: "416c413b2a6881ba87eaebad1f979d66".into(),
            c: "1".into(),
            e: 4102444800,
            p: Some(PasswordHash::new("s3cret")),
        };
        let token = v2_encode(&keys, &payload);
        assert!(
            token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        let back = v2_decode(&keys, &token, 0).unwrap();
        assert_eq!(back, payload);
        let ph = back.p.unwrap();
        assert!(ph.verify("s3cret"));
        assert!(!ph.verify("S3cret"));
        assert_eq!(
            v2_decode(&keys, &token, 4102444800),
            Err(LinkError::Expired)
        );
        let other = Keys::new(&[7u8; 32], "x".into()).unwrap();
        assert_eq!(v2_decode(&other, &token, 0), Err(LinkError::BadSignature));
    }

    #[test]
    fn v1_ciphertext_is_not_a_v2_token() {
        let keys = test_keys();
        let v1 = v1_encode(&keys, "1", 4102444800, "416c413b2a6881ba87eaebad1f979d66");
        let raw = STANDARD.decode(&v1.cipher_b64).unwrap();
        assert!(v2_decode(&keys, &URL_SAFE_NO_PAD.encode(raw), 0).is_err());
    }
}
