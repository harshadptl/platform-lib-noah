use noah::keys::KeyType;
use {
    crate::{signature::XfrSignature, XfrKeyPair, XfrPublicKey},
    noah::keys::SecretKey as NoahXfrSecretKey,
    noah_algebra::{
        hash::{Hash, Hasher},
        prelude::*,
        serialization::NoahFromToBytes,
    },
    serde::Serializer,
};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct XfrSecretKey(pub(crate) NoahXfrSecretKey);

impl XfrSecretKey {
    pub fn sign(&self, message: &[u8]) -> Result<XfrSignature> {
        Ok(XfrSignature(self.0.sign(message)?))
    }
    pub fn into_keypair(&self) -> XfrKeyPair {
        let kp = self.0.clone().into_keypair();
        XfrKeyPair {
            pub_key: XfrPublicKey(kp.get_pk()),
            sec_key: XfrSecretKey(kp.get_sk()),
        }
    }
    pub fn into_noah(&self) -> Result<NoahXfrSecretKey> {
        Ok(self.0.clone())
    }

    pub fn from_noah(value: &NoahXfrSecretKey) -> Result<Self> {
        Ok(XfrSecretKey(value.clone()))
    }
}

impl NoahFromToBytes for XfrSecretKey {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.noah_to_bytes();
        if KeyType::from_byte(bytes[0]) == KeyType::Ed25519 {
            bytes[1..33].to_vec()
        } else {
            bytes
        }
    }

    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        let sk = NoahXfrSecretKey::noah_from_bytes(bytes)?;
        Ok(XfrSecretKey(sk))
    }
}

impl Hash for XfrSecretKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.noah_to_bytes().hash(state)
    }
}

serialize_deserialize!(XfrSecretKey);

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{ SecretKey};
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_ed25519_keys() {
        let mut prng = ChaChaRng::seed_from_u64(123);
        let s = SecretKey::generate(&mut prng);

        let xsk = XfrSecretKey::noah_from_bytes(&s.to_bytes()).unwrap();

        assert_eq!(s.to_bytes().to_vec(), xsk.noah_to_bytes())
    }
}
