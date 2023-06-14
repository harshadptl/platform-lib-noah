use {
    crate::signature::XfrSignature,
    noah::keys::PublicKey as NoahXfrPublicKey,
    noah_algebra::{
        hash::{Hash, Hasher},
        prelude::*,
        serialization::NoahFromToBytes,
    },
    serde::Serializer,
    wasm_bindgen::prelude::*,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[wasm_bindgen]
pub struct XfrPublicKey(pub(crate) NoahXfrPublicKey);

serialize_deserialize!(XfrPublicKey);

impl XfrPublicKey {
    pub fn verify(&self, message: &[u8], signature: &XfrSignature) -> Result<()> {
        let pk: NoahXfrPublicKey = self.clone().into_noah()?;
        pk.verify(message, &signature.into_noah()?)
    }

    pub fn into_noah(&self) -> Result<NoahXfrPublicKey> {
        Ok(self.0)
    }

    pub fn from_noah(value: &NoahXfrPublicKey) -> Result<Self> {
        Ok(XfrPublicKey(value.clone()))
    }
}

impl NoahFromToBytes for XfrPublicKey {
    fn noah_to_bytes(&self) -> Vec<u8> {
        self.0.noah_to_bytes()
    }

    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        let pk = NoahXfrPublicKey::noah_from_bytes(bytes)?;
        Ok(XfrPublicKey(pk))
    }
}

impl Hash for XfrPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.noah_to_bytes().hash(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{PublicKey, SecretKey};
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_ed25519_keys() {
        let mut prng = ChaChaRng::seed_from_u64(123);
        let s = SecretKey::generate(&mut prng);
        let p: PublicKey = (&s).into();

        p.to_bytes();
        let xpk = XfrPublicKey::noah_from_bytes(&p.to_bytes()).unwrap();

        assert_eq!(p.to_bytes().to_vec(), xpk.noah_to_bytes())
    }
}
