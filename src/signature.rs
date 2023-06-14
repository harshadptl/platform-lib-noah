use noah::keys::KeyType;
use {
    noah::keys::Signature as NoahXfrSignature,
    noah_algebra::{prelude::*, serialization::NoahFromToBytes},
    serde::Serializer,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XfrSignature(pub(crate) NoahXfrSignature);

serialize_deserialize!(XfrSignature);

impl XfrSignature {
    pub fn into_noah(&self) -> Result<NoahXfrSignature> {
        Ok(self.0.clone())
    }

    pub fn from_noah(value: &NoahXfrSignature) -> Result<Self> {
        Ok(XfrSignature(value.clone()))
    }
}

impl NoahFromToBytes for XfrSignature {
    fn noah_to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.noah_to_bytes();

        // If key is of the Ed25519 Type then send the 64 byte signature
        if KeyType::from_byte(bytes[0]) == KeyType::Ed25519 {
            return bytes[1..65].to_vec();
        }
        bytes
    }

    fn noah_from_bytes(bytes: &[u8]) -> Result<Self> {
        let s = NoahXfrSignature::noah_from_bytes(bytes)?;
        Ok(XfrSignature(s))
    }
}
