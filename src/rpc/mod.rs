use std::error::Error;

use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Id {
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Method {
    pub method: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Params<T> {
    params: T,
}

#[derive(Debug, Clone)]
pub struct DecodedMessage {
    pub id: Option<String>,
    pub method: String,
    pub content: Vec<u8>,
}

pub fn decode(message: &str) -> Result<DecodedMessage, Box<dyn Error>> {
    let content = message.as_bytes();
    let id = from_slice::<Id>(content).ok();
    let method = from_slice::<Method>(content)?;

    Ok(DecodedMessage {
        id: id.map(|id| id.id),
        method: method.method,
        content: content.to_vec(),
    })
}

pub fn decode_params<'a, T: Deserialize<'a>>(content: &'a [u8]) -> serde_json::error::Result<T> {
    from_slice::<Params<T>>(content).map(|params| params.params)
}

pub fn encode<T: Serialize>(value: T) -> Result<Vec<u8>, Box<dyn Error>> {
    let content = to_string(&value)?;
    Ok(format!("content-length: {}\r\n\r\n{}", content.len(), content).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluid::prelude::*;

    #[test]
    fn test_decode() {
        let message = "{\"id:\"0\",\"method\":\"test\"}";
        let decoded = decode(message).unwrap();
        decoded.id.should().be_equal_to(Some("0".to_string()));
        decoded.method.should().be_equal_to("test");
        decoded.content.len().should().be_equal_to(25);
    }
    #[test]
    fn test_encode() {
        let base_message = Method {
            method: "test".to_string(),
        };

        let message = encode(base_message).unwrap();

        message
            .should()
            .be_equal_to("content-length: 17\r\n\r\n{\"method\":\"test\"}".as_bytes());
    }
}
