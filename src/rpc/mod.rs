use std::error::Error;

use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Method {
    pub method: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BaseMessage {
    pub method: String,
}

#[derive(Debug, Clone)]
pub struct DecodedMessage {
    pub method: String,
    pub content: Vec<u8>,
}

pub fn decode(message: &str) -> Result<DecodedMessage, Box<dyn Error>> {
    let split = message.split("\r\n\r\n").collect::<Vec<_>>();

    if split.len() != 2 {
        return Err("Invalid message".into());
    }

    let headers = split.first().ok_or("Invalid message")?.lines();
    let mut content_length = 0;

    for header in headers {
        if header.starts_with("content-length") {
            content_length = header.split(": ").collect::<Vec<_>>()[1].parse()?;
        }
    }

    if content_length == 0 {
        return Err("Invalid message".into());
    }

    let content = split
        .get(1)
        .ok_or("Invalid message")?
        .bytes()
        .take(content_length)
        .collect::<Vec<_>>();
    let method = from_slice::<Method>(&content)?;

    Ok(DecodedMessage {
        method: method.method,
        content,
    })
}

pub fn encode<T: Serialize>(value: T) -> Result<Vec<u8>, Box<dyn Error>> {
    let content = to_string(&value)?;
    Ok(format!("content-length: {}\r\n\r\n{}", content.len(), content).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode() {
        let message = "content-length: 17\r\n\r\n{\"method\":\"test\"}";
        let decoded = decode(message).unwrap();
        assert_eq!(decoded.method, "test");
        assert_eq!(decoded.content.len(), 17);
    }
    #[test]
    fn test_encode() {
        let base_message = BaseMessage {
            method: "test".to_string(),
        };

        let message = encode(base_message).unwrap();
        assert_eq!(
            String::from_utf8(message).unwrap(),
            "content-length: 17\r\n\r\n{\"method\":\"test\"}"
        );
    }
}
