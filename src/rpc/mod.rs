use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_string};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};

use crate::DynResult;

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
pub struct MessageInfo {
    pub id: Option<String>,
    pub method: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NetMessageInfo {
    pub id: Option<String>,
    pub method: Option<String>,
    pub content: Vec<u8>,
}

pub async fn decode(scanner: &mut BufReader<impl AsyncRead + Unpin>) -> DynResult<MessageInfo> {
    let content_length = read_headers(scanner).await?;

    // Read exact content
    let mut buffer = vec![0; content_length];
    scanner.read_exact(&mut buffer).await?;
    let message = String::from_utf8(buffer).map_err(|_| "Invalid UTF-8 in message content")?;

    let content = message.as_bytes();
    let id = from_slice::<Id>(content).ok();
    let method = from_slice::<Method>(content)?;

    Ok(MessageInfo {
        id: id.map(|id| id.id),
        method: method.method,
        content: content.to_vec(),
    })
}

pub async fn decode_message(message: String) -> DynResult<NetMessageInfo> {
    let scanner = &mut BufReader::new(message.as_bytes());

    let content_length = read_headers(scanner).await?;

    // Read exact content
    let mut buffer = vec![0; content_length];
    scanner.read_exact(&mut buffer).await?;
    let message = String::from_utf8(buffer).map_err(|_| "Invalid UTF-8 in message content")?;

    let content = message.as_bytes();
    let id = from_slice::<Id>(content).ok();
    let method = from_slice::<Method>(content).ok();

    Ok(NetMessageInfo {
        id: id.map(|id| id.id),
        method: method.map(|method| method.method),
        content: content.to_vec(),
    })
}

pub fn decode_params<'a, T: Deserialize<'a>>(content: &'a [u8]) -> DynResult<T> {
    from_slice::<Params<T>>(content)
        .map(|params| params.params)
        .map_err(|e| e.into())
}

pub fn encode<T: Serialize>(value: T) -> DynResult<Vec<u8>> {
    let content = to_string(&value)?;
    Ok(format!("content-length: {}\r\n\r\n{}\n", content.len(), content).into_bytes())
}

async fn read_headers(scanner: &mut BufReader<impl AsyncRead + Unpin>) -> DynResult<usize> {
    let mut content_length = None;

    // Read all headers
    loop {
        let mut line = String::new();
        scanner.read_line(&mut line).await?;

        // Empty line (just \r\n) marks end of headers
        if line == "\r\n" {
            break;
        }

        // Parse content-length if we find it
        if line.to_lowercase().starts_with("content-length: ") {
            content_length = Some(
                line[15..]
                    .trim()
                    .parse()
                    .map_err(|_| "Invalid content-length value")?,
            );
        }
    }

    content_length.ok_or("No content-length header found".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluid::prelude::*;

    #[tokio::test]
    async fn test_decode() {
        // arrange
        let message = "content-length: 26\r\n\r\n{\"id\":\"0\",\"method\":\"test\"}";
        let mut reader = BufReader::new(message.as_bytes());

        // act
        let decoded = decode(&mut reader).await.unwrap();

        // assert
        decoded.id.should().be_equal_to(Some("0".to_string()));
        decoded.method.should().be_equal_to("test");
        decoded.content.len().should().be_equal_to(26);
    }
    #[test]
    fn test_encode() {
        // arrange
        let base_message = Method {
            method: "test".to_string(),
        };

        // act
        let message = encode(base_message).unwrap();

        // assert
        message
            .should()
            .be_equal_to("content-length: 17\r\n\r\n{\"method\":\"test\"}".as_bytes());
    }
}
