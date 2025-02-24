use futures_util::SinkExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::{Message, Utf8Bytes};

use crate::{rpc, DynResult};

use super::{ClientInfo, InitializeRequest, Request, WsWriter};

pub async fn initialize<S: AsyncWrite + AsyncRead + Unpin>(
    write: &mut WsWriter<S>,
) -> DynResult<()> {
    let request = rpc::encode(Request::<InitializeRequest> {
        id: Some("1".to_string()),
        method: "initialize".to_string(),
        params: Some(InitializeRequest {
            process_id: None,
            client_info: Some(ClientInfo {
                name: "ppp".to_string(),
                version: Some("0.1.0".to_string()),
            }),
            root_path: None,
        }),
    })?;

    write
        .send(Message::Text(Utf8Bytes::try_from(request)?))
        .await?;

    Ok(())
}
