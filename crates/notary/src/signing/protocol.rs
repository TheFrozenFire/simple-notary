use anyhow::{Context, Result, bail};
use futures::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize, de::DeserializeOwned};

const MAX_MESSAGE_SIZE: u32 = 10 * 1024 * 1024; // 10 MB

/// Notary → Prover messages.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NotaryMessage {
    /// The HTTP context for the prover to review before requesting signing.
    Context { data: String },
    /// Signed attestation of the context.
    Signed {
        data: String,
        signature: String,
        public_key: String,
        algorithm: String,
    },
}

/// Prover → Notary messages.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ProverMessage {
    /// Request the notary to sign the full context.
    SignRequest,
}

/// Write a length-prefixed JSON message.
pub async fn write_message<W, T>(writer: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(msg).context("serializing message")?;
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await.context("writing length prefix")?;
    writer.write_all(&payload).await.context("writing payload")?;
    writer.flush().await.context("flushing writer")?;
    Ok(())
}

/// Read a length-prefixed JSON message.
pub async fn read_message<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.context("reading length prefix")?;
    let len = u32::from_be_bytes(len_buf);

    if len > MAX_MESSAGE_SIZE {
        bail!("message too large: {len} bytes (max {MAX_MESSAGE_SIZE})");
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await.context("reading payload")?;
    serde_json::from_slice(&payload).context("deserializing message")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    #[tokio::test]
    async fn roundtrip_notary_context_message() {
        let (client, server) = duplex(1024);
        let (mut server_r, _server_w) = server.compat().split();
        let (_client_r, mut client_w) = client.compat().split();

        let msg = NotaryMessage::Context {
            data: r#"{"request":{},"response":{}}"#.to_string(),
        };
        write_message(&mut client_w, &msg).await.unwrap();
        drop(client_w);

        let received: NotaryMessage = read_message(&mut server_r).await.unwrap();
        match received {
            NotaryMessage::Context { data } => {
                assert_eq!(data, r#"{"request":{},"response":{}}"#);
            }
            _ => panic!("expected Context message"),
        }
    }

    #[tokio::test]
    async fn roundtrip_prover_sign_request() {
        let (client, server) = duplex(1024);
        let (mut client_r, _client_w) = client.compat().split();
        let (_server_r, mut server_w) = server.compat().split();

        let msg = ProverMessage::SignRequest;
        write_message(&mut server_w, &msg).await.unwrap();
        drop(server_w);

        let received: ProverMessage = read_message(&mut client_r).await.unwrap();
        assert!(matches!(received, ProverMessage::SignRequest));
    }

    #[tokio::test]
    async fn roundtrip_signed_message() {
        let (client, server) = duplex(4096);
        let (mut server_r, _server_w) = server.compat().split();
        let (_client_r, mut client_w) = client.compat().split();

        let msg = NotaryMessage::Signed {
            data: "context".to_string(),
            signature: "deadbeef".to_string(),
            public_key: "cafebabe".to_string(),
            algorithm: "secp256k1".to_string(),
        };
        write_message(&mut client_w, &msg).await.unwrap();
        drop(client_w);

        let received: NotaryMessage = read_message(&mut server_r).await.unwrap();
        match received {
            NotaryMessage::Signed {
                data,
                signature,
                public_key,
                algorithm,
            } => {
                assert_eq!(data, "context");
                assert_eq!(signature, "deadbeef");
                assert_eq!(public_key, "cafebabe");
                assert_eq!(algorithm, "secp256k1");
            }
            _ => panic!("expected Signed message"),
        }
    }
}
