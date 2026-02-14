use anyhow::{Context, Result};
use alloy_primitives::keccak256;
use alloy_sol_types::{SolValue, sol};
use serde_json::Value;

use super::{ContextEncoder, EncodedContext};

sol! {
    struct Header {
        string name;
        string value;
    }

    struct Request {
        bool present;
        string method;
        string target;
        Header[] headers;
        bytes body;
        uint8 bodyEncoding;
    }

    struct Response {
        bool present;
        uint16 status;
        Header[] headers;
        bytes body;
        uint8 bodyEncoding;
    }

    struct Attestation {
        Request[] requests;
        Response[] responses;
    }
}

/// Body encoding discriminator.
const BODY_NONE: u8 = 0;
const BODY_RAW: u8 = 1;
const BODY_JSON_KV: u8 = 2;

/// Encodes context as ABI-encoded structs with keccak256 digest.
///
/// The encoded data is directly decodable in Solidity using `abi.decode`.
pub struct AbiEncoder;

impl ContextEncoder for AbiEncoder {
    fn encode(&self, context: &Value) -> Result<EncodedContext> {
        let attestation = parse_attestation(context)?;
        let data = attestation.abi_encode();
        let digest = keccak256(&data).to_vec();
        Ok(EncodedContext { data, digest })
    }

    fn name(&self) -> &str {
        "abi"
    }
}

pub(crate) fn parse_attestation(context: &Value) -> Result<Attestation> {
    let requests_val = context.get("requests")
        .and_then(|v| v.as_array())
        .unwrap_or(&Vec::new())
        .clone();

    let responses_val = context.get("responses")
        .and_then(|v| v.as_array())
        .unwrap_or(&Vec::new())
        .clone();

    let requests: Vec<Request> = requests_val.iter()
        .map(parse_request)
        .collect::<Result<_>>()?;

    let responses: Vec<Response> = responses_val.iter()
        .map(parse_response)
        .collect::<Result<_>>()?;

    Ok(Attestation { requests, responses })
}

fn parse_request(val: &Value) -> Result<Request> {
    // Null-replaced request → not present
    if val.is_null() {
        return Ok(Request {
            present: false,
            method: String::new(),
            target: String::new(),
            headers: vec![],
            body: vec![].into(),
            bodyEncoding: BODY_NONE,
        });
    }

    let method = val.get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let target = val.get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let headers = parse_headers(val.get("headers"));
    let (body, body_encoding) = parse_body(val.get("body"))?;

    Ok(Request {
        present: true,
        method,
        target,
        headers,
        body: body.into(),
        bodyEncoding: body_encoding,
    })
}

fn parse_response(val: &Value) -> Result<Response> {
    // Null-replaced response → not present
    if val.is_null() {
        return Ok(Response {
            present: false,
            status: 0,
            headers: vec![],
            body: vec![].into(),
            bodyEncoding: BODY_NONE,
        });
    }

    let status = val.get("status")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;

    let headers = parse_headers(val.get("headers"));
    let (body, body_encoding) = parse_body(val.get("body"))?;

    Ok(Response {
        present: true,
        status,
        headers,
        body: body.into(),
        bodyEncoding: body_encoding,
    })
}

fn parse_headers(val: Option<&Value>) -> Vec<Header> {
    let Some(arr) = val.and_then(|v| v.as_array()) else {
        return vec![];
    };

    arr.iter().map(|header| {
        // Null-replaced header → empty strings
        if header.is_null() {
            return Header { name: String::new(), value: String::new() };
        }
        // Headers are [name, value] tuples
        if let Some(pair) = header.as_array() {
            let name = pair.first()
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let value = pair.get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Header { name, value }
        } else {
            Header { name: String::new(), value: String::new() }
        }
    }).collect()
}

fn parse_body(val: Option<&Value>) -> Result<(Vec<u8>, u8)> {
    let Some(body_val) = val else {
        return Ok((vec![], BODY_NONE));
    };

    // Body can be null (no body / redacted)
    if body_val.is_null() {
        return Ok((vec![], BODY_NONE));
    }

    // Body is an enum: { "Json": ... } or { "Unknown": [bytes] }
    if let Some(json_val) = body_val.get("Json") {
        return encode_json_body(json_val);
    }

    if let Some(unknown_val) = body_val.get("Unknown") {
        // Unknown is serialized as an array of byte values
        if let Some(byte_arr) = unknown_val.as_array() {
            let bytes: Vec<u8> = byte_arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect();
            return Ok((bytes, BODY_RAW));
        }
    }

    Ok((vec![], BODY_NONE))
}

/// Encode a JSON body value.
///
/// Top-level objects become key-value pair encoding (bodyEncoding=2):
/// the body bytes are `abi.encode(string[] keys, string[] values)`.
/// Values are JSON-serialized strings.
///
/// Non-objects (arrays, scalars) fall back to raw UTF-8 JSON (bodyEncoding=1).
fn encode_json_body(json_val: &Value) -> Result<(Vec<u8>, u8)> {
    if let Some(obj) = json_val.as_object() {
        let keys: Vec<String> = obj.keys().cloned().collect();
        let values: Vec<String> = obj.values()
            .map(|v| serde_json::to_string(v).unwrap_or_default())
            .collect();

        let encoded = <(Vec<String>, Vec<String>)>::abi_encode(&(keys, values));
        Ok((encoded, BODY_JSON_KV))
    } else {
        // Non-object JSON → raw UTF-8
        let raw = serde_json::to_string(json_val)
            .context("serializing JSON body to string")?;
        Ok((raw.into_bytes(), BODY_RAW))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encode_simple_context() {
        let encoder = AbiEncoder;
        let context = json!({
            "requests": [{
                "target": "/",
                "method": "GET",
                "headers": [["Host", "example.com"]],
                "body": null
            }],
            "responses": [{
                "status": 200,
                "headers": [["Content-Length", "2"]],
                "body": { "Unknown": [79, 75] }
            }]
        });

        let encoded = encoder.encode(&context).unwrap();
        assert!(!encoded.data.is_empty());
        assert_eq!(encoded.digest.len(), 32, "keccak256 digest should be 32 bytes");

        // Verify roundtrip via ABI decode
        let decoded = <Attestation as SolValue>::abi_decode(&encoded.data, true).unwrap();
        assert_eq!(decoded.requests.len(), 1);
        assert_eq!(decoded.responses.len(), 1);
        assert!(decoded.requests[0].present);
        assert_eq!(decoded.requests[0].method, "GET");
        assert_eq!(decoded.requests[0].target, "/");
        assert_eq!(decoded.requests[0].headers.len(), 1);
        assert_eq!(decoded.requests[0].headers[0].name, "Host");
        assert_eq!(decoded.requests[0].bodyEncoding, BODY_NONE);
        assert!(decoded.responses[0].present);
        assert_eq!(decoded.responses[0].status, 200);
        assert_eq!(decoded.responses[0].body.as_ref(), &[79, 75]);
        assert_eq!(decoded.responses[0].bodyEncoding, BODY_RAW);
    }

    #[test]
    fn encode_with_redactions() {
        let encoder = AbiEncoder;
        let context = json!({
            "requests": [null],
            "responses": [{
                "status": 200,
                "headers": [null, ["Content-Type", "text/plain"]],
                "body": null
            }]
        });

        let encoded = encoder.encode(&context).unwrap();
        let decoded = <Attestation as SolValue>::abi_decode(&encoded.data, true).unwrap();

        // Null-replaced request
        assert!(!decoded.requests[0].present);
        assert_eq!(decoded.requests[0].method, "");

        // Response with null-replaced header
        assert!(decoded.responses[0].present);
        assert_eq!(decoded.responses[0].headers[0].name, "");
        assert_eq!(decoded.responses[0].headers[0].value, "");
        assert_eq!(decoded.responses[0].headers[1].name, "Content-Type");
        assert_eq!(decoded.responses[0].bodyEncoding, BODY_NONE);
    }

    #[test]
    fn encode_json_body_as_kv() {
        let encoder = AbiEncoder;
        let context = json!({
            "requests": [{
                "target": "/api",
                "method": "POST",
                "headers": [],
                "body": {
                    "Json": {
                        "name": "Alice",
                        "age": 30
                    }
                }
            }],
            "responses": []
        });

        let encoded = encoder.encode(&context).unwrap();
        let decoded = <Attestation as SolValue>::abi_decode(&encoded.data, true).unwrap();

        assert_eq!(decoded.requests[0].bodyEncoding, BODY_JSON_KV);
        assert!(!decoded.requests[0].body.is_empty());

        // Decode the body as (string[], string[])
        let (keys, values) = <(Vec<String>, Vec<String>)>::abi_decode(
            decoded.requests[0].body.as_ref(), true
        ).unwrap();
        assert!(keys.contains(&"name".to_string()));
        assert!(keys.contains(&"age".to_string()));
        let name_idx = keys.iter().position(|k| k == "name").unwrap();
        assert_eq!(values[name_idx], "\"Alice\"");
    }

    #[test]
    fn encode_json_array_body_as_raw() {
        let encoder = AbiEncoder;
        let context = json!({
            "requests": [],
            "responses": [{
                "status": 200,
                "headers": [],
                "body": {
                    "Json": [1, 2, 3]
                }
            }]
        });

        let encoded = encoder.encode(&context).unwrap();
        let decoded = <Attestation as SolValue>::abi_decode(&encoded.data, true).unwrap();

        // JSON array body falls back to raw
        assert_eq!(decoded.responses[0].bodyEncoding, BODY_RAW);
        let body_str = String::from_utf8(decoded.responses[0].body.to_vec()).unwrap();
        assert_eq!(body_str, "[1,2,3]");
    }

    #[test]
    fn deterministic_encoding() {
        let encoder = AbiEncoder;
        let context = json!({
            "requests": [{"target": "/", "method": "GET", "headers": [], "body": null}],
            "responses": [{"status": 200, "headers": [], "body": null}]
        });
        let enc1 = encoder.encode(&context).unwrap();
        let enc2 = encoder.encode(&context).unwrap();
        assert_eq!(enc1.data, enc2.data);
        assert_eq!(enc1.digest, enc2.digest);
    }

    #[test]
    fn digest_is_keccak256() {
        let encoder = AbiEncoder;
        let context = json!({
            "requests": [],
            "responses": []
        });
        let encoded = encoder.encode(&context).unwrap();
        let expected = keccak256(&encoded.data).to_vec();
        assert_eq!(encoded.digest, expected);
    }

    #[test]
    fn name_is_abi() {
        assert_eq!(AbiEncoder.name(), "abi");
    }

    #[test]
    fn missing_headers_key_produces_empty_array() {
        let encoder = AbiEncoder;
        let context = json!({
            "requests": [{"target": "/", "method": "GET"}],
            "responses": []
        });
        let encoded = encoder.encode(&context).unwrap();
        let decoded = <Attestation as SolValue>::abi_decode(&encoded.data, true).unwrap();
        assert!(decoded.requests[0].headers.is_empty());
    }
}
