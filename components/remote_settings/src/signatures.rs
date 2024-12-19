use core::clone::Clone;

use crate::{client::CollectionMetadata, RemoteSettingsRecord, Result};
use canonical_json;
use rc_crypto::contentsignature;
use serde_json::{json, Value};
use url::Url;
use viaduct::Request;

/// Remove `deleted` and `attachment` fields if it is null.
fn select_record_fields(value: &Value) -> Value {
    if let Value::Object(map) = value {
        let new_map = map
            .iter()
            .filter_map(|(key, v)| {
                if key == "deleted" || key == "attachment" && v.is_null() {
                    None
                } else {
                    Some((key.clone(), v.clone()))
                }
            })
            .collect();
        Value::Object(new_map)
    } else {
        value.clone() // Return the value as-is if it's not an object
    }
}

/// Serialize collection data into canonical JSON. This must match the server implementation.
fn serialize_data(timestamp: u64, records: Vec<RemoteSettingsRecord>) -> Result<Vec<u8>> {
    let mut sorted_records = records.to_vec();
    sorted_records.sort_by_cached_key(|r| r.id.clone());
    let serialized = canonical_json::to_string(&json!({
        "data": sorted_records.into_iter().map(|r| select_record_fields(&json!(r))).collect::<Vec<Value>>(),
        "last_modified": timestamp.to_string()
    }))?;
    let data = format!("Content-Signature:\x00{}", serialized);
    Ok(data.as_bytes().to_vec())
}

/// Verify that the timestamp and records match the signature in the metadata.
pub fn verify_signature(
    timestamp: u64,
    records: Vec<RemoteSettingsRecord>,
    metadata: CollectionMetadata,
    epoch_seconds: u64,
) -> Result<()> {
    // The signer name is hard-coded. This would have to be modified in the very (very)
    // unlikely situation where we would add a new collection signer.
    // And clients code would have to be modified to handle this new collection anyway.
    // https://searchfox.org/mozilla-central/rev/df850fa290fe962c2c5ae8b63d0943ce768e3cc4/services/settings/remote-settings.sys.mjs#40-48
    let subject_cn = format!(
        "{}.content-signature.mozilla.org",
        if metadata.bucket.contains("security-state") {
            "onecrl"
        } else {
            "remote-settings"
        }
    );

    let message = serialize_data(timestamp, records)?;

    // Fetch certificate chain
    let pem_req = Request::get(Url::parse(&metadata.signature.x5u)?);
    let pem_resp = pem_req.send()?;
    let pem_bytes = pem_resp.body;

    // Check that certificate chain is valid at specific date time, and
    // that signature matches the input message.
    contentsignature::verify(
        &message,
        metadata.signature.signature.as_bytes(),
        &pem_bytes,
        epoch_seconds,
        "",
        &subject_cn,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::serialize_data;
    use crate::{Attachment, RemoteSettingsRecord};
    use serde_json::json;

    #[test]
    fn test_records_canonicaljson_serialization() {
        let bytes = serialize_data(
            1337,
            vec![RemoteSettingsRecord {
                last_modified: 42,
                id: "bonjour".into(),
                deleted: false,
                attachment: None,
                fields: json!({"foo": "bar"}).as_object().unwrap().clone(),
            }],
        )
        .unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, "Content-Signature:\u{0}{\"data\":[{\"id\":\"bonjour\",\"last_modified\":42,\"foo\":\"bar\"}],\"last_modified\":\"1337\"}");
    }

    #[test]
    fn test_records_canonicaljson_serialization_with_attachment() {
        let bytes = serialize_data(
            1337,
            vec![RemoteSettingsRecord {
                last_modified: 42,
                id: "bonjour".into(),
                deleted: true,
                attachment: Some(Attachment {
                    filename: "pix.jpg".into(),
                    mimetype: "image/jpeg".into(),
                    location: "folder/file.jpg".into(),
                    hash: "aabbcc".into(),
                    size: 1234567,
                }),
                fields: json!({}).as_object().unwrap().clone(),
            }],
        )
        .unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, "Content-Signature:\0{\"data\":[{\"id\":\"bonjour\",\"last_modified\":42,\"attachment\":{\"filename\":\"pix.jpg\",\"mimetype\":\"image/jpeg\",\"location\":\"folder/file.jpg\",\"hash\":\"aabbcc\",\"size\":1234567}}],\"last_modified\":\"1337\"}");
    }
}
