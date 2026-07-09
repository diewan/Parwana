//! Local off-chain Sanad manifest cache and display (SANAD-MANIFEST-001).
//!
//! The manifest is *display/cache only* local state — never protocol authority
//! state. On create we cache the canonical [`SanadManifest`] together with the
//! [`SanadPayloadDescriptor`] it was built from, keyed by Sanad ID. On
//! `sanad show` we load it, cryptographically re-check that it binds to the
//! Sanad (the cached descriptor must hash to the Sanad's `descriptor_hash`, the
//! manifest's roots must match that descriptor, and the attachment root must be
//! self-consistent), and only then present it as verified metadata. Any
//! mismatch is reported and the metadata is refused rather than shown as
//! trusted.

use std::path::{Path, PathBuf};

use anyhow::Result;
use csv_codec::manual_encoder::CanonicalEncoding;
use csv_content::{MediaType, SanadManifest, SanadManifestAttachment};
use csv_hash::Hash;
use csv_protocol::SanadPayloadDescriptor;

use crate::output;
use crate::state::UnifiedStateManager;

/// Directory where per-Sanad manifest caches live, alongside the state file.
fn cache_dir(state: &UnifiedStateManager) -> PathBuf {
    let state_path = PathBuf::from(state.file_path());
    let base = state_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("sanad_manifests")
}

fn cache_file(state: &UnifiedStateManager, sanad_id_hex: &str) -> PathBuf {
    cache_dir(state).join(format!("{sanad_id_hex}.bin"))
}

/// Convert a descriptor `HashWire` into a `Hash`, failing closed on bad hex.
fn wire_to_hash(wire: &csv_protocol::wire::HashWire) -> Result<Hash> {
    let bytes = wire
        .as_bytes()
        .map_err(|e| anyhow::anyhow!("invalid descriptor hash: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("descriptor hash is not 32 bytes");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Hash::new(arr))
}

fn is_zero(h: &Hash) -> bool {
    h.as_bytes() == &[0u8; 32]
}

fn payload_codec_label(codec: u8) -> String {
    match codec {
        1 => "cbor".to_string(),
        2 => "json".to_string(),
        0 => "octet-stream".to_string(),
        other => format!("codec-{other}"),
    }
}

/// Build a canonical [`SanadManifest`] from a descriptor plus the attachment
/// files that were supplied to `sanad create`.
///
/// Attachment files are re-read here purely to populate display metadata
/// (name/size/hash); the manifest's `payload_hash` / `content_root` /
/// `attachment_root` are taken from the descriptor so the manifest can never
/// silently diverge from the Sanad it describes.
pub fn build_manifest(
    descriptor: &SanadPayloadDescriptor,
    attachment_paths: &Option<String>,
    title: Option<String>,
) -> Result<SanadManifest> {
    let payload_hash = wire_to_hash(&descriptor.payload_hash)?;
    let content_root = match &descriptor.content_root {
        Some(w) => Some(wire_to_hash(w)?),
        None => None,
    };
    let attachment_root = match &descriptor.attachment_root {
        Some(w) => Some(wire_to_hash(w)?),
        None => None,
    };
    let disclosure = wire_to_hash(&descriptor.disclosure_policy_hash)?;
    let proof = wire_to_hash(&descriptor.proof_policy_hash)?;

    let mut attachments = Vec::new();
    if let Some(paths) = attachment_paths {
        for path in paths.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let bytes = std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("failed to read attachment {path}: {e}"))?;
            let hash = Hash::sha256(&bytes);
            let name = Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string());
            attachments.push(SanadManifestAttachment {
                name,
                cid: None,
                media_type: MediaType::Custom("application/octet-stream".to_string()),
                size: bytes.len() as u64,
                hash,
                encrypted: false,
                encryption_key_id: None,
            });
        }
    }

    Ok(SanadManifest {
        version: csv_content::SANAD_MANIFEST_VERSION,
        title,
        description: None,
        schema: descriptor.schema_id.clone(),
        payload_codec: payload_codec_label(descriptor.payload_codec),
        payload_hash,
        content_root,
        attachments,
        attachment_root,
        disclosure_policy_hash: (!is_zero(&disclosure)).then_some(disclosure),
        proof_policy_hash: (!is_zero(&proof)).then_some(proof),
    })
}

/// A cached manifest plus the inputs needed to re-bind it to its Sanad ID.
struct CachedManifest {
    descriptor: SanadPayloadDescriptor,
    manifest: SanadManifest,
    salt: Vec<u8>,
    owner: Vec<u8>,
    commitment: Hash,
}

fn put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn take_field<'a>(blob: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let start = *pos;
    let len_end = start
        .checked_add(4)
        .filter(|&e| e <= blob.len())
        .ok_or_else(|| anyhow::anyhow!("manifest cache truncated (length prefix)"))?;
    let len = u32::from_le_bytes([
        blob[start],
        blob[start + 1],
        blob[start + 2],
        blob[start + 3],
    ]) as usize;
    let end = len_end
        .checked_add(len)
        .filter(|&e| e <= blob.len())
        .ok_or_else(|| anyhow::anyhow!("manifest cache truncated (field body)"))?;
    *pos = end;
    Ok(&blob[len_end..end])
}

/// Cache the descriptor + manifest (and the salt/owner/commitment needed to
/// re-derive the Sanad ID) for a Sanad. Best-effort: a cache write failure is
/// logged but never fails the create (manifest is display-only).
pub fn save(
    state: &UnifiedStateManager,
    sanad_id_hex: &str,
    descriptor: &SanadPayloadDescriptor,
    manifest: &SanadManifest,
    salt: &[u8],
    owner: &[u8],
    commitment: &Hash,
) {
    if let Err(e) = save_inner(
        state,
        sanad_id_hex,
        descriptor,
        manifest,
        salt,
        owner,
        commitment,
    ) {
        output::warning(&format!("Could not cache Sanad manifest: {e}"));
    }
}

#[allow(clippy::too_many_arguments)]
fn save_inner(
    state: &UnifiedStateManager,
    sanad_id_hex: &str,
    descriptor: &SanadPayloadDescriptor,
    manifest: &SanadManifest,
    salt: &[u8],
    owner: &[u8],
    commitment: &Hash,
) -> Result<()> {
    let dir = cache_dir(state);
    std::fs::create_dir_all(&dir)?;
    let desc_bytes = descriptor
        .encode_mce()
        .map_err(|e| anyhow::anyhow!("failed to encode descriptor: {e}"))?;

    let mut blob = Vec::new();
    put_field(&mut blob, &desc_bytes);
    put_field(&mut blob, &manifest.to_canonical_bytes());
    put_field(&mut blob, salt);
    put_field(&mut blob, owner);
    blob.extend_from_slice(commitment.as_bytes());
    std::fs::write(cache_file(state, sanad_id_hex), blob)?;
    Ok(())
}

/// Load a cached manifest bundle for a Sanad, if present.
fn load(state: &UnifiedStateManager, sanad_id_hex: &str) -> Result<Option<CachedManifest>> {
    let path = cache_file(state, sanad_id_hex);
    if !path.exists() {
        return Ok(None);
    }
    let blob = std::fs::read(&path)?;
    let mut pos = 0;
    let descriptor = SanadPayloadDescriptor::decode_mce(take_field(&blob, &mut pos)?)
        .map_err(|e| anyhow::anyhow!("failed to decode cached descriptor: {e}"))?;
    let manifest = SanadManifest::from_canonical_bytes(take_field(&blob, &mut pos)?)
        .map_err(|e| anyhow::anyhow!("failed to decode cached manifest: {e}"))?;
    let salt = take_field(&blob, &mut pos)?.to_vec();
    let owner = take_field(&blob, &mut pos)?.to_vec();
    let commitment_bytes = blob
        .get(pos..pos + 32)
        .ok_or_else(|| anyhow::anyhow!("manifest cache truncated (commitment)"))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(commitment_bytes);
    Ok(Some(CachedManifest {
        descriptor,
        manifest,
        salt,
        owner,
        commitment: Hash::new(arr),
    }))
}

/// Load, verify, and display the manifest for a Sanad on `sanad show`.
///
/// `sanad_id_hash` is the Sanad's 32-byte identifier. The manifest is presented
/// as verified metadata only if:
/// 1. re-deriving the Sanad ID from the cached descriptor/commitment/salt/owner
///    reproduces `sanad_id_hash` (binds the manifest to *this* Sanad),
/// 2. the manifest's roots match that descriptor, and
/// 3. the manifest's attachment root is self-consistent.
///
/// Otherwise it reports the situation and refuses to present the metadata as
/// verified.
pub fn show(state: &UnifiedStateManager, sanad_id_hex: &str, sanad_id_hash: &Hash) {
    let loaded = match load(state, sanad_id_hex) {
        Ok(v) => v,
        Err(e) => {
            output::warning(&format!("Manifest present but unreadable: {e}"));
            return;
        }
    };

    let Some(cached) = loaded else {
        output::header("Manifest");
        output::info(
            "No local manifest cached for this Sanad. Only on-chain commitment \
             hashes are available; run 'csv sanad create' with content to cache one.",
        );
        return;
    };
    let CachedManifest {
        descriptor,
        manifest,
        salt,
        owner,
        commitment,
    } = cached;

    // 1. Bind the cached bundle to this exact Sanad by re-deriving the owner-
    //    bound v2 Sanad ID and comparing it to the requested id.
    let derived = csv_hash::sanad::SanadId::from_descriptor_commitment_owner(
        descriptor.compute_hash(),
        commitment,
        &salt,
        &owner,
    );
    if derived.as_bytes() != sanad_id_hash.as_bytes() {
        output::warning(
            "Cached manifest does not match this Sanad (re-derived Sanad ID mismatch); \
             refusing to present it as verified metadata.",
        );
        return;
    }

    // 2. Manifest roots must match the descriptor.
    let (payload_hash, content_root, attachment_root) = match descriptor_roots(&descriptor) {
        Ok(roots) => roots,
        Err(e) => {
            output::warning(&format!("Cached descriptor is malformed: {e}"));
            return;
        }
    };
    if let Err(e) =
        manifest.matches_descriptor_roots(&payload_hash, &content_root, &attachment_root)
    {
        output::warning(&format!(
            "Cached manifest does not match the Sanad descriptor ({e}); \
             refusing to present it as verified metadata."
        ));
        return;
    }

    // 3. Attachment root self-consistency.
    if let Err(e) = manifest.validate_attachment_root() {
        output::warning(&format!(
            "Cached manifest attachments are inconsistent ({e}); \
             refusing to present it as verified metadata."
        ));
        return;
    }

    render(&manifest);
}

fn descriptor_roots(
    descriptor: &SanadPayloadDescriptor,
) -> Result<(Hash, Option<Hash>, Option<Hash>)> {
    let payload_hash = wire_to_hash(&descriptor.payload_hash)?;
    let content_root = match &descriptor.content_root {
        Some(w) => Some(wire_to_hash(w)?),
        None => None,
    };
    let attachment_root = match &descriptor.attachment_root {
        Some(w) => Some(wire_to_hash(w)?),
        None => None,
    };
    Ok((payload_hash, content_root, attachment_root))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> SanadPayloadDescriptor {
        SanadPayloadDescriptor::new(
            SanadPayloadDescriptor::SCHEMA_ID,
            Hash::new([1u8; 32]),       // schema_hash
            1,                          // payload_codec (cbor)
            Hash::new([2u8; 32]),       // payload_hash
            Some(Hash::new([3u8; 32])), // content_root
            Hash::new([0u8; 32]),       // disclosure_policy_hash (zero => None in manifest)
            Hash::new([4u8; 32]),       // proof_policy_hash
        )
    }

    #[test]
    fn built_manifest_matches_descriptor_roots() {
        let desc = descriptor();
        let manifest = build_manifest(&desc, &None, Some("Title".into())).unwrap();
        // The manifest's roots must match the descriptor it was built from.
        let (payload_hash, content_root, attachment_root) = descriptor_roots(&desc).unwrap();
        assert!(
            manifest
                .matches_descriptor_roots(&payload_hash, &content_root, &attachment_root)
                .is_ok()
        );
        assert_eq!(manifest.payload_codec, "cbor");
        assert_eq!(manifest.title.as_deref(), Some("Title"));
        // Zero policy hash is dropped, non-zero is kept.
        assert_eq!(manifest.disclosure_policy_hash, None);
        assert_eq!(manifest.proof_policy_hash, Some(Hash::new([4u8; 32])));
    }

    #[test]
    fn field_codec_roundtrips() {
        let mut blob = Vec::new();
        put_field(&mut blob, b"hello");
        put_field(&mut blob, &[]);
        put_field(&mut blob, b"world!!");
        let mut pos = 0;
        assert_eq!(take_field(&blob, &mut pos).unwrap(), b"hello");
        assert_eq!(take_field(&blob, &mut pos).unwrap(), b"");
        assert_eq!(take_field(&blob, &mut pos).unwrap(), b"world!!");
        // Truncated body fails closed.
        let mut pos2 = 0;
        assert!(take_field(&blob[..blob.len() - 1], &mut pos2).is_ok()); // first field ok
        assert!(take_field(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00], &mut 0).is_err());
    }
}

fn render(manifest: &SanadManifest) {
    output::header("Manifest (verified against Sanad descriptor)");
    if let Some(title) = &manifest.title {
        output::kv("Title", title);
    }
    if let Some(desc) = &manifest.description {
        output::kv("Description", desc);
    }
    output::kv("Schema", &manifest.schema);
    output::kv("Payload Codec", &manifest.payload_codec);
    output::kv_hash("Payload Hash", manifest.payload_hash.as_bytes());
    if let Some(root) = &manifest.content_root {
        output::kv_hash("Content Root", root.as_bytes());
    }
    if let Some(root) = &manifest.attachment_root {
        output::kv_hash("Attachment Root", root.as_bytes());
    }
    output::kv_hash("Manifest Hash", manifest.manifest_hash().as_bytes());

    if manifest.attachments.is_empty() {
        output::info("No attachments.");
    } else {
        output::kv("Attachments", &manifest.attachments.len().to_string());
        for (i, a) in manifest.attachments.iter().enumerate() {
            let label = a
                .name
                .clone()
                .or_else(|| a.cid.clone())
                .unwrap_or_else(|| format!("attachment {}", i + 1));
            output::kv(
                &format!("  {}", label),
                &format!(
                    "{} · {} bytes{}",
                    a.media_type.as_str(),
                    a.size,
                    if a.encrypted { " · encrypted" } else { "" }
                ),
            );
            output::kv_hash("    hash", a.hash.as_bytes());
        }
    }
}
