use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Occurrence {
    pub fingerprint: String,
    pub source: String,
    pub path: String,
    pub member_chain: Vec<String>,
    pub commit: Option<String>,
    pub tag: Option<String>,
    pub ref_name: Option<String>,
    pub blob: Option<String>,
    pub byte_start: usize,
    pub byte_end: usize,
    pub line_start: Option<usize>,
    pub line_end: Option<usize>,
    pub extraction_chain: Vec<String>,
    pub location_mapping: String,
    pub matched_path_level: Option<usize>,
    pub suppressions: Vec<SuppressionAudit>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuppressionAudit {
    pub id: String,
    pub owner: String,
    pub reason: String,
    pub ticket: String,
    pub expires: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub schema_version: u32,
    pub scan_id: String,
    pub secret_id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub description: String,
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub evidence_codes: Vec<String>,
    pub verification: String,
    pub remediation: String,
    pub value: String,
    pub lifecycle: String,
    pub occurrences: Vec<Occurrence>,
}

pub struct Identity {
    key: Vec<u8>,
    pub key_id: String,
}
impl Identity {
    pub fn from_bytes(key: Vec<u8>) -> Result<Self, String> {
        if key.len() != 32 {
            return Err("Identity key must contain exactly 32 random bytes.".into());
        }
        let key_id = hex::encode(Sha256::digest(&key))[..16].to_string();
        Ok(Self { key, key_id })
    }

    pub fn load(path: &Path, create: bool) -> Result<Self, String> {
        if create && !path.exists() {
            let parent = path.parent().ok_or("Invalid key path.")?;
            fs::create_dir_all(parent).map_err(|_| "Cannot create identity key directory.")?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|_| "Cannot protect key directory.")?;
            let mut key = [0u8; 32];
            getrandom::fill(&mut key).map_err(|_| "Cannot obtain secure randomness.")?;
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
            {
                Ok(mut file) => {
                    file.write_all(&key)
                        .and_then(|_| file.sync_all())
                        .map_err(|_| "Cannot persist identity key.")?;
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err("Cannot create identity key.".into()),
            }
        }
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| "Cannot safely open identity key.")?;
        let mut file = File::from(fd);
        let meta = file
            .metadata()
            .map_err(|_| "Cannot inspect identity key.")?;
        if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
            return Err(
                "Identity key must be a private regular file (0600, no hard links).".into(),
            );
        }
        let mut key = Vec::new();
        (&mut file)
            .take(33)
            .read_to_end(&mut key)
            .map_err(|_| "Cannot read identity key.")?;
        Self::from_bytes(key)
    }

    pub fn fingerprint(&self, domain: &str, values: &[&str]) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts 32-byte key");
        mac.update(domain.as_bytes());
        mac.update(&[0]);
        for value in values {
            mac.update(&(value.len() as u64).to_be_bytes());
            mac.update(value.as_bytes());
        }
        hex::encode(mac.finalize().into_bytes())
    }
}
