//! Şifrəli fayl kassası (vault) modulu.
//!
//! flutter_rust_bridge (FRB) ilə istifadə üçün nəzərdə tutulub:
//! - Açar materialı (MEK) heç vaxt Dart tərəfinə açıq bayt kimi ötürülmür;
//!   `VaultHandle` opaque struct kimi FRB tərəfindən Dart klassına
//!   çevrilir və yalnız metodları çağırıla bilər.
//! - Bütün açıq API-lər `Result<T, String>` qaytarır ki, FRB bunu
//!   avtomatik Dart-da `Exception` kimi tanısın.
//! - Böyük fayllar üçün nəticə birbaşa diskə yazılır (Vec<u8> kimi
//!   bridge üzərindən ötürülmür), yaddaş sıxıntısının qarşısı alınır.
//!
//! Cargo.toml asılılıqları (mövcud layihənizdə artıq var idi):
//! aes-gcm, argon2, zeroize, hex, serde, serde_json

use aes_gcm::aead::stream::{EncryptorBE32};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::Nonce as StreamNonce;
use aes_gcm::{Aes256Gcm, Key, Nonce as GcmNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, ErrorKind, Read, Result as IoResult, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Once};
use zeroize::{Zeroize, Zeroizing};

static RAYON_INIT: Once = Once::new();

/// Global Rayon thread pool-u `available_parallelism - 2` (minimum 1) ilə konfiqurasiya edir.
pub fn init_thread_pool() {
    RAYON_INIT.call_once(|| {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get().saturating_sub(2).max(1))
            .unwrap_or(1);

        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global();
    });
}

const CHUNK_SIZE: usize = 4 * 1024 * 1024;
const TAG_SIZE: usize = 16;
const ENCRYPTED_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;
const NONCE_SIZE: usize = 7;

const SALT_SIZE: usize = 16;
const HEADER_NONCE_SIZE: usize = 12;
const MEK_SIZE: usize = 32;

// Hər təsadüfi ad 16 baytın hex-encoded formasıdır (add_file-də
// obfuscated_name üçün istifadə olunan sxemlə eynidir).
const NAME_LEN: usize = 32;

// Başlıq (header) faylının PAYLOAD-u: MEK + metadata faylının adı +
// ehtiyat metadata faylının adı. Bu üç sahə də sabit uzunluqdadır,
// ona görə şifrələnmiş başlıq faylının ÜMUMİ ölçüsü HƏMİŞƏ eynidir
// (HEADER_TOTAL_SIZE). Kassa artıq nə ".vault_header", nə "metadata.dat"
// kimi tanınan sabit adlardan istifadə etmir — hər fayl təsadüfi hex
// addır. Başlığı tapmaq üçün qovluqdakı bütün faylları HEADER_TOTAL_SIZE
// ölçüsünə görə süzürük və hər namizədi parolla deşifrə etməyə çalışırıq;
// GCM autentifikasiya teqi sayəsində səhv fayl/parol demək olar ki, heç
// vaxt yanlışlıqla "uğurlu" sayılmır.
const HEADER_PAYLOAD_SIZE: usize = MEK_SIZE + NAME_LEN + NAME_LEN;
const ENCRYPTED_HEADER_PAYLOAD_SIZE: usize = HEADER_PAYLOAD_SIZE + TAG_SIZE;
const HEADER_TOTAL_SIZE: usize = SALT_SIZE + HEADER_NONCE_SIZE + ENCRYPTED_HEADER_PAYLOAD_SIZE;

// ---------------------------------------------------------------------
// FRB-dostu ictimai (public) data tipləri
// ---------------------------------------------------------------------

/// Kassadakı bir faylın metadata qeydi. FRB bunu Dart-da adi bir
/// klas (freezed olmayan sadə data class) kimi generasiya edəcək.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultFileEntry {
    /// Diskdə saxlanılan təsadüfi (obfuscated) fayl adı.
    pub obfuscated_name: String,
    /// İstifadəçiyə göstərilən əsl fayl adı.
    pub original_name: String,
}

/// Növbə ilə fayl əlavə etmək üçün giriş parametri.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultAddFileInput {
    pub source_file_path: String,
    pub original_name: String,
}

/// Növbə ilə fayl çıxarmaq üçün giriş parametri.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultExtractFileInput {
    pub obfuscated_name: String,
    pub dest_path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct VaultMetadata {
    file_map: HashMap<String, String>,
}

// ---------------------------------------------------------------------
// Köməkçi funksiyalar
// ---------------------------------------------------------------------

fn read_exact_up_to_end(reader: &mut impl Read, buffer: &mut [u8]) -> IoResult<usize> {
    let mut total_read = 0;
    while total_read < buffer.len() {
        match reader.read(&mut buffer[total_read..]) {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total_read)
}

/// Təsadüfi, uzantısız fayl/qovluq adı (16 təsadüfi baytın hex forması).
/// Kassadakı BÜTÜN fayllar (başlıq, metadata, ehtiyat metadata, məzmun
/// faylları) bu funksiyadan çıxan adları daşıyır.
fn random_hex_name() -> String {
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Başlıq faylının deşifrə olunmuş, sabit ölçülü payload-u.
struct HeaderPayload {
    mek: [u8; MEK_SIZE],
    metadata_name: String,
    metadata_backup_name: String,
}

impl Drop for HeaderPayload {
    fn drop(&mut self) {
        self.mek.zeroize();
    }
}

impl HeaderPayload {
    fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_PAYLOAD_SIZE);
        v.extend_from_slice(&self.mek);
        v.extend_from_slice(self.metadata_name.as_bytes());
        v.extend_from_slice(self.metadata_backup_name.as_bytes());
        v
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != HEADER_PAYLOAD_SIZE {
            return Err("Kassa başlığı zədəlidir (yanlış payload ölçüsü)".to_string());
        }
        let mut mek = [0u8; MEK_SIZE];
        mek.copy_from_slice(&bytes[0..MEK_SIZE]);

        let name_start = MEK_SIZE;
        let name_end = name_start + NAME_LEN;
        let metadata_name = String::from_utf8(bytes[name_start..name_end].to_vec())
            .map_err(|_| "Kassa başlığı zədəlidir (ad UTF-8 deyil)".to_string())?;

        let backup_start = name_end;
        let backup_end = backup_start + NAME_LEN;
        let metadata_backup_name = String::from_utf8(bytes[backup_start..backup_end].to_vec())
            .map_err(|_| "Kassa başlığı zədəlidir (ehtiyat ad UTF-8 deyil)".to_string())?;

        Ok(Self {
            mek,
            metadata_name,
            metadata_backup_name,
        })
    }
}

/// Qovluqdakı, HEADER_TOTAL_SIZE ölçüsünə uyğun gələn bütün faylların
/// yollarını qaytarır — bunlar "başlıq ola bilər" namizədləridir.
/// Real təsdiq yalnız parolla deşifrə cəhdi ilə olur (bax: unlock).
fn header_candidate_paths(vault_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(vault_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.to_string()),
    };
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if len == HEADER_TOTAL_SIZE as u64 {
            out.push(path);
        }
    }
    Ok(out)
}

fn header_candidate_exists(vault_dir: &Path) -> Result<bool, String> {
    Ok(!header_candidate_paths(vault_dir)?.is_empty())
}

fn derive_master_key(password: &str, salt: &[u8; SALT_SIZE]) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut master_key = Zeroizing::new([0u8; 32]);

    let params = Params::new(65536, 3, 4, Some(32)).map_err(|e| format!("Parametr xətası: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(password.as_bytes(), salt, master_key.as_mut())
        .map_err(|e| format!("Açar törədilə bilmədi: {}", e))?;
    Ok(master_key)
}

// ---------------------------------------------------------------------
// Aşağı səviyyəli stream şifrələmə/deşifrələmə (fayl <-> fayl)
// ---------------------------------------------------------------------

fn encrypt_bytes_to_file(data: &[u8], dest_path: &Path, key_bytes: &[u8; 32]) -> Result<(), String> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = StreamNonce::from_slice(&nonce_bytes);

    let aead = Aes256Gcm::new(key);
    let mut encryptor = EncryptorBE32::from_aead(aead, nonce);

    let tmp_path = tmp_path_for(dest_path);
    {
        let dest_file = File::create(&tmp_path).map_err(|e| e.to_string())?;
        let mut dest_file = BufWriter::new(dest_file);
        dest_file.write_all(&nonce_bytes).map_err(|e| e.to_string())?;

        if data.is_empty() {
            let encrypted_chunk = encryptor.encrypt_last(&[][..]).map_err(|e| format!("{:?}", e))?;
            dest_file.write_all(&encrypted_chunk).map_err(|e| e.to_string())?;
        } else {
            let mut chunks = data.chunks(CHUNK_SIZE).peekable();
            while let Some(chunk) = chunks.next() {
                if chunks.peek().is_none() {
                    let encrypted_chunk = encryptor.encrypt_last(chunk).map_err(|e| format!("{:?}", e))?;
                    dest_file.write_all(&encrypted_chunk).map_err(|e| e.to_string())?;
                    break;
                } else {
                    let encrypted_chunk = encryptor.encrypt_next(chunk).map_err(|e| format!("{:?}", e))?;
                    dest_file.write_all(&encrypted_chunk).map_err(|e| e.to_string())?;
                }
            }
        }
        dest_file.flush().map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp_path, dest_path).map_err(|e| e.to_string())?;
    Ok(())
}

/// Deterministik StreamBE32 nonce formatı:
///   [0..7]  = 7 baytlıq təsadüfi prefix
///   [7..11] = big-endian u32 chunk_index
///   [11]    = 0x01 (son parça) və ya 0x00 (aralıq parça)
pub(crate) fn derive_stream_nonce(
    nonce_prefix: &[u8; NONCE_SIZE],
    chunk_index: u64,
    is_last: bool,
) -> [u8; 12] {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..7].copy_from_slice(nonce_prefix);
    let idx32 = chunk_index as u32;
    nonce_bytes[7..11].copy_from_slice(&idx32.to_be_bytes());
    nonce_bytes[11] = if is_last { 1u8 } else { 0u8 };
    nonce_bytes
}

struct PlainChunk {
    index: u64,
    is_last: bool,
    data: Vec<u8>,
}

struct EncryptedChunk {
    index: u64,
    is_last: bool,
    data: Vec<u8>,
}

pub fn encrypt_file_parallel(
    source_path: &Path,
    dest_path: &Path,
    key_bytes: &[u8; 32],
) -> Result<(), String> {
    init_thread_pool();

    let mut source_file = File::open(source_path).map_err(|e| e.to_string())?;
    let file_len = source_file.metadata().map_err(|e| e.to_string())?.len();

    let mut nonce_prefix = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_prefix);

    let tmp_path = tmp_path_for(dest_path);
    let dest_file = File::create(&tmp_path).map_err(|e| e.to_string())?;
    let mut dest_writer = BufWriter::new(dest_file);
    if let Err(e) = dest_writer.write_all(&nonce_prefix) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.to_string());
    }

    let total_chunks = if file_len == 0 {
        1
    } else {
        (file_len + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64
    };

    let batch_size = (rayon::current_num_threads() * 4).clamp(8, 32);

    let mut chunk_index: u64 = 0;
    while chunk_index < total_chunks {
        let current_batch_size = std::cmp::min(batch_size as u64, total_chunks - chunk_index) as usize;
        let mut chunks = Vec::with_capacity(current_batch_size);

        for _ in 0..current_batch_size {
            let is_last = chunk_index == total_chunks - 1;
            let mut buf = vec![0u8; CHUNK_SIZE];
            let n = match read_exact_up_to_end(&mut source_file, &mut buf) {
                Ok(n) => n,
                Err(e) => {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(e.to_string());
                }
            };
            buf.truncate(n);
            chunks.push(PlainChunk {
                index: chunk_index,
                is_last,
                data: buf,
            });
            chunk_index += 1;
        }

        let encrypted_chunks: Result<Vec<Vec<u8>>, String> = chunks
            .into_par_iter()
            .map(|chunk| {
                let nonce_bytes = derive_stream_nonce(&nonce_prefix, chunk.index, chunk.is_last);
                let nonce = GcmNonce::from_slice(&nonce_bytes);
                let key = Key::<Aes256Gcm>::from_slice(key_bytes);
                let aead = Aes256Gcm::new(key);
                aead.encrypt(nonce, chunk.data.as_slice())
                    .map_err(|e| format!("Şifrələmə xətası (parça {}): {:?}", chunk.index, e))
            })
            .collect();

        let encrypted_chunks = match encrypted_chunks {
            Ok(c) => c,
            Err(e) => {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
        };

        for enc in encrypted_chunks {
            if let Err(e) = dest_writer.write_all(&enc) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.to_string());
            }
        }
    }

    if let Err(e) = dest_writer.flush() {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.to_string());
    }
    drop(dest_writer);

    fs::rename(&tmp_path, dest_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        e.to_string()
    })?;

    Ok(())
}

fn tmp_path_for(dest_path: &Path) -> PathBuf {
    let mut tmp = dest_path.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

pub fn decrypt_file_parallel_to_writer(
    source_path: &Path,
    key_bytes: &[u8; 32],
    writer: &mut impl Write,
) -> Result<(), String> {
    init_thread_pool();

    let mut source_file = File::open(source_path).map_err(|e| e.to_string())?;
    let file_len = source_file.metadata().map_err(|e| e.to_string())?.len();

    if file_len < (NONCE_SIZE + TAG_SIZE) as u64 {
        return Err("Fayl zədəlidir (çox kiçikdir)".to_string());
    }

    let mut nonce_prefix = [0u8; NONCE_SIZE];
    source_file
        .read_exact(&mut nonce_prefix)
        .map_err(|_| "Nonce oxuna bilmədi".to_string())?;

    let enc_payload_size = file_len - NONCE_SIZE as u64;
    let full_chunks = enc_payload_size / ENCRYPTED_CHUNK_SIZE as u64;
    let last_enc_rem = enc_payload_size % ENCRYPTED_CHUNK_SIZE as u64;

    if last_enc_rem > 0 && (last_enc_rem as usize) < TAG_SIZE {
        return Err("Fayl zədəlidir (son parça autentifikasiya teqindən kiçikdir)".to_string());
    }

    let (chunk_count, last_chunk_encrypted_size) = if last_enc_rem == 0 {
        (full_chunks, ENCRYPTED_CHUNK_SIZE)
    } else {
        (full_chunks + 1, last_enc_rem as usize)
    };

    if chunk_count == 0 {
        return Err("Fayl boşdur".to_string());
    }

    let batch_size = (rayon::current_num_threads() * 4).clamp(8, 32);

    let mut chunk_index: u64 = 0;
    while chunk_index < chunk_count {
        let current_batch_size = std::cmp::min(batch_size as u64, chunk_count - chunk_index) as usize;
        let mut chunks = Vec::with_capacity(current_batch_size);

        for _ in 0..current_batch_size {
            let is_last = chunk_index == chunk_count - 1;
            let enc_len = if is_last {
                last_chunk_encrypted_size
            } else {
                ENCRYPTED_CHUNK_SIZE
            };

            let mut buf = vec![0u8; enc_len];
            source_file
                .read_exact(&mut buf)
                .map_err(|e| format!("Parça oxuna bilmədi (indeks {}): {}", chunk_index, e))?;

            chunks.push(EncryptedChunk {
                index: chunk_index,
                is_last,
                data: buf,
            });
            chunk_index += 1;
        }

        let decrypted_chunks: Result<Vec<Vec<u8>>, String> = chunks
            .into_par_iter()
            .map(|chunk| {
                let nonce_bytes = derive_stream_nonce(&nonce_prefix, chunk.index, chunk.is_last);
                let nonce = GcmNonce::from_slice(&nonce_bytes);
                let key = Key::<Aes256Gcm>::from_slice(key_bytes);
                let aead = Aes256Gcm::new(key);
                aead.decrypt(nonce, chunk.data.as_slice())
                    .map_err(|e| format!("Deşifrələmə xətası (parça {}): {:?}", chunk.index, e))
            })
            .collect();

        let decrypted_chunks = decrypted_chunks?;

        for dec in decrypted_chunks {
            writer.write_all(&dec).map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}

pub fn decrypt_file_parallel(
    source_path: &Path,
    dest_path: &Path,
    key_bytes: &[u8; 32],
) -> Result<(), String> {
    let tmp_path = tmp_path_for(dest_path);
    {
        let out_file = File::create(&tmp_path).map_err(|e| e.to_string())?;
        let mut out_writer = BufWriter::new(out_file);
        if let Err(e) = decrypt_file_parallel_to_writer(source_path, key_bytes, &mut out_writer) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        if let Err(e) = out_writer.flush() {
            let _ = fs::remove_file(&tmp_path);
            return Err(e.to_string());
        }
    }
    fs::rename(&tmp_path, dest_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        e.to_string()
    })?;
    Ok(())
}

pub fn decrypt_file_parallel_to_bytes(
    source_path: &Path,
    key_bytes: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    decrypt_file_parallel_to_writer(source_path, key_bytes, &mut out)?;
    Ok(out)
}

fn decrypt_file_to_bytes(source_path: &Path, key_bytes: &[u8; 32]) -> Result<Vec<u8>, String> {
    decrypt_file_parallel_to_bytes(source_path, key_bytes)
}

// ---------------------------------------------------------------------
// Metadata oxu/yaz
// ---------------------------------------------------------------------

fn try_load_metadata_from(path: &Path, mek: &[u8; 32]) -> Result<VaultMetadata, String> {
    let decrypted_bytes = decrypt_file_to_bytes(path, mek)?;
    serde_json::from_slice(&decrypted_bytes).map_err(|e| e.to_string())
}

fn load_metadata(
    vault_dir: &Path,
    mek: &[u8; 32],
    metadata_name: &str,
    metadata_backup_name: &str,
) -> Result<VaultMetadata, String> {
    let metadata_path = vault_dir.join(metadata_name);
    let backup_path = vault_dir.join(metadata_backup_name);

    let metadata_exists = metadata_path.exists()
        && fs::metadata(&metadata_path).map(|m| m.len()).unwrap_or(0) > 0;

    if metadata_exists {
        match try_load_metadata_from(&metadata_path, mek) {
            Ok(m) => return Ok(m),
            Err(primary_err) => {
                let backup_exists = backup_path.exists()
                    && fs::metadata(&backup_path).map(|m| m.len()).unwrap_or(0) > 0;
                if backup_exists {
                    return try_load_metadata_from(&backup_path, mek).map_err(|backup_err| {
                        format!(
                            "Əsas metadata korlanıb ({}), ehtiyat nüsxə də oxuna bilmədi ({})",
                            primary_err, backup_err
                        )
                    });
                }
                return Err(format!("Metadata korlanıb və ehtiyat nüsxə yoxdur: {}", primary_err));
            }
        }
    }

    let backup_exists = backup_path.exists()
        && fs::metadata(&backup_path).map(|m| m.len()).unwrap_or(0) > 0;
    if backup_exists {
        return try_load_metadata_from(&backup_path, mek);
    }

    Ok(VaultMetadata::default())
}

fn save_metadata(
    vault_dir: &Path,
    mek: &[u8; 32],
    metadata_name: &str,
    metadata_backup_name: &str,
    metadata: &VaultMetadata,
) -> Result<(), String> {
    let metadata_path = vault_dir.join(metadata_name);
    let backup_path = vault_dir.join(metadata_backup_name);

    if metadata_path.exists() {
        fs::copy(&metadata_path, &backup_path)
            .map_err(|e| format!("Ehtiyat nüsxə yaradıla bilmədi: {}", e))?;
    }

    let json_bytes = serde_json::to_vec(metadata).map_err(|e| e.to_string())?;
    encrypt_bytes_to_file(&json_bytes, &metadata_path, mek)?;

    Ok(())
}

// ---------------------------------------------------------------------
// FRB-ə açılan ictimai (public) API: VaultHandle
// ---------------------------------------------------------------------

struct VaultInner {
    vault_dir: PathBuf,
    mek: Option<Zeroizing<[u8; 32]>>,
    metadata_name: Option<String>,
    metadata_backup_name: Option<String>,
}

impl Drop for VaultInner {
    fn drop(&mut self) {
        if let Some(mek) = self.mek.as_mut() {
            mek.zeroize();
        }
    }
}

#[derive(Clone)]
pub struct VaultHandle {
    inner: Arc<Mutex<VaultInner>>,
    file_queue_lock: Arc<Mutex<()>>,
}

impl VaultHandle {
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, VaultInner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn create_new(vault_dir: String, password: String) -> Result<VaultHandle, String> {
        init_thread_pool();

        let password = Zeroizing::new(password);
        let vault_path = PathBuf::from(&vault_dir);

        if vault_path.exists() && header_candidate_exists(&vault_path)? {
            return Err("Bu qovluqda artıq bir kassa mövcuddur".to_string());
        }
        fs::create_dir_all(&vault_path).map_err(|e| e.to_string())?;

        let mut salt = [0u8; SALT_SIZE];
        let mut mek = Zeroizing::new([0u8; MEK_SIZE]);
        let mut header_nonce = [0u8; HEADER_NONCE_SIZE];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(mek.as_mut());
        OsRng.fill_bytes(&mut header_nonce);

        let header_file_name = random_hex_name();
        let metadata_name = random_hex_name();
        let mut metadata_backup_name = random_hex_name();
        while metadata_backup_name == metadata_name {
            metadata_backup_name = random_hex_name();
        }

        let master_key_bytes = derive_master_key(&password, &salt)?;
        let master_key = Key::<Aes256Gcm>::from_slice(master_key_bytes.as_ref());
        let aead = Aes256Gcm::new(master_key);

        let payload = HeaderPayload {
            mek: *mek,
            metadata_name: metadata_name.clone(),
            metadata_backup_name: metadata_backup_name.clone(),
        };
        let payload_bytes = payload.to_bytes();
        let encrypted_payload = aead
            .encrypt(GcmNonce::from_slice(&header_nonce), payload_bytes.as_slice())
            .map_err(|e| format!("Başlıq şifrələnmədi: {:?}", e))?;

        let header_path = vault_path.join(&header_file_name);
        let header_tmp = tmp_path_for(&header_path);
        {
            let mut header_file = File::create(&header_tmp).map_err(|e| e.to_string())?;
            header_file.write_all(&salt).map_err(|e| e.to_string())?;
            header_file.write_all(&header_nonce).map_err(|e| e.to_string())?;
            header_file.write_all(&encrypted_payload).map_err(|e| e.to_string())?;
            header_file.flush().map_err(|e| e.to_string())?;
        }
        fs::rename(&header_tmp, &header_path).map_err(|e| e.to_string())?;

        let initial_metadata = VaultMetadata::default();
        save_metadata(&vault_path, &mek, &metadata_name, &metadata_backup_name, &initial_metadata)?;

        Ok(VaultHandle {
            inner: Arc::new(Mutex::new(VaultInner {
                vault_dir: vault_path,
                mek: Some(mek),
                metadata_name: Some(metadata_name),
                metadata_backup_name: Some(metadata_backup_name),
            })),
            file_queue_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn unlock(vault_dir: String, password: String) -> Result<VaultHandle, String> {
        init_thread_pool();

        let password = Zeroizing::new(password);
        let vault_path = PathBuf::from(&vault_dir);

        let candidates = header_candidate_paths(&vault_path)?;
        if candidates.is_empty() {
            return Err("Kassa başlığı tapılmadı!".to_string());
        }

        for candidate in &candidates {
            let mut header_file = match File::open(candidate) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let mut salt = [0u8; SALT_SIZE];
            let mut header_nonce = [0u8; HEADER_NONCE_SIZE];
            let mut encrypted_payload = vec![0u8; ENCRYPTED_HEADER_PAYLOAD_SIZE];

            if header_file.read_exact(&mut salt).is_err() {
                continue;
            }
            if header_file.read_exact(&mut header_nonce).is_err() {
                continue;
            }
            if header_file.read_exact(&mut encrypted_payload).is_err() {
                continue;
            }

            let master_key_bytes = match derive_master_key(&password, &salt) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let master_key = Key::<Aes256Gcm>::from_slice(master_key_bytes.as_ref());
            let aead = Aes256Gcm::new(master_key);

            let decrypted = match aead.decrypt(GcmNonce::from_slice(&header_nonce), encrypted_payload.as_slice()) {
                Ok(d) => Zeroizing::new(d),
                Err(_) => continue,
            };

            let payload = match HeaderPayload::from_bytes(&decrypted) {
                Ok(p) => p,
                Err(_) => continue,
            };

            let mek = Zeroizing::new(payload.mek);
            return Ok(VaultHandle {
                inner: Arc::new(Mutex::new(VaultInner {
                    vault_dir: vault_path,
                    mek: Some(mek),
                    metadata_name: Some(payload.metadata_name.clone()),
                    metadata_backup_name: Some(payload.metadata_backup_name.clone()),
                })),
                file_queue_lock: Arc::new(Mutex::new(())),
            });
        }

        Err("Yanlış şifrə və ya zədələnmiş kassa!".to_string())
    }

    pub fn exists(vault_dir: String) -> bool {
        header_candidate_exists(&PathBuf::from(&vault_dir)).unwrap_or(false)
    }

    pub fn lock(&self) {
        let mut inner = self.lock_inner();
        if let Some(mek) = inner.mek.as_mut() {
            mek.zeroize();
        }
        inner.mek = None;
        inner.metadata_name = None;
        inner.metadata_backup_name = None;
    }

    pub fn is_unlocked(&self) -> bool {
        self.lock_inner().mek.is_some()
    }

    pub fn add_files(&self, files: Vec<VaultAddFileInput>) -> Result<Vec<VaultFileEntry>, String> {
        let _queue_guard = self.file_queue_lock.lock().unwrap_or_else(|p| p.into_inner());

        let mut results = Vec::with_capacity(files.len());

        for file_input in files {
            let inner = self.lock_inner();
            let mek = inner.mek.as_ref().ok_or("Kassa kilidlidir".to_string())?;
            let metadata_name = inner.metadata_name.clone().ok_or("Kassa kilidlidir".to_string())?;
            let metadata_backup_name = inner
                .metadata_backup_name
                .clone()
                .ok_or("Kassa kilidlidir".to_string())?;
            let vault_dir = inner.vault_dir.clone();
            let mek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(**mek);
            drop(inner);

            let obfuscated_name = random_hex_name();
            let dest_encrypted_path = vault_dir.join(&obfuscated_name);

            if let Err(e) = encrypt_file_parallel(
                Path::new(&file_input.source_file_path),
                &dest_encrypted_path,
                &mek_bytes,
            ) {
                let _ = fs::remove_file(&dest_encrypted_path);
                return Err(e);
            }

            let mut metadata = match load_metadata(&vault_dir, &mek_bytes, &metadata_name, &metadata_backup_name) {
                Ok(m) => m,
                Err(e) => {
                    let _ = fs::remove_file(&dest_encrypted_path);
                    return Err(e);
                }
            };
            metadata.file_map.insert(obfuscated_name.clone(), file_input.original_name.clone());

            if let Err(e) = save_metadata(&vault_dir, &mek_bytes, &metadata_name, &metadata_backup_name, &metadata) {
                let _ = fs::remove_file(&dest_encrypted_path);
                return Err(e);
            }

            results.push(VaultFileEntry {
                obfuscated_name,
                original_name: file_input.original_name,
            });
        }

        Ok(results)
    }

    pub fn add_file(&self, source_file_path: String, original_name: String) -> Result<String, String> {
        let entries = self.add_files(vec![VaultAddFileInput {
            source_file_path,
            original_name,
        }])?;
        Ok(entries[0].obfuscated_name.clone())
    }

    pub fn delete_file(&self, obfuscated_name: String) -> Result<(), String> {
        let _queue_guard = self.file_queue_lock.lock().unwrap_or_else(|p| p.into_inner());

        let inner = self.lock_inner();
        let mek = inner.mek.as_ref().ok_or("Kassa kilidlidir".to_string())?;
        let metadata_name = inner.metadata_name.clone().ok_or("Kassa kilidlidir".to_string())?;
        let metadata_backup_name = inner
            .metadata_backup_name
            .clone()
            .ok_or("Kassa kilidlidir".to_string())?;
        let vault_dir = inner.vault_dir.clone();
        let mek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(**mek);
        drop(inner);

        let mut metadata = load_metadata(&vault_dir, &mek_bytes, &metadata_name, &metadata_backup_name)?;

        if metadata.file_map.remove(&obfuscated_name).is_none() {
            return Err("Silinmək istənən fayl kassada tapılmadı!".to_string());
        }

        save_metadata(&vault_dir, &mek_bytes, &metadata_name, &metadata_backup_name, &metadata)?;

        let encrypted_file_path = vault_dir.join(&obfuscated_name);
        if encrypted_file_path.exists() {
            fs::remove_file(&encrypted_file_path)
                .map_err(|e| format!("Fiziki fayl silinə bilmədi: {}", e))?;
        }

        Ok(())
    }

    pub fn rename_file(&self, obfuscated_name: String, new_original_name: String) -> Result<(), String> {
        let _queue_guard = self.file_queue_lock.lock().unwrap_or_else(|p| p.into_inner());

        let inner = self.lock_inner();
        let mek = inner.mek.as_ref().ok_or("Kassa kilidlidir".to_string())?;
        let metadata_name = inner.metadata_name.clone().ok_or("Kassa kilidlidir".to_string())?;
        let metadata_backup_name = inner
            .metadata_backup_name
            .clone()
            .ok_or("Kassa kilidlidir".to_string())?;
        let vault_dir = inner.vault_dir.clone();
        let mek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(**mek);
        drop(inner);

        let mut metadata = load_metadata(&vault_dir, &mek_bytes, &metadata_name, &metadata_backup_name)?;

        match metadata.file_map.get_mut(&obfuscated_name) {
            Some(entry) => *entry = new_original_name,
            None => return Err("Adlandırılmaq istənən fayl kassada tapılmadı!".to_string()),
        }

        save_metadata(&vault_dir, &mek_bytes, &metadata_name, &metadata_backup_name, &metadata)?;

        Ok(())
    }

    pub fn list_files(&self) -> Result<Vec<VaultFileEntry>, String> {
        let inner = self.lock_inner();
        let mek = inner.mek.as_ref().ok_or("Kassa kilidlidir".to_string())?;
        let metadata_name = inner.metadata_name.clone().ok_or("Kassa kilidlidir".to_string())?;
        let metadata_backup_name = inner
            .metadata_backup_name
            .clone()
            .ok_or("Kassa kilidlidir".to_string())?;
        let vault_dir = inner.vault_dir.clone();
        let mek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(**mek);
        drop(inner);

        let metadata = load_metadata(&vault_dir, &mek_bytes, &metadata_name, &metadata_backup_name)?;
        Ok(metadata
            .file_map
            .into_iter()
            .map(|(obfuscated_name, original_name)| VaultFileEntry {
                obfuscated_name,
                original_name,
            })
            .collect())
    }

    pub fn list_loose_files(&self) -> Result<Vec<String>, String> {
        let inner = self.lock_inner();
        let mek = inner.mek.as_ref().ok_or("Kassa kilidlidir".to_string())?;
        let metadata_name = inner.metadata_name.clone().ok_or("Kassa kilidlidir".to_string())?;
        let metadata_backup_name = inner
            .metadata_backup_name
            .clone()
            .ok_or("Kassa kilidlidir".to_string())?;
        let vault_dir = inner.vault_dir.clone();
        let mek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(**mek);
        drop(inner);

        let metadata = load_metadata(&vault_dir, &mek_bytes, &metadata_name, &metadata_backup_name)?;
        let known: std::collections::HashSet<&String> = metadata.file_map.keys().collect();

        let mut loose = Vec::new();
        let entries = fs::read_dir(&vault_dir).map_err(|e| e.to_string())?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if name == metadata_name || name == metadata_backup_name {
                continue;
            }
            if known.contains(&name) {
                continue;
            }
            let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
            if len == HEADER_TOTAL_SIZE as u64 {
                continue;
            }
            loose.push(name);
        }
        Ok(loose)
    }

    pub fn extract_files(&self, files: Vec<VaultExtractFileInput>) -> Result<(), String> {
        let _queue_guard = self.file_queue_lock.lock().unwrap_or_else(|p| p.into_inner());

        for file_input in files {
            let inner = self.lock_inner();
            let mek = inner.mek.as_ref().ok_or("Kassa kilidlidir".to_string())?;
            let vault_dir = inner.vault_dir.clone();
            let mek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(**mek);
            drop(inner);

            let source_path = vault_dir.join(&file_input.obfuscated_name);
            if !source_path.exists() {
                return Err(format!("Fayl kassada tapılmadı: {}", file_input.obfuscated_name));
            }

            decrypt_file_parallel(
                &source_path,
                Path::new(&file_input.dest_path),
                &mek_bytes,
            )?;
        }

        Ok(())
    }

    pub fn extract_file_to_path(&self, obfuscated_name: String, dest_path: String) -> Result<(), String> {
        self.extract_files(vec![VaultExtractFileInput {
            obfuscated_name,
            dest_path,
        }])
    }

    pub fn extract_file_to_bytes(&self, obfuscated_name: String) -> Result<Vec<u8>, String> {
        let _queue_guard = self.file_queue_lock.lock().unwrap_or_else(|p| p.into_inner());

        let inner = self.lock_inner();
        let mek = inner.mek.as_ref().ok_or("Kassa kilidlidir".to_string())?;
        let vault_dir = inner.vault_dir.clone();
        let mek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(**mek);
        drop(inner);

        let source_path = vault_dir.join(&obfuscated_name);
        if !source_path.exists() {
            return Err("Fayl kassada tapılmadı".to_string());
        }
        decrypt_file_parallel_to_bytes(&source_path, &mek_bytes)
    }

    pub fn open_stream(&self, obfuscated_name: String) -> Result<VaultFileStream, String> {
        let inner = self.lock_inner();
        if inner.mek.is_none() {
            return Err("Kassa kilidlidir".to_string());
        }
        let vault_dir = inner.vault_dir.clone();
        drop(inner);

        VaultFileStream::open(self.inner.clone(), vault_dir, obfuscated_name)
    }
}

// ---------------------------------------------------------------------
// VaultFileStream — Yuşaq, paralel, kilidsiz video axını oxuyucusu
// ---------------------------------------------------------------------

struct VaultFileStreamInner {
    file_path: PathBuf,
    vault_inner: Arc<Mutex<VaultInner>>,
    nonce_prefix: [u8; NONCE_SIZE],
    chunk_count: u64,
    last_chunk_encrypted_size: u64,
    total_decrypted_size: u64,
}

#[derive(Clone)]
pub struct VaultFileStream {
    inner: Arc<VaultFileStreamInner>,
}

impl VaultFileStream {
    fn open(
        vault_inner: Arc<Mutex<VaultInner>>,
        vault_dir: PathBuf,
        obfuscated_name: String,
    ) -> Result<Self, String> {
        let file_path = vault_dir.join(&obfuscated_name);
        if !file_path.exists() {
            return Err("Fayl kassada tapılmadı".to_string());
        }

        let file_len = fs::metadata(&file_path)
            .map_err(|e| e.to_string())?
            .len();

        if file_len < NONCE_SIZE as u64 {
            return Err("Fayl zədəlidir (çox kiçikdir)".to_string());
        }

        let mut file = File::open(&file_path).map_err(|e| e.to_string())?;
        let mut nonce_prefix = [0u8; NONCE_SIZE];
        file.read_exact(&mut nonce_prefix)
            .map_err(|_| "Nonce oxuna bilmədi".to_string())?;

        let enc_payload_size = file_len - NONCE_SIZE as u64;
        let full_chunks = enc_payload_size / ENCRYPTED_CHUNK_SIZE as u64;
        let last_enc_rem = enc_payload_size % ENCRYPTED_CHUNK_SIZE as u64;

        let (chunk_count, last_chunk_encrypted_size, last_chunk_plaintext_size) =
            if last_enc_rem == 0 {
                (full_chunks, ENCRYPTED_CHUNK_SIZE as u64, CHUNK_SIZE as u64)
            } else {
                let last_pt = last_enc_rem.saturating_sub(TAG_SIZE as u64);
                (full_chunks + 1, last_enc_rem, last_pt)
            };

        if chunk_count == 0 {
            return Err("Fayl boşdur".to_string());
        }

        let total_decrypted_size =
            (chunk_count - 1) * CHUNK_SIZE as u64 + last_chunk_plaintext_size;

        Ok(VaultFileStream {
            inner: Arc::new(VaultFileStreamInner {
                file_path,
                vault_inner,
                nonce_prefix,
                chunk_count,
                last_chunk_encrypted_size,
                total_decrypted_size,
            }),
        })
    }

    /// Deşifrə edilmiş ümumi fayl ölçüsü (bayt).
    /// HTTP `Content-Length` başlığı üçün istifadə olunur.
    pub fn total_size(&self) -> u64 {
        self.inner.total_decrypted_size
    }

    /// Bir parçanın plaintext ölçüsü (4 MiB).
    pub fn chunk_size(&self) -> u64 {
        CHUNK_SIZE as u64
    }

    /// Tək parçanı oxuyub deşifrə edir. Kilidsiz olduğu üçün concurrent çağırışlar seriallaşmır.
    fn read_and_decrypt_chunk(&self, chunk_index: u64, key_bytes: &[u8; 32]) -> Result<Vec<u8>, String> {
        if chunk_index >= self.inner.chunk_count {
            return Err(format!(
                "Parça indeksi ({}) həddindən artıqdır (cəmi {} parça)",
                chunk_index, self.inner.chunk_count
            ));
        }

        let is_last = chunk_index == self.inner.chunk_count - 1;
        let offset = NONCE_SIZE as u64 + chunk_index * ENCRYPTED_CHUNK_SIZE as u64;

        let enc_len = if is_last {
            self.inner.last_chunk_encrypted_size as usize
        } else {
            ENCRYPTED_CHUNK_SIZE
        };

        let mut file = File::open(&self.inner.file_path).map_err(|e| e.to_string())?;
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;

        let mut enc_buf = vec![0u8; enc_len];
        file.read_exact(&mut enc_buf)
            .map_err(|e| format!("Parça oxuna bilmədi (indeks {}): {}", chunk_index, e))?;

        let nonce_bytes = derive_stream_nonce(&self.inner.nonce_prefix, chunk_index, is_last);

        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let aead = Aes256Gcm::new(key);
        let nonce = GcmNonce::from_slice(&nonce_bytes);

        aead.decrypt(nonce, enc_buf.as_slice())
            .map_err(|e| format!("Parça deşifrəsi uğursuz oldu (indeks {}): {:?}", chunk_index, e))
    }

    /// Göstərilən parça indeksini (`chunk_index`) birbaşa diskdən oxuyub deşifrə edir.
    pub fn read_chunk(&self, chunk_index: u64) -> Result<Vec<u8>, String> {
        let key_bytes = {
            let vault = self.inner.vault_inner.lock().unwrap_or_else(|p| p.into_inner());
            match vault.mek.as_ref() {
                Some(k) => Zeroizing::new(**k),
                None => return Err("Kassa kilidlidir və ya açarlar artıq sıfırlanıb".to_string()),
            }
        };

        self.read_and_decrypt_chunk(chunk_index, &key_bytes)
    }

    /// HTTP `Range: bytes=start-end` sorğuları üçün video pleyerlərə xüsusi optimizasiya.
    /// Dəqiq tələb olunan bayt aralığını oxuyur və lazım olan parçaları Rayon ilə paralel deşifrə edir.
    pub fn read_range(&self, start_byte: u64, length: u64) -> Result<Vec<u8>, String> {
        if length == 0 {
            return Ok(Vec::new());
        }

        let total_size = self.inner.total_decrypted_size;
        if start_byte >= total_size {
            return Err("Başlanğıc baytı fayl ölçüsündən böyükdür".to_string());
        }

        let end_byte = (start_byte + length).min(total_size);
        let actual_len = (end_byte - start_byte) as usize;

        let start_chunk = start_byte / CHUNK_SIZE as u64;
        let end_chunk = (end_byte - 1) / CHUNK_SIZE as u64;

        let key_bytes = {
            let vault = self.inner.vault_inner.lock().unwrap_or_else(|p| p.into_inner());
            match vault.mek.as_ref() {
                Some(k) => Zeroizing::new(**k),
                None => return Err("Kassa kilidlidir və ya açarlar artıq sıfırlanıb".to_string()),
            }
        };

        init_thread_pool();

        let chunks_range: Vec<u64> = (start_chunk..=end_chunk).collect();

        // Çoxsaylı parçaları Rayon işçiləri ilə paralel deşifrə edirik
        let decrypted_chunks_res: Result<Vec<(u64, Vec<u8>)>, String> = chunks_range
            .into_par_iter()
            .map(|chunk_index| {
                let chunk_data = self.read_and_decrypt_chunk(chunk_index, &key_bytes)?;
                Ok((chunk_index, chunk_data))
            })
            .collect();

        let decrypted_chunks = decrypted_chunks_res?;

        let mut result = Vec::with_capacity(actual_len);
        for (chunk_index, chunk_bytes) in decrypted_chunks {
            let chunk_start_byte = chunk_index * CHUNK_SIZE as u64;

            let slice_start = if start_byte > chunk_start_byte {
                (start_byte - chunk_start_byte) as usize
            } else {
                0
            };

            let chunk_end_byte = chunk_start_byte + chunk_bytes.len() as u64;
            let slice_end = if end_byte < chunk_end_byte {
                (end_byte - chunk_start_byte) as usize
            } else {
                chunk_bytes.len()
            };

            if slice_start < slice_end && slice_start < chunk_bytes.len() {
                let actual_slice_end = slice_end.min(chunk_bytes.len());
                result.extend_from_slice(&chunk_bytes[slice_start..actual_slice_end]);
            }
        }

        Ok(result)
    }
}

// ---------------------------------------------------------------------
// Vahid testlər
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_thread_pool_init_idempotent() {
        init_thread_pool();
        init_thread_pool();
    }

    #[test]
    fn test_derive_stream_nonce() {
        let prefix = [1, 2, 3, 4, 5, 6, 7];
        let n0 = derive_stream_nonce(&prefix, 0, false);
        assert_eq!(&n0[..7], &prefix);
        assert_eq!(&n0[7..11], &[0, 0, 0, 0]);
        assert_eq!(n0[11], 0);

        let n1_last = derive_stream_nonce(&prefix, 42, true);
        assert_eq!(&n1_last[..7], &prefix);
        assert_eq!(&n1_last[7..11], &42u32.to_be_bytes());
        assert_eq!(n1_last[11], 1);
    }

    #[test]
    fn test_parallel_encryption_decryption_various_sizes() {
        let dir = std::env::temp_dir().join("xenonypt_test_parallel");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let test_sizes = [
            0,
            100,
            1024 * 1024,
            CHUNK_SIZE,
            CHUNK_SIZE + 1024,
            CHUNK_SIZE * 2 + 500,
        ];

        for (i, size) in test_sizes.iter().enumerate() {
            let original_data: Vec<u8> = (0..*size).map(|b| (b % 251) as u8).collect();
            let src_path = dir.join(format!("src_{}.bin", i));
            let enc_path = dir.join(format!("enc_{}.bin", i));
            let dec_path = dir.join(format!("dec_{}.bin", i));

            {
                let mut f = File::create(&src_path).unwrap();
                f.write_all(&original_data).unwrap();
            }

            encrypt_file_parallel(&src_path, &enc_path, &key).unwrap();

            decrypt_file_parallel(&enc_path, &dec_path, &key).unwrap();
            let decrypted_file_bytes = fs::read(&dec_path).unwrap();
            assert_eq!(original_data, decrypted_file_bytes, "Fayl ölçüsü {} üçün uyğunsuzluq", size);

            let decrypted_bytes = decrypt_file_parallel_to_bytes(&enc_path, &key).unwrap();
            assert_eq!(original_data, decrypted_bytes, "Bytes deşifrəsi {} üçün uyğunsuzluq", size);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_stream_read_range_parallel() {
        let dir = std::env::temp_dir().join("xenonypt_test_stream_range");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let total_size = CHUNK_SIZE * 3 + 1024;
        let original_data: Vec<u8> = (0..total_size).map(|b| (b % 251) as u8).collect();

        let src_path = dir.join("test_vid.mp4");
        let enc_name = "enc_vid".to_string();
        let enc_path = dir.join(&enc_name);

        fs::write(&src_path, &original_data).unwrap();
        encrypt_file_parallel(&src_path, &enc_path, &key).unwrap();

        let stream = VaultFileStream::open(
            Arc::new(Mutex::new(VaultInner {
                vault_dir: dir.clone(),
                mek: Some(Zeroizing::new(key)),
                metadata_name: None,
                metadata_backup_name: None,
            })),
            dir.clone(),
            enc_name,
        )
        .unwrap();

        let start = CHUNK_SIZE as u64 - 500;
        let len = CHUNK_SIZE as u64 * 2 + 1000;
        let range_bytes = stream.read_range(start, len).unwrap();

        let expected = &original_data[start as usize..(start + len) as usize];
        assert_eq!(range_bytes, expected);

        let _ = fs::remove_dir_all(&dir);
    }
}
