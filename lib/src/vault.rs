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

use aes_gcm::aead::stream::{DecryptorBE32, EncryptorBE32};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::Nonce as StreamNonce;
use aes_gcm::{Aes256Gcm, Key, Nonce as GcmNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Error as IoError, ErrorKind, Read, Result as IoResult, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

const CHUNK_SIZE: usize = 1024 * 1024;
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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct VaultMetadata {
    file_map: HashMap<String, String>,
}

// ---------------------------------------------------------------------
// Kömrkçi funksiyalar
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

    // Müvəqqəti fayla yazıb sonra atomik "rename" edirik ki, yazı
    // yarımçıq kəsilərsə (məs. tətbiq qəflətən bağlansa) mövcud fayl
    // korlanmasın.
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
                    break;
                }
            }
        }
        dest_file.flush().map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp_path, dest_path).map_err(|e| e.to_string())?;
    Ok(())
}

fn encrypt_file_large(source_path: &Path, dest_path: &Path, key_bytes: &[u8; 32]) -> Result<(), String> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = StreamNonce::from_slice(&nonce_bytes);

    let aead = Aes256Gcm::new(key);
    let mut encryptor = EncryptorBE32::from_aead(aead, nonce);

    let source_file = File::open(source_path).map_err(|e| e.to_string())?;
    let mut source_file = BufReader::new(source_file);

    let tmp_path = tmp_path_for(dest_path);
    {
        let dest_file = File::create(&tmp_path).map_err(|e| e.to_string())?;
        let mut dest_file = BufWriter::new(dest_file);
        dest_file.write_all(&nonce_bytes).map_err(|e| e.to_string())?;

        let mut current_buffer = vec![0u8; CHUNK_SIZE];
        let mut next_buffer = vec![0u8; CHUNK_SIZE];

        let mut current_bytes =
            read_exact_up_to_end(&mut source_file, &mut current_buffer).map_err(|e| e.to_string())?;

        loop {
            let next_bytes =
                read_exact_up_to_end(&mut source_file, &mut next_buffer).map_err(|e| e.to_string())?;

            if next_bytes == 0 {
                let encrypted_chunk = encryptor
                    .encrypt_last(&current_buffer[..current_bytes])
                    .map_err(|e| format!("{:?}", e))?;
                dest_file.write_all(&encrypted_chunk).map_err(|e| e.to_string())?;
                break;
            } else {
                let encrypted_chunk = encryptor
                    .encrypt_next(&current_buffer[..current_bytes])
                    .map_err(|e| format!("{:?}", e))?;
                dest_file.write_all(&encrypted_chunk).map_err(|e| e.to_string())?;
                std::mem::swap(&mut current_buffer, &mut next_buffer);
                current_bytes = next_bytes;
            }
        }
        dest_file.flush().map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp_path, dest_path).map_err(|e| e.to_string())?;
    Ok(())
}

fn tmp_path_for(dest_path: &Path) -> PathBuf {
    let mut tmp = dest_path.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

/// Şifrəli faylı oxuyan stream reader. Xəta baş verdikdə "poisoned"
/// vəziyyətinə keçir və bundan sonrakı bütün `read()` çağırışları
/// sükutla EOF (Ok(0)) yox, EYNİ xətanı qaytarır — beləliklə
/// korlanmış/manipulyasiya olunmuş fayl heç vaxt "uğurla tam oxundu"
/// kimi yozulmur.
struct EncryptedFileReader {
    file: BufReader<File>,
    decryptor: Option<DecryptorBE32<Aes256Gcm>>,
    current_buffer: Vec<u8>,
    next_buffer: Vec<u8>,
    current_len: usize,
    decrypted_chunk: Vec<u8>,
    chunk_cursor: usize,
    is_finished: bool,
    poison: Option<String>,
}

impl EncryptedFileReader {
    fn new(source_path: &Path, key_bytes: &[u8; 32]) -> Result<Self, String> {
        let file = File::open(source_path).map_err(|e| e.to_string())?;
        let mut file = BufReader::new(file);

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        file.read_exact(&mut nonce_bytes)
            .map_err(|_| "Fayl başlığı oxuna bilmədi (fayl zədəli ola bilər)".to_string())?;
        let nonce = StreamNonce::from_slice(&nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let aead = Aes256Gcm::new(key);
        let decryptor = DecryptorBE32::from_aead(aead, nonce);

        let mut current_buffer = vec![0u8; ENCRYPTED_CHUNK_SIZE];
        let next_buffer = vec![0u8; ENCRYPTED_CHUNK_SIZE];

        let current_len =
            read_exact_up_to_end(&mut file, &mut current_buffer).map_err(|e| e.to_string())?;

        if current_len == 0 {
            return Err("Fayl boşdur və ya zədəlidir".into());
        }

        Ok(Self {
            file,
            decryptor: Some(decryptor),
            current_buffer,
            next_buffer,
            current_len,
            decrypted_chunk: Vec::new(),
            chunk_cursor: 0,
            is_finished: false,
            poison: None,
        })
    }

    fn fetch_next_chunk(&mut self) -> IoResult<bool> {
        if let Some(msg) = &self.poison {
            return Err(IoError::new(ErrorKind::InvalidData, msg.clone()));
        }
        if self.is_finished {
            return Ok(false);
        }

        let decryptor = match self.decryptor.as_mut() {
            Some(d) => d,
            None => return Ok(false),
        };

        let next_len = read_exact_up_to_end(&mut self.file, &mut self.next_buffer)?;

        if next_len == 0 {
            let final_decryptor = self.decryptor.take().unwrap();
            match final_decryptor.decrypt_last(&self.current_buffer[..self.current_len]) {
                Ok(decrypted) => {
                    self.decrypted_chunk = decrypted;
                    self.chunk_cursor = 0;
                    self.is_finished = true;
                    Ok(true)
                }
                Err(e) => {
                    let msg = format!("Deşifrələmə xətası (son parça): {:?}", e);
                    self.poison = Some(msg.clone());
                    self.is_finished = true;
                    Err(IoError::new(ErrorKind::InvalidData, msg))
                }
            }
        } else {
            match decryptor.decrypt_next(&self.current_buffer[..self.current_len]) {
                Ok(decrypted) => {
                    self.decrypted_chunk = decrypted;
                    self.chunk_cursor = 0;
                    std::mem::swap(&mut self.current_buffer, &mut self.next_buffer);
                    self.current_len = next_len;
                    Ok(true)
                }
                Err(e) => {
                    let msg = format!("Deşifrələmə xətası: {:?}", e);
                    self.decryptor = None;
                    self.poison = Some(msg.clone());
                    Err(IoError::new(ErrorKind::InvalidData, msg))
                }
            }
        }
    }
}

impl Read for EncryptedFileReader {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if let Some(msg) = &self.poison {
            return Err(IoError::new(ErrorKind::InvalidData, msg.clone()));
        }
        if self.chunk_cursor >= self.decrypted_chunk.len() {
            let has_more = self.fetch_next_chunk()?;
            if !has_more {
                return Ok(0);
            }
        }
        let available = self.decrypted_chunk.len() - self.chunk_cursor;
        let to_copy = std::cmp::min(buf.len(), available);
        buf[..to_copy].copy_from_slice(&self.decrypted_chunk[self.chunk_cursor..self.chunk_cursor + to_copy]);
        self.chunk_cursor += to_copy;
        Ok(to_copy)
    }
}

fn decrypt_file_to_writer(source_path: &Path, key_bytes: &[u8; 32], writer: &mut impl Write) -> Result<(), String> {
    let mut reader = EncryptedFileReader::new(source_path, key_bytes)?;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => writer.write_all(&buffer[..n]).map_err(|e| e.to_string())?,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

fn decrypt_file_to_bytes(source_path: &Path, key_bytes: &[u8; 32]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    decrypt_file_to_writer(source_path, key_bytes, &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------
// Metadata oxu/yaz (backup fallback DÜZƏLDİLİB)
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
        // DÜZƏLİŞ: əsas fayl mövcuddur, amma KORLANMIŞ ola bilər.
        // Bu halda sükutla boş metadata qaytarmaq əvəzinə, backup-ı sınayırıq.
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

    // Nə əsas, nə də backup var — yeni/boş kassa.
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
    // encrypt_bytes_to_file artıq tmp+rename ilə atomik yazır.
    encrypt_bytes_to_file(&json_bytes, &metadata_path, mek)?;

    Ok(())
}

// ---------------------------------------------------------------------
// FRB-ə açılan ictimai (public) API: VaultHandle
// ---------------------------------------------------------------------

struct VaultInner {
    vault_dir: PathBuf,
    /// MEK yalnız burada saxlanılır və heç vaxt Dart tərəfinə
    /// ötürülmür. `None` olması kassanın kilidli (locked) olduğunu bildirir.
    mek: Option<Zeroizing<[u8; 32]>>,
    /// Metadata və ehtiyat metadata fayllarının təsadüfi adları. Bunlar
    /// artıq sabit ("metadata.dat") deyil — başlıqdan deşifrə olunaraq
    /// gəlir, ona görə kilid açılana qədər `None`-dur.
    metadata_name: Option<String>,
    metadata_backup_name: Option<String>,
}

impl Drop for VaultInner {
    fn drop(&mut self) {
        // Zeroizing artıq drop zamanı özünü sıfırlayır, bu əlavə təminatdır.
        if let Some(mek) = self.mek.as_mut() {
            mek.zeroize();
        }
    }
}

/// FRB tərəfindən Dart-da opaque klas kimi generasiya olunacaq handle.
/// Açar bytes-ları heç vaxt bu strukturdan kənara (Dart-a) çıxmır.
#[derive(Clone)]
pub struct VaultHandle {
    inner: Arc<Mutex<VaultInner>>,
}

impl VaultHandle {
    fn lock_inner(&self) -> std::sync::MutexGuard<'_, VaultInner> {
        // Mutex "poisoned" ola bilsə də (panic zamanı), FRB async worker-lərində
        // tətbiqi çökdürməmək üçün into_inner ilə davam edirik.
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Yeni kassa yaradır və birbaşa açılmış (unlocked) handle qaytarır.
    /// `vault_dir` mövcud deyilsə yaradılır.
    pub fn create_new(vault_dir: String, password: String) -> Result<VaultHandle, String> {
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

        // Başlıq, metadata və ehtiyat metadata faylları üçün təsadüfi,
        // uzantısız adlar — heç biri "header"/"metadata" kimi tanınmır.
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
        // master_key_bytes bu nöqtədən sonra artıq lazım deyil; Zeroizing
        // scope bitəndə avtomatik sıfırlanacaq.

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
        })
    }

    /// Mövcud kassanı parolla açır. Başlıq faylının adı sabit deyil,
    /// ona görə HEADER_TOTAL_SIZE ölçüsünə uyğun bütün faylları
    /// namizəd kimi sınayırıq — həqiqi başlıq parolla uğurla deşifrə
    /// olunan yeganə (praktikada) namizəddir; GCM autentifikasiyası
    /// sayəsində uyğun olmayan fayl/parol cütü sükutla "uğurlu" sayılmır.
    pub fn unlock(vault_dir: String, password: String) -> Result<VaultHandle, String> {
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
                Err(_) => continue, // bu fayl bizim başlığımız deyil, ya da parol səhvdir
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
            });
        }

        Err("Yanlış şifrə və ya zədələnmiş kassa!".to_string())
    }

    /// Verilən qovluqda kassa mövcud görünürmü (HEADER_TOTAL_SIZE ölçülü
    /// heç olmasa bir fayl varmı) — parol tələb etməyən, sırf UI üçün
    /// köməkçi yoxlama (Dart tərəfi bunu "Aç" / "Yarat" ekranları
    /// arasında seçim üçün istifadə edə bilər). Yanlış müsbət nəzəri
    /// mümkündür (təsadüfən eyni ölçüdə fayl), amma `unlock` bunu real
    /// parol yoxlaması ilə təsdiq edəcək.
    pub fn exists(vault_dir: String) -> bool {
        header_candidate_exists(&PathBuf::from(&vault_dir)).unwrap_or(false)
    }

    /// Açarı yaddaşdan sıfırlayır. Bundan sonra handle "locked" olur və
    /// digər metodlar xəta qaytaracaq. Dart tərəfdə istifadəçi tətbiqi
    /// arxa plana atanda / kassadan çıxanda çağırmaq tövsiyə olunur.
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

    /// Fayl əlavə edir. Xəta halında diskdə yetim (orphan) şifrəli fayl
    /// QALMIR — DÜZƏLİŞ: uğursuz metadata yazılışından sonra əlavə edilmiş
    /// şifrəli fayl geri silinir.
    pub fn add_file(&self, source_file_path: String, original_name: String) -> Result<String, String> {
        let inner = self.lock_inner();
        let mek = inner.mek.as_ref().ok_or("Kassa kilidlidir".to_string())?;
        let metadata_name = inner.metadata_name.clone().ok_or("Kassa kilidlidir".to_string())?;
        let metadata_backup_name = inner
            .metadata_backup_name
            .clone()
            .ok_or("Kassa kilidlidir".to_string())?;
        let vault_dir = inner.vault_dir.clone();
        let mek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(**mek);
        drop(inner); // uzun sürən şifrələmə zamanı mutex-i tutmuruq

        let obfuscated_name = random_hex_name();
        let dest_encrypted_path = vault_dir.join(&obfuscated_name);

        encrypt_file_large(Path::new(&source_file_path), &dest_encrypted_path, &mek_bytes)?;

        let mut metadata = match load_metadata(&vault_dir, &mek_bytes, &metadata_name, &metadata_backup_name) {
            Ok(m) => m,
            Err(e) => {
                let _ = fs::remove_file(&dest_encrypted_path);
                return Err(e);
            }
        };
        metadata.file_map.insert(obfuscated_name.clone(), original_name);

        if let Err(e) = save_metadata(&vault_dir, &mek_bytes, &metadata_name, &metadata_backup_name, &metadata) {
            // DÜZƏLİŞ: yetim faylı təmizləyirik ki, kassa ilə metadata
            // sinxronsuz qalmasın.
            let _ = fs::remove_file(&dest_encrypted_path);
            return Err(e);
        }

        Ok(obfuscated_name)
    }

    pub fn delete_file(&self, obfuscated_name: String) -> Result<(), String> {
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

        // Əvvəlcə metadata yazılır (mənbə həqiqət) — yalnız uğurlu olsa
        // fiziki fayl silinir. Beləcə proses arada kəsilsə belə, ən pis
        // halda "istifadə olunmayan fayl disk üzərində qalır", amma
        // metadata heç vaxt mövcud olmayan fayla işarə etmir.
        save_metadata(&vault_dir, &mek_bytes, &metadata_name, &metadata_backup_name, &metadata)?;

        let encrypted_file_path = vault_dir.join(&obfuscated_name);
        if encrypted_file_path.exists() {
            fs::remove_file(&encrypted_file_path)
                .map_err(|e| format!("Fiziki fayl silinə bilmədi: {}", e))?;
        }

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

    /// Kassa qovluğunda duran, amma hələ kassaya əlavə edilməmiş (yəni
    /// metadata-da qeydi olmayan) sadə mətn fayllarını tapır. Bunlara
    /// header/metadata/ehtiyat-metadata faylları və artıq kassaya aid olan
    /// şifrəli fayllar daxil edilmir — yalnız "yad" plaintext fayllar
    /// qaytarılır. Dart tərəfi bu siyahını istifadəçiyə göstərib, hər
    /// birini kassaya əlavə etmək (add_file) təklif edə bilər.
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

        // Başlıq özü də bu qovluqdadır, amma onun adını bilmirik (təsadüfi
        // hex ad, MEK-in özündə saxlanılmır) — ona görə HEADER_TOTAL_SIZE
        // ölçüsünə uyğun gələn faylları da "yad" siyahısından çıxarırıq ki,
        // istifadəçiyə səhvən başlığı "plaintext fayl" kimi göstərməyək.
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

    /// Faylı deşifrə edib GÖSTƏRİLƏN yola yazır (böyük fayllar üçün
    /// tövsiyə olunan üsul — bütün məzmun Dart bridge-i üzərindən
    /// keçmir, birbaşa diskə axır).
    pub fn extract_file_to_path(&self, obfuscated_name: String, dest_path: String) -> Result<(), String> {
        let inner = self.lock_inner();
        let mek = inner.mek.as_ref().ok_or("Kassa kilidlidir".to_string())?;
        let vault_dir = inner.vault_dir.clone();
        let mek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(**mek);
        drop(inner);

        let source_path = vault_dir.join(&obfuscated_name);
        if !source_path.exists() {
            return Err("Fayl kassada tapılmadı".to_string());
        }

        let tmp_out = tmp_path_for(Path::new(&dest_path));
        {
            let out_file = File::create(&tmp_out).map_err(|e| e.to_string())?;
            let mut out_file = BufWriter::new(out_file);
            decrypt_file_to_writer(&source_path, &mek_bytes, &mut out_file)?;
            out_file.flush().map_err(|e| e.to_string())?;
        }
        fs::rename(&tmp_out, &dest_path).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Kiçik fayllar üçün: deşifrə edilmiş bytes-ı birbaşa qaytarır.
    /// Böyük fayllarda `extract_file_to_path` istifadə edin.
    pub fn extract_file_to_bytes(&self, obfuscated_name: String) -> Result<Vec<u8>, String> {
        let inner = self.lock_inner();
        let mek = inner.mek.as_ref().ok_or("Kassa kilidlidir".to_string())?;
        let vault_dir = inner.vault_dir.clone();
        let mek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(**mek);
        drop(inner);

        let source_path = vault_dir.join(&obfuscated_name);
        if !source_path.exists() {
            return Err("Fayl kassada tapılmadı".to_string());
        }
        decrypt_file_to_bytes(&source_path, &mek_bytes)
    }
}