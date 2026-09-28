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
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Error as IoError, ErrorKind, Read, Result as IoResult, Write};
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

    // Heterogen nüvələr (Big.LITTLE / performans və səmərəlilik nüvələri) üçün
    // hər partiyaya kifayət qədər parça veririk ki, Rayon-un work-stealing
    // mexanizmi dinamik olaraq sürətli nüvələri işlə yükləsin.
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

        // Rayon work-stealing: parçalar mövcud işçi thread-lər arasında paralel şifrələnir
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

#[allow(dead_code)]
fn encrypt_file_large(source_path: &Path, dest_path: &Path, key_bytes: &[u8; 32]) -> Result<(), String> {
    encrypt_file_parallel(source_path, dest_path, key_bytes)
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
#[allow(dead_code)]
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

#[allow(dead_code)]
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

    // Heterogen nüvələr üçün Rayon work-stealing partiya ölçüsü
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

        // Rayon work-stealing: parçalar dinamik olaraq işçi thread-lər arasında deşifrələnir
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

#[allow(dead_code)]
fn decrypt_file_to_writer(source_path: &Path, key_bytes: &[u8; 32], writer: &mut impl Write) -> Result<(), String> {
    decrypt_file_parallel_to_writer(source_path, key_bytes, writer)
}

fn decrypt_file_to_bytes(source_path: &Path, key_bytes: &[u8; 32]) -> Result<Vec<u8>, String> {
    decrypt_file_parallel_to_bytes(source_path, key_bytes)
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
    file_queue_lock: Arc<Mutex<()>>,
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
            file_queue_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Mövcud kassanı parolla açır. Başlıq faylının adı sabit deyil,
    /// ona görə HEADER_TOTAL_SIZE ölçüsünə uyğun bütün faylları
    /// namizəd kimi sınayırıq — həqiqi başlıq parolla uğurla deşifrə
    /// olunan yeganə (praktikada) namizəddir; GCM autentifikasiyası
    /// sayəsində uyğun olmayan fayl/parol cütü sükutla "uğurlu" sayılmır.
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
                file_queue_lock: Arc::new(Mutex::new(())),
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

    /// Növbədən faylları bir-bir ardıcıl şifrələyib kassaya əlavə edir.
    /// Hər fərdi fayl üçün onun parçaları Rayon ilə paralel emal olunur.
    /// Metadata hər faylın tamamlanmasından sonra ardıcıl və təhlükəsiz yenilənir.
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
            drop(inner); // şifrələmə zamanı inner mutex-i tutmuruq

            let obfuscated_name = random_hex_name();
            let dest_encrypted_path = vault_dir.join(&obfuscated_name);

            // Rayon work-stealing ilə parçaların paralel şifrələnməsi
            if let Err(e) = encrypt_file_parallel(
                Path::new(&file_input.source_file_path),
                &dest_encrypted_path,
                &mek_bytes,
            ) {
                let _ = fs::remove_file(&dest_encrypted_path);
                return Err(e);
            }

            // Metadata-nın ardıcıl və təhlükəsiz yenilənməsi
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

    /// Tək fayl əlavə edir. Növbə mexanizmi vasitəsilə ardıcıl icra olunur,
    /// parçaları Rayon ilə paralel şifrələnir.
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

    /// Növbədən faylları bir-bir ardıcıl deşifrə edib diskə çıxarır.
    /// Hər fərdi fayl üçün onun parçaları Rayon ilə paralel deşifrələnir.
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

            // Rayon work-stealing ilə parçaların paralel deşifrələnməsi
            decrypt_file_parallel(
                &source_path,
                Path::new(&file_input.dest_path),
                &mek_bytes,
            )?;
        }

        Ok(())
    }

    /// Faylı deşifrə edib GÖSTƏRİLƏN yola yazır. Növbə mexanizmi vasitəsilə
    /// ardıcıl icra olunur, parçaları Rayon ilə paralel deşifrələnir.
    pub fn extract_file_to_path(&self, obfuscated_name: String, dest_path: String) -> Result<(), String> {
        self.extract_files(vec![VaultExtractFileInput {
            obfuscated_name,
            dest_path,
        }])
    }

    /// Kiçik fayllar üçün: deşifrə edilmiş bytes-ı birbaşa qaytarır.
    /// Növbə mexanizmi vasitəsilə ardıcıl icra olunur, parçaları Rayon ilə paralel deşifrələnir.
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

    /// Böyük fayllar (xüsusən videolar) üçün: faylı tam olaraq yaddaşa
    /// yükləmədən, hər dəfə yalnız tələb olunan parçanı (`chunk`) deşifrə
    /// etmək imkanı verən `VaultFileStream` handle-i qaytarır.
    /// Dart tərəfi bu handle-i localhost HTTP server vasitəsilə video
    /// pleyerə axın (streaming) üçün istifadə edə bilər.
    pub fn open_stream(&self, obfuscated_name: String) -> Result<VaultFileStream, String> {
        let inner = self.lock_inner();
        let mek = inner.mek.as_ref().ok_or("Kassa kilidlidir".to_string())?;
        let vault_dir = inner.vault_dir.clone();
        let mek_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(**mek);
        drop(inner);

        VaultFileStream::open(vault_dir, obfuscated_name, mek_bytes)
    }
}

// ---------------------------------------------------------------------
// VaultFileStream — hər parçanı ayrıca, birbaşa disk oxuyub deşifrə edir
// ---------------------------------------------------------------------

struct VaultFileStreamInner {
    file_path: PathBuf,
    /// Faylın əvvəlindən oxunan 7 baytlıq nonce prefiksi (StreamBE32 formatı).
    nonce_prefix: [u8; NONCE_SIZE],
    mek_bytes: Zeroizing<[u8; 32]>,
    /// Şifrəli fayldakı ümumi parça sayı.
    chunk_count: u64,
    /// Son parçanın şifrəli (disk üzərindəki) bayt sayı.
    last_chunk_encrypted_size: u64,
    /// Deşifrə edilmiş (plaintext) ümumi ölçü — HTTP Content-Length üçün lazımdır.
    total_decrypted_size: u64,
}

impl Drop for VaultFileStreamInner {
    fn drop(&mut self) {
        self.mek_bytes.zeroize();
    }
}

/// FRB tərəfindən Dart-da opaque klas kimi generasiya olunacaq stream handle.
/// MEK bu strukturda qalır və Dart tərəfinə açıq ötürülmür.
#[derive(Clone)]
pub struct VaultFileStream {
    inner: Arc<Mutex<VaultFileStreamInner>>,
}

impl VaultFileStream {
    fn open(vault_dir: PathBuf, obfuscated_name: String, mek_bytes: Zeroizing<[u8; 32]>) -> Result<Self, String> {
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

        // Faylın əvvəlindən nonce prefiksini oxu
        let mut nonce_prefix = [0u8; NONCE_SIZE];
        {
            let mut f = File::open(&file_path).map_err(|e| e.to_string())?;
            f.read_exact(&mut nonce_prefix)
                .map_err(|_| "Nonce oxuna bilmədi".to_string())?;
        }

        // Şifrəli payload ölçüsünü və parça sayını hesabla.
        //
        // StreamBE32 formatında hər parça (encrypt_next) tam ENCRYPTED_CHUNK_SIZE
        // baytdır; yalnız son parça (encrypt_last) daha kiçik ola bilər.
        //
        // encrypted_payload_size = file_len - NONCE_SIZE
        // full_chunks  = encrypted_payload_size / ENCRYPTED_CHUNK_SIZE
        // last_enc_rem = encrypted_payload_size % ENCRYPTED_CHUNK_SIZE
        //
        // Əgər qalıq 0-dırsa, bütün parçalar tam ölçülüdür; son parçanın
        // plaintext ölçüsü tam CHUNK_SIZE-dir. Əks halda, son şifrəli
        // parça `last_enc_rem` baytdır və plaintext ölçüsü `last_enc_rem - TAG_SIZE`-dir.
        let enc_payload_size = file_len - NONCE_SIZE as u64;
        let full_chunks = enc_payload_size / ENCRYPTED_CHUNK_SIZE as u64;
        let last_enc_rem = enc_payload_size % ENCRYPTED_CHUNK_SIZE as u64;

        let (chunk_count, last_chunk_encrypted_size, last_chunk_plaintext_size) =
            if last_enc_rem == 0 {
                // Bütün parçalar tam ölçülüdür
                (full_chunks, ENCRYPTED_CHUNK_SIZE as u64, CHUNK_SIZE as u64)
            } else {
                // Son parça daha kiçikdir
                let last_pt = last_enc_rem.saturating_sub(TAG_SIZE as u64);
                (full_chunks + 1, last_enc_rem, last_pt)
            };

        if chunk_count == 0 {
            return Err("Fayl boşdur".to_string());
        }

        let total_decrypted_size =
            (chunk_count - 1) * CHUNK_SIZE as u64 + last_chunk_plaintext_size;

        Ok(VaultFileStream {
            inner: Arc::new(Mutex::new(VaultFileStreamInner {
                file_path,
                nonce_prefix,
                mek_bytes,
                chunk_count,
                last_chunk_encrypted_size,
                total_decrypted_size,
            })),
        })
    }

    fn lock_inner(&self) -> std::sync::MutexGuard<'_, VaultFileStreamInner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    /// Deşifrə edilmiş (plaintext) ümumi fayl ölçüsü (bayt).
    /// HTTP `Content-Length` başlığı üçün istifadə olunur.
    pub fn total_size(&self) -> u64 {
        self.lock_inner().total_decrypted_size
    }

    /// Bir parçanın plaintext ölçüsü (son parça istisna olmaqla sabitdir: 32 MiB).
    /// Dart tərəfi byte-aralığını parça indeksinə çevirərkən bu dəyərdən istifadə edir.
    pub fn chunk_size(&self) -> u64 {
        CHUNK_SIZE as u64
    }

    /// Göstərilən parça indeksini (`chunk_index`) birbaşa diskdən oxuyub deşifrə edir.
    ///
    /// **Nonce yenidən qurulması:** StreamBE32 nonce formatı deterministikdir:
    ///   `full_nonce = prefix[0..7] ‖ BE32(chunk_index) ‖ last_flag`
    /// Bu sayədə hər parça müstəqil olaraq, əvvəlki parçaları deşifrə etmədən
    /// oxuna bilər — video üçün əsl `seeking` imkanı yaranır.
    pub fn read_chunk(&self, chunk_index: u64) -> Result<Vec<u8>, String> {
        let inner = self.lock_inner();

        if chunk_index >= inner.chunk_count {
            return Err(format!(
                "Parça indeksi ({}) həddindən artıqdır (cəmi {} parça)",
                chunk_index, inner.chunk_count
            ));
        }

        let is_last = chunk_index == inner.chunk_count - 1;

        // Şifrəli parçanın disk üzərindəki başlanğıc mövqeyi
        let offset = NONCE_SIZE as u64 + chunk_index * ENCRYPTED_CHUNK_SIZE as u64;

        // Parçanı diskdən oxu
        let enc_len = if is_last {
            inner.last_chunk_encrypted_size as usize
        } else {
            ENCRYPTED_CHUNK_SIZE
        };

        let mut enc_buf = vec![0u8; enc_len];
        {
            use std::io::Seek;
            let mut f = File::open(&inner.file_path).map_err(|e| e.to_string())?;
            f.seek(std::io::SeekFrom::Start(offset))
                .map_err(|e| e.to_string())?;
            f.read_exact(&mut enc_buf)
                .map_err(|e| format!("Parça oxuna bilmədi (indeks {}): {}", chunk_index, e))?;
        }

        // StreamBE32 nonce-unu yenidən qur:
        //   [0..7]  = 7 baytlıq prefix (faylın əvvəlindən oxunub)
        //   [7..11] = chunk_index-i big-endian u32 kimi
        //   [11]    = son parça bayrağı (0x01 = son, 0x00 = aralıq)
        // Bu format aes-gcm crate-in StreamBE32 implementasiyası ilə tam uyğundur.
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..7].copy_from_slice(&inner.nonce_prefix);
        let idx32 = chunk_index as u32;
        nonce_bytes[7..11].copy_from_slice(&idx32.to_be_bytes());
        nonce_bytes[11] = if is_last { 1u8 } else { 0u8 };

        // Birbaşa Aes256Gcm ilə deşifrə et (stream API-si yox)
        let key = Key::<Aes256Gcm>::from_slice(&*inner.mek_bytes);
        let aead = Aes256Gcm::new(key);
        let nonce = GcmNonce::from_slice(&nonce_bytes);

        aead.decrypt(nonce, enc_buf.as_slice())
            .map_err(|e| format!("Parça deşifrəsi uğursuz oldu (indeks {}): {:?}", chunk_index, e))
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
            0,                      // boş fayl
            100,                    // kiçik fayl
            1024 * 1024,            // 1 MiB
            CHUNK_SIZE,             // dəqiq 1 parça (4 MiB)
            CHUNK_SIZE + 1024,      // 2 parça (4 MiB + 1 KiB)
            CHUNK_SIZE * 2 + 500,   // 3 parça (~8.5 MiB)
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

            // Paralel şifrələmə
            encrypt_file_parallel(&src_path, &enc_path, &key).unwrap();

            // Paralel deşifrələmə (fayla)
            decrypt_file_parallel(&enc_path, &dec_path, &key).unwrap();
            let decrypted_file_bytes = fs::read(&dec_path).unwrap();
            assert_eq!(original_data, decrypted_file_bytes, "Fayl ölçüsü {} üçün uyğunsuzluq", size);

            // Paralel deşifrələmə (baytlara)
            let decrypted_bytes = decrypt_file_parallel_to_bytes(&enc_path, &key).unwrap();
            assert_eq!(original_data, decrypted_bytes, "Bytes deşifrəsi {} üçün uyğunsuzluq", size);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parallel_encrypted_stream_compatibility() {
        let dir = std::env::temp_dir().join("xenonypt_test_stream_compat");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        // 3 parça: 4 MiB + 4 MiB + 512 KiB = 8.5 MiB
        let total_size = CHUNK_SIZE * 2 + 512 * 1024;
        let original_data: Vec<u8> = (0..total_size).map(|b| (b % 241) as u8).collect();

        let src_path = dir.join("video.mp4");
        let enc_name = "enc_video".to_string();
        let enc_path = dir.join(&enc_name);

        {
            let mut f = File::create(&src_path).unwrap();
            f.write_all(&original_data).unwrap();
        }

        // Paralel şifrələyirik
        encrypt_file_parallel(&src_path, &enc_path, &key).unwrap();

        // VaultFileStream ilə açırıq (real-time streaming oxuyucusu)
        let stream = VaultFileStream::open(dir.clone(), enc_name, Zeroizing::new(key)).unwrap();
        assert_eq!(stream.total_size(), total_size as u64);
        assert_eq!(stream.chunk_size(), CHUNK_SIZE as u64);

        // Hər parçanı oxuyub birləşdiririk
        let c0 = stream.read_chunk(0).unwrap();
        let c1 = stream.read_chunk(1).unwrap();
        let c2 = stream.read_chunk(2).unwrap();

        assert_eq!(c0.len(), CHUNK_SIZE);
        assert_eq!(c1.len(), CHUNK_SIZE);
        assert_eq!(c2.len(), 512 * 1024);

        let mut reassembled = Vec::new();
        reassembled.extend_from_slice(&c0);
        reassembled.extend_from_slice(&c1);
        reassembled.extend_from_slice(&c2);

        assert_eq!(reassembled, original_data);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_vault_queue_operations() {
        let dir = std::env::temp_dir().join("xenonypt_test_vault_queue");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let vault_dir = dir.join("my_vault");
        let handle = VaultHandle::create_new(
            vault_dir.to_str().unwrap().to_string(),
            "SuperPassword123!".to_string(),
        ).unwrap();

        assert!(handle.is_unlocked());

        // Test faylları yaradırıq
        let f1_path = dir.join("doc1.txt");
        let f2_path = dir.join("doc2.txt");
        let f3_path = dir.join("doc3.bin");

        fs::write(&f1_path, b"Hello from doc 1!").unwrap();
        fs::write(&f2_path, b"Hello from doc 2!").unwrap();
        let f3_data: Vec<u8> = (0..1024 * 1024 * 5).map(|b| (b % 255) as u8).collect();
        fs::write(&f3_path, &f3_data).unwrap();

        // Növbə ilə çoxsaylı faylların ardıcıl əlavə olunması (add_files)
        let queue_items = vec![
            VaultAddFileInput {
                source_file_path: f1_path.to_str().unwrap().to_string(),
                original_name: "doc1.txt".to_string(),
            },
            VaultAddFileInput {
                source_file_path: f2_path.to_str().unwrap().to_string(),
                original_name: "doc2.txt".to_string(),
            },
            VaultAddFileInput {
                source_file_path: f3_path.to_str().unwrap().to_string(),
                original_name: "doc3.bin".to_string(),
            },
        ];

        let entries = handle.add_files(queue_items).unwrap();
        assert_eq!(entries.len(), 3);

        let list = handle.list_files().unwrap();
        assert_eq!(list.len(), 3);

        // Növbə ilə çoxsaylı faylların ardıcıl çıxarılması (extract_files)
        let out1 = dir.join("out1.txt");
        let out2 = dir.join("out2.txt");
        let out3 = dir.join("out3.bin");

        let extract_queue = vec![
            VaultExtractFileInput {
                obfuscated_name: entries[0].obfuscated_name.clone(),
                dest_path: out1.to_str().unwrap().to_string(),
            },
            VaultExtractFileInput {
                obfuscated_name: entries[1].obfuscated_name.clone(),
                dest_path: out2.to_str().unwrap().to_string(),
            },
            VaultExtractFileInput {
                obfuscated_name: entries[2].obfuscated_name.clone(),
                dest_path: out3.to_str().unwrap().to_string(),
            },
        ];

        handle.extract_files(extract_queue).unwrap();

        assert_eq!(fs::read(&out1).unwrap(), b"Hello from doc 1!");
        assert_eq!(fs::read(&out2).unwrap(), b"Hello from doc 2!");
        assert_eq!(fs::read(&out3).unwrap(), f3_data);

        // Tək fayl bayt çıxarışı
        let b1 = handle.extract_file_to_bytes(entries[0].obfuscated_name.clone()).unwrap();
        assert_eq!(b1, b"Hello from doc 1!");

        // Fayl silinməsi
        handle.delete_file(entries[0].obfuscated_name.clone()).unwrap();
        assert_eq!(handle.list_files().unwrap().len(), 2);

        // Kilidlənmə və yenidən açılma
        handle.lock();
        assert!(!handle.is_unlocked());

        let unlocked_handle = VaultHandle::unlock(
            vault_dir.to_str().unwrap().to_string(),
            "SuperPassword123!".to_string(),
        ).unwrap();
        assert_eq!(unlocked_handle.list_files().unwrap().len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }
}