//! flutter_rust_bridge_codegen bu faylı skan edərək Dart bind-lərini
//! generasiya edəcək. `VaultHandle` `vault.rs`-də təyin olunduğu üçün
//! FRB onu avtomatik opaque tip kimi tanıyacaq (çünki daxilində
//! `Arc<Mutex<..>>` var və `Clone`/`Copy` deyil).
//!
//! flutter_rust_bridge_codegen generate --rust-input src/api.rs
//! (versiyanızdan asılı olaraq əmr fərqli ola bilər — öz FRB
//! quraşdırmanızdakı konfiqurasiyaya uyğunlaşdırın)

pub use crate::vault::{
    init_thread_pool, VaultAddFileInput, VaultExtractFileInput, VaultFileEntry, VaultFileStream,
    VaultHandle,
};

/// Global Rayon thread pool-u `available_parallelism - 2` (minimum 1) ilə konfiqurasiya edir.
pub fn vault_init_thread_pool() {
    init_thread_pool();
}

/// Növbədən faylları bir-bir ardıcıl şifrələyib kassaya əlavə edir.
/// Hər fərdi faylın parçaları Rayon vasitəsilə paralel şifrələnir.
pub fn vault_add_files(
    handle: &VaultHandle,
    files: Vec<VaultAddFileInput>,
) -> Result<Vec<VaultFileEntry>, String> {
    handle.add_files(files)
}

/// Növbədən faylları bir-bir ardıcıl deşifrə edib diskə çıxarır.
/// Hər fərdi faylın parçaları Rayon vasitəsilə paralel deşifrələnir.
pub fn vault_extract_files(
    handle: &VaultHandle,
    files: Vec<VaultExtractFileInput>,
) -> Result<(), String> {
    handle.extract_files(files)
}

/// Yeni kassa yaradır.
pub fn vault_create_new(vault_dir: String, password: String) -> Result<VaultHandle, String> {
    VaultHandle::create_new(vault_dir, password)
}

/// Mövcud kassanı açır.
pub fn vault_unlock(vault_dir: String, password: String) -> Result<VaultHandle, String> {
    VaultHandle::unlock(vault_dir, password)
}

/// Verilən qovluqda kassa mövcud görünürmü — parol tələb etmədən, sırf
/// "Aç" / "Yarat" ekranı arasında seçim üçün. Əsl təsdiq `vault_unlock`
/// çağırılanda parolla olur.
pub fn vault_exists(vault_dir: String) -> bool {
    VaultHandle::exists(vault_dir)
}

/// Kassanı kilidləyir (açarı yaddaşdan silir).
pub fn vault_lock(handle: &VaultHandle) {
    handle.lock();
}

/// Kassanın kilidli olub olmadığını yoxlayır.
pub fn vault_is_unlocked(handle: &VaultHandle) -> bool {
    handle.is_unlocked()
}

/// Kassaya fayl əlavə edir.
pub fn vault_add_file(
    handle: &VaultHandle,
    source_file_path: String,
    original_name: String,
) -> Result<String, String> {
    handle.add_file(source_file_path, original_name)
}

/// Kassadan faylı silir.
pub fn vault_delete_file(handle: &VaultHandle, obfuscated_name: String) -> Result<(), String> {
    handle.delete_file(obfuscated_name)
}

/// Kassadakı faylın görünən adını yeniləyir (yalnız metadata dəyişir, fayl yenidən şifrələnmir).
pub fn vault_rename_file(
    handle: &VaultHandle,
    obfuscated_name: String,
    new_original_name: String,
) -> Result<(), String> {
    handle.rename_file(obfuscated_name, new_original_name)
}

/// Kassadakı bütün faylların siyahısını qaytarır.
pub fn vault_list_files(handle: &VaultHandle) -> Result<Vec<VaultFileEntry>, String> {
    handle.list_files()
}

/// Kassa qovluğunda olan amma hələ şifrələnməmiş (kassaya əlavə edilməmiş)
/// faylların adlarını qaytarır. Dart tərəfi bunları istifadəçiyə göstərib
/// kassaya qatmağı təklif edə bilər.
pub fn vault_list_loose_files(handle: &VaultHandle) -> Result<Vec<String>, String> {
    handle.list_loose_files()
}

/// Şifrəli faylı göstərilən yola çıxarır.
pub fn vault_extract_file_to_path(
    handle: &VaultHandle,
    obfuscated_name: String,
    dest_path: String,
) -> Result<(), String> {
    handle.extract_file_to_path(obfuscated_name, dest_path)
}

/// Kiçik faylları bytes kimi qaytarır.
pub fn vault_extract_file_to_bytes(
    handle: &VaultHandle,
    obfuscated_name: String,
) -> Result<Vec<u8>, String> {
    handle.extract_file_to_bytes(obfuscated_name)
}

// ─────────────────────────────────────────────────────────────────────────────
// Streaming API — böyük fayllar (video) üçün parça-parça deşifrə
// ─────────────────────────────────────────────────────────────────────────────

/// Şifrəli fayla birbaşa giriş üçün `VaultFileStream` handle-i yaradır.
/// Fayl tam yaddaşa yüklənmir; `vault_stream_read_chunk` çağırılanda yalnız
/// tələb olunan parça diskdən oxunub deşifrə edilir.
pub fn vault_open_stream(
    handle: &VaultHandle,
    obfuscated_name: String,
) -> Result<VaultFileStream, String> {
    handle.open_stream(obfuscated_name)
}

/// Deşifrə edilmiş (plaintext) ümumi fayl ölçüsünü baytla qaytarır.
/// Dart tərəfindəki HTTP serverinin `Content-Length` başlığı üçün lazımdır.
pub fn vault_stream_total_size(stream: &VaultFileStream) -> u64 {
    stream.total_size()
}

/// Bir parçanın (chunk) plaintext ölçüsünü qaytarır (son parça xaricində 32 MiB).
/// Dart tərəfi bu dəyərdən byte aralığını parça indeksinə çevirmək üçün istifadə edir.
pub fn vault_stream_chunk_size(stream: &VaultFileStream) -> u64 {
    stream.chunk_size()
}

/// Göstərilən parça indeksini diskdən oxuyub deşifrə edir.
/// Yalnız bu parça yaddaşa gətirilir — öncəki parçalar tələb olunmur.
pub fn vault_stream_read_chunk(
    stream: &VaultFileStream,
    chunk_index: u64,
) -> Result<Vec<u8>, String> {
    stream.read_chunk(chunk_index)
}