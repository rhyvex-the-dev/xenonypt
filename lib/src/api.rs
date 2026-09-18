//! flutter_rust_bridge_codegen bu faylı skan edərək Dart bind-lərini
//! generasiya edəcək. `VaultHandle` `vault.rs`-də təyin olunduğu üçün
//! FRB onu avtomatik opaque tip kimi tanıyacaq (çünki daxilində
//! `Arc<Mutex<..>>` var və `Clone`/`Copy` deyil).
//!
//! flutter_rust_bridge_codegen generate --rust-input src/api.rs
//! (versiyanızdan asılı olaraq əmr fərqli ola bilər — öz FRB
//! quraşdırmanızdakı konfiqurasiyaya uyğunlaşdırın)

pub use crate::vault::{VaultFileEntry, VaultHandle};

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