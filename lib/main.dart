import 'dart:async';
import 'dart:io';

import 'package:android_intent_plus/android_intent.dart';
import 'package:biometric_storage/biometric_storage.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_displaymode/flutter_displaymode.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'src/rust/api.dart';
import 'src/rust/frb_generated.dart';
import 'src/rust/vault.dart';

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  // Loaded once up-front so theme settings apply from the very first frame.
  final prefs = await SharedPreferences.getInstance();

  if(Platform.isAndroid) {
    try{
      await FlutterDisplayMode.setHighRefreshRate();
    } catch (_){
      //nothing 🙂
    }
  }
  runApp(ProviderScope(
    overrides: [sharedPreferencesProvider.overrideWithValue(prefs)],
    child: const XenonyptApp(),
  ));
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURE STORAGE KEY HELPERS
// ─────────────────────────────────────────────────────────────────────────────

// The vault *folder* itself must be as anonymous as the files vault.rs
// already stores inside it (random hex name, no extension) — otherwise a
// human-chosen folder name like "MyVault" or "Private" gives away exactly
// what it is. This mirrors the 16-random-byte hex scheme vault.rs uses for
// obfuscated_name, just generated on the Dart side before the folder exists.+++

String _normalizeVaultDirPath(String path) {
  var p = path;
  while (p.length > 1 && (p.endsWith('/') || p.endsWith(r'\'))) {
    p = p.substring(0, p.length - 1);
  }
  return p;
}

String _bioEnabledKey(String path) =>
    'bio_enabled:${_normalizeVaultDirPath(path)}';

// biometric_storage file names are used as on-disk identifiers by the
// plugin, so keep them filesystem-safe and stable across app restarts.
String _bioStorageName(String path) =>
    'bio_pw_${_normalizeVaultDirPath(path).replaceAll(RegExp(r'[^A-Za-z0-9]'), '_')}';

// Every read/write of the biometric-protected secret must pass through
// a fresh OS-level biometric check (no caching window). The resulting
// storage is backed by a non-exportable, hardware-bound key
// (Android Keystore w/ setUserAuthenticationRequired + invalidated on
// new biometric enrollment; iOS Keychain w/ biometryCurrentSet), so
// unlike the old "authenticate() then read a plain secret" flow, the
// secret cannot be unwrapped by copying app data + vault folder to a
// different device or enrolling a different fingerprint/face.
Future<BiometricStorageFile> _bioStorage(String path) {
  return BiometricStorage().getStorage(
    _bioStorageName(path),
    options: StorageFileInitOptions(
      authenticationValidityDurationSeconds: -1,
    ),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// APP ROOT
// ─────────────────────────────────────────────────────────────────────────────


class XenonyptApp extends ConsumerWidget {
  const XenonyptApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final mode = ref.watch(currentThemeProvider);
    final oled = ref.watch(trueDarkOledProvider);

    final ThemeData light;
    final ThemeData dark;
    final ThemeMode themeMode;
    if (mode == AppThemeMode.system) {
      // Follow the device: light/dark chosen by the OS, live.
      light = AppThemes.themeFor(AppThemeMode.xenonyptLight);
      dark = AppThemes.themeFor(AppThemeMode.xenonyptDark, oled: oled);
      themeMode = ThemeMode.system;
    } else {
      final t = AppThemes.themeFor(mode, oled: oled);
      light = t;
      dark = t;
      themeMode =
          t.brightness == Brightness.dark ? ThemeMode.dark : ThemeMode.light;
    }

    return MaterialApp(
      title: 'Xenonypt',
      debugShowCheckedModeBanner: false,
      theme: light,
      darkTheme: dark,
      themeMode: themeMode,
      home: const WelcomeScreen(),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// WELCOME SCREEN  (single smart button)
// ─────────────────────────────────────────────────────────────────────────────

class WelcomeScreen extends StatefulWidget {
  const WelcomeScreen({super.key});

  @override
  State<WelcomeScreen> createState() => _WelcomeScreenState();
}

class _WelcomeScreenState extends State<WelcomeScreen>
    with SingleTickerProviderStateMixin {
  bool _loading = false;
  late final AnimationController _glowCtrl;
  late final Animation<double> _glowAnim;

  @override
  void initState() {
    super.initState();
    _glowCtrl = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);
    _glowAnim = Tween<double>(begin: 0.3, end: 1.0).animate(
      CurvedAnimation(parent: _glowCtrl, curve: Curves.easeInOut),
    );
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _checkFirstLaunchStoragePermission();
    });
  }

  Future<void> _checkFirstLaunchStoragePermission() async {
    if (!Platform.isAndroid) return;

    final prefs = await SharedPreferences.getInstance();
    final hasSeenDialog =
        prefs.getBool('has_seen_manage_storage_dialog') ?? false;

    if (hasSeenDialog) return;

    final status = await Permission.manageExternalStorage.status;
    if (status.isGranted) return;

    if (!mounted) return;

    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (BuildContext context) {
        return const ManageStoragePermissionDialog();
      },
    );

    await prefs.setBool('has_seen_manage_storage_dialog', true);
  }

  @override
  void dispose() {
    _glowCtrl.dispose();
    super.dispose();
  }

  Future<void> _onOpenOrCreate() async {
    setState(() => _loading = true);
    try {
      final String? selectedPath = await FilePicker.getDirectoryPath(
        dialogTitle: 'Select folder for vault',
      );
      if (!mounted) return;
      if (selectedPath == null) return;

      // Auto-detect: vault.rs no longer writes a fixed ".vault_header"
      // name, so ask it to scan for a header-shaped (fixed-size) file
      // instead of checking a known filename ourselves.
      final isExisting = await vaultExists(vaultDir: selectedPath);
      if (!mounted) return;

      if (isExisting) {
        // Vault already exists → show unlock sheet
        await showModalBottomSheet(
          context: context,
          isScrollControlled: true,
          backgroundColor: Colors.transparent,
          builder: (_) => UnlockVaultSheet(directoryPath: selectedPath),
        );
      } else {
        // Fresh location → the folder the user just picked is only the
        // *container*. The actual vault lives in a randomly-named,
        // extension-less subfolder we generate here, so nothing about the
        // on-disk name hints that it's a vault.
        final vaultDirPath =
            '$selectedPath${Platform.pathSeparator}';
        Navigator.push(
          context,
          _slideRoute(CreateVaultScreen(
            directoryPath: vaultDirPath,
            containerPath: selectedPath,
          )),
        );
      }
    } catch (e) {
      if (mounted) {
        _showError('Error picking folder: $e');
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  void _showError(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
          content: Text(msg),
          backgroundColor: const Color.fromARGB(255, 249, 52, 52)),
    );
  }

  @override
  Widget build(BuildContext context) {
    final primary = Theme.of(context).colorScheme.primary;
    final secondary = Theme.of(context).colorScheme.secondary;
    final surface = Theme.of(context).colorScheme.surface;
    return Scaffold(
      body: Stack(
        children: [
          SafeArea(
            child: Padding(
              padding: const EdgeInsets.symmetric(
                  horizontal: 28.0, vertical: 36.0),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  // ── Logo ──
                  Column(
                    children: [
                      const SizedBox(height: 40),
                      AnimatedBuilder(
                        animation: _glowAnim,
                        builder: (_, __) => Container(
                          width: 90,
                          height: 90,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: primary
                                  .withValues(alpha: _glowAnim.value),
                              width: 1.5,
                            ),
                            boxShadow: [
                              BoxShadow(
                                color: primary.withValues(
                                    alpha: _glowAnim.value * 0.4),
                                blurRadius: 24,
                                spreadRadius: 4,
                              ),
                            ],
                          ),
                          child: Icon(
                            Icons.lock_outline_rounded,
                            size: 40,
                            color: primary,
                          ),
                        ),
                      ),
                      const SizedBox(height: 24),
                      Text(
                        'XENONYPT',
                        style: TextStyle(
                          fontSize: 28,
                          fontWeight: FontWeight.w900,
                          letterSpacing: 6,
                          color: context.ac.text,
                        ),
                      ),
                      const SizedBox(height: 10),
                      Text(
                        'Military-grade encrypted vault',
                        style: TextStyle(
                          fontSize: 13,
                          letterSpacing: 2,
                          color: primary.withValues(alpha: 0.7),
                        ),
                      ),
                    ],
                  ),
                  // ── Feature list ──
                  Container(
                    padding: const EdgeInsets.all(20),
                    decoration: BoxDecoration(
                      color: surface,
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: context.ac.divider),
                    ),
                    child: Column(
                      children: [
                        _InfoRow(Icons.shield_rounded,
                            'AES-256-GCM encryption'),
                        const SizedBox(height: 12),
                        _InfoRow(Icons.key_rounded,
                            'Argon2id key derivation'),
                        const SizedBox(height: 12),
                        _InfoRow(Icons.fingerprint_rounded,
                            'Biometric authentication'),
                        const SizedBox(height: 12),
                        _InfoRow(
                            Icons.no_encryption_gmailerrorred_rounded,
                            'Zero-knowledge — keys never leave device'),
                      ],
                    ),
                  ),
                  // ── Smart button ──
                  Column(
                    children: [
                      SizedBox(
                        width: double.infinity,
                        child: ElevatedButton.icon(
                          onPressed:
                              _loading ? null : _onOpenOrCreate,
                          icon: _loading
                              ? SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: Theme.of(context).scaffoldBackgroundColor,
                                  ),
                                )
                              : const Icon(
                                  Icons.folder_open_rounded),
                          label: Text(_loading
                              ? 'DETECTING...'
                              : 'OPEN / CREATE VAULT'),
                        ),
                      ),
                      const SizedBox(height: 12),
                      Text(
                        'Select a folder — we\'ll detect if it\'s already a vault',
                        textAlign: TextAlign.center,
                        style: TextStyle(
                          fontSize: 12,
                          color: primary.withValues(alpha: 0.5),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// UNLOCK VAULT BOTTOM SHEET
// ─────────────────────────────────────────────────────────────────────────────

class UnlockVaultSheet extends StatefulWidget {
  final String directoryPath;
  const UnlockVaultSheet({super.key, required this.directoryPath});

  @override
  State<UnlockVaultSheet> createState() => _UnlockVaultSheetState();
}

class _UnlockVaultSheetState extends State<UnlockVaultSheet> {
  final _passwordCtrl = TextEditingController();
  bool _obscure = true;
  bool _isLoading = false;
  bool _biometricAvailable = false;
  String? _errorText;

  @override
  void initState() {
    super.initState();
    _checkBiometric();
  }

  @override
  void dispose() {
    _passwordCtrl.dispose();
    super.dispose();
  }

  Future<void> _checkBiometric() async {
    final prefs = await SharedPreferences.getInstance();
    final bioEnabled =
        prefs.getBool(_bioEnabledKey(widget.directoryPath)) ?? false;
    if (!bioEnabled) return;
    try {
      final response = await BiometricStorage().canAuthenticate();
      if (mounted) {
        setState(() =>
            _biometricAvailable = response == CanAuthenticateResponse.success);
      }
    } catch (_) {}
  }

  Future<void> _unlockWithPassword([String? overridePw]) async {
    final pw = overridePw ?? _passwordCtrl.text.trim();
    if (pw.isEmpty) {
      setState(() => _errorText = 'Please enter your password');
      return;
    }
    setState(() {
      _isLoading = true;
      _errorText = null;
    });
    try {
      final handle = await vaultUnlock(
          vaultDir: widget.directoryPath, password: pw);
      if (!mounted) return;
      Navigator.of(context).pop();
      Navigator.of(context).push(_slideRoute(
        VaultContentScreen(
          directoryPath: widget.directoryPath,
          vaultHandle: handle,
        ),
      ));
    } catch (e) {
      if (mounted) {
        setState(() => _errorText = _friendlyError(e));
      }
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _unlockWithBiometric() async {
    try {
      final storage = await _bioStorage(widget.directoryPath);
      final pw = await storage.read(
        promptInfo: const PromptInfo(
          androidPromptInfo: AndroidPromptInfo(
            title: 'Unlock vault',
            subtitle: 'Authenticate to unlock your vault',
          ),
        ),
      );
      if (!mounted) return;
      if (pw == null || pw.isEmpty) {
        setState(() => _errorText =
            'No saved credentials — enter password manually');
        return;
      }
      await _unlockWithPassword(pw);
    } catch (e) {
      if (mounted) {
        setState(() => _errorText = 'Biometric error: $e');
      }
    }
  }

  String _friendlyError(Object e) {
    final s = e.toString();
    if (s.contains('Yanlış şifrə') || s.contains('Wrong password')) {
      return 'Wrong password. Try again.';
    }
    return s;
  }

  @override
  Widget build(BuildContext context) {
    final primary = Theme.of(context).colorScheme.primary;
    final surface = Theme.of(context).colorScheme.surface;
    return Padding(
      padding: EdgeInsets.only(
          bottom: MediaQuery.of(context).viewInsets.bottom),
      child: Container(
        decoration: BoxDecoration(
          color: surface,
          borderRadius:
              const BorderRadius.vertical(top: Radius.circular(24)),
          border: Border(
              top: BorderSide(color: context.ac.divider)),
        ),
        padding: const EdgeInsets.fromLTRB(24, 20, 24, 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // drag handle
            Center(
              child: Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: context.ac.border,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            const SizedBox(height: 20),
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: primary.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Icon(Icons.lock_open_rounded,
                      color: primary, size: 20),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('UNLOCK VAULT',
                          style: TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                              letterSpacing: 2,
                              color: context.ac.text)),
                      SizedBox(height: 2),
                      Text('Existing vault detected',
                          style: TextStyle(
                              fontSize: 12,
                              color: context.ac.textSecondary)),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              widget.directoryPath,
              style: TextStyle(
                  fontSize: 11,
                  color: context.ac.textMuted,
                  fontFamily: 'monospace'),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 20),
            TextField(
              controller: _passwordCtrl,
              obscureText: _obscure,
              autofocus: !_biometricAvailable,
              decoration: InputDecoration(
                labelText: 'Password',
                prefixIcon: Icon(Icons.key_rounded,
                    color: primary, size: 20),
                suffixIcon: IconButton(
                  icon: Icon(
                      _obscure
                          ? Icons.visibility_off
                          : Icons.visibility,
                      color: primary,
                      size: 20),
                  onPressed: () =>
                      setState(() => _obscure = !_obscure),
                ),
                errorText: _errorText,
              ),
              onSubmitted: (_) => _unlockWithPassword(),
            ),
            const SizedBox(height: 16),
            SizedBox(
              width: double.infinity,
              child: ElevatedButton(
                onPressed:
                    _isLoading ? null : _unlockWithPassword,
                child: _isLoading
                    ? SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Theme.of(context).scaffoldBackgroundColor))
                    : const Text('UNLOCK'),
              ),
            ),
            if (_biometricAvailable) ...[
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed:
                    _isLoading ? null : _unlockWithBiometric,
                icon: const Icon(Icons.fingerprint_rounded,
                    size: 20),
                label: const Text('USE BIOMETRIC'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// CREATE VAULT SCREEN
// ─────────────────────────────────────────────────────────────────────────────

class CreateVaultScreen extends StatefulWidget {
  final String directoryPath;
  // The human-visible parent folder the user picked. directoryPath itself
  // is the randomly-named subfolder that will actually hold the vault —
  // we show containerPath in the UI instead so the random name doesn't
  // need to mean anything to the user.
  final String? containerPath;
  const CreateVaultScreen(
      {super.key, required this.directoryPath, this.containerPath});

  @override
  State<CreateVaultScreen> createState() =>
      _CreateVaultScreenState();
}
bool _enableBiometric = false;
class _CreateVaultScreenState extends State<CreateVaultScreen> {
  final _formKey = GlobalKey<FormState>();

  final _nameCtrl = TextEditingController();
  final _pwCtrl = TextEditingController();
  final _confirmPwCtrl = TextEditingController();

  bool _obscurePw = true;
  bool _obscureConfirm = true;
  bool _isBiometricSupported = false;
  bool _isCreating = false;
  int _strength = 0; // 0–4

  @override
  void initState() {
    super.initState();
    _checkBiometricSupport();
    _pwCtrl.addListener(_updateStrength);
  }

  @override
  void dispose() {
    _nameCtrl.dispose();
    _pwCtrl.dispose();
    _confirmPwCtrl.dispose();
    super.dispose();
  }

  void _updateStrength() {
    final v = _pwCtrl.text;
    int s = 0;
    if (v.length >= 8) s++;
    if (RegExp(r'[A-Z]').hasMatch(v)) s++;
    if (RegExp(r'[0-9]').hasMatch(v)) s++;
    if (RegExp(r'[!@#\$&*~`()_\-+={[\]|:;<>,.?/\\]')
        .hasMatch(v)) { s++; }
    setState(() => _strength = s);
  }

  Future<void> _checkBiometricSupport() async {
    try {
      final response = await BiometricStorage().canAuthenticate();
      if (mounted) {
        setState(() => _isBiometricSupported =
            response == CanAuthenticateResponse.success);
      }
    } catch (_) {
      if (mounted) setState(() => _isBiometricSupported = false);
    }
  }

  String? _validatePassword(String? v) {
    if (v == null || v.isEmpty) return 'Password is required';
    if (v.length < 8) return 'At least 8 characters';
    if (!RegExp(r'[A-Z]').hasMatch(v)) return 'Add an uppercase letter';
    if (!RegExp(r'[a-z]').hasMatch(v)) return 'Add a lowercase letter';
    if (!RegExp(r'[0-9]').hasMatch(v)) return 'Add a number';
    if (!RegExp(r'[!@#\$&*~`()_\-+={[\]|:;<>,.?/\\]').hasMatch(v)) {
      return 'Add a special character';
    }
    return null;
  }

  Future<void> _createVault() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() => _isCreating = true);
    try {
      final name = _nameCtrl.text.trim().isEmpty
          ? 'My Vault'
          : _nameCtrl.text.trim();
      final pw = _pwCtrl.text;

      final handle = await vaultCreateNew(
          vaultDir: widget.directoryPath, password: pw);

      // Persist biometric preference + biometric-gated password.
      // The storage backing this is a non-exportable, hardware-bound
      // key that requires a fresh OS biometric check on every read,
      // so it can't be unwrapped by copying app data + vault folder
      // to another device, or by a different enrolled fingerprint/face.
      if (_enableBiometric) {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setBool(
            _bioEnabledKey(widget.directoryPath), true);
        final storage = await _bioStorage(widget.directoryPath);
        await storage.write(pw);
      }

      if (!mounted) return;
      Navigator.pushAndRemoveUntil(
        context,
        _slideRoute(VaultContentScreen(
          vaultName: name,
          directoryPath: widget.directoryPath,
          vaultHandle: handle,
        )),
        (route) => route.isFirst,
      );
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
              content: Text(e.toString()),
              backgroundColor: const Color(0xFFFF5252)),
        );
      }
    } finally {
      if (mounted) setState(() => _isCreating = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final primary = Theme.of(context).colorScheme.primary;
    final surface = Theme.of(context).colorScheme.surface;
    return Scaffold(
      appBar: AppBar(
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded,
              size: 18),
          onPressed: () => Navigator.pop(context),
        ),
        title: const Text('CREATE VAULT',
            style: TextStyle(
                fontSize: 14,
                letterSpacing: 3,
                fontWeight: FontWeight.bold)),
        centerTitle: true,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Form(
          key: _formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Path indicator
              Container(
                padding: const EdgeInsets.symmetric(
                    horizontal: 14, vertical: 10),
                decoration: BoxDecoration(
                  color: surface,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                      color: context.ac.divider),
                ),
                child: Row(
                  children: [
                    Icon(Icons.folder_rounded,
                        color: primary, size: 16),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        widget.containerPath ?? widget.directoryPath,
                        style: TextStyle(
                            fontSize: 12,
                            color: context.ac.textSecondary,
                            fontFamily: 'monospace'),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 24),

              // Vault name
              TextFormField(
                controller: _nameCtrl,
                decoration: InputDecoration(
                  labelText: 'Vault name (optional)',
                  prefixIcon: Icon(Icons.edit_rounded,
                      color: primary, size: 20),
                ),
              ),
              const SizedBox(height: 16),

              // Password
              TextFormField(
                controller: _pwCtrl,
                obscureText: _obscurePw,
                validator: _validatePassword,
                decoration: InputDecoration(
                  labelText: 'Password',
                  prefixIcon: Icon(Icons.lock_rounded,
                      color: primary, size: 20),
                  suffixIcon: IconButton(
                    icon: Icon(
                        _obscurePw
                            ? Icons.visibility_off
                            : Icons.visibility,
                        color: primary,
                        size: 20),
                    onPressed: () =>
                        setState(() => _obscurePw = !_obscurePw),
                  ),
                ),
              ),

              // Strength bar
              const SizedBox(height: 8),
              _PasswordStrengthBar(strength: _strength),
              const SizedBox(height: 16),

              // Confirm password
              TextFormField(
                controller: _confirmPwCtrl,
                obscureText: _obscureConfirm,
                validator: (v) {
                  if (v == null || v.isEmpty) {
                    return 'Please confirm your password';
                  }
                  if (v != _pwCtrl.text) {
                    return 'Passwords do not match';
                  }
                  return null;
                },
                decoration: InputDecoration(
                  labelText: 'Confirm password',
                  prefixIcon: Icon(Icons.lock_rounded,
                      color: primary, size: 20),
                  suffixIcon: IconButton(
                    icon: Icon(
                        _obscureConfirm
                            ? Icons.visibility_off
                            : Icons.visibility,
                        color: primary,
                        size: 20),
                    onPressed: () => setState(
                        () => _obscureConfirm = !_obscureConfirm),
                  ),
                ),
              ),
              const SizedBox(height: 20),

              // Biometric toggle
              if (_isBiometricSupported) ...[
                Container(
                  decoration: BoxDecoration(
                    color: surface,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                        color: context.ac.divider),
                  ),
                  child: SwitchListTile(
                    value: _enableBiometric,
                    onChanged: (v) =>
                        setState(() => _enableBiometric = v),
                    activeThumbColor: primary,
                    secondary: Icon(
                        Icons.fingerprint_rounded,
                        color: primary),
                    title: Text('Enable biometric login',
                        style: TextStyle(
                            fontSize: 14,
                            color: context.ac.text)),
                    subtitle: Text(
                        'Use fingerprint / face to unlock',
                        style: TextStyle(
                            fontSize: 12,
                            color: context.ac.textSecondary)),
                  ),
                ),
                const SizedBox(height: 20),
              ],

              // Warning box
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: const Color(0xFFFF5252)
                      .withValues(alpha: 0.07),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                      color: const Color(0xFFFF5252)
                          .withValues(alpha: 0.4)),
                ),
                child: const Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(Icons.warning_amber_rounded,
                        color: Color(0xFFFF5252), size: 18),
                    SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        'There is NO password recovery by design.\n'
                        'If you forget your password, all encrypted data is permanently lost.',
                        style: TextStyle(
                            color: Color(0xFFFF5252),
                            fontSize: 12,
                            height: 1.5),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 28),

              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed:
                      _isCreating ? null : _createVault,
                  child: _isCreating
                      ? SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: Theme.of(context).scaffoldBackgroundColor))
                      : const Text('CREATE VAULT'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// VAULT CONTENT SCREEN
// ─────────────────────────────────────────────────────────────────────────────

class VaultContentScreen extends StatefulWidget {
  final String directoryPath;
  final VaultHandle vaultHandle;
  final String vaultName;

  const VaultContentScreen({
    super.key,
    required this.directoryPath,
    required this.vaultHandle,
    this.vaultName = 'Vault',
  });

  @override
  State<VaultContentScreen> createState() =>
      _VaultContentScreenState();
}

class _VaultContentScreenState extends State<VaultContentScreen>
    with WidgetsBindingObserver {
  List<VaultFileEntry> _files = [];
  bool _loading = true;
  String? _error;
  bool _isPickingFile = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _loadFiles();
    _scanForLooseFiles();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  // Locks the moment the app leaves the foreground (backgrounded, app
  // switcher, screen off) or is being torn down — not just on a clean
  // exit. `inactive` (e.g. a brief system dialog/incoming call overlay)
  // is deliberately excluded so we don't re-lock on every tiny interrupt.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (_isPickingFile) return;

    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.detached) {
      vaultLock(handle: widget.vaultHandle);
    } else if (state == AppLifecycleState.resumed) {
      _bounceToWelcomeIfLocked();
    }
  }

  // If the OS kept this screen alive in the background (rather than fully
  // killing the process) the handle is now locked but the UI would still
  // be sitting on the file list — kick the user back to the unlock flow
  // instead of showing stale content or letting a call silently fail.
  Future<void> _bounceToWelcomeIfLocked() async {
    try {
      final unlocked = await vaultIsUnlocked(handle: widget.vaultHandle);
      if (!unlocked && mounted) {
        Navigator.of(context).popUntil((r) => r.isFirst);
      }
    } catch (_) {}
  }

  // Files that were sitting in the vault folder before it became a vault
  // (or dropped in later outside the app) show up here unencrypted. Offer
  // to pull each one into the vault, then ask separately whether to
  // remove the plaintext original.
  Future<void> _scanForLooseFiles() async {
    try {
      final looseNames =
          await vaultListLooseFiles(handle: widget.vaultHandle);
      for (final name in looseNames) {
        if (!mounted) return;
        final shouldEncrypt = await showDialog<bool>(
          context: context,
          barrierDismissible: false,
          builder: (ctx) => AlertDialog(
            title: Text('Unencrypted file found',
                style: TextStyle(color: context.ac.text)),
            content: Text(
              '"$name" is sitting in your vault folder but isn\'t encrypted yet. Add it to the vault?',
              style:
                  TextStyle(color: context.ac.textSecondary, fontSize: 13),
            ),
            actions: [
              TextButton(
                  onPressed: () => Navigator.pop(ctx, false),
                  child: const Text('SKIP')),
              TextButton(
                  onPressed: () => Navigator.pop(ctx, true),
                  child: const Text('ENCRYPT')),
            ],
          ),
        );
        if (shouldEncrypt != true) continue;

        final sourcePath = '${widget.directoryPath}$name';
        try {
          await vaultAddFile(
            handle: widget.vaultHandle,
            sourceFilePath: sourcePath,
            originalName: name,
          );
        } catch (e) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                  content: Text('Failed to encrypt "$name": $e'),
                  backgroundColor:
                      const Color.fromARGB(255, 253, 50, 50)),
            );
          }
          continue;
        }

        if (!mounted) return;
        final shouldDelete = await showDialog<bool>(
          context: context,
          barrierDismissible: false,
          builder: (ctx) => AlertDialog(
            backgroundColor: context.ac.card,
            shape:
                RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
            title: Text('Delete original?',
                style: TextStyle(color: context.ac.text)),
            content: Text(
              '"$name" was encrypted into the vault. Delete the original plaintext copy?',
              style:
                  TextStyle(color: context.ac.textSecondary, fontSize: 13),
            ),
            actions: [
              TextButton(
                  onPressed: () => Navigator.pop(ctx, false),
                  child: const Text('KEEP')),
              TextButton(
                onPressed: () => Navigator.pop(ctx, true),
                child: const Text('DELETE',
                    style:
                        TextStyle(color: Color.fromARGB(255, 255, 50, 50))),
              ),
            ],
          ),
        );
        if (shouldDelete == true) {
          try {
            await File(sourcePath).delete();
          } catch (_) {
            // Best-effort — the file is safely in the vault either way.
          }
        }
      }
      if (mounted && looseNames.isNotEmpty) await _loadFiles();
    } catch (_) {
      // Non-critical — don't block the vault UI if the scan itself fails.
    }
  }

  Future<void> _loadFiles() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final files =
          await vaultListFiles(handle: widget.vaultHandle);
      if (mounted) {
        setState(() {
          _files = files;
          _loading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _loading = false;
        });
      }
    }
  }

  Future<void> _addFile() async {
    _isPickingFile = true;
    try {
      final result = await FilePicker.pickFiles(
          allowMultiple: false);
      if (result == null || result.files.isEmpty) return;
      final file = result.files.first;
      if (file.path == null) return;

      setState(() => _loading = true);
      await vaultAddFile(
        handle: widget.vaultHandle,
        sourceFilePath: file.path!,
        originalName: file.name,
      );

      // Delete the temporary copy that FilePicker placed in the app cache.
      // Without this, the cache grows by the file size on every import.
      try {
        final tempFile = File(file.path!);
        if (await tempFile.exists()) {
          await tempFile.delete();
        }
      } catch (_) {
        // Deletion failure is non-fatal — the vault already has the file.
      }

      await _loadFiles();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
              content: Text('Failed to add file: $e'),
              backgroundColor: const Color.fromARGB(255, 253, 50, 50)),
        );
        setState(() => _loading = false);
      }
    } finally {
      _isPickingFile = false;
    }
  }

  Future<void> _deleteFile(VaultFileEntry entry) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: context.ac.card,
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16)),
        title: Text('Delete file?',
            style: TextStyle(color: context.ac.text)),
        content: Text(
          'Permanently delete "${entry.originalName}" from the vault?\nThis cannot be undone.',
          style: TextStyle(
              color: context.ac.textSecondary, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('CANCEL'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('DELETE',
                style: TextStyle(color: Color.fromARGB(255, 255, 50, 50))),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      setState(() => _loading = true);
      await vaultDeleteFile(
          handle: widget.vaultHandle,
          obfuscatedName: entry.obfuscatedName);
      await _loadFiles();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
              content: Text('Failed to delete: $e'),
              backgroundColor: const Color.fromARGB(255, 252, 43, 43)),
        );
        setState(() => _loading = false);
      }
    }
  }

  Future<void> _lockAndExit() async {
    await vaultLock(handle: widget.vaultHandle);
    if (mounted) {
      Navigator.of(context).popUntil((r) => r.isFirst);
    }
  }

  IconData _iconForFile(String name) {
    final ext = name.contains('.') ? name.split('.').last.toLowerCase() : '';
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'heic'].contains(ext)) {
      return Icons.image_rounded;
    }
    if (['mp4', 'mov', 'avi', 'mkv', 'webm'].contains(ext)) {
      return Icons.movie_rounded;
    }
    if (['mp3', 'wav', 'flac', 'aac', 'm4a'].contains(ext)) {
      return Icons.music_note_rounded;
    }
    if (['pdf'].contains(ext)) {
      return Icons.picture_as_pdf_rounded;
    }
    if (['doc', 'docx', 'txt', 'md'].contains(ext)) {
      return Icons.description_rounded;
    }
    if (['zip', 'rar', '7z', 'tar', 'gz'].contains(ext)) {
      return Icons.folder_zip_rounded;
    }
    return Icons.insert_drive_file_rounded;
  }

  @override
  Widget build(BuildContext context) {
    final primary = Theme.of(context).colorScheme.primary;
    return Scaffold(
      appBar: AppBar(
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_forward_ios_rounded,
              size: 18),
          onPressed: () => Navigator.push(context, _slideRoute(VaultNavigationDrawer(vaultName: widget.vaultName, onSettings: () {
            Navigator.pop(context);
            Navigator.push(
                context, _slideRoute(SettingsScreen(directoryPath: widget.directoryPath)));
          },),),)
        ),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              widget.vaultName.toUpperCase(),
              style: const TextStyle(
                  fontSize: 14,
                  letterSpacing: 2,
                  fontWeight: FontWeight.bold),
            ),
            Text(
              '${_files.length} file${_files.length != 1 ? 's' : ''}',
              style: TextStyle(
                  fontSize: 11, color: primary),
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Lock vault',
            icon: Icon(Icons.lock_rounded,
                color: primary),
            onPressed: _lockAndExit,
          ),
          IconButton(
            tooltip: 'Refresh',
            icon: Icon(Icons.refresh_rounded,
                color: context.ac.textSecondary),
            onPressed: _loadFiles,
          ),
        ],
      ),
      drawer: VaultNavigationDrawer(
        vaultName: widget.vaultName,
        onSettings: () {
          Navigator.pop(context);
          Navigator.push(
              context, _slideRoute(SettingsScreen(directoryPath: widget.directoryPath)));
        },
      ),
      body: _buildBody(),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _addFile,
        backgroundColor: primary,
        foregroundColor: Theme.of(context).scaffoldBackgroundColor,
        icon: const Icon(Icons.add_rounded),
        label: const Text('ADD FILE',
            style: TextStyle(
                fontWeight: FontWeight.bold, letterSpacing: 1)),
      ),
    );
  }

  Widget _buildBody() {
    final primary = Theme.of(context).colorScheme.primary;
    if (_loading) {
      return Center(
          child: CircularProgressIndicator(
              color: primary));
    }
    if (_error != null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline_rounded,
                color: Color(0xFFFF5252), size: 48),
            const SizedBox(height: 12),
            Text(_error!,
                style:
                    TextStyle(color: context.ac.textSecondary),
                textAlign: TextAlign.center),
            const SizedBox(height: 16),
            OutlinedButton(
                onPressed: _loadFiles,
                child: const Text('RETRY')),
          ],
        ),
      );
    }
    if (_files.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.shield_rounded,
                size: 64,
                color: primary.withValues(alpha: 0.3)),
            const SizedBox(height: 16),
            Text('Vault is empty',
                style: TextStyle(
                    color: context.ac.textSecondary, fontSize: 16)),
            const SizedBox(height: 8),
            Text(
                'Tap + ADD FILE to encrypt your first file',
                style: TextStyle(
                    color: context.ac.textMuted, fontSize: 13)),
          ],
        ),
      );
    }
    return ListView.separated(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 100),
      itemCount: _files.length,
      separatorBuilder: (_, __) =>
          Divider(color: context.ac.divider, height: 1),
      itemBuilder: (ctx, i) {
        final entry = _files[i];
        return Dismissible(
          key: Key(entry.obfuscatedName),
          direction: DismissDirection.endToStart,
          confirmDismiss: (_) async {
            await _deleteFile(entry);
            return false; // deletion handled manually
          },
          background: Container(
            color: const Color(0xFFFF5252).withValues(alpha: 0.15),
            alignment: Alignment.centerRight,
            padding: const EdgeInsets.only(right: 20),
            child: const Icon(Icons.delete_rounded,
                color: Color(0xFFFF5252)),
          ),
          child: ListTile(
            contentPadding: const EdgeInsets.symmetric(
                horizontal: 4, vertical: 6),
            leading: Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                color: primary.withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Icon(_iconForFile(entry.originalName),
                  color: primary, size: 22),
            ),
            title: Text(
              entry.originalName,
              style: TextStyle(
                  color: context.ac.text, fontSize: 14),
              overflow: TextOverflow.ellipsis,
            ),
            subtitle: Text(
              entry.obfuscatedName,
              style: TextStyle(
                  color: context.ac.textMuted,
                  fontSize: 11,
                  fontFamily: 'monospace'),
              overflow: TextOverflow.ellipsis,
            ),
            trailing: Icon(Icons.chevron_right_rounded,
                color: context.ac.textMuted),
            onTap: () {
              // TODO: show file action sheet (extract / preview)
            },
          ),
        );
      },
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// NAVIGATION DRAWER
// ─────────────────────────────────────────────────────────────────────────────

class VaultNavigationDrawer extends StatelessWidget {
  final String vaultName;
  final VoidCallback onSettings;

  const VaultNavigationDrawer(
      {super.key,
      required this.vaultName,
      required this.onSettings});

  @override
  Widget build(BuildContext context) {
    final primary = Theme.of(context).colorScheme.primary;
    return Drawer(
      child: SafeArea(
        child: Column(
          children: [
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                border: Border(
                    bottom:
                        BorderSide(color: context.ac.divider)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(Icons.lock_rounded,
                      color: primary, size: 28),
                  const SizedBox(height: 12),
                  Text(
                    vaultName,
                    style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: context.ac.text,
                        letterSpacing: 1),
                  ),
                  const SizedBox(height: 4),
                  Text('Active vault',
                      style: TextStyle(
                          fontSize: 12,
                          color: primary)),
                ],
              ),
            ),
            const Expanded(child: SizedBox()),
            Divider(color: context.ac.divider),
            ListTile(
              leading: Icon(Icons.settings_rounded,
                  color: context.ac.textSecondary),
              title: Text('Settings',
                  style: TextStyle(color: context.ac.textSecondary)),
              onTap: onSettings,
            ),
          ],
        ),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// THEME SYSTEM
//   • AppThemeMode      – every selectable theme (+ "system")
//   • _ThemePalette     – all colours of one theme (dark OR light)
//   • AppColors         – ThemeExtension so widgets read colours via
//                         `context.ac.*` instead of hardcoded hex values
//   • AppThemes         – builds ThemeData (+ OLED variants) from palettes
//   • ThemeNotifier / OledNotifier – persisted choices (loaded synchronously,
//                         so there is no flash of the default theme at launch)
// ─────────────────────────────────────────────────────────────────────────────

/// Set in main() with the already-loaded SharedPreferences instance.
final sharedPreferencesProvider = Provider<SharedPreferences>(
  (ref) => throw UnimplementedError(
      'sharedPreferencesProvider must be overridden in main()'),
);

// NOTE: enum *names* are persisted in SharedPreferences – never rename them.
enum AppThemeMode {
  xenonyptDark,
  amberLight,
  amberDark,
  purpleLight,
  darkPurple,
  darkGold,
  darkXenonypt,
  xenonyptLight,
  system,
}

final currentThemeProvider =
    NotifierProvider<ThemeNotifier, AppThemeMode>(ThemeNotifier.new);

/// Semantic colours that Material's ColorScheme has no slot for.
@immutable
class AppColors extends ThemeExtension<AppColors> {
  const AppColors({
    required this.text,
    required this.textSecondary,
    required this.textMuted,
    required this.border,
    required this.divider,
    required this.card,
  });

  final Color text; // primary text / titles
  final Color textSecondary; // subtitles, descriptions
  final Color textMuted; // hints, disabled, tertiary
  final Color border; // outlines, sheet handles, dialog borders
  final Color divider; // dividers, unfilled bars
  final Color card; // dialogs / raised containers

  @override
  AppColors copyWith({
    Color? text,
    Color? textSecondary,
    Color? textMuted,
    Color? border,
    Color? divider,
    Color? card,
  }) {
    return AppColors(
      text: text ?? this.text,
      textSecondary: textSecondary ?? this.textSecondary,
      textMuted: textMuted ?? this.textMuted,
      border: border ?? this.border,
      divider: divider ?? this.divider,
      card: card ?? this.card,
    );
  }

  @override
  AppColors lerp(ThemeExtension<AppColors>? other, double t) {
    if (other is! AppColors) return this;
    return AppColors(
      text: Color.lerp(text, other.text, t)!,
      textSecondary: Color.lerp(textSecondary, other.textSecondary, t)!,
      textMuted: Color.lerp(textMuted, other.textMuted, t)!,
      border: Color.lerp(border, other.border, t)!,
      divider: Color.lerp(divider, other.divider, t)!,
      card: Color.lerp(card, other.card, t)!,
    );
  }
}

extension AppColorsContext on BuildContext {
  AppColors get ac => Theme.of(this).extension<AppColors>()!;
}

class _ThemePalette {
  final Brightness brightness;
  final Color primary;
  final Color secondary;
  final Color background;
  final Color surface;
  final Color? onPrimaryOverride;
  final Color error;
  final Color text;
  final Color textSecondary;
  final Color textMuted;
  final Color border;
  final Color divider;
  final Color card;

  const _ThemePalette({
    required this.primary,
    required this.secondary,
    required this.background,
    required this.surface,
    this.brightness = Brightness.dark,
    this.onPrimaryOverride,
    this.error = const Color(0xFFFF3E3E),
    this.text = const Color(0xFFCFE8FF),
    this.textSecondary = const Color(0xFF7A95B0),
    this.textMuted = const Color(0xFF3D5166),
    this.border = const Color(0xFF2A3A4A),
    this.divider = const Color(0xFF1E2D3D),
    this.card = const Color(0xFF0E1318),
  });

  /// Text/icon colour drawn on top of [primary] (buttons, FAB…).
  Color get onPrimary =>
      onPrimaryOverride ??
      (brightness == Brightness.dark ? background : Colors.white);

  /// Same theme with pure-black backgrounds (OLED). Dark themes only.
  _ThemePalette toOled() => _ThemePalette(
        brightness: brightness,
        primary: primary,
        secondary: secondary,
        background: Colors.black,
        surface: const Color(0xFF0A0A0A),
        onPrimaryOverride: onPrimary,
        error: error,
        text: text,
        textSecondary: textSecondary,
        textMuted: textMuted,
        border: border,
        divider: divider,
        card: const Color(0xFF0A0A0A),
      );
}

class AppThemes {
  static const Map<AppThemeMode, _ThemePalette> _palettes = {
    // ── Xenonypt ──
    AppThemeMode.xenonyptDark: _ThemePalette(
      primary: Color.fromARGB(255, 28, 183, 255),
      secondary: Color(0xFF00E5CC),
      background: Color.fromARGB(255, 9, 12, 17),
      surface: Color.fromARGB(255, 6, 9, 11),
    ),
    AppThemeMode.darkXenonypt: _ThemePalette(
      primary: Color(0xFF4FC3F7),
      secondary: Color(0xFF29B6F6),
      background: Color.fromARGB(255, 6, 9, 12),
      surface: Color(0xFF06090B),
    ),
    AppThemeMode.xenonyptLight: _ThemePalette(
      brightness: Brightness.light,
      primary: Color(0xFF0277BD),
      secondary: Color(0xFF00897B),
      background: Color(0xFFF4F8FB),
      surface: Color(0xFFFFFFFF),
      error: Color(0xFFD32F2F),
      text: Color(0xFF0D1B2A),
      textSecondary: Color(0xFF4A6178),
      textMuted: Color(0xFF8DA2B5),
      border: Color(0xFFC5D3E0),
      divider: Color(0xFFDCE6EF),
      card: Color(0xFFFFFFFF),
    ),
    // ── Amber ──
    AppThemeMode.amberLight: _ThemePalette(
      brightness: Brightness.light,
      primary: Color(0xFFC77800),
      secondary: Color(0xFFFFB300),
      background: Color(0xFFFFF9EE),
      surface: Color(0xFFFFFFFF),
      error: Color(0xFFD32F2F),
      text: Color(0xFF2B2113),
      textSecondary: Color(0xFF6B5A3E),
      textMuted: Color(0xFFA8977A),
      border: Color(0xFFE6D8BC),
      divider: Color(0xFFF0E4CB),
      card: Color(0xFFFFFFFF),
    ),
    AppThemeMode.amberDark: _ThemePalette(
      primary: Color(0xFFFFA000),
      secondary: Color.fromARGB(255, 213, 146, 39),
      background: Color.fromARGB(255, 15, 10, 5),
      surface: Color(0xFF090601),
    ),
    // ── Purple ──
    AppThemeMode.purpleLight: _ThemePalette(
      brightness: Brightness.light,
      primary: Color(0xFF7B1FA2),
      secondary: Color(0xFFAB47BC),
      background: Color(0xFFF8F3FB),
      surface: Color(0xFFFFFFFF),
      error: Color(0xFFD32F2F),
      text: Color(0xFF1E1226),
      textSecondary: Color(0xFF5E4A6E),
      textMuted: Color(0xFF9C8BAA),
      border: Color(0xFFDCCBE8),
      divider: Color(0xFFEADFF2),
      card: Color(0xFFFFFFFF),
    ),
    AppThemeMode.darkPurple: _ThemePalette(
      primary: Color(0xFF673AB7),
      secondary: Color(0xFF7C4DFF),
      background: Color.fromARGB(255, 10, 6, 18),
      surface: Color(0xFF060410),
    ),
    // ── Gold ──
    AppThemeMode.darkGold: _ThemePalette(
      primary: Color(0xFFFFD54F),
      secondary: Color(0xFFFFEB3B),
      background: Color.fromARGB(255, 14, 11, 4),
      surface: Color(0xFF090701),
    ),
  };

  /// Regular themes (every mode except `system`).
  static final Map<AppThemeMode, ThemeData> themes = {
    for (final e in _palettes.entries) e.key: _buildTheme(e.value),
  };

  /// Pure-black variants of the dark themes.
  static final Map<AppThemeMode, ThemeData> _oledThemes = {
    for (final e in _palettes.entries)
      if (e.value.brightness == Brightness.dark)
        e.key: _buildTheme(e.value.toOled()),
  };

  /// Resolves a mode to ThemeData. [mode] must not be `system`
  /// (XenonyptApp handles that one via MaterialApp.themeMode).
  static ThemeData themeFor(AppThemeMode mode, {bool oled = false}) {
    assert(mode != AppThemeMode.system);
    if (oled) {
      final t = _oledThemes[mode];
      if (t != null) return t;
    }
    return themes[mode]!;
  }

  /// Order shown in the theme picker.
  static const List<AppThemeMode> pickerOrder = [
    AppThemeMode.system,
    AppThemeMode.xenonyptDark,
    AppThemeMode.darkXenonypt,
    AppThemeMode.xenonyptLight,
    AppThemeMode.amberDark,
    AppThemeMode.amberLight,
    AppThemeMode.darkPurple,
    AppThemeMode.purpleLight,
    AppThemeMode.darkGold,
  ];

  /// Accent colour for the picker swatch (null for `system`).
  static Color? swatch(AppThemeMode mode) => _palettes[mode]?.primary;

  /// null for `system`.
  static Brightness? brightnessOf(AppThemeMode mode) =>
      _palettes[mode]?.brightness;

  /// The dark/light sibling used by the "Dark mode" switch.
  static AppThemeMode counterpart(AppThemeMode mode) {
    switch (mode) {
      case AppThemeMode.xenonyptDark:
      case AppThemeMode.darkXenonypt:
        return AppThemeMode.xenonyptLight;
      case AppThemeMode.xenonyptLight:
        return AppThemeMode.xenonyptDark;
      case AppThemeMode.amberLight:
        return AppThemeMode.amberDark;
      case AppThemeMode.amberDark:
      case AppThemeMode.darkGold:
        return AppThemeMode.amberLight;
      case AppThemeMode.purpleLight:
        return AppThemeMode.darkPurple;
      case AppThemeMode.darkPurple:
        return AppThemeMode.purpleLight;
      case AppThemeMode.system:
        return AppThemeMode.system;
    }
  }

  static String label(AppThemeMode mode) {
    switch (mode) {
      case AppThemeMode.system:
        return 'System default';
      case AppThemeMode.xenonyptDark:
        return 'Xenonypt (Default)';
      case AppThemeMode.darkXenonypt:
        return 'Xenonypt Cyan';
      case AppThemeMode.xenonyptLight:
        return 'Xenonypt Light';
      case AppThemeMode.amberLight:
        return 'Amber Light';
      case AppThemeMode.amberDark:
        return 'Amber Dark';
      case AppThemeMode.purpleLight:
        return 'Purple Light';
      case AppThemeMode.darkPurple:
        return 'Deep Purple';
      case AppThemeMode.darkGold:
        return 'Gold';
    }
  }

  static ThemeData _buildTheme(_ThemePalette p) {
    final isDark = p.brightness == Brightness.dark;
    final scheme = isDark
        ? ColorScheme.dark(
            primary: p.primary,
            onPrimary: p.onPrimary,
            secondary: p.secondary,
            onSecondary: p.onPrimary,
            surface: p.surface,
            onSurface: p.text,
            error: p.error,
            onError: Colors.white,
            outline: p.border,
            outlineVariant: p.divider,
          )
        : ColorScheme.light(
            primary: p.primary,
            onPrimary: p.onPrimary,
            secondary: p.secondary,
            onSecondary: p.onPrimary,
            surface: p.surface,
            onSurface: p.text,
            error: p.error,
            onError: Colors.white,
            outline: p.border,
            outlineVariant: p.divider,
          );

    OutlineInputBorder outline(Color c, [double w = 1.0]) => OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: c, width: w),
        );

    return ThemeData(
      useMaterial3: true,
      brightness: p.brightness,
      scaffoldBackgroundColor: p.background,
      colorScheme: scheme,
      fontFamily: 'monospace',
      extensions: <ThemeExtension<dynamic>>[
        AppColors(
          text: p.text,
          textSecondary: p.textSecondary,
          textMuted: p.textMuted,
          border: p.border,
          divider: p.divider,
          card: p.card,
        ),
      ],
      appBarTheme: AppBarTheme(
        backgroundColor: p.background,
        elevation: 0,
        scrolledUnderElevation: 0,
        surfaceTintColor: Colors.transparent,
        foregroundColor: p.text,
        // Status-bar icons must contrast with the app bar in light themes.
        systemOverlayStyle:
            (isDark ? SystemUiOverlayStyle.light : SystemUiOverlayStyle.dark)
                .copyWith(statusBarColor: Colors.transparent),
      ),
      drawerTheme: DrawerThemeData(
        backgroundColor: p.surface,
        surfaceTintColor: Colors.transparent,
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: p.surface,
        surfaceTintColor: Colors.transparent,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      ),
      bottomSheetTheme: BottomSheetThemeData(
        backgroundColor: p.surface,
        surfaceTintColor: Colors.transparent,
        shape: const RoundedRectangleBorder(
            borderRadius: BorderRadius.vertical(top: Radius.circular(24))),
      ),
      dividerTheme: DividerThemeData(color: p.divider),
      listTileTheme: ListTileThemeData(
        textColor: p.text,
        iconColor: p.primary,
      ),
      progressIndicatorTheme: ProgressIndicatorThemeData(color: p.primary),
      textSelectionTheme: TextSelectionThemeData(
        cursorColor: p.primary,
        selectionHandleColor: p.primary,
        selectionColor: p.primary.withValues(alpha: 0.30),
      ),
      floatingActionButtonTheme: FloatingActionButtonThemeData(
        backgroundColor: p.primary,
        foregroundColor: p.onPrimary,
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(foregroundColor: p.primary),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: p.surface,
        contentPadding:
            const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
        border: outline(p.border),
        enabledBorder: outline(p.border),
        focusedBorder: outline(p.primary, 1.5),
        errorBorder: outline(p.error),
        focusedErrorBorder: outline(p.error, 1.5),
        labelStyle: TextStyle(color: p.textSecondary),
        hintStyle: TextStyle(color: p.textMuted),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: p.primary,
          foregroundColor: p.onPrimary,
          padding: const EdgeInsets.symmetric(vertical: 16),
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          textStyle: const TextStyle(
              fontWeight: FontWeight.bold, fontSize: 15, letterSpacing: 1.2),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: p.primary,
          side: BorderSide(color: p.primary),
          padding: const EdgeInsets.symmetric(vertical: 16),
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          textStyle: const TextStyle(
              fontWeight: FontWeight.bold, fontSize: 15, letterSpacing: 1.2),
        ),
      ),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: p.surface,
        contentTextStyle: TextStyle(color: p.text),
      ),
    );
  }
}

class ThemeNotifier extends Notifier<AppThemeMode> {
  static const _key = 'selected_theme';

  @override
  AppThemeMode build() {
    final saved = ref.read(sharedPreferencesProvider).getString(_key);
    return AppThemeMode.values.firstWhere(
      (m) => m.name == saved,
      orElse: () => AppThemeMode.xenonyptDark,
    );
  }

  void setTheme(AppThemeMode mode) {
    state = mode;
    unawaited(ref.read(sharedPreferencesProvider).setString(_key, mode.name));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// OLED / TRUE DARK PROVIDER
// ─────────────────────────────────────────────────────────────────────────────

final trueDarkOledProvider =
    NotifierProvider<OledNotifier, bool>(OledNotifier.new);

class OledNotifier extends Notifier<bool> {
  static const _key = 'true_dark_oled';

  @override
  bool build() =>
      ref.read(sharedPreferencesProvider).getBool(_key) ?? false;

  void setOled(bool val) {
    state = val;
    unawaited(ref.read(sharedPreferencesProvider).setBool(_key, val));
  }
}



// ─────────────────────────────────────────────────────────────────────────────
// SETTINGS SCREEN
// ─────────────────────────────────────────────────────────────────────────────

class SettingsScreen extends ConsumerStatefulWidget {
  final String directoryPath;
  const SettingsScreen({super.key, required this.directoryPath});

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  bool _enableBiometric = false;
  bool _isBiometricSupported = false;
  bool _isLoading = false;

  @override
  void initState() {
    super.initState();
    _checkBiometricSupport();
    _loadBiometricPreference();
  }

  Future<void> _checkBiometricSupport() async {
    try {
      final response = await BiometricStorage().canAuthenticate();
      if (mounted) {
        setState(() => _isBiometricSupported =
            response == CanAuthenticateResponse.success);
      }
    } catch (_) {
      if (mounted) setState(() => _isBiometricSupported = false);
    }
  }

  Future<void> _loadBiometricPreference() async {
    final prefs = await SharedPreferences.getInstance();
    final enabled =
        prefs.getBool(_bioEnabledKey(widget.directoryPath)) ?? false;
    if (mounted) {
      setState(() => _enableBiometric = enabled);
    }
  }

  Future<void> _handleBiometricToggle(bool val) async {
    if (val) {
      // Biometrikanı aktivləşdirmək üçün şifrə tələb olunur
      final password = await _showPasswordPromptDialog();
      if (password == null || password.isEmpty) return;

      setState(() => _isLoading = true);
      try {
        // Şifrənin düzgünlüyünü yoxlamaq üçün vault-u açmağa cəhd edirik
        final handle = await vaultUnlock(
            vaultDir: widget.directoryPath, password: password);
        await vaultLock(handle: handle);

        // Uğurludursa, biometrik saxlanca yazırıq
        final prefs = await SharedPreferences.getInstance();
        await prefs.setBool(_bioEnabledKey(widget.directoryPath), true);
        
        final storage = await _bioStorage(widget.directoryPath);
        await storage.write(password);

        if (mounted) {
          setState(() => _enableBiometric = true);
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Biometric login enabled successfully')),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Wrong password or biometric error: $e'),
              backgroundColor: const Color(0xFFFF5252),
            ),
          );
        }
      } finally {
        if (mounted) setState(() => _isLoading = false);
      }
    } else {
      // Biometrikanı söndürürük
      setState(() => _isLoading = true);
      try {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setBool(_bioEnabledKey(widget.directoryPath), false);
        
        // Saxlanılan biometrik məlumatı təmizləyirik
        final storage = await _bioStorage(widget.directoryPath);
        await storage.delete();

        if (mounted) {
          setState(() => _enableBiometric = false);
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Biometric login disabled')),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Error disabling biometric: $e'),
              backgroundColor: const Color(0xFFFF5252),
            ),
          );
        }
      } finally {
        if (mounted) setState(() => _isLoading = false);
      }
    }
  }

  Future<String?> _showPasswordPromptDialog() async {
    final passwordController = TextEditingController();
    bool obscure = true;

    return showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          backgroundColor: context.ac.card,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
          title: Text('Confirm Password',
              style: TextStyle(color: context.ac.text)),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'Enter your vault password to enable biometric login.',
                style: TextStyle(color: context.ac.textSecondary, fontSize: 13),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: passwordController,
                obscureText: obscure,
                autofocus: true,
                decoration: InputDecoration(
                  labelText: 'Password',
                  prefixIcon: Icon(Icons.lock_rounded, color: Theme.of(context).colorScheme.primary),
                  suffixIcon: IconButton(
                    icon: Icon(obscure ? Icons.visibility_off : Icons.visibility,
                        color: Theme.of(context).colorScheme.primary),
                    onPressed: () => setDialogState(() => obscure = !obscure),
                  ),
                ),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, null),
              child: const Text('CANCEL'),
            ),
            ElevatedButton(
              onPressed: () => Navigator.pop(ctx, passwordController.text),
              child: const Text('CONFIRM'),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final primary = Theme.of(context).colorScheme.primary;
    final isDarkMode = Theme.of(context).brightness == Brightness.dark;
    return Scaffold(
      appBar: AppBar(
        elevation: 0,
        title: const Text('SETTINGS',
            style: TextStyle(
                fontSize: 14,
                letterSpacing: 3,
                fontWeight: FontWeight.bold)),
        centerTitle: true,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: _isLoading
          ? Center(child: CircularProgressIndicator(color: primary))
          : ListView(
              children: [
                const _SettingsHeader(title: 'APPEARANCE'),
                ListTile(
                  leading: Icon(Icons.palette_rounded, color: primary),
                  title: Text('Theme', style: TextStyle(color: context.ac.text)),
                  subtitle: Text(AppThemes.label(ref.watch(currentThemeProvider)),
                      style: TextStyle(color: context.ac.textSecondary, fontSize: 12)),
                  trailing: Icon(Icons.chevron_right_rounded,
                      color: context.ac.textSecondary),
                  onTap: _pickTheme,
                ),
                SwitchListTile(
                  secondary: Icon(Icons.brightness_6_rounded, color: primary),
                  title: Text('Dark mode',
                      style: TextStyle(color: context.ac.text)),
                  subtitle: Text('Switch between dark and light',
                      style: TextStyle(
                          color: context.ac.textSecondary, fontSize: 12)),
                  value: isDarkMode,
                  onChanged: (val) {
                    final cur = ref.read(currentThemeProvider);
                    final next = cur == AppThemeMode.system
                        ? (val
                            ? AppThemeMode.xenonyptDark
                            : AppThemeMode.xenonyptLight)
                        : AppThemes.counterpart(cur);
                    ref.read(currentThemeProvider.notifier).setTheme(next);
                  },
                ),
                SwitchListTile(
                  secondary:
                      Icon(Icons.brightness_1_rounded, color: primary),
                  title: Text('True dark / OLED',
                      style: TextStyle(color: context.ac.text)),
                  subtitle: Text(
                      isDarkMode
                          ? 'Pure black backgrounds'
                          : 'Available in dark themes',
                      style: TextStyle(
                          color: context.ac.textSecondary, fontSize: 12)),
                  value: ref.watch(trueDarkOledProvider),
                  onChanged: isDarkMode
                      ? (val) =>
                          ref.read(trueDarkOledProvider.notifier).setOled(val)
                      : null,
                ),
                Divider(color: context.ac.divider),
                const _SettingsHeader(title: 'SECURITY'),
                _buildTile(Icons.enhanced_encryption_rounded,
                    'Encryption', 'AES-256-GCM + Argon2id'),
                if (_isBiometricSupported)
                  SwitchListTile(
                    secondary: Icon(Icons.fingerprint_rounded,
                        color: primary),
                    title: Text('Biometric login',
                        style: TextStyle(color: context.ac.text)),
                    subtitle: Text('Enable or disable for this vault',
                        style: TextStyle(color: context.ac.textSecondary, fontSize: 12)),
                    value: _enableBiometric,
                    onChanged: _handleBiometricToggle,
                  ),
                Divider(color: context.ac.divider),
                const _SettingsHeader(title: 'ABOUT'),
                _buildTile(Icons.language_rounded, 'Language', 'English'),
                _buildTile(Icons.code_rounded, 'Source code', 'Version: alpha'),
                _buildTile(Icons.book_rounded, 'Third-party libraries', ''),
                const SizedBox(height: 8),
                ListTile(
                  leading: const Icon(Icons.workspace_premium_rounded,
                      color: Colors.amber),
                  title: const Text('Premium',
                      style: TextStyle(
                          color: Colors.amber, fontWeight: FontWeight.bold)),
                  subtitle: Text('Unlock advanced features',
                      style: TextStyle(color: context.ac.textSecondary, fontSize: 12)),
                  onTap: () {},
                ),
              ],
            ),
    );
  }

  Future<void> _pickTheme() async {
    final current = ref.read(currentThemeProvider);
    final selected = await showModalBottomSheet<AppThemeMode>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) {
        final sheetPrimary = Theme.of(ctx).colorScheme.primary;
        return SafeArea(
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const SizedBox(height: 8),
                for (final mode in AppThemes.pickerOrder)
                  ListTile(
                    leading: AppThemes.swatch(mode) == null
                        ? Icon(Icons.brightness_auto_rounded,
                            color: sheetPrimary)
                        : Container(
                            width: 24,
                            height: 24,
                            decoration: BoxDecoration(
                              color: AppThemes.swatch(mode),
                              shape: BoxShape.circle,
                              border: Border.all(color: ctx.ac.border),
                            ),
                          ),
                    title: Text(AppThemes.label(mode),
                        style: TextStyle(color: ctx.ac.text)),
                    subtitle: Text(
                        switch (AppThemes.brightnessOf(mode)) {
                          Brightness.dark => 'Dark',
                          Brightness.light => 'Light',
                          null => 'Follows your device',
                        },
                        style: TextStyle(
                            color: ctx.ac.textSecondary, fontSize: 12)),
                    trailing: mode == current
                        ? Icon(Icons.check_circle_rounded, color: sheetPrimary)
                        : null,
                    onTap: () => Navigator.pop(ctx, mode),
                  ),
                const SizedBox(height: 8),
              ],
            ),
          ),
        );
      },
    );
    if (selected != null) {
      ref.read(currentThemeProvider.notifier).setTheme(selected);
    }
  }

  Widget _buildTile(IconData icon, String title, String subtitle) {
    final primary = Theme.of(context).colorScheme.primary;
    return ListTile(
      leading: Icon(icon, color: primary),
      title: Text(title, style: TextStyle(color: context.ac.text)),
      subtitle: subtitle.isNotEmpty
          ? Text(subtitle,
              style: TextStyle(color: context.ac.textSecondary, fontSize: 12))
          : null,
      onTap: () {},
    );
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// SHARED WIDGETS
// ─────────────────────────────────────────────────────────────────────────────

class _SettingsHeader extends StatelessWidget {
  final String title;
  const _SettingsHeader({required this.title});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(left: 16, top: 20, bottom: 4),
      child: Text(
        title,
        style: TextStyle(
          color: Theme.of(context).colorScheme.primary,
          fontWeight: FontWeight.bold,
          fontSize: 11,
          letterSpacing: 2,
        ),
      ),
    );
  }
}

class _InfoRow extends StatelessWidget {
  final IconData icon;
  final String label;
  const _InfoRow(this.icon, this.label);

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Icon(icon, size: 16, color: Theme.of(context).colorScheme.secondary),
        const SizedBox(width: 10),
        Expanded(
          child: Text(label,
              style: TextStyle(
                  fontSize: 13, color: context.ac.textSecondary)),
        ),
      ],
    );
  }
}

class _PasswordStrengthBar extends StatelessWidget {
  final int strength; // 0–4
  const _PasswordStrengthBar({required this.strength});

  @override
  Widget build(BuildContext context) {
    const labels = ['', 'Weak', 'Fair', 'Strong', 'Very strong'];
    // Strength colours are semantic (red -> cyan) and stay theme-independent;
    // only the unfilled track follows the theme.
    final colors = [
      context.ac.divider,
      const Color(0xFFFF5252),
      const Color(0xFFFFB347),
      const Color.fromARGB(255, 79, 195, 247),
      const Color.fromARGB(255, 0, 229, 204),
    ];
    return Row(
      children: [
        Expanded(
          child: Row(
            children: List.generate(4, (i) {
              return Expanded(
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 250),
                  height: 4,
                  margin: const EdgeInsets.only(right: 4),
                  decoration: BoxDecoration(
                    color: i < strength
                        ? colors[strength]
                        : context.ac.divider,
                    borderRadius: BorderRadius.circular(2),
                  ),
                ),
              );
            }),
          ),
        ),
        const SizedBox(width: 10),
        SizedBox(
          width: 70,
          child: Text(
            strength > 0 ? labels[strength] : '',
            style: TextStyle(
                fontSize: 11,
                color: colors[strength],
                fontWeight: FontWeight.bold),
            textAlign: TextAlign.right,
          ),
        ),
      ],
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// NAVIGATION HELPERS
// ─────────────────────────────────────────────────────────────────────────────

PageRouteBuilder<T> _slideRoute<T>(Widget page) {
  return PageRouteBuilder<T>(
    pageBuilder: (_, __, ___) => page,
    transitionsBuilder: (_, anim, __, child) {
      final tween = Tween(
              begin: const Offset(1.0, 0.0), end: Offset.zero)
          .chain(CurveTween(curve: Curves.easeOutCubic));
      return SlideTransition(
          position: anim.drive(tween), child: child);
    },
    transitionDuration: const Duration(milliseconds: 320),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// MANAGE EXTERNAL STORAGE PERMISSION DIALOG
// ─────────────────────────────────────────────────────────────────────────────

class ManageStoragePermissionDialog extends StatelessWidget {
  const ManageStoragePermissionDialog({super.key});

  Future<void> _openStorageSettings(BuildContext context) async {
    final nav = Navigator.of(context);
    try {
      final status = await Permission.manageExternalStorage.request();
      if (!status.isGranted && Platform.isAndroid) {
        try {
          const intent = AndroidIntent(
            action: 'android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION',
            data: 'package:com.example.xenonypt',
          );
          await intent.launch();
        } catch (_) {
          await openAppSettings();
        }
      }
    } catch (_) {
      if (Platform.isAndroid) {
        try {
          const intent = AndroidIntent(
            action: 'android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION',
            data: 'package:com.example.xenonypt',
          );
          await intent.launch();
        } catch (_) {
          await openAppSettings();
        }
      } else {
        await openAppSettings();
      }
    }
    if (nav.mounted) {
      nav.pop();
    }
  }

  @override
  Widget build(BuildContext context) {
    final primary = Theme.of(context).colorScheme.primary;
    return AlertDialog(
      // background comes from dialogTheme (follows theme + OLED)
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
        side: BorderSide(color: context.ac.border, width: 1.5),
      ),
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: primary.withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(
              Icons.folder_special_rounded,
              color: primary,
              size: 28,
            ),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Text(
              'Full Storage Access',
              style: TextStyle(
                color: context.ac.text,
                fontSize: 18,
                fontWeight: FontWeight.bold,
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
      ),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Xenonypt requires All Files Access (MANAGE_EXTERNAL_STORAGE) to securely create, discover, and manage encrypted vaults across your device storage.',
              style: TextStyle(
                color: context.ac.textSecondary,
                fontSize: 14,
                height: 1.5,
                fontFamily: 'monospace',
              ),
            ),
            const SizedBox(height: 14),
            Text(
              'Please grant full storage access in the system settings page to proceed seamlessly.',
              style: TextStyle(
                color: context.ac.textSecondary,
                fontSize: 13,
                height: 1.4,
                fontFamily: 'monospace',
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: Text(
            'Later',
            style: TextStyle(
              color: context.ac.textSecondary,
              fontWeight: FontWeight.w600,
              fontFamily: 'monospace',
            ),
          ),
        ),
        ElevatedButton.icon(
          onPressed: () => _openStorageSettings(context),
          style: ElevatedButton.styleFrom(
            padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(10),
            ),
          ),
          icon: const Icon(Icons.settings_suggest_rounded, size: 18),
          label: const Text(
            'Grant Access',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              fontSize: 14,
              fontFamily: 'monospace',
            ),
          ),
        ),
      ],
    );
  }
}