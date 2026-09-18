import 'dart:async';
import 'dart:io';
import 'dart:math' as dart_math;

import 'package:android_intent_plus/android_intent.dart';
import 'package:biometric_storage/biometric_storage.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_displaymode/flutter_displaymode.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'src/rust/api.dart';
import 'src/rust/frb_generated.dart';
import 'src/rust/vault.dart';

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();

  if(Platform.isAndroid) {
    try{
      await FlutterDisplayMode.setHighRefreshRate();
    } catch (_){
      //nothing 🙂
    }
  }
  runApp(const XenonyptApp());
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURE STORAGE KEY HELPERS
// ─────────────────────────────────────────────────────────────────────────────

// The vault *folder* itself must be as anonymous as the files vault.rs
// already stores inside it (random hex name, no extension) — otherwise a
// human-chosen folder name like "MyVault" or "Private" gives away exactly
// what it is. This mirrors the 16-random-byte hex scheme vault.rs uses for
// obfuscated_name, just generated on the Dart side before the folder exists.+++


String _bioEnabledKey(String path) => 'bio_enabled:$path';

// biometric_storage file names are used as on-disk identifiers by the
// plugin, so keep them filesystem-safe and stable across app restarts.
String _bioStorageName(String path) =>
    'bio_pw_${path.replaceAll(RegExp(r'[^A-Za-z0-9]'), '_')}';

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


class XenonyptApp extends StatelessWidget {
  const XenonyptApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Xenonypt',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF080B0F),
        colorScheme: const ColorScheme.dark(
          primary: Color.fromARGB(255, 28, 183, 255),
          secondary: Color(0xFF00E5CC),
          surface: Color.fromARGB(255, 6, 9, 11),
          error: Color.fromARGB(255, 255, 62, 62),
        ),
        fontFamily: 'monospace',
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: const Color.fromARGB(255, 10, 13, 17),
          contentPadding:
              const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: Color(0xFF2A3A4A)),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: Color(0xFF2A3A4A)),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide:
                const BorderSide(color: Color(0xFF4FC3F7), width: 1.5),
          ),
          errorBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: Color.fromARGB(255, 250, 53, 53)),
          ),
          focusedErrorBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide:
                const BorderSide(color: Color.fromARGB(255, 253, 49, 49), width: 1.5),
          ),
          labelStyle: const TextStyle(color: Color(0xFF7A95B0)),
          hintStyle: const TextStyle(color: Color(0xFF3D5166)),
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color.fromARGB(255, 57, 192, 255),
            foregroundColor: const Color(0xFF080B0F),
            padding: const EdgeInsets.symmetric(vertical: 16),
            shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12)),
            textStyle: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 15,
                letterSpacing: 1.2),
          ),
        ),
        outlinedButtonTheme: OutlinedButtonThemeData(
          style: OutlinedButton.styleFrom(
            foregroundColor: const Color.fromARGB(255, 50, 190, 255),
            side: const BorderSide(color: Color(0xFF4FC3F7)),
            padding: const EdgeInsets.symmetric(vertical: 16),
            shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12)),
            textStyle: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 15,
                letterSpacing: 1.2),
          ),
        ),
        snackBarTheme: const SnackBarThemeData(
          backgroundColor: Color(0xFF1A2530),
          contentTextStyle: TextStyle(color: Color(0xFFCFE8FF)),
        ),
      ),
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
                              color: const Color(0xFF4FC3F7)
                                  .withValues(alpha: _glowAnim.value),
                              width: 1.5,
                            ),
                            boxShadow: [
                              BoxShadow(
                                color: const Color(0xFF4FC3F7).withValues(
                                    alpha: _glowAnim.value * 0.4),
                                blurRadius: 24,
                                spreadRadius: 4,
                              ),
                            ],
                          ),
                          child: const Icon(
                            Icons.lock_outline_rounded,
                            size: 40,
                            color: Color(0xFF4FC3F7),
                          ),
                        ),
                      ),
                      const SizedBox(height: 24),
                      const Text(
                        'XENONYPT',
                        style: TextStyle(
                          fontSize: 28,
                          fontWeight: FontWeight.w900,
                          letterSpacing: 6,
                          color: Color(0xFFCFE8FF),
                        ),
                      ),
                      const SizedBox(height: 10),
                      Text(
                        'Military-grade encrypted vault',
                        style: TextStyle(
                          fontSize: 13,
                          letterSpacing: 2,
                          color: const Color(0xFF4FC3F7)
                              .withValues(alpha: 0.7),
                        ),
                      ),
                    ],
                  ),
                  // ── Feature list ──
                  Container(
                    padding: const EdgeInsets.all(20),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0E1318),
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(color: const Color(0xFF1E2D3D)),
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
                              ? const SizedBox(
                                  width: 18,
                                  height: 18,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: Color(0xFF080B0F),
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
                          color: const Color(0xFF4FC3F7)
                              .withValues(alpha: 0.5),
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
    return Padding(
      padding: EdgeInsets.only(
          bottom: MediaQuery.of(context).viewInsets.bottom),
      child: Container(
        decoration: const BoxDecoration(
          color: Color(0xFF0E1318),
          borderRadius:
              BorderRadius.vertical(top: Radius.circular(24)),
          border: Border(
              top: BorderSide(color: Color(0xFF1E2D3D))),
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
                  color: const Color(0xFF2A3A4A),
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
                    color: const Color(0xFF4FC3F7)
                        .withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: const Icon(Icons.lock_open_rounded,
                      color: Color(0xFF4FC3F7), size: 20),
                ),
                const SizedBox(width: 12),
                const Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('UNLOCK VAULT',
                          style: TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                              letterSpacing: 2,
                              color: Color(0xFFCFE8FF))),
                      SizedBox(height: 2),
                      Text('Existing vault detected',
                          style: TextStyle(
                              fontSize: 12,
                              color: Color(0xFF4FC3F7))),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 6),
            Text(
              widget.directoryPath,
              style: const TextStyle(
                  fontSize: 11,
                  color: Color(0xFF3D5166),
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
                prefixIcon: const Icon(Icons.key_rounded,
                    color: Color(0xFF4FC3F7), size: 20),
                suffixIcon: IconButton(
                  icon: Icon(
                      _obscure
                          ? Icons.visibility_off
                          : Icons.visibility,
                      color: const Color(0xFF4FC3F7),
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
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Color(0xFF080B0F)))
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

class _CreateVaultScreenState extends State<CreateVaultScreen> {
  final _formKey = GlobalKey<FormState>();

  final _nameCtrl = TextEditingController();
  final _pwCtrl = TextEditingController();
  final _confirmPwCtrl = TextEditingController();

  bool _obscurePw = true;
  bool _obscureConfirm = true;
  bool _isBiometricSupported = false;
  bool _enableBiometric = false;
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
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF080B0F),
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
                  color: const Color(0xFF0E1318),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                      color: const Color(0xFF1E2D3D)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.folder_rounded,
                        color: Color(0xFF4FC3F7), size: 16),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        widget.containerPath ?? widget.directoryPath,
                        style: const TextStyle(
                            fontSize: 12,
                            color: Color(0xFF7A95B0),
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
                decoration: const InputDecoration(
                  labelText: 'Vault name (optional)',
                  prefixIcon: Icon(Icons.edit_rounded,
                      color: Color(0xFF4FC3F7), size: 20),
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
                  prefixIcon: const Icon(Icons.lock_rounded,
                      color: Color(0xFF4FC3F7), size: 20),
                  suffixIcon: IconButton(
                    icon: Icon(
                        _obscurePw
                            ? Icons.visibility_off
                            : Icons.visibility,
                        color: const Color(0xFF4FC3F7),
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
                  prefixIcon: const Icon(Icons.lock_rounded,
                      color: Color(0xFF4FC3F7), size: 20),
                  suffixIcon: IconButton(
                    icon: Icon(
                        _obscureConfirm
                            ? Icons.visibility_off
                            : Icons.visibility,
                        color: const Color(0xFF4FC3F7),
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
                    color: const Color(0xFF0E1318),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                        color: const Color(0xFF1E2D3D)),
                  ),
                  child: SwitchListTile(
                    value: _enableBiometric,
                    onChanged: (v) =>
                        setState(() => _enableBiometric = v),
                    activeThumbColor: const Color(0xFF4FC3F7),
                    secondary: const Icon(
                        Icons.fingerprint_rounded,
                        color: Color(0xFF4FC3F7)),
                    title: const Text('Enable biometric login',
                        style: TextStyle(
                            fontSize: 14,
                            color: Color(0xFFCFE8FF))),
                    subtitle: const Text(
                        'Use fingerprint / face to unlock',
                        style: TextStyle(
                            fontSize: 12,
                            color: Color(0xFF7A95B0))),
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
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: Color(0xFF080B0F)))
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
            backgroundColor: const Color(0xFF0E1318),
            shape:
                RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
            title: const Text('Unencrypted file found',
                style: TextStyle(color: Color(0xFFCFE8FF))),
            content: Text(
              '"$name" is sitting in your vault folder but isn\'t encrypted yet. Add it to the vault?',
              style:
                  const TextStyle(color: Color(0xFF7A95B0), fontSize: 13),
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
            backgroundColor: const Color(0xFF0E1318),
            shape:
                RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
            title: const Text('Delete original?',
                style: TextStyle(color: Color(0xFFCFE8FF))),
            content: Text(
              '"$name" was encrypted into the vault. Delete the original plaintext copy?',
              style:
                  const TextStyle(color: Color(0xFF7A95B0), fontSize: 13),
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
        backgroundColor: const Color(0xFF0E1318),
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16)),
        title: const Text('Delete file?',
            style: TextStyle(color: Color(0xFFCFE8FF))),
        content: Text(
          'Permanently delete "${entry.originalName}" from the vault?\nThis cannot be undone.',
          style: const TextStyle(
              color: Color(0xFF7A95B0), fontSize: 13),
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
    return Scaffold(
      backgroundColor: const Color(0xFF080B0F),
      appBar: AppBar(
        backgroundColor: const Color(0xFF080B0F),
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded,
              size: 18),
          onPressed: () => Navigator.pop(context),
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
              style: const TextStyle(
                  fontSize: 11, color: Color(0xFF4FC3F7)),
            ),
          ],
        ),
        actions: [
          IconButton(
            tooltip: 'Lock vault',
            icon: const Icon(Icons.lock_rounded,
                color: Color(0xFF4FC3F7)),
            onPressed: _lockAndExit,
          ),
          IconButton(
            tooltip: 'Refresh',
            icon: const Icon(Icons.refresh_rounded,
                color: Color(0xFF7A95B0)),
            onPressed: _loadFiles,
          ),
        ],
      ),
      drawer: VaultNavigationDrawer(
        vaultName: widget.vaultName,
        onSettings: () {
          Navigator.pop(context);
          Navigator.push(
              context, _slideRoute(const SettingsScreen()));
        },
      ),
      body: _buildBody(),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _addFile,
        backgroundColor: const Color(0xFF4FC3F7),
        foregroundColor: const Color(0xFF080B0F),
        icon: const Icon(Icons.add_rounded),
        label: const Text('ADD FILE',
            style: TextStyle(
                fontWeight: FontWeight.bold, letterSpacing: 1)),
      ),
    );
  }

  Widget _buildBody() {
    if (_loading) {
      return const Center(
          child: CircularProgressIndicator(
              color: Color(0xFF4FC3F7)));
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
                    const TextStyle(color: Color(0xFF7A95B0)),
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
                color: const Color(0xFF4FC3F7)
                    .withValues(alpha: 0.3)),
            const SizedBox(height: 16),
            const Text('Vault is empty',
                style: TextStyle(
                    color: Color(0xFF7A95B0), fontSize: 16)),
            const SizedBox(height: 8),
            const Text(
                'Tap + ADD FILE to encrypt your first file',
                style: TextStyle(
                    color: Color(0xFF3D5166), fontSize: 13)),
          ],
        ),
      );
    }
    return ListView.separated(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 100),
      itemCount: _files.length,
      separatorBuilder: (_, __) =>
          const Divider(color: Color(0xFF1E2D3D), height: 1),
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
                color: const Color(0xFF4FC3F7)
                    .withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Icon(_iconForFile(entry.originalName),
                  color: const Color(0xFF4FC3F7), size: 22),
            ),
            title: Text(
              entry.originalName,
              style: const TextStyle(
                  color: Color(0xFFCFE8FF), fontSize: 14),
              overflow: TextOverflow.ellipsis,
            ),
            subtitle: Text(
              entry.obfuscatedName,
              style: const TextStyle(
                  color: Color(0xFF3D5166),
                  fontSize: 11,
                  fontFamily: 'monospace'),
              overflow: TextOverflow.ellipsis,
            ),
            trailing: const Icon(Icons.chevron_right_rounded,
                color: Color(0xFF3D5166)),
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
    return Drawer(
      backgroundColor: const Color(0xFF0E1318),
      child: SafeArea(
        child: Column(
          children: [
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(24),
              decoration: const BoxDecoration(
                border: Border(
                    bottom:
                        BorderSide(color: Color(0xFF1E2D3D))),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(Icons.lock_rounded,
                      color: Color(0xFF4FC3F7), size: 28),
                  const SizedBox(height: 12),
                  Text(
                    vaultName,
                    style: const TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: Color(0xFFCFE8FF),
                        letterSpacing: 1),
                  ),
                  const SizedBox(height: 4),
                  const Text('Active vault',
                      style: TextStyle(
                          fontSize: 12,
                          color: Color(0xFF4FC3F7))),
                ],
              ),
            ),
            const Expanded(child: SizedBox()),
            const Divider(color: Color(0xFF1E2D3D)),
            ListTile(
              leading: const Icon(Icons.settings_rounded,
                  color: Color(0xFF7A95B0)),
              title: const Text('Settings',
                  style: TextStyle(color: Color(0xFF7A95B0))),
              onTap: onSettings,
            ),
          ],
        ),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SETTINGS SCREEN
// ─────────────────────────────────────────────────────────────────────────────

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _trueDarkOled = true;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF080B0F),
        elevation: 0,
        title: const Text('SETTINGS',
            style: TextStyle(
                fontSize: 14,
                letterSpacing: 3,
                fontWeight: FontWeight.bold)),
        centerTitle: true,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded,
              size: 18),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: ListView(
        children: [
          const _SettingsHeader(title: 'APPEARANCE'),
          const ListTile(
            leading: Icon(Icons.palette_rounded,
                color: Color(0xFF4FC3F7)),
            title: Text('Theme',
                style: TextStyle(color: Color(0xFFCFE8FF))),
            subtitle: Text('Dark (Xenonypt)',
                style: TextStyle(
                    color: Color(0xFF7A95B0), fontSize: 12)),
          ),
          SwitchListTile(
            secondary: const Icon(Icons.brightness_1_rounded,
                color: Color(0xFF4FC3F7)),
            title: const Text('True dark / OLED',
                style: TextStyle(color: Color(0xFFCFE8FF))),
            subtitle: const Text('Pure black backgrounds',
                style: TextStyle(
                    color: Color(0xFF7A95B0), fontSize: 12)),
            value: _trueDarkOled,
            onChanged: (val) =>
                setState(() => _trueDarkOled = val),
          ),
          const Divider(color: Color(0xFF1E2D3D)),
          const _SettingsHeader(title: 'SECURITY'),
          _buildTile(Icons.enhanced_encryption_rounded,
              'Encryption', 'AES-256-GCM + Argon2id'),
          _buildTile(Icons.fingerprint_rounded, 'Biometrics',
              'Configured per vault'),
          const Divider(color: Color(0xFF1E2D3D)),
          const _SettingsHeader(title: 'ABOUT'),
          _buildTile(Icons.language_rounded, 'Language', 'English'),
          _buildTile(
              Icons.code_rounded, 'Source code', 'Version: alpha'),
          _buildTile(Icons.book_rounded,
              'Third-party libraries', ''),
          const SizedBox(height: 8),
          ListTile(
            leading: const Icon(Icons.workspace_premium_rounded,
                color: Colors.amber),
            title: const Text('Premium',
                style: TextStyle(
                    color: Colors.amber,
                    fontWeight: FontWeight.bold)),
            subtitle: const Text('Unlock advanced features',
                style: TextStyle(
                    color: Color(0xFF7A95B0), fontSize: 12)),
            onTap: () {},
          ),
        ],
      ),
    );
  }

  Widget _buildTile(
      IconData icon, String title, String subtitle) {
    return ListTile(
      leading: Icon(icon, color: const Color(0xFF4FC3F7)),
      title: Text(title,
          style: const TextStyle(color: Color(0xFFCFE8FF))),
      subtitle: subtitle.isNotEmpty
          ? Text(subtitle,
              style: const TextStyle(
                  color: Color(0xFF7A95B0), fontSize: 12))
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
        style: const TextStyle(
          color: Color(0xFF4FC3F7),
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
        Icon(icon, size: 16, color: const Color(0xFF00E5CC)),
        const SizedBox(width: 10),
        Expanded(
          child: Text(label,
              style: const TextStyle(
                  fontSize: 13, color: Color(0xFF7A95B0))),
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
    const colors = [
      Color(0xFF1E2D3D),
      Color(0xFFFF5252),
      Color(0xFFFFB347),
      Color(0xFF4FC3F7),
      Color(0xFF00E5CC),
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
                        : const Color(0xFF1E2D3D),
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
// ANIMATED HEX GRID BACKGROUND
// ─────────────────────────────────────────────────────────────────────────────

class _HexGrid extends StatefulWidget {
  const _HexGrid();

  @override
  State<_HexGrid> createState() => _HexGridState();
}

class _HexGridState extends State<_HexGrid>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(
        vsync: this, duration: const Duration(seconds: 8))
      ..repeat();
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _ctrl,
      builder: (_, __) => CustomPaint(
        painter: _HexGridPainter(_ctrl.value),
        child: Container(),
      ),
    );
  }
}

class _HexGridPainter extends CustomPainter {
  final double progress;
  _HexGridPainter(this.progress);

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = const Color(0xFF4FC3F7).withValues(alpha: 0.035)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 0.5;

    const spacing = 48.0;
    final cols = (size.width / spacing).ceil() + 2;
    final rows = (size.height / spacing).ceil() + 2;
    final scrollOffset = (progress * spacing * 0.87) % (spacing * 0.87);

    for (int r = -1; r < rows; r++) {
      for (int c = -1; c < cols; c++) {
        final ox = c * spacing + (r.isOdd ? spacing / 2 : 0);
        final oy = r * spacing * 0.87 + scrollOffset;
        _drawHex(canvas, paint, Offset(ox, oy), spacing / 2 - 2);
      }
    }
  }

  void _drawHex(
      Canvas canvas, Paint paint, Offset center, double radius) {
    final path = Path();
    for (int i = 0; i < 6; i++) {
      final angle = (i * 60 - 30) * dart_math.pi / 180;
      final x = center.dx + radius * dart_math.cos(angle);
      final y = center.dy + radius * dart_math.sin(angle);
      if (i == 0) {
        path.moveTo(x, y);
      } else {
        path.lineTo(x, y);
      }
    }
    path.close();
    canvas.drawPath(path, paint);
  }

  @override
  bool shouldRepaint(_HexGridPainter oldDelegate) =>
      oldDelegate.progress != progress;
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
    return AlertDialog(
      backgroundColor: const Color(0xFF0F1722),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
        side: const BorderSide(color: Color(0xFF2A3A4A), width: 1.5),
      ),
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: const Color(0xFF1CB7FF).withValues(alpha: 0.15),
              borderRadius: BorderRadius.circular(12),
            ),
            child: const Icon(
              Icons.folder_special_rounded,
              color: Color(0xFF1CB7FF),
              size: 28,
            ),
          ),
          const SizedBox(width: 14),
          const Expanded(
            child: Text(
              'Full Storage Access',
              style: TextStyle(
                color: Colors.white,
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
          children: const [
            Text(
              'Xenonypt requires All Files Access (MANAGE_EXTERNAL_STORAGE) to securely create, discover, and manage encrypted vaults across your device storage.',
              style: TextStyle(
                color: Color(0xFF94A3B8),
                fontSize: 14,
                height: 1.5,
                fontFamily: 'monospace',
              ),
            ),
            SizedBox(height: 14),
            Text(
              'Please grant full storage access in the system settings page to proceed seamlessly.',
              style: TextStyle(
                color: Color(0xFF64748B),
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
          child: const Text(
            'Later',
            style: TextStyle(
              color: Color(0xFF64748B),
              fontWeight: FontWeight.w600,
              fontFamily: 'monospace',
            ),
          ),
        ),
        ElevatedButton.icon(
          onPressed: () => _openStorageSettings(context),
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF1CB7FF),
            foregroundColor: const Color(0xFF080B0F),
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