// vault_viewer.dart
//
// In-app media viewing for the vault:
//  * Images: decrypted straight into RAM, decoded, and the plaintext bytes
//    are zero-filled right after decoding. No file is ever written.
//  * Video: a loopback-only HTTP server (random token in the URL) answers
//    Range requests by decrypting one 4 MiB chunk at a time through
//    `vaultStreamReadChunk`. Nothing touches disk; every buffer is zero-filled
//    when evicted, when the player closes, or when the app leaves the
//    foreground.
//
// pubspec.yaml:  video_player: ^2.9.0   (any recent version)

import 'dart:async';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:video_player/video_player.dart';

import 'src/rust/api.dart';
import 'src/rust/vault.dart';

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

enum VaultMediaKind { image, video, other }

VaultMediaKind vaultMediaKind(String name) {
  final ext = _extOf(name);
  if (const {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'heic'}
      .contains(ext)) {
    return VaultMediaKind.image;
  }
  if (const {'mp4', 'm4v', 'mov', 'mkv', 'webm', '3gp', 'avi'}
      .contains(ext)) {
    return VaultMediaKind.video;
  }
  return VaultMediaKind.other;
}

String _extOf(String name) =>
    name.contains('.') ? name.split('.').last.trim().toLowerCase() : '';

String _mimeFor(String name) {
  switch (_extOf(name)) {
    case 'mov':
      return 'video/quicktime';
    case 'webm':
      return 'video/webm';
    case 'mkv':
      return 'video/x-matroska';
    case 'avi':
      return 'video/x-msvideo';
    case '3gp':
      return 'video/3gpp';
    default:
      return 'video/mp4';
  }
}

void _wipe(Uint8List? b) {
  if (b == null) return;
  try {
    b.fillRange(0, b.length, 0);
  } catch (_) {
    // Unmodifiable view — nothing we can do.
  }
}

/// Removes this viewer's own route (safe even if a dialog is on top) so the
/// State's dispose() runs and wipes everything.
void _closeViewerRoute(BuildContext context) {
  final route = ModalRoute.of(context);
  if (route != null) Navigator.of(context).removeRoute(route);
}

bool _leftForeground(AppLifecycleState s) =>
    s == AppLifecycleState.paused ||
    s == AppLifecycleState.hidden ||
    s == AppLifecycleState.detached;

// ─────────────────────────────────────────────────────────────────────────────
// VAULT MEDIA REGISTRY (Binds streaming & RAM cache zeroing to Vault lifecycle)
// ─────────────────────────────────────────────────────────────────────────────

/// Global registry that tightly binds all active in-app viewers and loopback
/// stream servers to the vault lifecycle.
///
/// If a vault is locked (manually, via timeout, or unexpectedly), calling
/// [VaultMediaRegistry.onVaultLocked] instantly:
/// 1. Closes all loopback HTTP servers so no further network requests are served.
/// 2. Zero-fills all cached plaintext chunks in RAM.
/// 3. Drops and disposes the Rust stream handles.
/// 4. Notifies all open media viewers (video/image) to dismiss their UI routes and tear down.
class VaultMediaRegistry {
  static final Set<VaultStreamServer> _activeServers = {};
  static final Set<void Function(VaultHandle? lockedHandle)> _lockListeners = {};

  static void registerServer(VaultStreamServer server) {
    _activeServers.add(server);
  }

  static void unregisterServer(VaultStreamServer server) {
    _activeServers.remove(server);
  }

  static void registerLockListener(void Function(VaultHandle? lockedHandle) listener) {
    _lockListeners.add(listener);
  }

  static void unregisterLockListener(void Function(VaultHandle? lockedHandle) listener) {
    _lockListeners.remove(listener);
  }

  /// Immediately terminates all active streams, wipes plaintext RAM caches,
  /// and closes open media viewer routes.
  static Future<void> onVaultLocked([VaultHandle? handle]) async {
    final listeners = List<void Function(VaultHandle? lockedHandle)>.from(_lockListeners);
    for (final l in listeners) {
      try {
        l(handle);
      } catch (_) {}
    }

    final servers = List<VaultStreamServer>.from(_activeServers);
    for (final s in servers) {
      if (handle == null || s.handle == handle) {
        try {
          await s.close();
        } catch (_) {}
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// IMAGE VIEWER  (RAM only)
// ─────────────────────────────────────────────────────────────────────────────

class VaultImageViewer extends StatefulWidget {
  final VaultHandle handle;
  final VaultFileEntry entry;
  const VaultImageViewer({super.key, required this.handle, required this.entry});

  @override
  State<VaultImageViewer> createState() => _VaultImageViewerState();
}

class _VaultImageViewerState extends State<VaultImageViewer>
    with WidgetsBindingObserver {
  ui.Image? _image;
  String? _error;
  Timer? _lockCheckTimer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    VaultMediaRegistry.registerLockListener(_onVaultLocked);
    _lockCheckTimer = Timer.periodic(
        const Duration(milliseconds: 500), (_) => _checkUnlocked());
    _load();
  }

  void _onVaultLocked(VaultHandle? lockedHandle) {
    if (lockedHandle == null || lockedHandle == widget.handle) {
      if (mounted) _closeViewerRoute(context);
    }
  }

  Future<void> _checkUnlocked() async {
    if (!mounted) return;
    try {
      final unlocked = await vaultIsUnlocked(handle: widget.handle);
      if (!unlocked && mounted) _closeViewerRoute(context);
    } catch (_) {
      if (mounted) _closeViewerRoute(context);
    }
  }

  Future<void> _load() async {
    Uint8List? bytes;
    try {
      bytes = await vaultExtractFileToBytes(
        handle: widget.handle,
        obfuscatedName: widget.entry.obfuscatedName,
      );
      // instantiateImageCodec copies the buffer, so wiping after is safe.
      final codec = await ui.instantiateImageCodec(bytes);
      final frame = await codec.getNextFrame();
      codec.dispose();
      if (!mounted) {
        frame.image.dispose();
        return;
      }
      setState(() => _image = frame.image);
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    } finally {
      _wipe(bytes);
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (_leftForeground(state) && mounted) _closeViewerRoute(context);
  }

  @override
  void dispose() {
    _lockCheckTimer?.cancel();
    VaultMediaRegistry.unregisterLockListener(_onVaultLocked);
    WidgetsBinding.instance.removeObserver(this);
    _image?.dispose(); // frees the decoded pixels
    _image = null;
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        foregroundColor: Colors.white,
        title: Text(widget.entry.originalName,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(fontSize: 14)),
      ),
      body: _error != null
          ? Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Text(_error!,
                    style: const TextStyle(color: Colors.white70),
                    textAlign: TextAlign.center),
              ),
            )
          : _image == null
              ? const Center(child: CircularProgressIndicator())
              : InteractiveViewer(
                  maxScale: 8,
                  child: SizedBox.expand(
                    child: RawImage(image: _image, fit: BoxFit.contain),
                  ),
                ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// LOOPBACK STREAM SERVER  (chunk-by-chunk decrypt, Range support)
// ─────────────────────────────────────────────────────────────────────────────

class _Range {
  final int start, end;
  final bool unsatisfiable;
  const _Range(this.start, this.end, {this.unsatisfiable = false});
}

class VaultStreamServer {
  static const int _pieceSize = 1024 * 1024; // 1 MiB per socket write
  static const int _maxCachedChunks = 8; // ≈ 32 MiB of plaintext in RAM (smooth 2K/4K buffer)

  final VaultHandle handle;
  final VaultFileStream stream;
  final int _total;
  final int _chunkSize;
  final String _mime;
  final String _ext;
  final String _token;

  late final HttpServer _http;
  bool _closed = false;

  // Insertion-ordered: first key = least recently used.
  final Map<int, Uint8List> _cache = {};
  Future<void> _lock = Future.value();

  VaultStreamServer._(this.handle, this.stream, this._total, this._chunkSize, this._mime,
      this._ext, this._token);

  static Future<VaultStreamServer> start({
    required VaultHandle handle,
    required VaultFileStream stream,
    required String fileName,
  }) async {
    final total = (await vaultStreamTotalSize(stream: stream)).toInt();
    // Read the real chunk size from Rust — don't hardcode it.
    final chunk = (await vaultStreamChunkSize(stream: stream)).toInt();
    final rnd = math.Random.secure();
    final token = List.generate(
            16, (_) => rnd.nextInt(256).toRadixString(16).padLeft(2, '0'))
        .join();
    final ext = _extOf(fileName);
    final s = VaultStreamServer._(
        handle, stream, total, chunk, _mimeFor(fileName), ext.isEmpty ? 'mp4' : ext, token);
    s._http = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    s._http.listen(s._handle, onError: (_) {});
    VaultMediaRegistry.registerServer(s);
    return s;
  }

  Uri get uri =>
      Uri.parse('http://127.0.0.1:${_http.port}/$_token/video.$_ext');

  // Serialises Rust reads + cache mutation so nothing is wiped while in use.
  Future<T> _sync<T>(Future<T> Function() f) {
    final run = _lock.then((_) => f());
    _lock = run.then((_) {}, onError: (_) {});
    return run;
  }

  /// Returns a zero-copy slice of up to [maxLen] plaintext bytes starting at [pos]
  /// (never crosses a chunk boundary).
  Future<Uint8List> _readSlice(int pos, int maxLen) => _sync(() async {
        if (_closed) throw StateError('closed');
        final idx = pos ~/ _chunkSize;
        Uint8List? chunk = _cache.remove(idx);
        if (chunk == null) {
          try {
            chunk = await vaultStreamReadChunk(
              stream: stream,
              chunkIndex: BigInt.from(idx),
            );
          } catch (e) {
            // Decryption failed (e.g. vault locked / MEK zeroized in Rust).
            // Instantly shut down the server and wipe all cached RAM chunks.
            unawaited(close());
            throw StateError('Vault is locked or decryption failed: $e');
          }
        }
        if (_closed) {
          _wipe(chunk);
          throw StateError('closed');
        }
        _cache[idx] = chunk; // mark most-recent
        while (_cache.length > _maxCachedChunks) {
          _wipe(_cache.remove(_cache.keys.first));
        }
        final off = pos - idx * _chunkSize;
        final take = math.min(maxLen, chunk.length - off);
        if (take <= 0) throw StateError('range beyond chunk');
        return Uint8List.sublistView(chunk, off, off + take);
      });

  _Range? _parseRange(String? header) {
    if (header == null) return null;
    final m = RegExp(r'^bytes=(\d*)-(\d*)$').firstMatch(header.trim());
    if (m == null) return null; // multi-range etc. → just send everything
    final s = m.group(1)!, e = m.group(2)!;
    if (s.isEmpty && e.isEmpty) return null;
    const bad = _Range(0, 0, unsatisfiable: true);
    if (s.isEmpty) {
      final n = int.tryParse(e);
      if (n == null || n == 0) return bad;
      return _Range(math.max(0, _total - n), _total - 1);
    }
    final start = int.tryParse(s);
    if (start == null) return bad;
    final end = e.isEmpty
        ? _total - 1
        : math.min(int.tryParse(e) ?? _total - 1, _total - 1);
    if (start >= _total || start > end) return bad;
    return _Range(start, end);
  }

  Future<void> _handle(HttpRequest req) async {
    final res = req.response;
    try {
      final seg = req.uri.pathSegments;
      if (_closed || seg.isEmpty || seg.first != _token) {
        res.statusCode = HttpStatus.notFound;
        await res.close();
        return;
      }
      if (req.method != 'GET' && req.method != 'HEAD') {
        res.statusCode = HttpStatus.methodNotAllowed;
        await res.close();
        return;
      }

      final range = _parseRange(req.headers.value(HttpHeaders.rangeHeader));
      if (range != null && range.unsatisfiable) {
        res.statusCode = HttpStatus.requestedRangeNotSatisfiable;
        res.headers.set(HttpHeaders.contentRangeHeader, 'bytes */$_total');
        await res.close();
        return;
      }

      final start = range?.start ?? 0;
      final end = range?.end ?? _total - 1;
      res.statusCode = range == null ? HttpStatus.ok : HttpStatus.partialContent;
      if (range != null) {
        res.headers
            .set(HttpHeaders.contentRangeHeader, 'bytes $start-$end/$_total');
      }
      res.headers
        ..set(HttpHeaders.acceptRangesHeader, 'bytes')
        ..set(HttpHeaders.cacheControlHeader, 'no-store')
        ..contentType = ContentType.parse(_mime);
      res.contentLength = end - start + 1;

      if (req.method == 'HEAD') {
        await res.close();
        return;
      }

      var pos = start;
      while (pos <= end && !_closed) {
        final piece = await _readSlice(pos, math.min(_pieceSize, end - pos + 1));
        res.add(piece);
        pos += piece.length;
      }
      await res.close();
    } catch (_) {
      // Player aborted the request (seek/close) or we're shutting down.
      try {
        await res.close();
      } catch (_) {}
    }
  }

  /// Stops serving, zero-fills every cached chunk and drops the Rust stream
  /// handle.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    VaultMediaRegistry.unregisterServer(this);
    try {
      await _http.close(force: true);
    } catch (_) {}
    try {
      await _lock; // let an in-flight Rust read finish (it wipes itself)
    } catch (_) {}
    for (final c in _cache.values) {
      _wipe(c);
    }
    _cache.clear();
    try {
      if (!stream.isDisposed) stream.dispose();
    } catch (_) {}
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// VIDEO VIEWER
// ─────────────────────────────────────────────────────────────────────────────

class VaultVideoViewer extends StatefulWidget {
  final VaultHandle handle;
  final VaultFileEntry entry;
  const VaultVideoViewer({super.key, required this.handle, required this.entry});

  @override
  State<VaultVideoViewer> createState() => _VaultVideoViewerState();
}

class _VaultVideoViewerState extends State<VaultVideoViewer>
    with WidgetsBindingObserver {
  VaultStreamServer? _server;
  VideoPlayerController? _ctrl;
  String? _error;
  bool _tornDown = false;
  Timer? _lockCheckTimer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    VaultMediaRegistry.registerLockListener(_onVaultLocked);
    _lockCheckTimer = Timer.periodic(
        const Duration(milliseconds: 500), (_) => _checkUnlocked());
    _start();
  }

  void _onVaultLocked(VaultHandle? lockedHandle) {
    if (lockedHandle == null || lockedHandle == widget.handle) {
      if (mounted) {
        _closeViewerRoute(context);
      }
    }
  }

  Future<void> _checkUnlocked() async {
    if (_tornDown || !mounted) return;
    try {
      final unlocked = await vaultIsUnlocked(handle: widget.handle);
      if (!unlocked && mounted) {
        _closeViewerRoute(context);
      }
    } catch (_) {
      if (mounted) _closeViewerRoute(context);
    }
  }

  Future<void> _start() async {
    VaultFileStream? stream;
    try {
      final unlocked = await vaultIsUnlocked(handle: widget.handle);
      if (!unlocked) throw StateError('Vault is locked');

      stream = await vaultOpenStream(
        handle: widget.handle,
        obfuscatedName: widget.entry.obfuscatedName,
      );
      if (_tornDown) {
        stream.dispose();
        return;
      }
      final server = await VaultStreamServer.start(
          handle: widget.handle,
          stream: stream,
          fileName: widget.entry.originalName);
      stream = null; // the server owns it now
      if (_tornDown) {
        await server.close();
        return;
      }
      _server = server;
      final ctrl = VideoPlayerController.networkUrl(server.uri);
      _ctrl = ctrl;
      await ctrl.initialize();
      if (_tornDown || !mounted) return;
      await ctrl.play();
      setState(() {});
    } catch (e) {
      try {
        if (stream != null && !stream.isDisposed) stream.dispose();
      } catch (_) {}
      _teardown();
      if (mounted) setState(() => _error = e.toString());
    }
  }

  void _teardown() {
    if (_tornDown) return;
    _tornDown = true;
    final c = _ctrl, s = _server;
    _ctrl = null;
    _server = null;
    unawaited(() async {
      try {
        await c?.pause();
      } catch (_) {}
      try {
        await c?.dispose(); // stop the player first…
      } catch (_) {}
      await s?.close(); // …then wipe + close the server and Rust stream
    }());
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (_leftForeground(state) && mounted) _closeViewerRoute(context);
  }

  @override
  void dispose() {
    _lockCheckTimer?.cancel();
    VaultMediaRegistry.unregisterLockListener(_onVaultLocked);
    WidgetsBinding.instance.removeObserver(this);
    _teardown();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = _ctrl;
    Widget body;
    if (_error != null) {
      body = Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Text(_error!,
              style: const TextStyle(color: Colors.white70),
              textAlign: TextAlign.center),
        ),
      );
    } else if (c == null || !c.value.isInitialized) {
      body = const Center(child: CircularProgressIndicator());
    } else {
      body = GestureDetector(
        behavior: HitTestBehavior.opaque,
        onTap: () => c.value.isPlaying ? c.pause() : c.play(),
        child: Stack(
          children: [
            Center(
              child: AspectRatio(
                aspectRatio: c.value.aspectRatio,
                child: VideoPlayer(c),
              ),
            ),
            ValueListenableBuilder<VideoPlayerValue>(
              valueListenable: c,
              builder: (_, v, __) => v.isPlaying
                  ? const SizedBox.shrink()
                  : const Center(
                      child: Icon(Icons.play_arrow_rounded,
                          size: 72, color: Colors.white70)),
            ),
            Align(
              alignment: Alignment.bottomCenter,
              child: SafeArea(
                child: VideoProgressIndicator(
                  c,
                  allowScrubbing: true,
                  padding: const EdgeInsets.all(20),
                ),
              ),
            ),
          ],
        ),
      );
    }

    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        foregroundColor: Colors.white,
        title: Text(widget.entry.originalName,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(fontSize: 14)),
      ),
      body: body,
    );
  }
}
