import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';

import 'key_store.dart';
import 'vault_change.dart';
import 'vault_exception.dart';
import 'vault_log.dart';

/// Fast, encrypted key-value storage.
///
/// Everything is loaded into memory by [open], so reads are synchronous and
/// cost the same as a map lookup. Writes update memory straight away and are
/// then encrypted with AES-256-GCM and appended to the vault file in the
/// background. The returned future completes once the write has reached the
/// disk.
///
/// ```dart
/// final vault = await SecureVault.open('session');
///
/// await vault.setString('token', 'eyJhbGciOi...');
/// final token = vault.getString('token'); // synchronous
///
/// vault.watch<String>('token').listen((token) => print('token: $token'));
/// ```
///
/// The 256-bit key is generated on first use and kept in a [VaultKeyStore],
/// by default the platform keychain via `flutter_secure_storage`.
class SecureVault {
  SecureVault._(
    this.name,
    this._file,
    this._handle,
    this._cipher,
    this._entries,
    this._records,
  );

  static final Map<String, Future<SecureVault>> _instances = {};
  static final _namePattern = RegExp(r'^[A-Za-z0-9_\-]{1,64}$');

  /// The vault name given to [open].
  final String name;

  final File _file;
  RandomAccessFile _handle;
  final RecordCipher _cipher;
  final Map<String, Object> _entries;
  int _records;
  bool _closed = false;

  Future<void> _tail = Future.value();
  final StreamController<VaultChange> _changes =
      StreamController<VaultChange>.broadcast();

  /// Opens the vault called [name], creating it if needed.
  ///
  /// Opening the same vault again returns the same instance until it is
  /// closed.
  ///
  /// - [keyStore] keeps the encryption key. Defaults to
  ///   [SecureStorageKeyStore].
  /// - [encryptionKey] supplies a 32-byte key directly instead of using a key
  ///   store, for example one derived from a user passphrase.
  /// - [directory] is where the vault file lives. Defaults to a
  ///   `secure_vault` folder in the app support directory.
  /// - [onCorruption] decides what happens when the file cannot be decrypted.
  ///
  /// [name] may contain letters, digits, `_` and `-`, up to 64 characters.
  static Future<SecureVault> open(
    String name, {
    VaultKeyStore? keyStore,
    List<int>? encryptionKey,
    Directory? directory,
    VaultCorruptionPolicy onCorruption = VaultCorruptionPolicy.reset,
  }) async {
    _checkName(name);
    if (encryptionKey != null && encryptionKey.length != 32) {
      throw ArgumentError.value(
        encryptionKey.length,
        'encryptionKey',
        'must be 32 bytes',
      );
    }
    final file = await _fileFor(name, directory);
    return _instances.putIfAbsent(file.path, () async {
      try {
        return await _load(
          name,
          file,
          keyStore ?? const SecureStorageKeyStore(),
          encryptionKey == null ? null : Uint8List.fromList(encryptionKey),
          onCorruption,
        );
      } catch (_) {
        _instances.remove(file.path);
        rethrow;
      }
    });
  }

  /// Deletes the vault file and its key. Closes the vault first if open.
  static Future<void> destroy(
    String name, {
    VaultKeyStore? keyStore,
    Directory? directory,
  }) async {
    _checkName(name);
    final file = await _fileFor(name, directory);
    final open = _instances[file.path];
    if (open != null) await (await open).close();
    if (await file.exists()) await file.delete();
    await (keyStore ?? const SecureStorageKeyStore()).delete(_keyId(name));
  }

  static void _checkName(String name) {
    if (!_namePattern.hasMatch(name)) {
      throw ArgumentError.value(
        name,
        'name',
        'use 1 to 64 letters, digits, "_" or "-"',
      );
    }
  }

  static String _keyId(String name) => 'secure_vault.$name';

  static Future<File> _fileFor(String name, Directory? directory) async {
    final dir =
        directory ??
        Directory(
          '${(await getApplicationSupportDirectory()).path}'
          '${Platform.pathSeparator}secure_vault',
        );
    return File('${dir.path}${Platform.pathSeparator}$name.vault');
  }

  static Future<SecureVault> _load(
    String name,
    File file,
    VaultKeyStore keyStore,
    Uint8List? suppliedKey,
    VaultCorruptionPolicy onCorruption,
  ) async {
    await file.parent.create(recursive: true);
    var bytes = await file.exists() ? await file.readAsBytes() : Uint8List(0);

    Future<void> resetOrThrow(VaultErrorCode code, String message) async {
      if (onCorruption == VaultCorruptionPolicy.throwError) {
        throw VaultException(code, message);
      }
      await file.writeAsBytes(const [], flush: true);
      bytes = Uint8List(0);
    }

    var key = suppliedKey ?? await keyStore.read(_keyId(name));
    if (key == null) {
      // data without a key can never be read again, typically a backup
      // restored onto a new device
      if (bytes.length > headerLength) {
        await resetOrThrow(
          VaultErrorCode.missingKey,
          'vault "$name" has data but its key is missing',
        );
      }
      key = _generateKey();
      await keyStore.write(_keyId(name), key);
    }

    // large vaults decrypt off the UI isolate
    final keyBytes = key;
    final data = bytes;
    var result = data.length > 64 * 1024
        ? await Isolate.run(() => parseVault(data, keyBytes, name))
        : parseVault(data, keyBytes, name);

    if (result.failure != null) {
      await resetOrThrow(
        VaultErrorCode.corrupted,
        'vault "$name" could not be decrypted: ${result.failure}',
      );
      result = parseVault(bytes, keyBytes, name);
    }

    final RandomAccessFile handle;
    try {
      handle = await file.open(mode: FileMode.append);
      if (result.validLength < bytes.length) {
        // FileMode.append only seeks to the end on open, so move back too or
        // the next write leaves a gap where the torn record was
        await handle.truncate(result.validLength);
        await handle.setPosition(result.validLength);
      }
      if (result.validLength == 0) {
        await handle.writeFrom(vaultHeader());
        await handle.flush();
      }
    } on FileSystemException catch (e) {
      throw VaultException(VaultErrorCode.io, 'cannot open vault "$name"', e);
    }

    return SecureVault._(
      name,
      file,
      handle,
      RecordCipher(keyBytes, name),
      Map.of(result.entries),
      result.records,
    );
  }

  static Uint8List _generateKey() {
    final random = Random.secure();
    return Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)));
  }

  // ---------------------------------------------------------------- reading

  /// Whether [key] has a value.
  bool containsKey(String key) => _entries.containsKey(key);

  /// All keys currently stored.
  Iterable<String> get keys => List.unmodifiable(_entries.keys);

  /// Number of stored keys.
  int get length => _entries.length;

  /// Whether the vault holds no keys.
  bool get isEmpty => _entries.isEmpty;

  /// Returns the value for [key] as [T], or `null` when absent.
  ///
  /// Lists and maps come back as fresh `List<dynamic>` / `Map<String,
  /// dynamic>` copies, so changing them does not change the vault. Throws a
  /// [TypeError] when the stored value is not a [T].
  T? get<T>(String key) => _read(key) as T?;

  /// Returns the value for [key] whatever its type.
  Object? operator [](String key) => _read(key);

  /// Returns the string stored at [key].
  String? getString(String key) => get<String>(key);

  /// Returns the int stored at [key].
  int? getInt(String key) => get<int>(key);

  /// Returns the number stored at [key] as a double.
  double? getDouble(String key) => get<num>(key)?.toDouble();

  /// Returns the bool stored at [key].
  bool? getBool(String key) => get<bool>(key);

  /// Returns the string list stored at [key].
  List<String>? getStringList(String key) =>
      get<List<dynamic>>(key)?.cast<String>().toList();

  /// Returns the map stored at [key].
  Map<String, dynamic>? getMap(String key) => get<Map<String, dynamic>>(key);

  /// Returns the bytes stored at [key].
  Uint8List? getBytes(String key) => get<Uint8List>(key);

  Object? _read(String key) {
    final value = _entries[key];
    return switch (value) {
      JsonValue() => value.decode(),
      Uint8List() => Uint8List.fromList(value),
      _ => value,
    };
  }

  // ---------------------------------------------------------------- writing

  /// Stores [value] at [key]. Storing `null` removes the key.
  ///
  /// [value] may be a `String`, `num`, `bool`, `Uint8List`, or a `List` /
  /// `Map<String, dynamic>` of JSON-encodable values. Anything else throws an
  /// [ArgumentError] and leaves the vault unchanged.
  ///
  /// The new value is readable immediately. The future completes once it is
  /// encrypted and flushed to disk.
  Future<void> set(String key, Object? value) {
    if (value == null) return remove(key);
    _checkOpen();
    final stored = _toStored(value);
    _entries[key] = stored;
    _emit(VaultChange(key: key, value: _read(key)));
    final record = _cipher.encodeSet(key, stored);
    return _append([record]);
  }

  /// Stores a string.
  Future<void> setString(String key, String value) => set(key, value);

  /// Stores an int.
  Future<void> setInt(String key, int value) => set(key, value);

  /// Stores a double.
  Future<void> setDouble(String key, double value) => set(key, value);

  /// Stores a bool.
  Future<void> setBool(String key, bool value) => set(key, value);

  /// Stores a list of strings.
  Future<void> setStringList(String key, List<String> value) => set(key, value);

  /// Stores a JSON-encodable map.
  Future<void> setMap(String key, Map<String, dynamic> value) =>
      set(key, value);

  /// Stores raw bytes, such as a private key or a token blob.
  Future<void> setBytes(String key, Uint8List value) => set(key, value);

  /// Stores several values with a single disk flush. `null` values remove
  /// their keys. Every value is validated before anything changes.
  Future<void> setAll(Map<String, Object?> values) {
    _checkOpen();
    final stored = {
      for (final entry in values.entries)
        entry.key: entry.value == null ? null : _toStored(entry.value!),
    };
    final records = <Uint8List>[];
    for (final MapEntry(:key, :value) in stored.entries) {
      if (value == null) {
        if (_entries.remove(key) == null) continue;
        records.add(_cipher.encodeRemove(key));
      } else {
        _entries[key] = value;
        records.add(_cipher.encodeSet(key, value));
      }
      _emit(VaultChange(key: key, value: _read(key)));
    }
    return _append(records);
  }

  /// Removes [key].
  Future<void> remove(String key) {
    _checkOpen();
    if (_entries.remove(key) == null) return _tail;
    _emit(VaultChange(key: key, value: null));
    return _append([_cipher.encodeRemove(key)]);
  }

  /// Removes every key.
  Future<void> clear() {
    _checkOpen();
    _entries.clear();
    _emit(const VaultChange(key: null, value: null));
    return _append([_cipher.encodeClear()]);
  }

  Object _toStored(Object value) {
    switch (value) {
      case String() || num() || bool():
        if (value is double && !value.isFinite) {
          throw ArgumentError.value(value, 'value', 'must be finite');
        }
        return value;
      case Uint8List():
        return Uint8List.fromList(value);
      case List() || Map():
        try {
          return JsonValue(jsonEncode(value));
        } on JsonUnsupportedObjectError catch (e) {
          throw ArgumentError.value(
            value,
            'value',
            'is not JSON-encodable: $e',
          );
        }
      default:
        throw ArgumentError.value(
          value,
          'value',
          'must be a String, num, bool, Uint8List, List or Map',
        );
    }
  }

  // ------------------------------------------------------------- observing

  /// Every change made to this vault, in order.
  Stream<VaultChange> get changes => _changes.stream;

  /// Emits the value of [key] whenever it changes, starting with the current
  /// value.
  Stream<T?> watch<T>(String key) async* {
    yield get<T>(key);
    yield* changes
        .where((change) => change.isClear || change.key == key)
        .map((_) => get<T>(key));
  }

  void _emit(VaultChange change) {
    if (_changes.hasListener) _changes.add(change);
  }

  // ------------------------------------------------------------ maintenance

  /// Completes when every pending write has reached the disk.
  Future<void> flush() => _tail;

  /// Rewrites the file with one record per key, dropping overwritten history.
  ///
  /// Runs automatically once the file holds far more records than keys, so
  /// calling it yourself is rarely needed.
  Future<void> compact() {
    _checkOpen();
    return _enqueue(_compactNow);
  }

  /// Flushes pending writes and releases the file. Further use throws.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _tail;
    await _handle.close();
    await _changes.close();
    _instances.remove(_file.path);
  }

  void _checkOpen() {
    if (_closed) {
      throw VaultException(VaultErrorCode.closed, 'vault "$name" is closed');
    }
  }

  Future<void> _append(List<Uint8List> records) {
    if (records.isEmpty) return _tail;
    return _enqueue(() async {
      try {
        final builder = BytesBuilder(copy: false);
        records.forEach(builder.add);
        await _handle.writeFrom(builder.takeBytes());
        await _handle.flush();
      } on FileSystemException catch (e) {
        throw VaultException(VaultErrorCode.io, 'write to "$name" failed', e);
      }
      _records += records.length;
      if (_records > _entries.length * 2 + 128) {
        // the write itself already landed, so a failed compaction must not
        // fail it; the next write tries again
        try {
          await _compactNow();
        } on VaultException {
          // ignore
        }
      }
    });
  }

  // writes run one at a time in call order; a failed write doesn't block
  // the ones after it
  Future<void> _enqueue(Future<void> Function() job) {
    final next = _tail.then((_) => job());
    _tail = next.then((_) {}, onError: (_) {});
    return next;
  }

  Future<void> _compactNow() async {
    final builder = BytesBuilder(copy: false)..add(vaultHeader());
    for (final MapEntry(:key, :value) in _entries.entries) {
      builder.add(_cipher.encodeSet(key, value));
    }
    final temp = File('${_file.path}.tmp');
    try {
      await temp.writeAsBytes(builder.takeBytes(), flush: true);
    } on FileSystemException catch (e) {
      throw VaultException(VaultErrorCode.io, 'compacting "$name" failed', e);
    }
    await _handle.close();
    try {
      // rename is atomic, so a crash leaves either the old or the new file
      await temp.rename(_file.path);
      _records = _entries.length;
    } on FileSystemException catch (e) {
      throw VaultException(VaultErrorCode.io, 'compacting "$name" failed', e);
    } finally {
      // reopen whichever file is now in place so later writes keep working
      _handle = await _file.open(mode: FileMode.append);
    }
  }
}
