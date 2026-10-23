import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Where a `SecureVault` keeps its encryption key.
///
/// The default, [SecureStorageKeyStore], uses the iOS/macOS Keychain, the
/// Android Keystore and the platform secret stores on desktop. Implement this
/// to plug in your own key management, such as a key from your backend.
abstract interface class VaultKeyStore {
  /// Returns the key stored under [id], or `null` if there is none.
  Future<Uint8List?> read(String id);

  /// Stores [key] under [id], replacing any previous key.
  Future<void> write(String id, Uint8List key);

  /// Removes the key stored under [id].
  Future<void> delete(String id);
}

/// A [VaultKeyStore] backed by `flutter_secure_storage`.
///
/// Keys are stored with `first_unlock_this_device` accessibility on Apple
/// platforms, so vaults can be opened by background tasks after the first
/// unlock and the key never syncs to iCloud.
class SecureStorageKeyStore implements VaultKeyStore {
  /// Creates a key store. Pass [storage] to customise platform options.
  const SecureStorageKeyStore({this.storage = _defaultStorage});

  static const _defaultStorage = FlutterSecureStorage(
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
    ),
    mOptions: MacOsOptions(
      accessibility: KeychainAccessibility.first_unlock_this_device,
    ),
  );

  /// The secure storage instance used to hold keys.
  final FlutterSecureStorage storage;

  @override
  Future<Uint8List?> read(String id) async {
    final encoded = await storage.read(key: id);
    return encoded == null ? null : base64Decode(encoded);
  }

  @override
  Future<void> write(String id, Uint8List key) =>
      storage.write(key: id, value: base64Encode(key));

  @override
  Future<void> delete(String id) => storage.delete(key: id);
}

/// A [VaultKeyStore] that only lives in memory. Useful for tests.
class MemoryKeyStore implements VaultKeyStore {
  final Map<String, Uint8List> _keys = {};

  @override
  Future<Uint8List?> read(String id) async => _keys[id];

  @override
  Future<void> write(String id, Uint8List key) async =>
      _keys[id] = Uint8List.fromList(key);

  @override
  Future<void> delete(String id) async => _keys.remove(id);
}
