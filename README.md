# secure_vault

Fast, encrypted key-value storage for Flutter. Your data is encrypted with
AES-256-GCM and its key lives in the iOS/macOS Keychain or the Android
Keystore, just like `flutter_secure_storage`, but reads are synchronous and
served from memory.

```dart
final vault = await SecureVault.open('session');

await vault.setString('token', 'eyJhbGciOi...');
final token = vault.getString('token'); // synchronous, no await
```

## Why

`flutter_secure_storage` sends every read and write over a platform channel
to the keychain, which is slow and async-only. It also isn't built for more
than a handful of small values. `shared_preferences` is fast but stores
everything in plaintext.

`secure_vault` keeps only one thing in the keychain: a random 256-bit key.
Everything else lives in an encrypted file that is loaded into memory once.

200 writes and 200 reads, measured with the `example/` app:

| | iOS simulator (debug) | Android emulator (release) |
| --- | --- | --- |
| **secure_vault**, default `sync` durability | write 56 ms, read **0.1 ms** | write 4,405 ms, read **0.17 ms** |
| **secure_vault**, `buffered` durability | write **20 ms** | write 664 ms |
| flutter_secure_storage | write 836 ms, read 87 ms | write 578 ms, read 535 ms |

Reads are always hundreds of times faster. Writes depend on durability. The
default waits for `fsync` on every write, which is very slow on the Android
emulator's disk. `buffered` skips that wait and is on par with
`flutter_secure_storage` there (which doesn't `fsync` either). Real devices
have much faster storage than the emulator; run the example app on yours.

Opening a 5,000-key (600 KB) vault on the iOS simulator takes 14 ms with
native CryptoKit, against 52 ms in pure Dart.

## Features

- **Synchronous reads** after a single `open()`.
- **Native crypto on Apple platforms**: CryptoKit decrypts the whole vault
  in one batch on open, and re-encrypts it on compaction.
- **Pick your durability**: `fsync` every write (default), or `buffered` for
  speed. Writes made while one is in flight share a single `fsync`.
- **Typed API**: `String`, `int`, `double`, `bool`, `List<String>`, JSON maps
  and lists, and raw `Uint8List` bytes.
- **Reactive**: `vault.changes` streams every change, and `vault.watch('key')`
  streams one key's value.
- **Crash safe**: writes are appended and fsync'd. A record torn by a crash
  is dropped on the next open, and compaction swaps files atomically.
- **Tamper evident**: every record is authenticated. A modified, truncated
  or swapped file is detected, never silently misread.
- **Batch writes**: `setAll` writes many values with one disk flush.
- **Bring your own key**: pass `encryptionKey` (for example derived from a
  passphrase) or implement `VaultKeyStore`.
- **Multiple vaults**: each name is a separate file with its own key.
- Android, iOS, macOS, Windows and Linux.

## Usage

```dart
import 'package:secure_vault/secure_vault.dart';

final vault = await SecureVault.open('settings');

// write: memory updates immediately, the future completes once on disk
await vault.setBool('onboarded', true);
await vault.setMap('profile', {'name': 'Ada', 'plan': 'pro'});
await vault.setBytes('private_key', keyBytes);
await vault.setAll({'theme': 'dark', 'fontScale': 1.2});

// read
vault.getBool('onboarded');      // true
vault.getMap('profile')?['plan']; // 'pro'
vault.get<String>('theme');      // 'dark'
vault.containsKey('token');      // false

// remove
await vault.remove('theme');
await vault.clear();

// observe
vault.watch<bool>('onboarded').listen((value) => print(value));

// delete the file and its key entirely, for example on logout
await SecureVault.destroy('settings');
```

### Opening options

```dart
await SecureVault.open(
  'session',
  keyStore: const SecureStorageKeyStore(), // where the key lives (default)
  encryptionKey: null,                     // or a 32-byte key of your own
  directory: null,                         // defaults to app support dir
  onCorruption: VaultCorruptionPolicy.reset,
  durability: VaultDurability.sync,        // or .buffered
  nativeCrypto: true,                      // CryptoKit on iOS / macOS
);
```

`durability` controls when a write's future completes:

- `sync` (the default) waits until the OS confirms the data is on physical
  storage. It survives app crashes and power loss.
- `buffered` hands the data to the OS and returns. It survives app crashes,
  but the latest writes can be lost if the device loses power. The file is
  still `fsync`'d on `close()` and before compaction.

`onCorruption` decides what happens when the file can't be decrypted:

- `reset` (the default) wipes the unreadable data and starts empty.
- `throwError` throws a `VaultException` and leaves the file alone.

It applies when the key is gone (`VaultErrorCode.missingKey`) or when
authentication fails (`VaultErrorCode.corrupted`).

## Security model

- Each vault has its own random 256-bit key, made with `Random.secure()`.
  `SecureStorageKeyStore` stores it with `first_unlock_this_device`
  accessibility on Apple platforms. That means it never syncs to iCloud and
  stays readable by background tasks after the first unlock.
- Every record is encrypted with AES-256-GCM and a random 96-bit nonce. The
  vault name is bound in as associated data, so records can't be moved
  between vaults.
- The key is device-bound, so a vault file restored onto another device
  can't be read. You'll get `missingKey`, which the `reset` policy handles by
  starting fresh. Treat vault contents like a cache of secrets, not the only
  copy of important data.
- Decrypted values live in memory while the vault is open, like any
  in-memory cache. This protects data at rest. It does not protect against
  code running inside your app or on a compromised, rooted device.

## Notes

- Everything is held in memory, so this is built for settings, tokens,
  credentials and small records. Up to a few megabytes is fine. It is not a
  replacement for a database of large blobs.
- Opening a vault decrypts every record. On iOS and macOS this runs in
  CryptoKit on a background thread. Elsewhere, vaults above 64 KB decrypt on
  a background isolate, so the first frame isn't blocked either way.
- Single writes always use the Dart cipher. For one small record it's faster
  than a round trip to native code.
- Android, Windows and Linux use the Dart cipher for everything. On Android,
  `javax.crypto` measured no faster than Dart, because of its setup cost per
  record.
- Web isn't supported, because the browser has no secure place for the key.
