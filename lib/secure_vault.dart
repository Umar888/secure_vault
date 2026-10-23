/// Fast, encrypted key-value storage for Flutter.
///
/// Open a vault once with `SecureVault.open`, then read synchronously and
/// write without blocking the UI. Data is encrypted with AES-256-GCM and the
/// key is kept in the platform keychain.
library;

export 'src/key_store.dart';
export 'src/secure_vault.dart';
export 'src/vault_change.dart';
export 'src/vault_durability.dart';
export 'src/vault_exception.dart';
