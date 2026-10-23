## 0.2.0

- Native AES-256-GCM through CryptoKit on iOS and macOS. Opening a vault
  decrypts every record in one batch on a background thread, and compaction
  re-encrypts in one batch. Same file format, so existing vaults just work.
  Turn it off with `nativeCrypto: false`.
- New `durability` option. `VaultDurability.sync` (default) keeps the
  `fsync`-per-write behaviour, and `VaultDurability.buffered` skips the wait
  for much faster writes on slow storage.
- Group commit: writes made while a write is in flight are batched into one
  `fsync`.
- `SecureVault.usesNativeCrypto` and `SecureVault.durability` getters.
- README benchmarks now cover Android as well as iOS.

## 0.1.0

- Initial release: AES-256-GCM encrypted key-value vault with the key in
  the platform keychain, synchronous reads, typed getters and setters, batch
  writes, change streams, crash-safe append log with automatic compaction,
  and corruption policies.
