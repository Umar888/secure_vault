/// How hard a `SecureVault` works to make each write survive a crash.
enum VaultDurability {
  /// Wait for the OS to confirm each write is on physical storage (`fsync`)
  /// before the write's future completes. Survives app crashes and power
  /// loss. Writes made while one is in flight share a single `fsync`.
  sync,

  /// Hand writes to the OS and complete without waiting for `fsync`. Survives
  /// an app crash, but the latest writes can be lost if the device loses
  /// power or the OS crashes. Much faster on devices with slow storage. The
  /// file is still `fsync`'d on `close` and before compaction swaps files.
  buffered,
}
