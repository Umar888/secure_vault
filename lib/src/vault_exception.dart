/// What a `SecureVault` does when its file cannot be decrypted, for example
/// after the key was lost or the file was tampered with.
enum VaultCorruptionPolicy {
  /// Delete the unreadable data and start with an empty vault.
  reset,

  /// Throw a [VaultException] from `SecureVault.open` and leave the file
  /// untouched.
  throwError,
}

/// Why a [VaultException] was thrown.
enum VaultErrorCode {
  /// The file failed authentication: wrong key, tampering or disk damage.
  corrupted,

  /// The file exists but its key is gone from the key store, which happens
  /// when a backup is restored onto another device.
  missingKey,

  /// Reading or writing the vault file failed.
  io,

  /// The vault was used after `SecureVault.close`.
  closed,
}

/// An error raised by a `SecureVault`.
class VaultException implements Exception {
  /// Creates an exception with a [code] and human readable [message].
  const VaultException(this.code, this.message, [this.cause]);

  /// The kind of failure.
  final VaultErrorCode code;

  /// A description of what went wrong.
  final String message;

  /// The underlying error, if any.
  final Object? cause;

  @override
  String toString() =>
      'VaultException(${code.name}): $message${cause == null ? '' : ' ($cause)'}';
}
