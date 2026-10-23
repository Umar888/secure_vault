/// A change made to a `SecureVault`, delivered on `SecureVault.changes`.
class VaultChange {
  /// Creates a change event.
  const VaultChange({required this.key, required this.value});

  /// The key that changed, or `null` when the whole vault was cleared.
  final String? key;

  /// The new value, or `null` when the key was removed or the vault cleared.
  final Object? value;

  /// Whether this change cleared every key.
  bool get isClear => key == null;

  @override
  String toString() =>
      isClear ? 'VaultChange(clear)' : 'VaultChange($key: $value)';
}
