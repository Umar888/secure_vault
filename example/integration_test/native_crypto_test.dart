import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:secure_vault/secure_vault.dart';

// runs against the real CryptoKit / javax.crypto implementation
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  final keys = MemoryKeyStore();

  Future<SecureVault> open(String name, {required bool native}) =>
      SecureVault.open(
        name,
        keyStore: keys,
        nativeCrypto: native,
        onCorruption: VaultCorruptionPolicy.throwError,
      );

  tearDown(() async {
    for (final name in ['dart_to_native', 'native_to_dart']) {
      await SecureVault.destroy(name, keyStore: keys);
    }
  });

  testWidgets('native crypto is on for Apple platforms only', (tester) async {
    final vault = await open('dart_to_native', native: true);
    expect(vault.usesNativeCrypto, Platform.isIOS || Platform.isMacOS);
    await vault.close();
  });

  testWidgets('native open reads what Dart wrote', (tester) async {
    var vault = await open('dart_to_native', native: false);
    await vault.setAll({for (var i = 0; i < 200; i++) 'k$i': 'value $i'});
    await vault.close();

    vault = await open('dart_to_native', native: true);
    expect(vault.length, 200);
    expect(vault.getString('k199'), 'value 199');
    await vault.close();
  });

  testWidgets('Dart open reads what native compaction wrote', (tester) async {
    var vault = await open('native_to_dart', native: true);
    await vault.setAll({for (var i = 0; i < 200; i++) 'k$i': i});
    await vault.compact();
    await vault.close();

    vault = await open('native_to_dart', native: false);
    expect(vault.length, 200);
    expect(vault.getInt('k123'), 123);
    await vault.close();
  });
}
