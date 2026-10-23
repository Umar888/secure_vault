import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secure_vault/secure_vault.dart';
import 'package:secure_vault/src/native_crypto.dart';

const _channel = MethodChannel('secure_vault/crypto');

// mimics the CryptoKit / javax.crypto handlers: combined nonce+ct+tag boxes
final class _FakeNative {
  final aes = DartAesGcm.with256bits();
  int decryptBatches = 0;
  int encryptBatches = 0;
  bool failDecrypt = false;

  Future<Object?> handle(MethodCall call) async {
    if (call.method == 'ping') return true;
    final args = call.arguments as Map;
    final key = SecretKeyData(args['key'] as Uint8List);
    final aad = args['aad'] as Uint8List;
    final items = splitFrames(args['frames'] as Uint8List).cast<Uint8List>();
    final out = BytesBuilder(copy: false);
    void frame(Uint8List? payload) {
      out.add(
        (ByteData(
          4,
        )..setUint32(0, payload?.length ?? 0xFFFFFFFF)).buffer.asUint8List(),
      );
      if (payload != null) out.add(payload);
    }

    switch (call.method) {
      case 'decryptAll':
        decryptBatches++;
        if (failDecrypt) throw PlatformException(code: 'crypto_failed');
        for (final box in items) {
          try {
            frame(
              Uint8List.fromList(
                aes.decryptSync(
                  SecretBox.fromConcatenation(
                    box,
                    nonceLength: 12,
                    macLength: 16,
                  ),
                  secretKeyData: key,
                  aad: aad,
                ),
              ),
            );
          } on SecretBoxAuthenticationError {
            frame(null);
          }
        }
      case 'encryptAll':
        encryptBatches++;
        for (final clear in items) {
          frame(
            Uint8List.fromList(
              aes
                  .encryptSync(clear, secretKeyData: key, aad: aad)
                  .concatenation(),
            ),
          );
        }
      default:
        return null;
    }
    return out.takeBytes();
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  late Directory dir;
  late MemoryKeyStore keys;
  late _FakeNative native;

  Future<SecureVault> open({bool nativeCrypto = true, String name = 'n'}) =>
      SecureVault.open(
        name,
        keyStore: keys,
        directory: dir,
        nativeCrypto: nativeCrypto,
        onCorruption: VaultCorruptionPolicy.throwError,
      );

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('secure_vault_native');
    keys = MemoryKeyStore();
    native = _FakeNative();
    NativeCrypto.resetAvailability();
    messenger.setMockMethodCallHandler(_channel, native.handle);
  });

  tearDown(() async {
    messenger.setMockMethodCallHandler(_channel, null);
    NativeCrypto.resetAvailability();
    await dir.delete(recursive: true);
  });

  test('no handler means the Dart path', () async {
    messenger.setMockMethodCallHandler(_channel, null);
    NativeCrypto.resetAvailability();
    final vault = await open();
    expect(vault.usesNativeCrypto, isFalse);
    await vault.close();
  });

  test('open decrypts natively in one batch', () async {
    var vault = await open(nativeCrypto: false);
    for (var i = 0; i < 50; i++) {
      await vault.setInt('k$i', i);
    }
    await vault.close();

    vault = await open();
    expect(vault.usesNativeCrypto, isTrue);
    expect(native.decryptBatches, 1);
    expect(vault.getInt('k49'), 49);
    await vault.close();
  });

  test('natively compacted files read back with pure Dart', () async {
    var vault = await open();
    await vault.setAll({for (var i = 0; i < 100; i++) 'k$i': 'v$i'});
    await vault.compact();
    expect(native.encryptBatches, 1);
    await vault.close();

    vault = await open(nativeCrypto: false);
    expect(vault.length, 100);
    expect(vault.getString('k99'), 'v99');
    await vault.close();
  });

  test('small compactions stay in Dart', () async {
    final vault = await open();
    await vault.setAll({'a': 1, 'b': 2});
    await vault.compact();
    expect(native.encryptBatches, 0);
    await vault.close();
  });

  test('falls back to Dart when the native side errors', () async {
    var vault = await open(nativeCrypto: false);
    await vault.setString('safe', 'yes');
    await vault.close();

    native.failDecrypt = true;
    vault = await open();
    expect(native.decryptBatches, 1);
    expect(vault.getString('safe'), 'yes');
    await vault.close();
  });

  test('tampering is still caught on the native path', () async {
    final vault = await open(nativeCrypto: false);
    await vault.setString('a', 'b');
    await vault.close();
    final file = File('${dir.path}/n.vault');
    final bytes = await file.readAsBytes();
    bytes[bytes.length - 2] ^= 0x01;
    await file.writeAsBytes(bytes);

    await expectLater(
      open(),
      throwsA(
        isA<VaultException>().having(
          (e) => e.code,
          'code',
          VaultErrorCode.corrupted,
        ),
      ),
    );
    expect(native.decryptBatches, 1);
  });
}
