import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:secure_vault/secure_vault.dart';

void main() {
  late Directory dir;
  late MemoryKeyStore keys;

  Future<SecureVault> open({
    String name = 'test',
    VaultCorruptionPolicy onCorruption = VaultCorruptionPolicy.reset,
    List<int>? encryptionKey,
  }) => SecureVault.open(
    name,
    keyStore: keys,
    directory: dir,
    onCorruption: onCorruption,
    encryptionKey: encryptionKey,
  );

  // close and reopen so values come from disk, not memory
  Future<SecureVault> reopen(SecureVault vault, {String name = 'test'}) async {
    await vault.close();
    return open(name: name);
  }

  File fileOf(String name) => File('${dir.path}/$name.vault');

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('secure_vault_test');
    keys = MemoryKeyStore();
  });

  tearDown(() => dir.delete(recursive: true));

  test('round-trips every supported type through the disk', () async {
    var vault = await open();
    await vault.setString('s', 'hello');
    await vault.setInt('i', 42);
    await vault.setDouble('d', 2.0);
    await vault.setBool('b', true);
    await vault.setStringList('l', ['a', 'b']);
    await vault.setMap('m', {
      'nested': [
        1,
        2,
        {'x': null},
      ],
    });
    await vault.setBytes('bytes', Uint8List.fromList([0, 1, 254, 255]));

    vault = await reopen(vault);
    expect(vault.getString('s'), 'hello');
    expect(vault.getInt('i'), 42);
    expect(vault.getDouble('d'), 2.0);
    expect(vault.getDouble('i'), 42.0);
    expect(vault.getBool('b'), isTrue);
    expect(vault.getStringList('l'), ['a', 'b']);
    expect(vault.getMap('m'), {
      'nested': [
        1,
        2,
        {'x': null},
      ],
    });
    expect(vault.getBytes('bytes'), [0, 1, 254, 255]);
    expect(vault.length, 7);
    await vault.close();
  });

  test('reads are synchronous right after a write', () async {
    final vault = await open();
    final pending = vault.setString('token', 'abc');
    expect(vault.getString('token'), 'abc');
    await pending;
    await vault.close();
  });

  test('stores nothing in plaintext', () async {
    final vault = await open();
    await vault.setString('api_token', 'super-secret-value');
    await vault.close();
    final raw = latin1.decode(await fileOf('test').readAsBytes());
    expect(raw, isNot(contains('super-secret-value')));
    expect(raw, isNot(contains('api_token')));
  });

  test('remove, null and clear persist', () async {
    var vault = await open();
    await vault.setAll({'a': 1, 'b': 2, 'c': 3});
    await vault.remove('a');
    await vault.set('b', null);
    vault = await reopen(vault);
    expect(vault.keys, ['c']);

    await vault.clear();
    vault = await reopen(vault);
    expect(vault.isEmpty, isTrue);
    await vault.close();
  });

  test('returned collections are copies', () async {
    final vault = await open();
    final source = {
      'list': [1],
    };
    await vault.setMap('m', source);
    source['list']!.add(2);
    vault.getMap('m')!['list'].add(3);
    expect(vault.getMap('m'), {
      'list': [1],
    });
    await vault.close();
  });

  test('rejects unsupported values without changing anything', () async {
    final vault = await open();
    await vault.setInt('keep', 1);
    expect(() => vault.set('bad', DateTime(2026)), throwsArgumentError);
    expect(() => vault.set('bad', {'x': Object()}), throwsArgumentError);
    expect(() => vault.set('bad', double.nan), throwsArgumentError);
    expect(() => vault.setAll({'ok': 1, 'bad': Object()}), throwsArgumentError);
    expect(vault.keys, ['keep']);
    await vault.close();
  });

  test('keeps every write when many are fired without awaiting', () async {
    var vault = await open();
    for (var i = 0; i < 300; i++) {
      vault.setInt('k${i % 50}', i);
    }
    await vault.flush();
    vault = await reopen(vault);
    expect(vault.length, 50);
    expect(vault.getInt('k0'), 250);
    expect(vault.getInt('k49'), 299);
    await vault.close();
  });

  test('buffered durability persists across close and reopen', () async {
    var vault = await SecureVault.open(
      'buffered',
      keyStore: keys,
      directory: dir,
      durability: VaultDurability.buffered,
    );
    expect(vault.durability, VaultDurability.buffered);
    for (var i = 0; i < 100; i++) {
      await vault.setInt('n', i);
    }
    await vault.close();
    vault = await open(name: 'buffered');
    expect(vault.getInt('n'), 99);
    await vault.close();
  });

  test('writes made during a flush land in the next batch', () async {
    var vault = await open();
    final first = vault.setString('a', '1');
    // these join one pending batch while the first is being written
    final rest = [for (var i = 0; i < 20; i++) vault.setString('b$i', '$i')];
    await Future.wait([first, ...rest]);
    vault = await reopen(vault);
    expect(vault.length, 21);
    expect(vault.getString('b19'), '19');
    await vault.close();
  });

  test('compacts overwritten history', () async {
    var vault = await open();
    for (var i = 0; i < 2000; i++) {
      await vault.setInt('counter', i);
    }
    final size = await fileOf('test').length();
    // 2000 records would be ~100 KB without compaction
    expect(size, lessThan(10 * 1024));
    vault = await reopen(vault);
    expect(vault.getInt('counter'), 1999);
    await vault.compact();
    expect(vault.getInt('counter'), 1999);
    await vault.close();
  });

  test('drops a torn write left by a crash', () async {
    var vault = await open();
    await vault.setString('safe', 'yes');
    await vault.close();

    // simulate a crash mid-append: a length prefix with half a record
    final file = fileOf('test');
    await file.writeAsBytes([0, 0, 0, 80, 1, 2, 3], mode: FileMode.append);
    final tornSize = await file.length();

    vault = await open();
    expect(vault.getString('safe'), 'yes');
    expect(await file.length(), lessThan(tornSize));
    await vault.setString('after', 'crash');
    vault = await reopen(vault);
    expect(vault.getString('after'), 'crash');
    await vault.close();
  });

  group('corruption', () {
    Future<void> tamper() async {
      final vault = await open();
      await vault.setString('a', 'b');
      await vault.close();
      final bytes = await fileOf('test').readAsBytes();
      bytes[bytes.length - 3] ^= 0xFF;
      await fileOf('test').writeAsBytes(bytes);
    }

    test('reset policy starts fresh after tampering', () async {
      await tamper();
      final vault = await open();
      expect(vault.isEmpty, isTrue);
      await vault.setString('new', 'data');
      expect((await reopen(vault)).getString('new'), 'data');
    });

    test('throwError policy reports tampering and keeps the file', () async {
      await tamper();
      final before = await fileOf('test').readAsBytes();
      await expectLater(
        open(onCorruption: VaultCorruptionPolicy.throwError),
        throwsA(
          isA<VaultException>().having(
            (e) => e.code,
            'code',
            VaultErrorCode.corrupted,
          ),
        ),
      );
      expect(await fileOf('test').readAsBytes(), before);
    });

    test('a missing key is reported or reset', () async {
      final vault = await open();
      await vault.setString('a', 'b');
      await vault.close();
      keys = MemoryKeyStore();

      await expectLater(
        open(onCorruption: VaultCorruptionPolicy.throwError),
        throwsA(
          isA<VaultException>().having(
            (e) => e.code,
            'code',
            VaultErrorCode.missingKey,
          ),
        ),
      );
      final fresh = await open();
      expect(fresh.isEmpty, isTrue);
      await fresh.close();
    });

    test('a wrong supplied key cannot read the data', () async {
      final key = List.filled(32, 7);
      final vault = await open(encryptionKey: key);
      await vault.setString('a', 'b');
      await vault.close();
      await expectLater(
        open(
          encryptionKey: List.filled(32, 8),
          onCorruption: VaultCorruptionPolicy.throwError,
        ),
        throwsA(isA<VaultException>()),
      );
      final again = await open(encryptionKey: key);
      expect(again.getString('a'), 'b');
      await again.close();
    });

    test('records cannot be moved between vaults', () async {
      final a = await open(name: 'a');
      await a.setString('k', 'v');
      await a.close();
      final b = await open(name: 'b');
      await b.close();
      // b's key differs anyway, so give both the same key to test the AAD
      final key = List.filled(32, 1);
      final a2 = await SecureVault.open(
        'a2',
        encryptionKey: key,
        directory: dir,
      );
      await a2.setString('k', 'v');
      await a2.close();
      await fileOf('a2').copy(fileOf('b2').path);
      await expectLater(
        SecureVault.open(
          'b2',
          encryptionKey: key,
          directory: dir,
          onCorruption: VaultCorruptionPolicy.throwError,
        ),
        throwsA(isA<VaultException>()),
      );
    });
  });

  test('watch emits the current value then every change', () async {
    final vault = await open();
    await vault.setInt('n', 1);
    final seen = <int?>[];
    final sub = vault.watch<int>('n').listen(seen.add);
    await pumpEventQueue();
    await vault.setInt('n', 2);
    await vault.setInt('other', 9);
    await vault.remove('n');
    await vault.setInt('n', 3);
    await vault.clear();
    await pumpEventQueue();
    expect(seen, [1, 2, null, 3, null]);
    await sub.cancel();
    await vault.close();
  });

  test('opening twice shares one instance until closed', () async {
    final a = await open();
    final b = await open();
    expect(identical(a, b), isTrue);
    await a.close();
    expect(() => a.setInt('x', 1), throwsA(isA<VaultException>()));
    final c = await open();
    expect(identical(a, c), isFalse);
    await c.close();
  });

  test('destroy removes the file and the key', () async {
    final vault = await open();
    await vault.setString('a', 'b');
    await SecureVault.destroy('test', keyStore: keys, directory: dir);
    expect(await fileOf('test').exists(), isFalse);
    expect(await keys.read('secure_vault.test'), isNull);
  });

  test('validates names and key length', () async {
    expect(() => open(name: '../escape'), throwsArgumentError);
    expect(() => open(name: ''), throwsArgumentError);
    expect(() => open(encryptionKey: [1, 2, 3]), throwsArgumentError);
  });

  test('large vaults load on a background isolate', () async {
    var vault = await open();
    await vault.setAll({
      for (var i = 0; i < 2000; i++) 'key$i': 'value-$i' * 5,
    });
    expect(await fileOf('test').length(), greaterThan(64 * 1024));
    vault = await reopen(vault);
    expect(vault.length, 2000);
    expect(vault.getString('key1999'), 'value-1999' * 5);
    await vault.close();
  });
}
