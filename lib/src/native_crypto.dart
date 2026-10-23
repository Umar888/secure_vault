import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Batch AES-256-GCM through CryptoKit on iOS and macOS.
///
/// Android is left on the Dart cipher on purpose: javax.crypto's per-record
/// setup cost cancelled out its speed in benchmarks.
///
/// Every item is a combined box (nonce + ciphertext + tag), the same layout
/// the Dart path uses. Calls cross the platform channel once per batch, so
/// this only pays off for many records at a time: loading and compaction.
/// Single writes stay in Dart where they are cheaper.
abstract final class NativeCrypto {
  static const _channel = MethodChannel('secure_vault/crypto');
  static Future<bool>? _available;

  /// Whether a native implementation is registered on this platform.
  static Future<bool> isAvailable() => _available ??= _ping();

  static Future<bool> _ping() async {
    try {
      return await _channel.invokeMethod<bool>('ping') ?? false;
    } on Object {
      // MissingPluginException off Apple platforms, or no binding in tests
      return false;
    }
  }

  /// Forgets the cached availability check.
  @visibleForTesting
  static void resetAvailability() => _available = null;

  /// Decrypts every framed box in [frames], the record section of a vault
  /// file. A `null` entry means that record failed authentication.
  static Future<List<Uint8List?>> decryptAll(
    Uint8List key,
    Uint8List aad,
    Uint8List frames, {
    required int count,
  }) async {
    final result = await _invoke('decryptAll', key, aad, frames);
    final plaintexts = splitFrames(result);
    if (plaintexts.length != count) {
      throw PlatformException(
        code: 'bad_result',
        message: 'native decryptAll returned ${plaintexts.length} of $count',
      );
    }
    return plaintexts;
  }

  /// Encrypts [plaintexts] with fresh random nonces and returns framed
  /// records, ready to write to a vault file as is.
  static Future<Uint8List> encryptAll(
    Uint8List key,
    Uint8List aad,
    List<Uint8List> plaintexts,
  ) async {
    final input = BytesBuilder(copy: false);
    for (final plaintext in plaintexts) {
      input
        ..add(_length(plaintext.length))
        ..add(plaintext);
    }
    final result = await _invoke('encryptAll', key, aad, input.takeBytes());
    final boxes = splitFrames(result);
    if (boxes.length != plaintexts.length || boxes.contains(null)) {
      throw PlatformException(
        code: 'bad_result',
        message: 'native encryptAll returned a malformed batch',
      );
    }
    return result;
  }

  static Future<Uint8List> _invoke(
    String method,
    Uint8List key,
    Uint8List aad,
    Uint8List frames,
  ) async {
    final result = await _channel.invokeMethod<Uint8List>(method, {
      'key': key,
      'aad': aad,
      'frames': frames,
    });
    if (result == null) {
      throw PlatformException(code: 'bad_result', message: '$method: null');
    }
    return result;
  }

  static Uint8List _length(int value) =>
      (ByteData(4)..setUint32(0, value)).buffer.asUint8List();
}

/// Marks a record that failed authentication in native decrypt output.
const _failed = 0xFFFFFFFF;

/// Splits a blob of frames (u32 big-endian length + payload) into payload
/// views. A frame with the failure marker becomes `null`.
@visibleForTesting
List<Uint8List?> splitFrames(Uint8List blob) {
  final view = ByteData.sublistView(blob);
  final out = <Uint8List?>[];
  var offset = 0;
  while (offset + 4 <= blob.length) {
    final length = view.getUint32(offset);
    offset += 4;
    if (length == _failed) {
      out.add(null);
      continue;
    }
    if (offset + length > blob.length) {
      throw PlatformException(code: 'bad_result', message: 'truncated frame');
    }
    out.add(Uint8List.sublistView(blob, offset, offset + length));
    offset += length;
  }
  return out;
}
