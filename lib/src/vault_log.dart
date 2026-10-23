import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

// File layout:
//   header: "SVLT" + format version (1 byte)
//   records: u32 big-endian length, then a box: nonce (12) + ciphertext +
//   GCM tag (16)
// Each record holds one JSON-encoded operation. Replaying them in order
// rebuilds the vault, and compaction rewrites the file with one set per key.
// Boxes use the standard combined layout, so the Dart and native crypto
// paths read each other's output.

const _magic = [0x53, 0x56, 0x4C, 0x54];
const _formatVersion = 1;
const _nonceLength = 12;
const _macLength = 16;

/// Length of the file header in bytes.
const headerLength = 5;

/// Header bytes written at the start of every vault file.
Uint8List vaultHeader() => Uint8List.fromList([..._magic, _formatVersion]);

/// Associated data bound into every record, so a record copied from one
/// vault file into another fails authentication.
Uint8List vaultAad(String vaultName) =>
    utf8.encode('secure_vault:v$_formatVersion:$vaultName');

// operation codes stored in each record
const _opSet = 0;
const _opRemove = 1;
const _opClear = 2;
const _opSetBytes = 3;
const _opSetJson = 4;

/// A list or map held in memory in encoded form, so callers always get a
/// fresh copy and can never mutate the cache by accident.
final class JsonValue {
  const JsonValue(this.encoded);

  final String encoded;

  Object? decode() => jsonDecode(encoded);
}

/// Builds operation plaintexts and seals them with AES-256-GCM in Dart.
class RecordCipher {
  RecordCipher(this.key, String vaultName) : aad = vaultAad(vaultName);

  static final _aes = DartAesGcm.with256bits();

  final Uint8List key;
  final Uint8List aad;
  late final SecretKeyData _secret = SecretKeyData(key);

  static Uint8List setOp(String key, Object value) => _op(switch (value) {
    Uint8List() => [_opSetBytes, key, base64Encode(value)],
    JsonValue() => [_opSetJson, key, value.encoded],
    _ => [_opSet, key, value],
  });

  static Uint8List removeOp(String key) => _op([_opRemove, key]);

  static Uint8List clearOp() => _op(const [_opClear]);

  static Uint8List _op(List<Object?> op) => utf8.encode(jsonEncode(op));

  /// Encrypts [plaintext] and returns a framed record ready to append.
  Uint8List seal(Uint8List plaintext) {
    final box = _aes.encryptSync(plaintext, secretKeyData: _secret, aad: aad);
    return frame(
      (BytesBuilder(copy: false)
            ..add(box.nonce)
            ..add(box.cipherText)
            ..add(box.mac.bytes))
          .takeBytes(),
    );
  }

  /// Decrypts one box, or returns `null` if it fails authentication.
  Uint8List? open(Uint8List box) {
    if (box.length < _nonceLength + _macLength) return null;
    final end = box.length;
    try {
      return Uint8List.fromList(
        _aes.decryptSync(
          SecretBox(
            Uint8List.sublistView(box, _nonceLength, end - _macLength),
            nonce: Uint8List.sublistView(box, 0, _nonceLength),
            mac: Mac(Uint8List.sublistView(box, end - _macLength)),
          ),
          secretKeyData: _secret,
          aad: aad,
        ),
      );
    } on SecretBoxAuthenticationError {
      return null;
    }
  }

  /// Prefixes [box] with its big-endian u32 length.
  static Uint8List frame(Uint8List box) =>
      (BytesBuilder(copy: false)
            ..add((ByteData(4)..setUint32(0, box.length)).buffer.asUint8List())
            ..add(box))
          .takeBytes();
}

/// The boxes found in a vault file, before decryption.
final class FrameScan {
  const FrameScan(this.boxes, this.validLength, [this.failure]);

  final List<Uint8List> boxes;

  /// Bytes that framed cleanly. Anything past this is a torn write from a
  /// crash and gets truncated. 0 means the header needs writing.
  final int validLength;

  /// Set when the file is not a readable vault at all.
  final String? failure;
}

/// Splits a vault file into boxes without decrypting anything.
FrameScan scanFrames(Uint8List bytes) {
  // empty or a header torn mid-write: nothing was ever stored
  if (bytes.length < headerLength) return const FrameScan([], 0);
  for (var i = 0; i < _magic.length; i++) {
    if (bytes[i] != _magic[i]) {
      return const FrameScan([], 0, 'not a secure_vault file');
    }
  }
  if (bytes[_magic.length] != _formatVersion) {
    return FrameScan(
      const [],
      0,
      'unsupported format version ${bytes[_magic.length]}',
    );
  }

  final view = ByteData.sublistView(bytes);
  final boxes = <Uint8List>[];
  var offset = headerLength;
  while (offset + 4 <= bytes.length) {
    final length = view.getUint32(offset);
    if (length < _nonceLength + _macLength ||
        offset + 4 + length > bytes.length) {
      break;
    }
    boxes.add(Uint8List.sublistView(bytes, offset + 4, offset + 4 + length));
    offset += 4 + length;
  }
  return FrameScan(boxes, offset);
}

/// Outcome of reading a vault file.
final class LoadResult {
  const LoadResult({
    required this.entries,
    required this.records,
    required this.validLength,
    this.failure,
  });

  const LoadResult.failed(String this.failure)
    : entries = const {},
      records = 0,
      validLength = 0;

  final Map<String, Object> entries;

  /// Number of records replayed, used to decide when to compact.
  final int records;

  /// See [FrameScan.validLength].
  final int validLength;

  /// Set when the file is unreadable as a whole.
  final String? failure;
}

/// Replays decrypted operations into a key-value map. A `null` plaintext is
/// a record that failed authentication and fails the whole load.
LoadResult replay(FrameScan scan, List<Uint8List?> plaintexts) {
  final entries = <String, Object>{};
  for (var i = 0; i < plaintexts.length; i++) {
    final clear = plaintexts[i];
    if (clear == null) {
      return LoadResult.failed('record $i failed authentication');
    }
    try {
      _apply(entries, jsonDecode(utf8.decode(clear)) as List<Object?>);
    } on Object catch (e) {
      return LoadResult.failed('record $i is malformed: $e');
    }
  }
  return LoadResult(
    entries: entries,
    records: plaintexts.length,
    validLength: scan.validLength,
  );
}

/// Reads a whole vault with the Dart cipher. Pure and synchronous so it can
/// run on a background isolate.
LoadResult loadWithDart(Uint8List bytes, Uint8List key, String vaultName) {
  final scan = scanFrames(bytes);
  if (scan.failure != null) return LoadResult.failed(scan.failure!);
  final cipher = RecordCipher(key, vaultName);
  return replay(scan, [for (final box in scan.boxes) cipher.open(box)]);
}

void _apply(Map<String, Object> entries, List<Object?> op) {
  switch (op[0]) {
    case _opSet:
      entries[op[1]! as String] = op[2]!;
    case _opSetJson:
      entries[op[1]! as String] = JsonValue(op[2]! as String);
    case _opSetBytes:
      entries[op[1]! as String] = base64Decode(op[2]! as String);
    case _opRemove:
      entries.remove(op[1]);
    case _opClear:
      entries.clear();
    default:
      throw FormatException('unknown operation ${op[0]}');
  }
}
