import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

// File layout:
//   header: "SVLT" + format version (1 byte)
//   records: u32 big-endian length, then nonce (12) + ciphertext + GCM tag (16)
// Each record holds one JSON-encoded operation. Replaying them in order
// rebuilds the vault, and compaction rewrites the file with one set per key.

const _magic = [0x53, 0x56, 0x4C, 0x54];
const _formatVersion = 1;
const _nonceLength = 12;
const _macLength = 16;

/// Length of the file header in bytes.
const headerLength = 5;

/// Header bytes written at the start of every vault file.
Uint8List vaultHeader() => Uint8List.fromList([..._magic, _formatVersion]);

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

/// Encrypts and decrypts individual records with AES-256-GCM.
///
/// The vault name is bound in as associated data, so a record copied from
/// one vault file into another fails authentication.
class RecordCipher {
  RecordCipher(Uint8List key, String vaultName)
    : _key = SecretKeyData(key),
      _aad = utf8.encode('secure_vault:v$_formatVersion:$vaultName');

  static final _aes = DartAesGcm.with256bits();

  final SecretKeyData _key;
  final List<int> _aad;

  Uint8List encodeSet(String key, Object value) => switch (value) {
    Uint8List() => _encode([_opSetBytes, key, base64Encode(value)]),
    JsonValue() => _encode([_opSetJson, key, value.encoded]),
    _ => _encode([_opSet, key, value]),
  };

  Uint8List encodeRemove(String key) => _encode([_opRemove, key]);

  Uint8List encodeClear() => _encode(const [_opClear]);

  Uint8List _encode(List<Object?> op) {
    final box = _aes.encryptSync(
      utf8.encode(jsonEncode(op)),
      secretKeyData: _key,
      aad: _aad,
    );
    final length =
        box.nonce.length + box.cipherText.length + box.mac.bytes.length;
    return (BytesBuilder(copy: false)
          ..add((ByteData(4)..setUint32(0, length)).buffer.asUint8List())
          ..add(box.nonce)
          ..add(box.cipherText)
          ..add(box.mac.bytes))
        .takeBytes();
  }

  /// Decrypts the record body at [offset]. Throws
  /// [SecretBoxAuthenticationError] when the record was not written with this
  /// key and vault name.
  List<Object?> decode(Uint8List bytes, int offset, int length) {
    final end = offset + length;
    final box = SecretBox(
      Uint8List.sublistView(bytes, offset + _nonceLength, end - _macLength),
      nonce: Uint8List.sublistView(bytes, offset, offset + _nonceLength),
      mac: Mac(Uint8List.sublistView(bytes, end - _macLength, end)),
    );
    final clear = _aes.decryptSync(box, secretKeyData: _key, aad: _aad);
    return jsonDecode(utf8.decode(clear)) as List<Object?>;
  }
}

/// Outcome of reading a vault file.
final class LoadResult {
  const LoadResult({
    required this.entries,
    required this.records,
    required this.validLength,
    this.failure,
  });

  final Map<String, Object> entries;

  /// Number of records replayed, used to decide when to compact.
  final int records;

  /// Bytes that parsed cleanly. Anything past this is a torn write from a
  /// crash and gets truncated. 0 means the header needs writing.
  final int validLength;

  /// Set when the file is unreadable as a whole.
  final String? failure;
}

/// Replays every record in [bytes]. Pure and synchronous so it can run on a
/// background isolate for large vaults.
LoadResult parseVault(Uint8List bytes, Uint8List key, String vaultName) {
  final entries = <String, Object>{};
  // empty or a header torn mid-write: nothing was ever stored
  if (bytes.length < headerLength) {
    return LoadResult(entries: entries, records: 0, validLength: 0);
  }
  for (var i = 0; i < _magic.length; i++) {
    if (bytes[i] != _magic[i]) {
      return LoadResult(
        entries: entries,
        records: 0,
        validLength: 0,
        failure: 'not a secure_vault file',
      );
    }
  }
  if (bytes[_magic.length] != _formatVersion) {
    return LoadResult(
      entries: entries,
      records: 0,
      validLength: 0,
      failure: 'unsupported format version ${bytes[_magic.length]}',
    );
  }

  final cipher = RecordCipher(key, vaultName);
  final view = ByteData.sublistView(bytes);
  var offset = headerLength;
  var records = 0;
  while (offset + 4 <= bytes.length) {
    final length = view.getUint32(offset);
    if (length < _nonceLength + _macLength ||
        offset + 4 + length > bytes.length) {
      break;
    }
    try {
      _apply(entries, cipher.decode(bytes, offset + 4, length));
    } on Object catch (e) {
      return LoadResult(
        entries: const {},
        records: 0,
        validLength: 0,
        failure: e is SecretBoxAuthenticationError
            ? 'record at byte $offset failed authentication'
            : 'record at byte $offset is malformed: $e',
      );
    }
    records++;
    offset += 4 + length;
  }
  return LoadResult(entries: entries, records: records, validLength: offset);
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
