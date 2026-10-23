import CryptoKit
import Foundation

#if os(iOS)
  import Flutter
#else
  import FlutterMacOS
#endif

/// Batch AES-256-GCM for secure_vault using CryptoKit.
///
/// Both calls take and return one blob of frames (u32 big-endian length +
/// payload) so a whole vault crosses the channel as a single byte array.
/// Boxes are nonce (12) + ciphertext + tag (16), the same layout the Dart
/// fallback writes, so either side can read the other's files.
public class SecureVaultPlugin: NSObject, FlutterPlugin {
  // off the platform thread so big vaults don't stall the UI
  private let queue = DispatchQueue(label: "secure_vault.crypto", qos: .userInitiated)

  // marks a record that failed authentication in decrypt output
  private static let failed: UInt32 = 0xFFFF_FFFF

  public static func register(with registrar: FlutterPluginRegistrar) {
    #if os(iOS)
      let messenger = registrar.messenger()
    #else
      let messenger = registrar.messenger
    #endif
    let channel = FlutterMethodChannel(name: "secure_vault/crypto", binaryMessenger: messenger)
    registrar.addMethodCallDelegate(SecureVaultPlugin(), channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    if call.method == "ping" {
      result(true)
      return
    }
    guard call.method == "decryptAll" || call.method == "encryptAll" else {
      result(FlutterMethodNotImplemented)
      return
    }
    guard let args = call.arguments as? [String: Any],
      let key = (args["key"] as? FlutterStandardTypedData)?.data,
      let aad = (args["aad"] as? FlutterStandardTypedData)?.data,
      let frames = (args["frames"] as? FlutterStandardTypedData)?.data,
      key.count == 32
    else {
      result(FlutterError(code: "bad_args", message: "expected key, aad and frames", details: nil))
      return
    }

    let symmetricKey = SymmetricKey(data: key)
    let decrypt = call.method == "decryptAll"
    queue.async {
      do {
        let output = try Self.transform(frames) { payload in
          if decrypt {
            guard let box = try? AES.GCM.SealedBox(combined: payload),
              let clear = try? AES.GCM.open(box, using: symmetricKey, authenticating: aad)
            else { return nil }
            return clear
          }
          // default nonce is 12 random bytes, so combined is always non-nil
          return try AES.GCM.seal(payload, using: symmetricKey, authenticating: aad).combined!
        }
        DispatchQueue.main.async { result(FlutterStandardTypedData(bytes: output)) }
      } catch {
        DispatchQueue.main.async {
          result(FlutterError(code: "crypto_failed", message: "\(error)", details: nil))
        }
      }
    }
  }

  // maps each frame's payload through `body`; nil becomes a failed marker
  private static func transform(_ input: Data, _ body: (Data) throws -> Data?) throws -> Data {
    let bytes = [UInt8](input)
    var output = Data(capacity: bytes.count + bytes.count / 8)
    var offset = 0
    while offset + 4 <= bytes.count {
      let length =
        Int(bytes[offset]) << 24 | Int(bytes[offset + 1]) << 16
        | Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
      let start = offset + 4
      guard start + length <= bytes.count else {
        throw NSError(domain: "secure_vault", code: 1, userInfo: [NSLocalizedDescriptionKey: "truncated frame"])
      }
      if let out = try body(Data(bytes[start..<start + length])) {
        append(&output, UInt32(out.count))
        output.append(out)
      } else {
        append(&output, failed)
      }
      offset = start + length
    }
    return output
  }

  private static func append(_ data: inout Data, _ value: UInt32) {
    var bigEndian = value.bigEndian
    withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
  }
}
