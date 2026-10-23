#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint secure_vault.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'secure_vault'
  s.version          = '0.2.0'
  s.summary          = 'Native AES-256-GCM for secure_vault.'
  s.description      = <<-DESC
Batch AES-256-GCM encryption for the secure_vault Flutter package, using CryptoKit.
                       DESC
  s.homepage         = 'https://github.com/Umar888/secure_vault'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'umar-ghaffar' => 'https://github.com/Umar888' }

  s.source           = { :path => '.' }
  s.source_files = 'secure_vault/Sources/secure_vault/**/*'

  # If your plugin requires a privacy manifest, for example if it collects user
  # data, update the PrivacyInfo.xcprivacy file to describe your plugin's
  # privacy impact, and then uncomment this line. For more information,
  # see https://developer.apple.com/documentation/bundleresources/privacy_manifest_files
  # s.resource_bundles = {'secure_vault_privacy' => ['secure_vault/Sources/secure_vault/PrivacyInfo.xcprivacy']}

  s.dependency 'FlutterMacOS'

  s.platform = :osx, '10.15'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
end
