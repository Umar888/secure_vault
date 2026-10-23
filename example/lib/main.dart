import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:secure_vault/secure_vault.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final vault = await SecureVault.open('demo');
  runApp(VaultDemoApp(vault: vault));
}

class VaultDemoApp extends StatelessWidget {
  const VaultDemoApp({super.key, required this.vault});

  final SecureVault vault;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'secure_vault',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorSchemeSeed: Colors.teal),
      darkTheme: ThemeData(
        colorSchemeSeed: Colors.teal,
        brightness: Brightness.dark,
      ),
      home: DemoPage(vault: vault),
    );
  }
}

class DemoPage extends StatefulWidget {
  const DemoPage({super.key, required this.vault});

  final SecureVault vault;

  @override
  State<DemoPage> createState() => _DemoPageState();
}

class _DemoPageState extends State<DemoPage> {
  final _keyController = TextEditingController(text: 'api_token');
  final _valueController = TextEditingController();
  bool _benchmarking = false;
  _BenchResult? _vaultResult;
  _BenchResult? _secureStorageResult;

  SecureVault get _vault => widget.vault;

  @override
  void initState() {
    super.initState();
    // flutter run --dart-define=AUTOBENCH=true runs the benchmark on launch
    if (const bool.fromEnvironment('AUTOBENCH')) {
      WidgetsBinding.instance.addPostFrameCallback((_) => _runBenchmark());
    }
  }

  @override
  void dispose() {
    _keyController.dispose();
    _valueController.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final key = _keyController.text.trim();
    if (key.isEmpty) return;
    await _vault.setString(key, _valueController.text);
    _valueController.clear();
  }

  Future<void> _runBenchmark() async {
    setState(() => _benchmarking = true);
    const count = 200;

    final bench = await SecureVault.open('benchmark');
    await bench.clear();
    final vaultWrite = Stopwatch()..start();
    for (var i = 0; i < count; i++) {
      await bench.setString('key$i', 'value-$i');
    }
    vaultWrite.stop();
    final vaultRead = Stopwatch()..start();
    for (var i = 0; i < count; i++) {
      bench.getString('key$i');
    }
    vaultRead.stop();
    await SecureVault.destroy('benchmark');

    const storage = FlutterSecureStorage();
    final storageWrite = Stopwatch()..start();
    for (var i = 0; i < count; i++) {
      await storage.write(key: 'bench_key$i', value: 'value-$i');
    }
    storageWrite.stop();
    final storageRead = Stopwatch()..start();
    for (var i = 0; i < count; i++) {
      await storage.read(key: 'bench_key$i');
    }
    storageRead.stop();
    for (var i = 0; i < count; i++) {
      await storage.delete(key: 'bench_key$i');
    }

    if (!mounted) return;
    setState(() {
      _benchmarking = false;
      _vaultResult = _BenchResult(vaultWrite.elapsed, vaultRead.elapsed);
      _secureStorageResult = _BenchResult(
        storageWrite.elapsed,
        storageRead.elapsed,
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final text = Theme.of(context).textTheme;

    return Scaffold(
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(28),
                gradient: const LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    Color(0xFF00695C),
                    Color(0xFF00897B),
                    Color(0xFF26A69A),
                  ],
                ),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(Icons.lock_rounded, color: Colors.white, size: 36),
                  const SizedBox(height: 12),
                  Text(
                    'secure_vault',
                    style: text.headlineMedium?.copyWith(
                      color: Colors.white,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                  const SizedBox(height: 4),
                  StreamBuilder<VaultChange>(
                    stream: _vault.changes,
                    builder: (context, _) => Text(
                      '${_vault.length} encrypted keys · AES-256-GCM',
                      style: const TextStyle(color: Colors.white70),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),
            Text('Store a value', style: text.titleMedium),
            const SizedBox(height: 8),
            TextField(
              controller: _keyController,
              decoration: const InputDecoration(
                labelText: 'Key',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _valueController,
              decoration: const InputDecoration(
                labelText: 'Value',
                border: OutlineInputBorder(),
              ),
              onSubmitted: (_) => _save(),
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: FilledButton.icon(
                    onPressed: _save,
                    icon: const Icon(Icons.save_rounded),
                    label: const Text('Save'),
                  ),
                ),
                const SizedBox(width: 8),
                OutlinedButton(
                  onPressed: _vault.clear,
                  child: const Text('Clear all'),
                ),
              ],
            ),
            const SizedBox(height: 20),
            Text('Live contents', style: text.titleMedium),
            const SizedBox(height: 4),
            Text(
              'Rebuilt from vault.changes. Restart the app to see it persist.',
              style: text.bodySmall?.copyWith(color: scheme.onSurfaceVariant),
            ),
            const SizedBox(height: 8),
            StreamBuilder<VaultChange>(
              stream: _vault.changes,
              builder: (context, _) {
                final keys = _vault.keys.toList()..sort();
                if (keys.isEmpty) {
                  return const Card(
                    child: ListTile(title: Text('Nothing stored yet')),
                  );
                }
                return Card(
                  child: Column(
                    children: [
                      for (final key in keys)
                        ListTile(
                          title: Text(key),
                          subtitle: Text('${_vault[key]}'),
                          trailing: IconButton(
                            icon: const Icon(Icons.delete_outline),
                            onPressed: () => _vault.remove(key),
                          ),
                        ),
                    ],
                  ),
                );
              },
            ),
            const SizedBox(height: 20),
            Text('Benchmark: 200 writes + 200 reads', style: text.titleMedium),
            const SizedBox(height: 8),
            FilledButton.tonalIcon(
              onPressed: _benchmarking ? null : _runBenchmark,
              icon: _benchmarking
                  ? const SizedBox.square(
                      dimension: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.speed_rounded),
              label: Text(_benchmarking ? 'Running...' : 'Run benchmark'),
            ),
            if (_vaultResult != null && _secureStorageResult != null) ...[
              const SizedBox(height: 12),
              _BenchCard(
                label: 'secure_vault',
                result: _vaultResult!,
                highlight: true,
              ),
              const SizedBox(height: 8),
              _BenchCard(
                label: 'flutter_secure_storage',
                result: _secureStorageResult!,
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _BenchResult {
  const _BenchResult(this.write, this.read);

  final Duration write;
  final Duration read;
}

class _BenchCard extends StatelessWidget {
  const _BenchCard({
    required this.label,
    required this.result,
    this.highlight = false,
  });

  final String label;
  final _BenchResult result;
  final bool highlight;

  String _ms(Duration d) =>
      '${(d.inMicroseconds / 1000).toStringAsFixed(1)} ms';

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Card(
      color: highlight ? scheme.primaryContainer : null,
      child: ListTile(
        title: Text(label, style: const TextStyle(fontWeight: FontWeight.w700)),
        subtitle: Text(
          'write ${_ms(result.write)}  ·  read ${_ms(result.read)}',
        ),
      ),
    );
  }
}
