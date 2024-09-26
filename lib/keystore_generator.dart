import 'dart:convert';
import 'dart:io';

import 'password_generator.dart';

class KeystoreGenerator {
  /// This method generates a keystore file and an alias.
  /// It reuses the password and DN for all keystore fields.
  static Future<void> generateKeystore(
    String keystorePath, {
    String? providedPassword,
    List<String>? keystoreAliases,
  }) async {
    final keystoreFile = File(keystorePath);
    final existingKeystore = keystoreFile.existsSync();

    final (keystorePassword, generatedPassword) = _validatePassword(
      providedPassword,
      existingKeystore,
    );

    final DistingushedName distingushedName;
    if (existingKeystore) {
      listExistingAliases(keystoreFile, keystorePassword);
      distingushedName = await _getDistingushedNameFromKeystore(
        keystoreFile,
        keystorePassword,
      );
    } else {
      distingushedName = _askDistingushedName();
    }

    // if no alias is provided, ask for one
    if (keystoreAliases == null || keystoreAliases.isEmpty) {
      final alias = _askInput('Enter the alias');
      if (alias != null && alias.isNotEmpty) {
        keystoreAliases = [alias];
      } else {
        stderr.writeln('Error: the alias must not be empty.');
        return;
      }
    }

    if (!existingKeystore) {
      // create parent directories for the keystore file
      keystoreFile.parent.createSync(recursive: true);
    }

    for (final alias in keystoreAliases) {
      stdout.writeln('Generating alias: $alias');
      await _generateAlias(
        keystoreFile,
        keystorePassword,
        alias,
        distingushedName,
      );
    }

    _outputReport(
      keystoreFile,
      keystoreAliases,
      generatedPassword ? keystorePassword : null,
      distingushedName,
    );
  }
}

(String keystorePassword, bool generated) _validatePassword(
  String? keystorePassword,
  bool existingKeystore,
) {
  bool generated = false;
  // ask for the keystore password if not provided
  if (keystorePassword == null || keystorePassword.isEmpty) {
    keystorePassword = _askInput(
      'Enter the keystore password',
      fallbackText: existingKeystore ? null : 'generated',
      fallback: null,
    );
    if (keystorePassword == null || keystorePassword.isEmpty) {
      String generatedPassword = PasswordGenerator.generatePassword(32);
      stdout.writeln('Generated password: $generatedPassword');
      keystorePassword = generatedPassword;
      generated = true;
    }
  }

  if (keystorePassword.isEmpty || keystorePassword.length < 6) {
    stderr.writeln('Error: the password must be at least 6 characters long.');
    throw StateError('Invalid password');
  }

  return (keystorePassword, generated);
}

Future<void> _generateAlias(
  File keystoreFile,
  String keystorePassword,
  String alias,
  DistingushedName distingushedName,
) async {
  if (alias.isEmpty) {
    stderr.writeln('Error: the alias must not be empty.');
    return;
  }
  final process = await Process.start('keytool', [
    '-genkey',
    '-v',
    '-keystore',
    keystoreFile.path,
    '-storepass',
    keystorePassword,
    '-keypass',
    keystorePassword,
    '-alias',
    alias,
    '-dname',
    distingushedName.toString(),
    '-keyalg',
    'RSA',
    '-keysize',
    '2048',
    '-validity',
    '25000',
  ]);

  final output = await process.stdout.transform(utf8.decoder).join();
  stdout.writeln(output);
}

Future<void> listExistingAliases(
  File keystoreFile,
  String keystorePassword,
) async {
  final aliases = await readAliases(keystoreFile, keystorePassword);
  if (aliases.isNotEmpty) {
    stdout.writeln('Keystore contains aliases: ${aliases.join(', ')}');
  }
}

Future<DistingushedName> _getDistingushedNameFromKeystore(
  File keystoreFile,
  String keystorePassword,
) async {
  final firstAlias = (await readAliases(keystoreFile, keystorePassword)).first;
  final distingushedName = await _readDistingushedNameFromAlias(
      keystoreFile, keystorePassword, firstAlias);
  stdout.writeln('Reusing DN from $firstAlias: $distingushedName');
  return distingushedName;
}

DistingushedName _askDistingushedName() {
  stdout.writeln('Enter the keystore distinguished name (DN):');
  final commonName = _askInput('Common Name (CN)', fallback: 'Unknown');
  final organizationalUnit =
      _askInput('Organizational Unit (OU)', fallback: 'Unknown');
  final organization = _askInput('Organization (O)', fallback: 'Unknown');
  final locality = _askInput('Locality (L)', fallback: 'Unknown');
  final state = _askInput('State (S)', fallback: 'Unknown');
  final country = _askInput('Country Code (C)', fallback: 'Unknown');

  final distingushedName = DistingushedName(
    commonName: commonName!,
    organizationalUnit: organizationalUnit!,
    organization: organization!,
    locality: locality!,
    state: state!,
    country: country!,
  );

  return distingushedName;
}

Future<List<String>> readAliases(
  File keystoreFile,
  String keystorePassword,
) async {
  final process = await Process.start('keytool', [
    '-list',
    '-v',
    '-keystore',
    keystoreFile.path,
    '-storepass',
    keystorePassword,
  ]);

  if (await process.exitCode != 0) {
    throw StateError('Could not read from keystore file.');
  }

  final output = await process.stdout.transform(utf8.decoder).join();
  final lines = output.split('\n');
  final aliases = <String>[];
  for (final line in lines) {
    if (line.startsWith('Alias name:')) {
      aliases.add(line.split(':').last.trim());
    }
  }
  return aliases;
}

Future<DistingushedName> _readDistingushedNameFromAlias(
  File keystoreFile,
  String keystorePassword,
  String alias,
) async {
  final process = await Process.start('keytool', [
    '-list',
    '-v',
    '-keystore',
    keystoreFile.path,
    '-storepass',
    keystorePassword,
    '-alias',
    alias,
  ]);

  final output = await process.stdout.transform(utf8.decoder).join();
  final lines = output.split('\n');
  for (final line in lines) {
    if (line.startsWith('Owner:')) {
      final parts = line.split(',');
      final commonName = parts.first.split('=')[1].trim();
      final organizationalUnit = parts[1].split('=')[1].trim();
      final organization = parts[2].split('=')[1].trim();
      final locality = parts[3].split('=')[1].trim();
      final state = parts[4].split('=')[1].trim();
      final country = parts[5].split('=')[1].trim();
      return DistingushedName(
        commonName: commonName,
        organizationalUnit: organizationalUnit,
        organization: organization,
        locality: locality,
        state: state,
        country: country,
      );
    }
  }
  return DistingushedName(
    commonName: 'Unknown',
    organizationalUnit: 'Unknown',
    organization: 'Unknown',
    locality: 'Unknown',
    state: 'Unknown',
    country: 'Unknown',
  );
}

class DistingushedName {
  final String commonName;
  final String organizationalUnit;
  final String organization;
  final String locality;
  final String state;
  final String country;

  DistingushedName({
    required this.commonName,
    required this.organizationalUnit,
    required this.organization,
    required this.locality,
    required this.state,
    required this.country,
  });

  @override
  String toString() {
    return 'CN=$commonName, OU=$organizationalUnit, O=$organization, L=$locality, S=$state, C=$country';
  }
}

String? _askInput(
  String question, {
  String? fallback,
  String? fallbackText,
}) {
  fallbackText ??= fallback;
  final showFallback = fallbackText != null;
  final fallbackDisplay = showFallback ? ' ($fallbackText)' : '';

  stdout.writeln('$question:$fallbackDisplay');
  final line = stdin.readLineSync();
  if (line == null || line.isEmpty) {
    return fallback;
  }
  return line;
}

void _outputReport(
  File keystoreFile,
  List<String> keystoreAliases,
  String? generatedPassword,
  DistingushedName distingushedName,
) {
  stdout.writeln('Keystore file: ${keystoreFile.path}');
  stdout.writeln('Keystore aliases: ${keystoreAliases.join(', ')}');
  stdout.writeln('Keystore DN: $distingushedName');
  if (generatedPassword != null) {
    stdout.writeln('Generated password: $generatedPassword');
  }
}
