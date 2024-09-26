import 'package:args/args.dart';
import 'package:ssa_keystore/keystore_generator.dart';

const String version = '0.0.1';

ArgParser buildParser() {
  return ArgParser()
    ..addFlag(
      'help',
      abbr: 'h',
      negatable: false,
      help: 'Print this usage information.',
    )
    ..addFlag(
      'verbose',
      abbr: 'v',
      negatable: false,
      help: 'Show additional command output.',
    )
    ..addFlag(
      'version',
      negatable: false,
      help: 'Print the tool version.',
    )
    ..addOption(
      'password',
      abbr: 'p',
      help: 'The password to use for the keystore and the alias',
    )
    ..addMultiOption(
      'alias',
      abbr: 'a',
      help: 'The alias to use for the keystore',
    );
}

void printUsage(ArgParser argParser) {
  print('Usage: ssa_keystore <flags> [keystore-file]');
  print(argParser.usage);
}

Future<void> main(List<String> arguments) async {
  final ArgParser argParser = buildParser();
  try {
    final ArgResults results = argParser.parse(arguments);
    bool verbose = false;

    // Process the parsed arguments.
    if (results.wasParsed('help')) {
      printUsage(argParser);
      return;
    }
    if (results.wasParsed('version')) {
      print('ssa_keystore version: $version');
      return;
    }
    final List<String> positionalArguments = results.rest;
    if (positionalArguments.isEmpty) {
      throw FormatException('No keystore file provided.');
    }

    if (results.wasParsed('verbose')) {
      verbose = true;
    }

    if (verbose) {
      print('[VERBOSE] All arguments: ${results.arguments}');
    }

    final keystorePath = positionalArguments.first;
    final keystorePassword = results['password'] as String?;
    final keystoreAliases = results['alias'] as List<String>?;

    await KeystoreGenerator.generateKeystore(
      keystorePath,
      providedPassword: keystorePassword,
      keystoreAliases: keystoreAliases,
    );
  } on FormatException catch (e) {
    // Print usage information if an invalid argument was provided.
    print(e.message);
    print('');
    printUsage(argParser);
  }
}
