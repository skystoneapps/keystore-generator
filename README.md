# Skystone Apps Keystore generator

## Usage

```bash
dart run bin/ssa_keystore.dart <options> [keystore file]
```

## Options

- `--help` or `-h`: Show help message
- `--password` or `-p`: Set keystore password
- `--alias` or `-a`: Set keystore alias, this can be added multiple times

## Example

```bash
dart run bin/ssa_keystore.dart -p password -a com.skystoneapps.example -a com.skystoneapps.example.staging keystore.jks
```
