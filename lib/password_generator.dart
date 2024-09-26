import 'dart:math';

class PasswordGenerator {
  static String generatePassword(int length) {
    final lowercase = 'abcdefghijklmnopqrstuvwxyz';
    final uppercase = lowercase.toUpperCase();
    final numbers = '0123456789';
    final symbols = '!@?#%&';
    final allChars = lowercase + uppercase + numbers + symbols;

    final random = Random.secure();
    final password = StringBuffer();

    // Ensure at least one character from each category
    password.write(lowercase[random.nextInt(lowercase.length)]);
    password.write(uppercase[random.nextInt(uppercase.length)]);
    password.write(numbers[random.nextInt(numbers.length)]);
    password.write(symbols[random.nextInt(symbols.length)]);

    // Fill remaining characters with random selection from all characters
    for (int i = 0; i < length - 4; i++) {
      password.write(allChars[random.nextInt(allChars.length)]);
    }

    return password.toString();
  }
}
