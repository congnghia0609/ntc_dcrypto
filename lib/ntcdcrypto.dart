/*
 * Copyright 2020 nghiatc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
///
/// @author nghiatc
/// @since Mar 16, 2020

library ntcdcrypto;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

class SSS {
  final BigInt prime =
      BigInt.parse("115792089237316195423570985008687907853269984665640564039457584007913129639747", radix: 10);
  var rand = Random.secure();

  /// 16bit, because random.nextInt() only supports (2^32)-1 possible values.
  final part = 16; // 256bit / 16bit
  final maxInt16 = 1 << 16; // 2^16

  /// Generate number 256-bits base 10.
  String genNumber() {
    String combinedVal = "";
    // random parts
    for (var i = 0; i < part; i++) {
      int part = rand.nextInt(maxInt16);
      combinedVal += part.toRadixString(10);
    }
    return combinedVal;
  }

  /// Returns a random number from the range (0, PRIME-1) inclusive
  BigInt randomNumber() {
    BigInt rs = BigInt.parse(genNumber());
    while (rs.compareTo(prime) >= 0) {
      rs = BigInt.parse(genNumber());
    }
    return rs;
  }

  /// Convert hex string to Uint8List
  Uint8List hexToU8(String hex) {
    if (hex.length % 2 == 1) {
      hex = "0" + hex;
    }

    int len = hex.length ~/ 2;
    Uint8List u8 = new Uint8List(len);

    var j = 0;
    for (int i = 0; i < len; i++) {
      u8[i] = int.parse(hex.substring(j, j + 2), radix: 16);
      j += 2;
    }

    return u8;
  }

  /// Convert Uint8List to hex string
  String u8ToHex(Uint8List u8) {
    String hex = "";
    int len = u8.length;
    for (int i = 0; i < len; i++) {
      hex += u8[i].toRadixString(16).padLeft(2, '0');
    }
    return hex;
  }

  /// Return Base64Url string from BigInt 256 bits long
  String toBase64Url(BigInt number) {
    String hexData = number.toRadixString(16);
    int n = 64 - hexData.length;
    for (int i = 0; i < n; i++) {
      hexData = "0" + hexData;
    }
    return base64Url.encode(hexToU8(hexData));
  }

  /// Return BigInt from Base64Url string.
  BigInt fromBase64Url(String number) {
    return BigInt.parse(u8ToHex(base64Url.decode(number)), radix: 16);
  }

  /// Return Base64 string from BigInt 256 bits long
  String toBase64(BigInt number) {
    String hexData = number.toRadixString(16);
    int n = 64 - hexData.length;
    for (int i = 0; i < n; i++) {
      hexData = "0" + hexData;
    }
    return base64Url.encode(utf8.encode(hexData));
  }

  /// Return BigInt from Base64 string.
  BigInt fromBase64(String number) {
    return BigInt.parse(utf8.decode(base64Url.decode(number)), radix: 16);
  }

  /// Return Hex string from BigInt 256 bits long
  String toHex(BigInt number) {
    String hexData = number.toRadixString(16);
    int n = 64 - hexData.length;
    for (int i = 0; i < n; i++) {
      hexData = "0" + hexData;
    }
    return hexData;
  }

  /// Return BigInt from Hex string.
  BigInt fromHex(String number) {
    return BigInt.parse(number, radix: 16);
  }

  /// Converts a byte array into an a 256-bit BigInt, array based upon size of
  /// the input byte; all values are right-padded to length 256 bit, even if the most
  /// significant bit is zero.
  List<BigInt> splitSecretToBigInt(String secret) {
    final stringBuffer = StringBuffer();
    for (final byte in utf8.encode(secret)) {
      if (byte < 0 || byte > 255) throw const FormatException();
      stringBuffer.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    final hex = stringBuffer.toString();
    return [
      for (var i = 0; i < hex.length; i += 64)
        BigInt.parse(
          i + 64 < hex.length
              ? hex.substring(i, i + 64)
              : hex.substring(i).padRight(64, '0'),
          radix: 16,
        )
    ];
  }

  /// Remove right doubled characters '0' (zero byte in hex)
  String trimRightDoubledZero(String hexData) {
    int end = hexData.length;
    for (int i = hexData.length - 1; i > 2; i -= 2) {
      if (hexData[i] == '0' && hexData[i - 1] == '0') {
        end = i - 1;
      } else {
        break;
      }
    }
    return end == hexData.length ? hexData : hexData.substring(0, end);
  }

  /// Converts Hex String to byte array
  Uint8List hexToBytes(String value) => Uint8List.fromList([
    for (var i = 0; i < value.length; i += 2)
      int.parse(value.substring(i, i + 2), radix: 16)
  ]);

  /// Converts an array of BigInt to the original byte array, removing any least significant nulls.
  String mergeBigIntToString(List<BigInt> secrets) {
    final stringBuffer = StringBuffer();
    for (final s in secrets) {
      stringBuffer.write(s.toRadixString(16).padLeft(64, '0'));
    }
    return utf8.decode(hexToBytes(trimRightDoubledZero(stringBuffer.toString())));
  }

  /// inNumbers(array, value) returns boolean whether or not value is in array.
  bool inNumbers(List<BigInt> numbers, BigInt value) {
    for (BigInt n in numbers) {
      if (n.compareTo(value) == 0) {
        return true;
      }
    }
    return false;
  }

  /// Compute the polynomial value using Horner's method.
  /// https://en.wikipedia.org/wiki/Horner%27s_method
  /// y = a + bx + cx^2 + dx^3 = ((dx + c)x + b)x + a
  BigInt evaluatePolynomial(List<List<BigInt>> poly, int part, BigInt x) {
    int last = poly[part].length - 1;
    BigInt accum = poly[part][last];
    for (int i = last - 1; i >= 0; --i) {
      accum = ((accum * x) + poly[part][i]) % prime;
    }
    return accum;
  }

  /// Takes in a given string to check if it is a valid secret
  /// Requirements:
  /// 	 Length multiple of 88
  ///	 Can decode each 44 character block as Base64
  /// Returns only success/failure (bool)
  bool isValidShareBase64(String candidate) {
    if (candidate.isEmpty) {
      return false;
    }
    if (candidate.length % 88 != 0) {
      return false;
    }
    int count = candidate.length ~/ 44;
    for (int i = 0; i < count; i++) {
      String part = candidate.substring(i * 44, (i + 1) * 44);
      BigInt decode = fromBase64Url(part);
      // decode <= 0 || decode >= PRIME ==> false
      if (decode.compareTo(BigInt.zero) <= 0 || decode.compareTo(prime) >= 0) {
        return false;
      }
    }
    return true;
  }

  /// Takes a string array of shares encoded in Base64 created via Shamir's
  /// Algorithm; each string must be of equal length of a multiple of 88 characters
  /// as a single 88 character share is a pair of 256-bit numbers (x, y).
  List<List<List<BigInt>>> decodeShareBase64(List<String> shares) {
    String first = shares[0];
    int parts = first.length ~/ 88;

    // Recreate the original object of x, y points, based upon number of shares
    // and size of each share (number of parts in the secret).
    //
    // points[shares][parts][2]
    var points = List<List<List<BigInt>>>.generate(
        shares.length, (i) => List<List<BigInt>>.generate(parts, (j) => List<BigInt>.generate(2, (k) => BigInt.zero)));

    // For each share...
    for (int i = 0; i < shares.length; i++) {
      // ensure that it is valid
      if (isValidShareBase64(shares[i]) == false) {
        throw new Exception("one of the shares is invalid");
      }

      // find the number of parts it represents.
      String share = shares[i];
      int count = share.length ~/ 88;

      // and for each part, find the x,y pair...
      for (int j = 0; j < count; j++) {
        String pair = share.substring(j * 88, (j + 1) * 88);
        // decoding from Hex.
        points[i][j][0] = fromBase64Url(pair.substring(0, 44));
        points[i][j][1] = fromBase64Url(pair.substring(44, 88));
      }
    }
    return points;
  }

  /// Takes in a given string to check if it is a valid secret
  /// Requirements:
  /// 	 Length multiple of 128
  ///	 Can decode each 64 character block as Hex
  /// Returns only success/failure (bool)
  bool isValidShareHex(String candidate) {
    if (candidate.isEmpty) {
      return false;
    }
    if (candidate.length % 128 != 0) {
      return false;
    }
    int count = candidate.length ~/ 64;
    for (int i = 0; i < count; i++) {
      String part = candidate.substring(i * 64, (i + 1) * 64);
      BigInt decode = fromHex(part);
      // decode <= 0 || decode >= PRIME ==> false
      if (decode.compareTo(BigInt.zero) <= 0 || decode.compareTo(prime) >= 0) {
        return false;
      }
    }
    return true;
  }

  /// Takes a string array of shares encoded in Hex created via Shamir's
  /// Algorithm; each string must be of equal length of a multiple of 128 characters
  /// as a single 128 character share is a pair of 256-bit numbers (x, y).
  List<List<List<BigInt>>> decodeShareHex(List<String> shares) {
    String first = shares[0];
    int parts = first.length ~/ 128;

    // Recreate the original object of x, y points, based upon number of shares
    // and size of each share (number of parts in the secret).
    //
    // points[shares][parts][2]
    var points = List<List<List<BigInt>>>.generate(
        shares.length, (i) => List<List<BigInt>>.generate(parts, (j) => List<BigInt>.generate(2, (k) => BigInt.zero)));

    // For each share...
    for (int i = 0; i < shares.length; i++) {
      // ensure that it is valid
      if (isValidShareHex(shares[i]) == false) {
        throw new Exception("one of the shares is invalid");
      }

      // find the number of parts it represents.
      String share = shares[i];
      int count = share.length ~/ 128;

      // and for each part, find the x,y pair...
      for (int j = 0; j < count; j++) {
        String pair = share.substring(j * 128, (j + 1) * 128);
        // decoding from Hex.
        points[i][j][0] = fromHex(pair.substring(0, 64));
        points[i][j][1] = fromHex(pair.substring(64, 128));
      }
    }
    return points;
  }

  /// Returns a new array of secret shares (encoding x,y pairs as Base64 or Hex strings)
  /// created by Shamir's Secret Sharing Algorithm requiring a minimum number of
  /// share to recreate, of length shares, from the input secret raw as a string.
  List<String> create(int minimum, int shares, String secret, bool isBase64) {
    List<String> rs = [];
    // Verify minimum isn't greater than shares; there is no way to recreate
    // the original polynomial in our current setup, therefore it doesn't make
    // sense to generate fewer shares than are needed to reconstruct the secret.
    if (minimum <= 0 || shares <= 0) {
      throw new Exception("minimum or shares is invalid");
    }
    if (minimum > shares) {
      throw new Exception("cannot require more shares then existing");
    }
    if (secret.isEmpty) {
      throw new Exception("secret is NULL or empty");
    }

    // Convert the secret to its respective 256-bit BigInteger representation
    List<BigInt> secrets = splitSecretToBigInt(secret);

    // List of currently used numbers in the polynomial
    List<BigInt> numbers = [];
    numbers.add(BigInt.zero);

    // Create the polynomial of degree (minimum - 1); that is, the highest
    // order term is (minimum-1), though as there is a constant term with
    // order 0, there are (minimum) number of coefficients.
    //
    // However, the polynomial object is a 2d array, because we are constructing
    // a different polynomial for each part of the secret
    //
    // polynomial[parts][minimum]
    // BigInt[][] polynomial = new BigInt[secrets.size()][minimum];
    var polynomial =
        List<List<BigInt>>.generate(secrets.length, (i) => List<BigInt>.generate(minimum, (j) => BigInt.zero));
    for (int i = 0; i < secrets.length; i++) {
      polynomial[i][0] = secrets[i];
      for (int j = 1; j < minimum; j++) {
        // Each coefficient should be unique
        BigInt number = randomNumber();
        while (inNumbers(numbers, number)) {
          number = randomNumber();
        }
        numbers.add(number);

        polynomial[i][j] = number;
      }
    }

    // Create the points object; this holds the (x, y) points of each share.
    // Again, because secrets is an array, each share could have multiple parts
    // over which we are computing Shamir's Algorithm. The last dimension is
    // always two, as it is storing an x, y pair of points.
    //
    // For every share...
    for (int i = 0; i < shares; i++) {
      String s = "";
      // and every part of the secret...
      for (int j = 0; j < secrets.length; j++) {
        // generate a new x-coordinate
        BigInt x = randomNumber();
        while (inNumbers(numbers, x)) {
          x = randomNumber();
        }
        numbers.add(x);

        // and evaluate the polynomial at that point
        BigInt y = evaluatePolynomial(polynomial, j, x);
        if (isBase64) {
          // encode to Base64.
          s += toBase64Url(x);
          s += toBase64Url(y);
        } else {
          // encode to Hex.
          s += toHex(x);
          s += toHex(y);
        }
      }
      rs.add(s);
    }

    return rs;
  }

  /// Takes a string array of shares encoded in Base64 or Hex created via Shamir's Algorithm
  /// Note: the polynomial will converge if the specified minimum number of shares
  ///       or more are passed to this function. Passing thus does not affect it
  ///       Passing fewer however, simply means that the returned secret is wrong.
  String combine(List<String> shares, bool isBase64) {
    String rs = "";
    if (shares.isEmpty) {
      throw new Exception("shares is NULL or empty");
    }

    // Recreate the original object of x, y points, based upon number of shares
    // and size of each share (number of parts in the secret).
    //
    // points[shares][parts][2]
    var points;
    if (isBase64) {
      points = decodeShareBase64(shares);
    } else {
      points = decodeShareHex(shares);
    }

    // Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
    // For each part of the secret (clearest to iterate over)...
    List<BigInt> secrets = [];
    int numSecret = points[0].length;
    for (int j = 0; j < numSecret; j++) {
      secrets.add(BigInt.zero);
      // and every share...
      for (int i = 0; i < shares.length; i++) {
        // LPI sum loop
        // remember the current x and y values
        BigInt ax = points[i][j][0]; // ax
        BigInt ay = points[i][j][1]; // ay
        BigInt numerator = BigInt.one; // LPI numerator
        BigInt denominator = BigInt.one; // LPI denominator
        // and for every other point...
        for (int k = 0; k < shares.length; k++) {
          // LPI product loop
          if (k != i) {
            // combine them via half products
            // x=0 ==> [(0-bx)/(ax-bx)] * ...
            BigInt bx = points[k][j][0]; // bx
            numerator = (numerator * -bx) % prime; // (0-bx)*...
            denominator = (denominator * (ax - bx)) % prime; // (ax-bx)*...
          }
        }

        // LPI product: x=0, y = ay * [(x-bx)/(ax-bx)] * ...
        // multiply together the points (ay)(numerator)(denominator)^-1 ...
        BigInt fx = (ay * numerator) % prime;
        fx = (fx * (denominator.modInverse(prime))) % prime;

        // LPI sum: s = fx + fx + ...
        secrets[j] = (secrets[j] + fx) % prime;
      }
    }

    // recover secret string.
    rs = mergeBigIntToString(secrets);
    return rs;
  }
}
