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
///
/// @author alexandrim0@gmail.com
/// @since Aug 16, 2022
///

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

typedef BigIntGeneretor = BigInt Function({required List<BigInt> excluding});

extension on List<BigInt> {
  BigInt addAndReturn(BigInt value) {
    this.add(value);
    return value;
  }
}

final _random = Random.secure();
final _randomStringBuffer = StringBuffer();
final _prime = BigInt.parse('43'.padLeft(64, 'f'), radix: 16);

/// Returns a new array of secret shares (encoding x,y pairs as Base64 or Hex strings)
/// created by Shamir's Secret Sharing Algorithm requiring a minimum number of
/// share to recreate, of length shares, from the input secret raw as a string.
List<String> splitSecret({
  required int treshold,
  required int shares,
  required String secret,
  bool isBase64 = true,
  BigIntGeneretor generateRandomNumber = generateRandomNumber,
}) {
  if (secret.isEmpty) throw Exception('secret is empty');
  if (shares <= 0) throw Exception('Invalid shares count');
  if (treshold <= 0 || treshold > shares) throw Exception('Invalid treshold');

  // Convert the secret to its respective 256-bit BigInteger representation
  final chunks = splitSecretToChunks(secret);
  final numbers = [BigInt.zero]; // List of unique numbers in the polynomial

  // Create the polynomial of degree (treshold - 1); that is, the highest
  // order term is (treshold-1), though as there is a constant term with
  // order 0, there are (treshold) number of coefficients.
  // However, the polynomial object is a 2d array, because we are constructing
  // a different polynomial for each part of the secret
  final polynomial = [
    for (final chunk in chunks)
      <BigInt>[
        chunk,
        numbers.addAndReturn(generateRandomNumber(excluding: numbers)),
      ]
  ];
  // Create the points object; this holds the (x, y) points of each share.
  // Again, because secrets is an array, each shard could have multiple parts
  // over which we are computing Shamir's Algorithm. The last dimension is
  // always two, as it is storing an x, y pair of points.
  final result = <String>[];
  final stringBuffer = StringBuffer();
  // For every share...
  for (var i = 0; i < shares; i++) {
    // and every part of the secret...
    for (var j = 0; j < chunks.length; j++) {
      // generate a new unique x-coordinate
      final x = numbers.addAndReturn(generateRandomNumber(excluding: numbers));
      // and evaluate the polynomial at that point
      final y = evaluatePolynomial(polynomial, j, x);
      stringBuffer.write(encodeNumber(x, isBase64));
      stringBuffer.write(encodeNumber(y, isBase64));
    }
    result.add(stringBuffer.toString());
    stringBuffer.clear();
  }
  return result;
}

/// Takes a string array of shares encoded in Base64 or Hex created via Shamir's Algorithm
/// Note: the polynomial will converge if the specified minimum number of shares
///       or more are passed to this function. Passing thus does not affect it
///       Passing fewer however, simply means that the returned secret is wrong.
String restoreSecret({
  required List<String> shares,
  bool isBase64 = true,
}) {
  final points = sharesToPoints(shares, isBase64);
  final secrets = <BigInt>[];

  // Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
  // For each part of the secret (clearest to iterate over)...
  for (var part = 0; part < points.first.length; part++) {
    secrets.add(BigInt.zero);
    // and every share...
    for (var share = 0; share < shares.length; share++) {
      // LPI sum loop
      // remember the current x and y values
      final ax = points[share][part][0];
      final ay = points[share][part][1];
      var numerator = BigInt.one; // LPI numerator
      var denominator = BigInt.one; // LPI denominator
      // and for every other point...
      for (var k = 0; k < shares.length; k++) {
        // LPI product loop
        if (k == share) continue;
        // combine them via half products
        // x=0 ==> [(0-bx)/(ax-bx)] * ...
        final bx = points[k][part][0];
        numerator = (numerator * -bx) % _prime;
        denominator = (denominator * (ax - bx)) % _prime;
      }
      // LPI product: x=0, y = ay * [(x-bx)/(ax-bx)] * ...
      // multiply together the points (ay)(numerator)(denominator)^-1 ...
      var fx = (ay * numerator) % _prime;
      fx = (fx * (denominator.modInverse(_prime))) % _prime;
      secrets[part] =
          (secrets[part] + fx) % _prime; // LPI sum: s = fx + fx + ...
    }
  }
  return combineChunksToSecret(secrets); // recover secret string.
}

/// Returns a random number from the range (0, PRIME-1) inclusive
BigInt generateRandomNumber({required List<BigInt> excluding}) {
  var result = BigInt.zero;
  do {
    while (_randomStringBuffer.length < 64) {
      _randomStringBuffer.write(_random.nextInt(15).toRadixString(16));
    }
    result = BigInt.parse(_randomStringBuffer.toString(), radix: 16);
    _randomStringBuffer.clear();
  } while (result >= _prime || excluding.contains(result));
  return result;
}

/// Converts Hex String to byte array
Uint8List hexToBytes(String value) => Uint8List.fromList([
      for (var i = 0; i < value.length; i += 2)
        int.parse(value.substring(i, i + 2), radix: 16)
    ]);

/// Encode BignInt to string (base64 or hex) with left padding to 64 chars
String encodeNumber(BigInt value, bool encodeToBase64) {
  final hex = value.toRadixString(16).padLeft(64, '0');
  return encodeToBase64 ? base64UrlEncode(hexToBytes(hex)) : hex;
}

/// Converts a byte array into an a 256-bit BigInt, array based upon size of
/// the input byte; all values are right-padded to length 256 bit, even if the most
/// significant bit is zero.
List<BigInt> splitSecretToChunks(String secret) {
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

/// Compute the polynomial value using Horner's method.
/// https://en.wikipedia.org/wiki/Horner%27s_method
/// y = a + bx + cx^2 + dx^3 = ((dx + c)x + b)x + a
BigInt evaluatePolynomial(List<List<BigInt>> poly, int part, BigInt x) {
  final last = poly[part].length - 1;
  var accum = poly[part][last];
  for (var i = last - 1; i >= 0; i--) {
    accum = ((accum * x) + poly[part][i]) % _prime;
  }
  return accum;
}

/// Remove right doubled characters '0' (zero byte in hex)
String trimRightDoubledZero(String value) {
  var end = value.length;
  for (var i = value.length - 1; i > 2; i -= 2) {
    if (value[i] == '0' && value[i - 1] == '0')
      end = i - 1;
    else
      break;
  }
  return end == value.length ? value : value.substring(0, end);
}

/// Converts an array of BigInt to the original byte array, removing any least significant nulls.
String combineChunksToSecret(List<BigInt> chunks) {
  final stringBuffer = StringBuffer();
  for (final chunk in chunks) {
    stringBuffer.write(chunk.toRadixString(16).padLeft(64, '0'));
  }
  return utf8.decode(hexToBytes(trimRightDoubledZero(stringBuffer.toString())));
}

/// Returns a number from base64 or Hex string (0 to PRIME-1 inclusive)
BigInt decodeNumber(String value, bool isBase64) {
  if (isBase64) {
    final stringBuffer = StringBuffer();
    base64Decode(value).forEach(
        (e) => stringBuffer.write(e.toRadixString(16).padLeft(2, '0')));
    value = stringBuffer.toString();
  }
  final result = BigInt.parse(value, radix: 16);
  if (result <= BigInt.zero || result >= _prime) throw const FormatException();
  return result;
}

/// Takes a string array of shares encoded in Base64 created via Shamir's Algorithm
/// Each string must be of equal length (a multiple of 88 characters for base64 or 128 for hex)
/// as a single chunk is a pair of 256-bit numbers (x, y).
List<List<List<BigInt>>> sharesToPoints(List<String> shares, bool isBase64) {
  // Check if shares are correct
  final shardLength = shares[0].length;
  if (shardLength == 0 || shardLength % (isBase64 ? 88 : 128) != 0) {
    throw const FormatException();
  }
  for (final shard in shares) {
    if (shard.length != shardLength) throw const FormatException();
  }
  // Recreate the original object of x, y points, based upon number of shares
  // and size of each share (number of parts in the secret).
  // points[shares][parts][x,y]
  final length = isBase64 ? 88 : 128;
  final half = length ~/ 2;
  return [
    for (final shard in shares)
      [
        for (var i = 0; i < shares[0].length; i += length)
          [
            decodeNumber(shard.substring(i, i + half), isBase64),
            decodeNumber(shard.substring(i + half, i + length), isBase64),
          ]
      ]
  ];
}
