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
/**
 *
 * @author nghiatc
 * @since Mar 16, 2020
 */

library ntcdcrypto;

import 'dart:convert';
import 'dart:math';
import "package:hex/hex.dart";

import 'dart:typed_data';

class SSS {
  final BigInt prime =
      BigInt.parse("115792089237316195423570985008687907853269984665640564039457584007913129639747", radix: 10);
  var rand = Random.secure();

  // 16bit, because random.nextInt() only supports (2^32)-1 possible values.
  final part = 16; // 256bit / 16bit
  final maxInt16 = 1 << 16; // 2^16

  String genNumber() {
    String combinedVal = "";
    // random parts
    for (var i = 0; i < part; i++) {
      int part = rand.nextInt(maxInt16);
      combinedVal += part.toRadixString(10);
    }
    return combinedVal;
  }

  BigInt randomNumber() {
    BigInt rs = BigInt.parse(genNumber());
    while (rs.compareTo(prime) >= 0) {
      rs = BigInt.parse(genNumber());
    }
    return rs;
  }

  String toBase64(BigInt number) {
    String hexdata = number.toRadixString(16);
    int n = 64 - hexdata.length;
    for (int i = 0; i < n; i++) {
      hexdata = "0" + hexdata;
    }
    var bytedata = utf8.encode(hexdata); //ascii.encode(hexdata);
    var enbase64 = new Base64Encoder.urlSafe();
    return enbase64.convert(bytedata);
  }

  BigInt fromBase64(String number) {
    var debase64 = new Base64Decoder();
    String hexdata = utf8.decode(debase64.convert(number));
    return BigInt.parse(hexdata, radix: 16);
  }

  String toHex(BigInt number) {
    String hexdata = number.toRadixString(16);
    int n = 64 - hexdata.length;
    for (int i = 0; i < n; i++) {
      hexdata = "0" + hexdata;
    }
    return hexdata;
  }

  BigInt fromHex(String number) {
    return BigInt.parse(number, radix: 16);
  }

  List<BigInt> splitSecretToBigInt(String secret) {
    List<BigInt> rs = List();
    if (secret != null && secret.isNotEmpty) {
      String hexData = HEX.encode(utf8.encode(secret));
      int count = (hexData.length / 64.0).ceil();
      for (int i = 0; i < count; i++) {
        if ((i + 1) * 64 < hexData.length) {
          BigInt bi = BigInt.parse(hexData.substring(i * 64, (i + 1) * 64), radix: 16);
          rs.add(bi);
        } else {
          String last = hexData.substring(i * 64, hexData.length);
          int n = 64 - last.length;
          for (int j = 0; j < n; j++) {
            last += "0";
          }
          BigInt bi = BigInt.parse(last, radix: 16);
          rs.add(bi);
        }
      }
    }
    return rs;
  }

  String trimRight(String hexData) {
    int i = hexData.length - 1;
    while (i >= 0 && hexData[i] == '0') {
      --i;
    }
    return hexData.substring(0, i + 1);
  }

  String mergeBigIntToString(List<BigInt> secrets) {
    String rs = "";
    String hexData = "";
    for (BigInt s in secrets) {
      String tmp = s.toRadixString(16);
      int n = 64 - tmp.length;
      for (int j = 0; j < n; j++) {
        tmp = "0" + tmp;
      }
      hexData = hexData + tmp;
    }
    hexData = trimRight(hexData);
    //print(hexData);
    rs = utf8.decode(HEX.decode(hexData));
    return rs;
  }

  bool inNumbers(List<BigInt> numbers, BigInt value) {
    for (BigInt n in numbers) {
      if (n.compareTo(value) == 0) {
        return true;
      }
    }
    return false;
  }

  BigInt evaluatePolynomial(List<List<BigInt>> poly, int part, BigInt x) {
    int last = poly[part].length - 1;
    BigInt accum = poly[part][last];
    for (int i = last - 1; i >= 0; --i) {
      accum = ((accum * x) + poly[part][i]) % prime;
    }
    return accum;
  }

  List<String> create(int minimum, int shares, String secret) {
    List<String> rs = List();
    // Verify minimum isn't greater than shares; there is no way to recreate
    // the original polynomial in our current setup, therefore it doesn't make
    // sense to generate fewer shares than are needed to reconstruct the secret.
    if (minimum > shares) {
      throw new Exception("cannot require more shares then existing");
    }

    // Convert the secret to its respective 256-bit BigInteger representation
    List<BigInt> secrets = splitSecretToBigInt(secret);

    // List of currently used numbers in the polynomial
    List<BigInt> numbers = List();
    numbers.add(BigInt.zero);

    // Create the polynomial of degree (minimum - 1); that is, the highest
    // order term is (minimum-1), though as there is a constant term with
    // order 0, there are (minimum) number of coefficients.
    //
    // However, the polynomial object is a 2d array, because we are constructing
    // a different polynomial for each part of the secret
    //
    // polynomial[parts][minimum]
    //BigInt[][] polynomial = new BigInteger[secrets.size()][minimum];
    var polynomial = List<List<BigInt>>.generate(secrets.length, (i) => List<BigInt>.generate(minimum, (j) => BigInt.zero));
    for (int i=0; i<secrets.length; i++) {
      polynomial[i][0] = secrets[i];
      for (int j=1; j<minimum; j++) {
        // Each coefficient should be unique
        BigInt number = randomNumber();
        while (inNumbers(numbers, number)) {
          number = randomNumber();
        }
        numbers.add(number);

        polynomial[i][j] = number;
      }
    }
    //System.out.println(Arrays.deepToString(polynomial));

    // Create the points object; this holds the (x, y) points of each share.
    // Again, because secrets is an array, each share could have multiple parts
    // over which we are computing Shamir's Algorithm. The last dimension is
    // always two, as it is storing an x, y pair of points.
    //
    // points[shares][parts][2]
    //BigInteger[][][] points = new BigInteger[shares][secrets.size()][2];
    var points = List<List<List<BigInt>>>.generate(shares, (i) => List<List<BigInt>>.generate(secrets.length, (j) => List<BigInt>.generate(2, (k) => BigInt.zero)));

    // For every share...
    for (int i=0; i<shares; i++) {
      String s = "";
      // and every part of the secret...
      for (int j=0; j<secrets.length; j++) {
        // generate a new x-coordinate
        BigInt number = randomNumber();
        while (inNumbers(numbers, number)) {
          number = randomNumber();
        }
        numbers.add(number);

        // and evaluate the polynomial at that point
        points[i][j][0] = number;
        points[i][j][1] = evaluatePolynomial(polynomial, j, number);

        // encode to Hex.
        s += toHex(points[i][j][0]);
        s += toHex(points[i][j][1]);
        //System.out.println("x[share-"+i+"][part-"+j+"]: " + points[i][j][0].toString(10));
        //System.out.println("y[share-"+i+"][part-"+j+"]: " + points[i][j][1].toString(10));
      }
      rs.add(s);
    }

    return rs;
  }

  bool isValidShareHex(String candidate) {
    if (candidate == null || candidate.isEmpty) {
      return false;
    }
    if (candidate.length % 128 != 0) {
      return false;
    }
    int count = (candidate.length / 64).toInt();
    for (int i = 0; i < count; i++) {
      String part = candidate.substring(i * 64, (i + 1) * 64);
      BigInt decode = fromHex(part);
      // decode < 0 || decode > PRIME ==> false
      if (decode.compareTo(BigInt.one) == -1 || decode.compareTo(prime) == 1) {
        return false;
      }
    }
    return true;
  }

  List<List<List<BigInt>>> decodeShareHex(List<String> shares) {
    String first = shares[0];
    int nparts = (first.length / 128).toInt();

    // Recreate the original object of x, y points, based upon number of shares
    // and size of each share (number of parts in the secret).
    //
    // points[shares][parts][2]
    var points = List<List<List<BigInt>>>.generate(
        shares.length, (i) => List<List<BigInt>>.generate(nparts, (j) => List<BigInt>.generate(2, (k) => BigInt.zero)));

    // For each share...
    for (int i = 0; i < shares.length; i++) {
      // ensure that it is valid
      if (isValidShareHex(shares[i]) == false) {
        throw new Exception("one of the shares is invalid");
      }

      // find the number of parts it represents.
      String share = shares[i];
      int count = (share.length / 128).toInt();

      // and for each part, find the x,y pair...
      for (int j = 0; j < count; j++) {
        String cshare = share.substring(j * 128, (j + 1) * 128);
        // decoding from Hex.
        points[i][j][0] = fromHex(cshare.substring(0, 64));
        points[i][j][1] = fromHex(cshare.substring(64, 128));
      }
    }
    return points;
  }

  String combine(List<String> shares) {
    String rs = "";
    if (shares == null || shares.isEmpty) {
      throw new Exception("shares is NULL or empty");
    }

    // Recreate the original object of x, y points, based upon number of shares
    // and size of each share (number of parts in the secret).
    //
    // points[shares][parts][2]
    var points = decodeShareHex(shares);

    // Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
    // For each part of the secret (clearest to iterate over)...
    List<BigInt> secrets = List();
    int numSecret = points[0].length;
    for (int j = 0; j < numSecret; j++) {
      secrets.add(BigInt.zero);
      // and every share...
      for (int i = 0; i < shares.length; i++) { // LPI sum loop
        // remember the current x and y values
        BigInt ax = points[i][j][0]; // ax
        BigInt ay = points[i][j][1]; // ay
        BigInt numerator = BigInt.one; // LPI numerator
        BigInt denominator = BigInt.one; // LPI denominator
        // and for every other point...
        for (int k = 0; k < shares.length; k++) { // LPI product loop
          if (k != i) {
            // combine them via half products
            // x=0 ==> [(0-bx)/(ax-bx)] * ...
            BigInt bx = points[k][j][0]; // bx
            BigInt negbx = -bx; // (0-bx)
            BigInt axbx = ax - bx; // (ax-bx)
            numerator = (numerator * negbx) % prime; // (0-bx)*...
            denominator = (denominator * axbx) % prime; // (ax-bx)*...
          }
        }

        // LPI product: x=0, y = ay * [(x-bx)/(ax-bx)] * ...
        // multiply together the points (ay)(numerator)(denominator)^-1 ...
        BigInt fx = (ay * numerator) % prime;
        fx = (fx * (denominator.modInverse(prime))) % prime;

        // LPI sum: s = fx + fx + ...
        BigInt secret = secrets[j];
        secret = (secret + fx) % prime;
        secrets[j] = secret;
      }
    }

    // recover secret string.
    rs = mergeBigIntToString(secrets);
    return rs;
  }

}

main() {
  SSS sss = new SSS();
  // Test Dev
//  // Dev1: random numbers
//  for(var i=0;i<100;i++) {
//    var rd = sss.randomNumber();
//    print("rd: ${rd.toRadixString(10)}");
//  }

//  // Dev2: encode / decode
//  BigInt number = BigInt.parse("67356225285819719212258382314594931188352598651646313425411610888829358649431");
//  print(number.toRadixString(10));
//  var b64data = sss.toBase64(number);
//  print(b64data.length); // 88
//  print(b64data);  // lOpFwywpCeVAcK0/LOKG+YtW71xyj1bX06CcW7VZMFc=
//  // OTRlYTQ1YzMyYzI5MDllNTQwNzBhZDNmMmNlMjg2Zjk4YjU2ZWY1YzcyOGY1NmQ3ZDNhMDljNWJiNTU5MzA1Nw==
//  var hexdata = sss.toHex(number);
//  print(hexdata.length); // 65
//  print(hexdata); // 94ea45c32c2909e54070ad3f2ce286f98b56ef5c728f56d7d3a09c5bb5593057
//  var numb64decode = sss.fromBase64(b64data);
//  print(numb64decode);
//  var numhexdecode = sss.fromHex(hexdata);
//  print(numhexdecode);

//  // Dev3: split & merge
//  String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
//  print(s);
//  print(s.length);
//  var arr = sss.splitSecretToBigInt(s);
//  print(arr);
//  print(sss.inNumbers(arr, BigInt.parse("49937119214509114343548691117920141602615245118674498473442528546336026425464")));
//  var rs = sss.mergeBigIntToString(arr);
//  print(rs);
//  print(rs.length);

//  // Dev4: Generate Matrix 2D
//  final size = 5;
//  final grid = List<List<int>>.generate(
//      size, (i) => List<int>.generate(size, (j) => 0));
//  print(grid);


//  // test1
//  String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
//  print("secret: ${s}");
//  print("secret.length: ${s.length}");
//  // creates a set of shares
//  List<String> arr = sss.create(3, 6, s);
//  print(arr);
//
//  // combines shares into secret
//  var s1 = sss.combine(arr.sublist(0, 3));
//  print("combines shares 1 length = ${arr.sublist(0, 3).length}");
//  print("secret: ${s1}");
//  print("secret.length: ${s1.length}");
//
//  var s2 = sss.combine(arr.sublist(3, arr.length));
//  print("combines shares 2 length = ${arr.sublist(3, arr.length).length}");
//  print("secret: ${s2}");
//  print("secret.length: ${s2.length}");
//
//  var s3 = sss.combine(arr.sublist(1, 5));
//  print("combines shares 3 length = ${arr.sublist(1, 5).length}");
//  print("secret: ${s3}");
//  print("secret.length: ${s3.length}");


  // test2
  String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  print("secret: ${s}");
  print("secret.length: ${s.length}");
  // creates a set of shares
  List<String> arr = List();
  arr.add("fb57922a2e9c65fa3ab813d9407aca04c5e395d2af9a63808ac3d9fb598c4aaac300d578573808fab2e714aac4011cf6d1d82a769e183241b8e77760aaa4a37486b68684f3a36d8fc7f8060db91b27a4546ed2c4f25e62ef614a72ee48fdf4716426cd2caaf1c06c89b35292b8af53baf4e75ea5e6865744b1131940d66adb148713204887b9bf932b1f323a856990bcabbd46f4ab69caf86f19a09ab7b749f8a119d86abe0325af1737a093dfe30253ce351173bf8eb8217048034c5ee05837cf976bc2bd3520c18d0e76e66d57e7ae907dbbca2175631d86be0f2be4662a07704fe613ee8703be3aabc629f9ffaf9c0095edec58ea9d0c8e6eec113bc79e34");
  arr.add("bb56025e23e7845cb10d579e24312c4a78eab9b0c2913938a9ea05630ddba625d1da75753543bb2d3e5511f69b025a8b8ee9efc73f7a3f2348e42bc1c3a3820b3abecd51f417710b4fd5531aaa3eede026ae69ddc3838231f38ea85115777200add59f23af85661546a6089602795192169e69bbccf72783ae5d1a6535076d5dcc2051b9d03cf6fbc66caa56d8e089affd102c0af52639e000b145494e0a8dd1575c2bda511b647a9d527ce0773a9c2ae37d60a21fab78a74dddeabce79a43ed1463e0f8ad07dbb217371896ad543a9755de297b38e6188dcc3dc2d82960ebdb9123135780e861d88e4219f2decc94d5b4dc41cdb4838169ce552e253066ad5b");
  arr.add("8e9d3dfa8e02f8a270a16a3dbf299313b38f20285ccd2b87752a2510384dc28a061a6709d42cc385c7f4e19c3e15e4727c3ba990e355b7951fd5bac00cbf8eb7cf367ba2e783f29044fd078ffbe483aa253159d1b668148258a3015807bd90f0544cd8c5ab5800efb403e8b6b3e56333e80cfd7993bfa1c58ad4d93aaaed7d6b334c104375c954e86ca7096617e5f40267dddd8718be8a23c4958e9dc7cd7923b1cdf99f8a5efe97d3c10e8f57fd514405961dc34b1fb2d593f5d8bb92425eb0028ce40dfaaca5f3a43ccecc3f9504be4e26250e7706b132a26fbace1575c3a92c2f981dcd93f9e098c83db646ed41a972382e77424d6ad566138757a350c6d1");
  arr.add("671bd45a8bbc5d01ab3cba50279c7c7af1163c733b92b71224c3be538ef5b0fd9c5ca7b19a1805d954a0eba4790e632968892bfcce13d306b9183ad1c2d7f97d08d4c4e1175438911d17e674f1062cf057d354ad3a0f7034ff997e8b79d7266e7c4b98f0861246b35723e390160709e799a097a0ea9aff11d54afaeff3bf9492c94c856a81db4c40d389f976edf60472442fe4d6614059a8ea07558b4ab9f77ba0691ed0bc4f18541f53d331477f3c23b385e48164abf0baa9bc5e95f1afad6a73c5009e03e8b0ef894f1939e32364224818078b17386f11a773a3fc694c0975ee832d30e268506f76d88700912c9c1c23f82ccf1c047687f2922d3e3684673b");
  arr.add("c58b906aa93eaca1a19e67246cac713a8079f93fefb95a186545264c95e4e479ced656ccf2f8e7a41df5c0a9dd79524b9ab9d1731067471a211f4bb0890d95ace9861f599a19e2ec399ba7c3f523aeee644b9d704b7199a71df25452c94c7e7ce68651bb71fe5bcc400d82d2f503f9f49f1bd778a58285d5e46d893de45729aa32667dfe73df71713007df58de20c4045c9e72589772bc325817d3a5d34861cb2afa8959bd9fc8ff30c29695d24b35f10260db5e5f6e119172961a3f193d1cd9e1cd3853ec3d1b7a15ce8f3a1e443969de9f9691b6fb0d348055686e907156b33921b281b8dbd07848d0ce743dac94e983250b873848dd0afcc907110fc7921e");
  arr.add("76a5d1a340078c86c85a809c3cdfb539dccbc8af95e7cefba1ab6447eaec38636ec099086e72de93aef8d0c28fa0a9677e0fd2e3b6792c7d8feee462a570926a1779bf8b6ee15c3d46eb94d8e98049c4fcd1c27958a853ff1b177233c8ffd0fbc0ac2d5d05a48b102145927149c07457ce2d39f4f9f1a7df1ace57b5611459f488a4b1f49d8df025d67f12517a18e43f54d6eb4dfa5fb3869075b73e701f86e032a7c33bffad4a94460f41a76a2153d31444442460eb50e17754d458bac65bbd386f38e8a11e0f87201f5d3a0df4d0fd2d291d5b34fdcb4b504c3ea585ff032185b21d95b3b97a7a1be36833c5fd4a248b8375b7c03a8acf2301167b4fece766");
  print(arr);

  // combines shares into secret
  var s1 = sss.combine(arr.sublist(0, 3));
  print("combines shares 1 length = ${arr.sublist(0, 3).length}");
  print("secret: ${s1}");
  print("secret.length: ${s1.length}");

  var s2 = sss.combine(arr.sublist(3, arr.length));
  print("combines shares 2 length = ${arr.sublist(3, arr.length).length}");
  print("secret: ${s2}");
  print("secret.length: ${s2.length}");

  var s3 = sss.combine(arr.sublist(1, 5));
  print("combines shares 3 length = ${arr.sublist(1, 5).length}");
  print("secret: ${s3}");
  print("secret.length: ${s3.length}");


}
