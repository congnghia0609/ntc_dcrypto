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

  // Dev3: split & merge
  String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  print(s);
  print(s.length);
  var arr = sss.splitSecretToBigInt(s);
  print(arr);
  print(sss.inNumbers(arr, BigInt.parse("49937119214509114343548691117920141602615245118674498473442528546336026425464")));
  var rs = sss.mergeBigIntToString(arr);
  print(rs);
  print(rs.length);

}
