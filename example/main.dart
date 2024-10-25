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

import '../lib/ntcdcrypto.dart';

main() {
  SSS sss = new SSS();

  String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  print("Secret key origin: $s");

  // 1. SSS create & combine with Hex encode/decode
  // creates a set of shares
  List<String> arrHex = sss.create(3, 6, s, false);
  print("Array key shares Hex:");
  print(arrHex);
  // combines shares into secret
  var s1 = sss.combine(arrHex.sublist(0, 3), false);
  print("Secret key combine Hex: $s1");

  // 2. SSS create & combine with Base64Url encode/decode
  // creates a set of shares
  List<String> arrBase64 = sss.create(3, 6, s, true);
  print("Array key shares Base64Url:");
  print(arrBase64);
  // combines shares into secret
  var s2 = sss.combine(arrBase64.sublist(0, 3), true);
  print("Secret key combine Base64Url: $s2");
}
