# ntc_dcrypto
ntc_dcrypto is module dart cryptography.

## Use this package as a library
Add this to your package's pubspec.yaml file:  
```yaml
dependencies:
  ntcdcrypto: ^0.0.5
```

## 1. An implementation of Shamir's Secret Sharing Algorithm 256-bits in Dart

### Usage
**Use encode/decode Base64Url**  
```dart
import 'package:ntcdcrypto/ntcdcrypto.dart';

main() {
  SSS sss = new SSS();
  String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  print("secret: ${s}");
  print("secret.length: ${s.length}");
  // creates a set of shares
  List<String> arr = sss.create(3, 6, s, true);
  //print(arr);

  // combines shares into secret
  var s1 = sss.combine(arr.sublist(0, 3), true);
  print("combines shares 1 length = ${arr.sublist(0, 3).length}");
  print("secret: ${s1}");
  print("secret.length: ${s1.length}");

  var s2 = sss.combine(arr.sublist(3, arr.length), true);
  print("combines shares 2 length = ${arr.sublist(3, arr.length).length}");
  print("secret: ${s2}");
  print("secret.length: ${s2.length}");

  var s3 = sss.combine(arr.sublist(1, 5), true);
  print("combines shares 3 length = ${arr.sublist(1, 5).length}");
  print("secret: ${s3}");
  print("secret.length: ${s3.length}");
}
```

**Use encode/decode Hex**  
```dart
import 'package:ntcdcrypto/ntcdcrypto.dart';

main() {
  SSS sss = new SSS();
  String s = "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  print("secret: ${s}");
  print("secret.length: ${s.length}");
  // creates a set of shares
  List<String> arr = sss.create(3, 6, s, false);
  //print(arr);

  // combines shares into secret
  var s1 = sss.combine(arr.sublist(0, 3), false);
  print("combines shares 1 length = ${arr.sublist(0, 3).length}");
  print("secret: ${s1}");
  print("secret.length: ${s1.length}");

  var s2 = sss.combine(arr.sublist(3, arr.length), false);
  print("combines shares 2 length = ${arr.sublist(3, arr.length).length}");
  print("secret: ${s2}");
  print("secret.length: ${s2.length}");

  var s3 = sss.combine(arr.sublist(1, 5), false);
  print("combines shares 3 length = ${arr.sublist(1, 5).length}");
  print("secret: ${s3}");
  print("secret.length: ${s3.length}");
}
```

## License
This code is under the [Apache License v2](https://www.apache.org/licenses/LICENSE-2.0).  
