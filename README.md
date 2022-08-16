# sss256
sss256 is a library with utilities for encode\decode secret with Shamir`s Secret Sharing algo


## Use this package as a library
Add this to your package's pubspec.yaml file:  
```yaml
dependencies:
  sss256: ^1.0.0
```


## 1. An implementation of Shamir's Secret Sharing Algorithm 256-bits in Dart


### Usage
**Use encode/decode Base64Url**  
```dart
import 'package:sss256';

main() {
  const secret = 'Very secret "foo bar"';

  print('Secret before encoding: $secret');
  final shares = splitSecret(
    secret: secret,
    treshold: 3,
    shares: 6,
  );

  print('Secret splited shares:');
  print(shares);
  final restoredSecret = restoreSecret(shares: shares.sublist(0, 3));
  print('\nRestored secret: $restoredSecret');
}
```


**Use encode/decode Hex**  
```dart
import 'package:sss256';

main() {
  const secret = 'Very secret "foo bar"';

  print('Secret before encoding: $secret');
  final shares = splitSecret(
    isBase64: false,
    secret: secret,
    treshold: 3,
    shares: 6,

  );

  print('Secret splited shares:');
  print(shares);
  final restoredSecret = restoreSecret(shares: shares.sublist(0, 3), isBase64: false);
  print('\nRestored secret: $restoredSecret');
}
```


### Run Unit Test
```shell
flutter test
```


## License
This code is under the [Apache License v2](https://www.apache.org/licenses/LICENSE-2.0).  
