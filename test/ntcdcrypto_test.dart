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

import 'package:flutter_test/flutter_test.dart';

import 'package:ntcdcrypto/ntcdcrypto.dart';

// Run unittest
// cd ntc_dcrypto
// flutter test
void main() {
  SSS sss = new SSS();

  test('Test encode & decode', () {
    BigInt number = BigInt.parse(
        "67356225285819719212258382314594931188352598651646313425411610888829358649431");
    var b64data = sss.toBase64Url(number);
    expect(b64data.length, 44);
    expect(b64data, "lOpFwywpCeVAcK0_LOKG-YtW71xyj1bX06CcW7VZMFc=");
    var hexdata = sss.toHex(number);
    expect(hexdata.length, 64);
    expect(
        hexdata ==
            "94ea45c32c2909e54070ad3f2ce286f98b56ef5c728f56d7d3a09c5bb5593057",
        true);
    var numb64decode = sss.fromBase64Url(b64data);
    expect(numb64decode.compareTo(number), 0);
    var numhexdecode = sss.fromHex(hexdata);
    expect(numhexdecode.compareTo(number), 0);
  });

  test('Test split & merge', () {
    String s =
        "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    var arr = sss.splitSecretToBigInt(s);
    expect(
        sss.inNumbers(
            arr,
            BigInt.parse(
                "49937119214509114343548691117920141602615245118674498473442528546336026425464")),
        true);
    var rs = sss.mergeBigIntToString(arr);
    expect(rs, s);
  });

  test('Test create & combine Hex', () {
    String s =
        "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    // creates a set of shares
    List<String> arr = sss.create(3, 6, s, false);
    expect(arr.length, 6);

    // combines shares into secret
    var s1 = sss.combine(arr.sublist(0, 3), false);
    expect(s1, s);

    var s2 = sss.combine(arr.sublist(3, arr.length), false);
    expect(s2, s);

    var s3 = sss.combine(arr.sublist(1, 5), false);
    expect(s3, s);
  });

  test('Test combine Hex', () {
    String s =
        "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    // creates a set of shares
    List<String> arr = [];
    arr.add(
        "fb57922a2e9c65fa3ab813d9407aca04c5e395d2af9a63808ac3d9fb598c4aaac300d578573808fab2e714aac4011cf6d1d82a769e183241b8e77760aaa4a37486b68684f3a36d8fc7f8060db91b27a4546ed2c4f25e62ef614a72ee48fdf4716426cd2caaf1c06c89b35292b8af53baf4e75ea5e6865744b1131940d66adb148713204887b9bf932b1f323a856990bcabbd46f4ab69caf86f19a09ab7b749f8a119d86abe0325af1737a093dfe30253ce351173bf8eb8217048034c5ee05837cf976bc2bd3520c18d0e76e66d57e7ae907dbbca2175631d86be0f2be4662a07704fe613ee8703be3aabc629f9ffaf9c0095edec58ea9d0c8e6eec113bc79e34");
    arr.add(
        "bb56025e23e7845cb10d579e24312c4a78eab9b0c2913938a9ea05630ddba625d1da75753543bb2d3e5511f69b025a8b8ee9efc73f7a3f2348e42bc1c3a3820b3abecd51f417710b4fd5531aaa3eede026ae69ddc3838231f38ea85115777200add59f23af85661546a6089602795192169e69bbccf72783ae5d1a6535076d5dcc2051b9d03cf6fbc66caa56d8e089affd102c0af52639e000b145494e0a8dd1575c2bda511b647a9d527ce0773a9c2ae37d60a21fab78a74dddeabce79a43ed1463e0f8ad07dbb217371896ad543a9755de297b38e6188dcc3dc2d82960ebdb9123135780e861d88e4219f2decc94d5b4dc41cdb4838169ce552e253066ad5b");
    arr.add(
        "8e9d3dfa8e02f8a270a16a3dbf299313b38f20285ccd2b87752a2510384dc28a061a6709d42cc385c7f4e19c3e15e4727c3ba990e355b7951fd5bac00cbf8eb7cf367ba2e783f29044fd078ffbe483aa253159d1b668148258a3015807bd90f0544cd8c5ab5800efb403e8b6b3e56333e80cfd7993bfa1c58ad4d93aaaed7d6b334c104375c954e86ca7096617e5f40267dddd8718be8a23c4958e9dc7cd7923b1cdf99f8a5efe97d3c10e8f57fd514405961dc34b1fb2d593f5d8bb92425eb0028ce40dfaaca5f3a43ccecc3f9504be4e26250e7706b132a26fbace1575c3a92c2f981dcd93f9e098c83db646ed41a972382e77424d6ad566138757a350c6d1");
    arr.add(
        "671bd45a8bbc5d01ab3cba50279c7c7af1163c733b92b71224c3be538ef5b0fd9c5ca7b19a1805d954a0eba4790e632968892bfcce13d306b9183ad1c2d7f97d08d4c4e1175438911d17e674f1062cf057d354ad3a0f7034ff997e8b79d7266e7c4b98f0861246b35723e390160709e799a097a0ea9aff11d54afaeff3bf9492c94c856a81db4c40d389f976edf60472442fe4d6614059a8ea07558b4ab9f77ba0691ed0bc4f18541f53d331477f3c23b385e48164abf0baa9bc5e95f1afad6a73c5009e03e8b0ef894f1939e32364224818078b17386f11a773a3fc694c0975ee832d30e268506f76d88700912c9c1c23f82ccf1c047687f2922d3e3684673b");
    arr.add(
        "c58b906aa93eaca1a19e67246cac713a8079f93fefb95a186545264c95e4e479ced656ccf2f8e7a41df5c0a9dd79524b9ab9d1731067471a211f4bb0890d95ace9861f599a19e2ec399ba7c3f523aeee644b9d704b7199a71df25452c94c7e7ce68651bb71fe5bcc400d82d2f503f9f49f1bd778a58285d5e46d893de45729aa32667dfe73df71713007df58de20c4045c9e72589772bc325817d3a5d34861cb2afa8959bd9fc8ff30c29695d24b35f10260db5e5f6e119172961a3f193d1cd9e1cd3853ec3d1b7a15ce8f3a1e443969de9f9691b6fb0d348055686e907156b33921b281b8dbd07848d0ce743dac94e983250b873848dd0afcc907110fc7921e");
    arr.add(
        "76a5d1a340078c86c85a809c3cdfb539dccbc8af95e7cefba1ab6447eaec38636ec099086e72de93aef8d0c28fa0a9677e0fd2e3b6792c7d8feee462a570926a1779bf8b6ee15c3d46eb94d8e98049c4fcd1c27958a853ff1b177233c8ffd0fbc0ac2d5d05a48b102145927149c07457ce2d39f4f9f1a7df1ace57b5611459f488a4b1f49d8df025d67f12517a18e43f54d6eb4dfa5fb3869075b73e701f86e032a7c33bffad4a94460f41a76a2153d31444442460eb50e17754d458bac65bbd386f38e8a11e0f87201f5d3a0df4d0fd2d291d5b34fdcb4b504c3ea585ff032185b21d95b3b97a7a1be36833c5fd4a248b8375b7c03a8acf2301167b4fece766");
    expect(arr.length, 6);

    // combines shares into secret
    var s1 = sss.combine(arr.sublist(0, 3), false);
    expect(s1, s);

    var s2 = sss.combine(arr.sublist(3, arr.length), false);
    expect(s2, s);

    var s3 = sss.combine(arr.sublist(1, 5), false);
    expect(s3, s);
  });

  test('Test create & combine Base64Url', () {
    String s =
        "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    // creates a set of shares
    List<String> arr = sss.create(3, 6, s, true);
    expect(arr.length, 6);

    // combines shares into secret
    var s1 = sss.combine(arr.sublist(0, 3), true);
    expect(s1, s);

    var s2 = sss.combine(arr.sublist(3, arr.length), true);
    expect(s2, s);

    var s3 = sss.combine(arr.sublist(1, 5), true);
    expect(s3, s);
  });

  test('Test combine Base64Url', () {
    String s =
        "nghiatcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    // creates a set of shares
    List<String> arr = [];
    arr.add(
        "5K658W3HsUJznGuG-Wopl5RmlgfnOlIywIXNMK3FLk8=o3nzK8zTmfbDGStLLeKsE0jJrCMFOpLY1KAGHWFVzmw=wDyZ65yO8m4cQFRgfePvv9Bm13lqPnn89-mGCM6fG4A=IJrdRsJYkPCW9EeHu0x2k7nYcjdybQNMo97rpqhutck=vUw82_ma8GcxtutzRDlGPuzH4-xEeDt7F4HBoQ-BiIQ=xLoPS4AkYTi7neR6U2X36nA9EritybvqpeW5Fk2rH2M=cts237KejOmRLCFlcJuQak6yWNlspWYbpG--159CDsI=uF2CE31BTxuNw52ArvOWU012pKhUSbh8RZyVLgkB1Fs=");
    arr.add(
        "fTcsa9KUZ3Bj90Kjby3lQbWvw-qIz7qd3Hcp2GXFvOU=0I3lmm7QkNWceXgE7HlfqXFTjx9IC8DHJFxq1SHI38g=m-iAPMRkSeLhjBmpFCcVmK-ij717mo4A5CJb59x_WHc=QljK8TBqpMcGajO36Iq6TSY9i2sIpqryBUR-sM8AbS8=s_-MPlE5uyVL_x0tW4oqkhtUQ_p3ewck4SUhu_8BW7c=ngY2QG-0pw8dLUt6-n3Z8ZXAbu6omHsE487etr766U4=rBwse8m7gBiM-2sSSghUsZ6NyTr2AaUzlzYY73xySSQ=PlVKJLNYTQJQVrfr5xAYynR0jbOY1JRZlnxDX7jnvMg=");
    arr.add(
        "w3Jkf6Z7Yu1AZ6MKItRcctLnfbYAdFCXL2GQ5MFHiMY=RkRsomEVMrDNTcRp9z0-7OuxejYPHS-8KaCe7zU4J8M=yewuhylKn3k-lEtWGzGr3GWcwq6Iq1C3K04gtUwDjr4=v7Brej_SAU1ZgeUbNATPG6b0DG4W_UvWKWP-y1zwf8E=y_7M0EXAsGNb1RczU5O3ETSdLP6ZnmNfe_GbFzDQTvI=sCM7OcGlgDdzqOJtGPJmFdqqlSSsl-cxESbMGdWmDaM=BsGo_7_Ex9yD6I4_NNRDdTJlBaSapklJjmqnklAHtVY=SnGjhnGzb44mW-Znf66gQ2-EQpPrzq3qKENlh6sraHI=");
    arr.add(
        "csGGaMUuHDAaDonxJL0KfyG0Ss-T1dbuwZOJ-hxNI0o=UQlyoA6i2VMc2Kysl1sH1TC1zLeXOuAD8bHO0ojTRbc=IqdpT9Kx3J7k9-yU1D3pTKO2p3vX0H2NzipoQOWToNk=Q6ZE-2epO7xYtQs7fIQzn1gzgVDRxAVhqxIkIF_mJP4=M8wNAoP-KRL-aRx92guGJHG0aqB7Sil6dGWMhTGDwWk=SJhC8RRdnXJzpzdiGPGrJwUhyw0fURpwLSlVK20UxtY=9Vtngtd1PMfw9cIapuKX6ItqueqUG6S1VNGyWYmSCqk=h3zbVA1kDoxD_SiNGasrJX4vtW9kJs0KxA7KPogv9vA=");
    arr.add(
        "9QKSk5UpqHTDgqNzABhY1cpKJHW2Pa_qbMBlHS5sRwU=-MLMyVwzt3o9IbtsAfmslyniAJQ-jTfqrL2LFGoNRMs=x7qgHtj-OjDYv6WYtfklWEOyFguuZLHOCjn5Jn5a6J0=oM0tg3QDP8LsBDTWctnLHFtNpC9rs89FywzRL6KgJ70=e28jTt7Q-T9Ao4fZjZjZ0FRpfkvT9wSuXR17mEWSzSI=ZTFKrvAsNsmcQG0Ca4dSixgD20gXqQLJj8vdO30bzdM=Yy-smQCOzm2UVUPY7FX6_EkDoSrS4K6sfQ7X8CQedq8=xHp9pi-NJPosjyRQPypxs95j126JEk0D5qLZL6scx40=");
    arr.add(
        "jBMScPNqLqtB3GASqZ3XZux0Bh3vhGYw2h1SeaZJjEo=ZiguZLL3xU7FaEAynDjifHkynzRlm00eVNPhnr2NNW4=hJ_hcVm45CFYD9UrzxBrrJDyY_8l2wQ-M0PSH-V4Ck8=fpZJLvbIv85XS8CRutjavpY_Fdf76G-DirfnL6Nz3y0=3ZKJZ0WF-e79ZpaLT2MELiCbN3xRqNMzMrLbQ4A0qXc=deCGm9koob82zKVR-6XPiavInSatUnIEwJaTtEpbsJs=7xoGyz4IJG2SimElIYA-0lvnIKvZBbkK2PydA1TzOb0=dJ0OrQKkVhZNg9DIDRtW1MA7OvaMr385D4Q8MxiPaLQ=");
    expect(arr.length, 6);

    // combines shares into secret
    var s1 = sss.combine(arr.sublist(0, 3), true);
    expect(s1, s);

    var s2 = sss.combine(arr.sublist(3, arr.length), true);
    expect(s2, s);

    var s3 = sss.combine(arr.sublist(1, 5), true);
    expect(s3, s);
  });

  test('Test create & combine Hex with special cases: not Latin symbols', () {
    String s = "бар"; // Cyrillic
    // creates a set of shares
    List<String> arr = sss.create(3, 6, s, false);
    expect(arr.length, 6);

    // combines shares into secret
    var s1 = sss.combine(arr.sublist(0, 3), false);
    expect(s1, s);

    var s2 = sss.combine(arr.sublist(3, arr.length), false);
    expect(s2, s);

    var s3 = sss.combine(arr.sublist(1, 5), false);
    expect(s3, s);
  });

  test('Test create & combine Base64Url with special cases: not Latin symbols',
      () {
    String s = "бар"; // Cyrillic
    // creates a set of shares
    List<String> arr = sss.create(3, 6, s, true);
    expect(arr.length, 6);

    // combines shares into secret
    var s1 = sss.combine(arr.sublist(0, 3), true);
    expect(s1, s);

    var s2 = sss.combine(arr.sublist(3, arr.length), true);
    expect(s2, s);

    var s3 = sss.combine(arr.sublist(1, 5), true);
    expect(s3, s);
  });
}
