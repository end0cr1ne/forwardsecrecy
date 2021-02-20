import 'dart:typed_data';
import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/asn1/object_identifiers.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/src/utils.dart';

Uint8List ecPublicKeyParser(String key) {
  var bytes = base64Decode(key
      .replaceAll('-----BEGIN PUBLIC KEY-----', '')
      .replaceAll('-----END PUBLIC KEY-----', ''));
  var asn1Parser = ASN1Parser(bytes);
  var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

  // print(((topLevelSeq.elements[0] as ASN1Sequence).elements[1] as ASN1Sequence)
  //     .elements);

  var algorithmIdentifierSequence = topLevelSeq.elements[0] as ASN1Sequence;
  var curveNameOi =
      algorithmIdentifierSequence.elements.elementAt(0) as ASN1ObjectIdentifier;
  var curveName;
  var data = ObjectIdentifiers.getIdentifierByIdentifier(
      curveNameOi.objectIdentifierAsString);
  if (data != null) {
    curveName = data['readableName'];
    // print("curve $curveName");
  }

  var subjectPublicKey = topLevelSeq.elements[1] as ASN1BitString;
  var pubBytes = subjectPublicKey.valueBytes;
  if (pubBytes.elementAt(0) == 0) {
    pubBytes = pubBytes.sublist(1);
  }

  // Looks good so far!
  var firstByte = pubBytes.elementAt(0);

  var x = pubBytes.sublist(1, (pubBytes.length / 2).round());
  // var y = pubBytes.sublist(1 + x.length, pubBytes.length);
  return x;
}

//parser : take out last 64 bits

Uint8List xKeyExtractor(String key) {
  var bytes = base64Decode(key
      .replaceAll('-----BEGIN PUBLIC KEY-----', '')
      .replaceAll('-----END PUBLIC KEY-----', ''));
  bytes = bytes.sublist(bytes.length - 64);
  var keybytes = bytes.sublist(0, (bytes.length / 2).round());
  return keybytes;
}

Uint8List writeBigInt(BigInt number) {
  // Not handling negative numbers. Decide how you want to do that.
  int bytes = (number.bitLength + 7) >> 3;
  var b256 = new BigInt.from(256);
  var result = new Uint8List(bytes);
  for (int i = 0; i < bytes; i++) {
    result[i] = number.remainder(b256).toInt();
    number = number >> 8;
  }
  return result;
}

String okey(List<int> keyBytes) {
  print("HACK!");

  var b = [
    0x30,
    0x82,
    0x01,
    0x31,
    0x30,
    0x81,
    0xEA,
    0x06,
    0x07,
    0x2A,
    0x86,
    0x48,
    0xCE,
    0x3D,
    0x02,
    0x01,
    0x30,
    0x81,
    0xDE,
    0x02,
    0x01,
    0x01,
    0x30,
    0x2B,
    0x06,
    0x07,
    0x2A,
    0x86,
    0x48,
    0xCE,
    0x3D,
    0x01,
    0x01,
    0x02,
    0x20,
    0x7F,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xED,
    0x30,
    0x44,
    0x04,
    0x20,
    0x2A,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0x98,
    0x49,
    0x14,
    0xA1,
    0x44,
    0x04,
    0x20,
    0x7B,
    0x42,
    0x5E,
    0xD0,
    0x97,
    0xB4,
    0x25,
    0xED,
    0x09,
    0x7B,
    0x42,
    0x5E,
    0xD0,
    0x97,
    0xB4,
    0x25,
    0xED,
    0x09,
    0x7B,
    0x42,
    0x5E,
    0xD0,
    0x97,
    0xB4,
    0x26,
    0x0B,
    0x5E,
    0x9C,
    0x77,
    0x10,
    0xC8,
    0x64,
    0x04,
    0x41,
    0x04,
    0x2A,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAA,
    0xAD,
    0x24,
    0x5A,
    0x20,
    0xAE,
    0x19,
    0xA1,
    0xB8,
    0xA0,
    0x86,
    0xB4,
    0xE0,
    0x1E,
    0xDD,
    0x2C,
    0x77,
    0x48,
    0xD1,
    0x4C,
    0x92,
    0x3D,
    0x4D,
    0x7E,
    0x6D,
    0x7C,
    0x61,
    0xB2,
    0x29,
    0xE9,
    0xC5,
    0xA2,
    0x7E,
    0xCE,
    0xD3,
    0xD9,
    0x02,
    0x20,
    0x10,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x14,
    0xDE,
    0xF9,
    0xDE,
    0xA2,
    0xF7,
    0x9C,
    0xD6,
    0x58,
    0x12,
    0x63,
    0x1A,
    0x5C,
    0xF5,
    0xD3,
    0xED,
    0x02,
    0x01,
    0x08,
    0x03,
    0x42,
    0x00,
    0x04
  ];

  var q = keyBytes +
      [
        63,
        158,
        201,
        195,
        194,
        240,
        169,
        114,
        121,
        46,
        169,
        141,
        207,
        169,
        78,
        24,
        40,
        85,
        116,
        54,
        95,
        73,
        39,
        189,
        100,
        30,
        52,
        223,
        121,
        34,
        247,
        40
      ];
  // var qBigie = decodeBigIntWithSign(1, q);

  var bigie = decodeBigIntWithSign(1, keyBytes);
  var ybigisq = bigie.pow(3) + BigInt.from(486662) * bigie.pow(2) + bigie;
  var ybigie = bigSqrt(ybigisq);
  var y = writeBigInt(ybigie);
  // print(qBigie.toString() + "\n" + bigie.toString());
  print("y: $y");
  //var a = b + keyBytes + y;
  var a = b + Uint8List.fromList(keyBytes);
  var dataBase64 = base64.encode(a);

  print("""-----BEGIN PUBLIC KEY-----$dataBase64-----END PUBLIC KEY-----""");
  return "";
}

BigInt bigSqrt(BigInt n) {
  if (0 == n) return BigInt.zero;
  var n1 = (n >> 1) + BigInt.one;
  var n2 = (n1 + (n ~/ n1)) >> 1;
  while (n2 < n1) {
    n1 = n2;
    n2 = (n1 + (n ~/ n1)) >> 1;
  }

  return n1;
}

BigInt decodeBigIntWithSign(int sign, List<int> magnitude) {
  if (sign == 0) {
    return BigInt.zero;
  }

  BigInt result;

  if (magnitude.length == 1) {
    result = BigInt.from(magnitude[0]);
  } else {
    result = BigInt.from(0);
    for (var i = 0; i < magnitude.length; i++) {
      var item = magnitude[magnitude.length - i - 1];
      result |= (BigInt.from(item) << (8 * i));
    }
  }

  if (result != BigInt.zero) {
    if (sign < 0) {
      result = result.toSigned(result.bitLength);
    } else {
      result = result.toUnsigned(result.bitLength);
    }
  }
  return result;
}
