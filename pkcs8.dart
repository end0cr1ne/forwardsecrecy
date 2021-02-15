import 'dart:typed_data';
import 'dart:convert';

import 'package:pointycastle/asn1/object_identifiers.dart';
import 'package:pointycastle/pointycastle.dart';

Uint8List ecPublicKeyParser(String key) {
  var bytes = base64Decode(key
      .replaceAll('-----BEGIN PUBLIC KEY-----', '')
      .replaceAll('-----END PUBLIC KEY-----', ''));
  var asn1Parser = ASN1Parser(bytes);
  var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
  
  print(topLevelSeq.elements[1].valueBytes);

  // var algorithmIdentifierSequence = topLevelSeq.elements[0] as ASN1Sequence;
  // var curveNameOi =
  //     algorithmIdentifierSequence.elements.elementAt(1) as ASN1ObjectIdentifier;
  // var curveName;
  // var data = ObjectIdentifiers.getIdentifierByIdentifier(
  //     curveNameOi.objectIdentifierAsString);
  // if (data != null) {
  //   curveName = data['readableName'];
  // }
  // print(curveName);

  var subjectPublicKey = topLevelSeq.elements[1] as ASN1BitString;
  var pubBytes = subjectPublicKey.valueBytes;
  if (pubBytes.elementAt(0) == 0) {
    pubBytes = pubBytes.sublist(1);
  }
  //Compressed Tag
  pubBytes = pubBytes.sublist(1);

  return pubBytes;
}
