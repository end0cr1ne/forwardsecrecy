import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import 'pkcs8.dart';
import 'forwardSec.dart';

List<int> xor(List<int> a, List<int> b) {
  List<int> result = new List(a.length);
  for (int i = 0; i < a.length; i++) result[i] = a[i] ^ b[i];
  return result;
}

Future<void> main() async {
  final keyPair1 = await x25519.newKeyPair();
  final nonce1 = Nonce.randomBytes(32);
  final keyPair2 = await x25519.newKeyPair();
  final nonce2 = Nonce.randomBytes(32);
  final message = utf8.encode("abcdef");
  const cipher = aesGcm;

  final hkdf = Hkdf(Hmac(sha256));

  var sharedSecret1 = await x25519.sharedSecret(
    localPrivateKey: keyPair1.privateKey,
    remotePublicKey: keyPair2.publicKey,
  );

  var sharedSecret2 = await x25519.sharedSecret(
    localPrivateKey: keyPair2.privateKey,
    remotePublicKey: keyPair1.publicKey,
  );

  final xordNonces = xor(nonce1.bytes, nonce2.bytes);
  final iv = Nonce.randomBytes(32); //Nonce(xordNonces.sublist(20, 32));

  final encrypted = await cipher.encrypt(
    message,
    secretKey: sharedSecret1,
    nonce: iv,
  );

  // Decrypt
  final decrypted = await cipher.decrypt(
    encrypted,
    secretKey: sharedSecret2,
    nonce: iv,
  );

  print(utf8.decode(decrypted));
  print(base64.encode(utf8.encode('Encrypted message')));
}
