import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'pkcs8.dart';

List<int> xor(List<int> a, List<int> b) {
  List<int> result = [];
  for (int i = 0; i < a.length; i++) result[i] = a[i] ^ b[i];
  return result;
}

Future<void> main() async {
  final message = utf8.encode('Encrypted message');
  final remotePublicKey = PublicKey(ecPublicKeyParser(
      '-----BEGIN PUBLIC KEY-----MIIBMTCB6gYHKoZIzj0CATCB3gIBATArBgcqhkjOPQEBAiB/////////////////////////////////////////7TBEBCAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqYSRShRAQge0Je0Je0Je0Je0Je0Je0Je0Je0Je0Je0JgtenHcQyGQEQQQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0kWiCuGaG4oIa04B7dLHdI0UySPU1+bXxhsinpxaJ+ztPZAiAQAAAAAAAAAAAAAAAAAAAAFN753qL3nNZYEmMaXPXT7QIBCANCAARL73a7EbIOstB8nng5rg4dHmE1I6/xd09O6aib6qRMwEeS4lLRARWDQAb3ygdKmXsj7fGdBdsj6cC1IWE1TBRq-----END PUBLIC KEY-----'));
  final remoteNonce =
      Nonce(base64Decode('UTZaeXVBSkdPUGhHVnFhQ3hPSlhLWXRydlFuZHJTYTk='));

  const cipher = aesGcm;
  final localNonce = Nonce.randomBytes(32);
  final hkdf = Hkdf(Hmac(sha256));

  //Key Exchange

  // Let's generate two keypairs.
  final localKeyPair = await x25519.newKeyPair();

  // We can now calculate a shared secret
  var sharedSecret = await x25519.sharedSecret(
    localPrivateKey: localKeyPair.privateKey,
    remotePublicKey: remotePublicKey,
  );

  //Key Derivation
  final xordNonces = xor(remoteNonce.bytes, localNonce.bytes);
  final salt = Nonce(xordNonces.getRange(0, 20));
  final iv = Nonce(xordNonces.getRange(20, 32));
  final sessionKey =
      await hkdf.deriveKey(sharedSecret, outputLength: 32, nonce: salt);

  //Encryption

  // Encrypt
  final encrypted = await cipher.encrypt(
    message,
    secretKey: sessionKey,
    nonce: iv,
  );

  // Decrypt
  // final decrypted = await cipher.decrypt(
  //   encrypted,
  //   secretKey: sessionKey,
  //   nonce: iv,
  // );

  print({
    'data': base64Encode(encrypted),
    'localNonce': localNonce,
    'publicKey': localKeyPair.publicKey
  });
}
