import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter_sodium/flutter_sodium.dart';
import 'package:flutter_sodium/src/bindings/crypto_secretstream_bindings.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUpAll(Sodium.init);

  test('stream outputs match native bytes and remain owned after native reuse',
      () {
    final bindings = CryptoSecretstreamBindings();
    final key = Uint8List.fromList(List.generate(32, (i) => i));
    final init = Sodium.cryptoSecretstreamXchacha20poly1305InitPush(key);
    final referenceState =
        calloc<Uint8>(Sodium.cryptoSecretstreamXchacha20poly1305Statebytes);
    referenceState
        .asTypedList(Sodium.cryptoSecretstreamXchacha20poly1305Statebytes)
        .setAll(
            0,
            init.state.asTypedList(
                Sodium.cryptoSecretstreamXchacha20poly1305Statebytes));
    final pull =
        Sodium.cryptoSecretstreamXchacha20poly1305InitPull(init.header, key);
    final retained = <({Uint8List output, Uint8List expected})>[];
    try {
      final lengths = [0, 1, 4 * 1024 * 1024, 17];
      for (var index = 0; index < lengths.length; index++) {
        final length = lengths[index];
        final backing = Uint8List(length + 11);
        final message = Uint8List.sublistView(backing, 3, length + 3);
        for (var i = 0; i < length; i++) message[i] = (i * 131 + 19) & 255;
        final tag = index == lengths.length - 1
            ? Sodium.cryptoSecretstreamXchacha20poly1305TagFinal
            : index == 2
                ? Sodium.cryptoSecretstreamXchacha20poly1305TagRekey
                : Sodium.cryptoSecretstreamXchacha20poly1305TagMessage;
        final nativeMessage = calloc<Uint8>(length);
        final cipherLength =
            length + Sodium.cryptoSecretstreamXchacha20poly1305Abytes;
        final nativeCipher = calloc<Uint8>(cipherLength);
        final nativeLength = calloc<Uint64>();
        try {
          nativeMessage.asTypedList(length).setAll(0, message);
          expect(
              bindings.crypto_secretstream_xchacha20poly1305_push(
                  referenceState,
                  nativeCipher,
                  nativeLength,
                  nativeMessage,
                  length,
                  nullptr,
                  0,
                  tag),
              0);
          final expected =
              Uint8List.fromList(nativeCipher.asTypedList(nativeLength.value));
          final cipher = Sodium.cryptoSecretstreamXchacha20poly1305Push(
              init.state, message, null, tag);
          expect(cipher, expected);
          final decoded = Sodium.cryptoSecretstreamXchacha20poly1305Pull(
              pull, cipher, null);
          expect(decoded.m, message);
          expect(decoded.tag, tag);
          retained.add((output: cipher, expected: expected));
          retained
              .add((output: decoded.m, expected: Uint8List.fromList(message)));
          for (var attempt = 0; attempt < 8; attempt++) {
            final allocation = calloc<Uint8>(cipherLength);
            allocation
                .asTypedList(cipherLength)
                .fillRange(0, cipherLength, 0xA5);
            calloc.free(allocation);
          }
          for (final item in retained) expect(item.output, item.expected);
        } finally {
          calloc.free(nativeMessage);
          calloc.free(nativeCipher);
          calloc.free(nativeLength);
        }
      }
    } finally {
      calloc.free(init.state);
      calloc.free(referenceState);
      calloc.free(pull);
    }
  });
}
