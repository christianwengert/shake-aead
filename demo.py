import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import struct


# SHAKE wrapper using cryptography
class SHAKE256:
    def __init__(self):
        self.backend = default_backend()
        self._init_digest()

    def _init_digest(self):
        self.digest = hashes.Hash(hashes.SHAKE256(512), backend=self.backend)

    def absorb(self, data: bytes):
        self.digest.update(data)

    def squeeze(self, outlen: int) -> bytes:
        output = self.digest.finalize()[:outlen]
        self._init_digest()  # Reset for next squeeze
        return output


# Basic Overwrite Duplex construction (OD) using SHAKE
class OD:
    def __init__(self, capacity=512, rate=136):
        self.rate = rate
        self.capacity = capacity
        self.state = bytearray(rate)

    def permute(self):
        shake = SHAKE256()
        shake.absorb(self.state)
        self.state = bytearray(shake.squeeze(self.rate))

    def absorb(self, data: bytes):
        for i in range(len(data)):
            self.state[i % self.rate] ^= data[i]
            if (i + 1) % self.rate == 0:
                self.permute()

    def overwrite(self, data: bytes):
        for i in range(len(data)):
            self.state[i % self.rate] = data[i]
            if (i + 1) % self.rate == 0:
                self.permute()

    def squeeze(self, outlen: int) -> bytes:
        output = bytearray()
        while len(output) < outlen:
            self.permute()
            output += self.state[:self.rate]
        return bytes(output[:outlen])


# ODWrap authenticated encryption mode
class ODWrap:
    def __init__(self, key: bytes, nonce: bytes, ad: bytes = b''):
        if len(nonce) > 65535:
            raise ValueError("Nonce length must not exceed 65535 bytes")
        if len(ad) > 65535:
            raise ValueError("Associated data length must not exceed 65535 bytes")
        self.od = OD()
        self.od.absorb(b'ODWrap')
        self.od.absorb(struct.pack('<H', len(key)) + key)
        self.od.absorb(struct.pack('<H', len(nonce)) + nonce)
        self.od.absorb(struct.pack('<H', len(ad)) + ad)
        self.od.permute()

    def encrypt(self, plaintext: bytes, tag_len=16):
        ciphertext = bytearray()
        for b in plaintext:
            keystream = self.od.squeeze(1)
            c = b ^ keystream[0]
            ciphertext.append(c)
            self.od.overwrite(bytes([c]))
        tag = self.od.squeeze(tag_len)
        return bytes(ciphertext), tag

    def decrypt(self, ciphertext: bytes, tag: bytes):
        plaintext = bytearray()
        for b in ciphertext:
            keystream = self.od.squeeze(1)
            p = b ^ keystream[0]
            plaintext.append(p)
            self.od.overwrite(bytes([b]))
        test_tag = self.od.squeeze(len(tag))
        if test_tag != tag:
            raise ValueError("Invalid authentication tag")
        return bytes(plaintext)


# Upperdeck interface for Deck-BO mode
class DeckBO:
    def __init__(self, key: bytes, sid: bytes = b'', ad: bytes = b''):
        if len(sid) > 65535:
            raise ValueError("Session ID length must not exceed 65535 bytes")
        if len(ad) > 65535:
            raise ValueError("Associated data length must not exceed 65535 bytes")
        self.od = OD()
        self.od.absorb(b'Deck-BO')
        self.od.absorb(struct.pack('<H', len(key)) + key)
        self.od.absorb(struct.pack('<H', len(sid)) + sid)
        self.od.absorb(struct.pack('<H', len(ad)) + ad)
        self.od.permute()

    def wrap(self, plaintext: bytes, tag_len=16):
        ciphertext = bytearray()
        for b in plaintext:
            keystream = self.od.squeeze(1)
            c = b ^ keystream[0]
            ciphertext.append(c)
            self.od.overwrite(bytes([c]))
        tag = self.od.squeeze(tag_len)
        return bytes(ciphertext), tag

    def unwrap(self, ciphertext: bytes, tag: bytes):
        plaintext = bytearray()
        for b in ciphertext:
            keystream = self.od.squeeze(1)
            p = b ^ keystream[0]
            plaintext.append(p)
            self.od.overwrite(bytes([b]))
        test_tag = self.od.squeeze(len(tag))
        if test_tag != tag:
            raise ValueError("Invalid authentication tag")
        return bytes(plaintext)


# Example usage
if __name__ == '__main__':
    key = b'secretkey1234567'
    nonce = secrets.token_bytes(32)  # that should be enough
    ad = b'associated_data' + b'01' * 100 + b'FF'
    plaintext = b'Hello, lets shake up authenticated encryption. This will kick aes-gcm\'s ass big time. Furthermore I just want to go on and on and on. Nevermind.'

    print("Original:", plaintext)

    # ODWrap
    odwrap = ODWrap(key, nonce, ad)
    ciphertext, tag = odwrap.encrypt(plaintext)
    print("Ciphertext:", ciphertext)
    print("Tag:", tag)

    odwrap2 = ODWrap(key, nonce, ad)
    decrypted = odwrap2.decrypt(ciphertext, tag)
    print("Decrypted:", decrypted)

    # Deck-BO
    print("Deck - BOexample: ")
    deck = DeckBO(key, sid=b'session_id', ad=ad)
    msg1 = b'First message'
    msg2 = b'Second message'

    # Encrypt two messages in one session
    c1, t1 = deck.wrap(msg1)
    c2, t2 = deck.wrap(msg2)

    print("Message 1 Ciphertext:", c1)
    print("Message 1 Tag:", t1)
    print("Message 2 Ciphertext:", c2)
    print("Message 2 Tag:", t2)

    # Resume session for decryption by using the same session ID
    deck_resume1 = DeckBO(key, sid=b'session_id', ad=ad)
    p1 = deck_resume1.unwrap(c1, t1)
    p2 = deck_resume1.unwrap(c2, t2)

    print("Resumed Session Decrypted Message 1:", p1)
    print("Resumed Session Decrypted Message 2:", p2)
