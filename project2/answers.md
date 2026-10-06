Part 1

1.1

-pbkdf2 tells OpenSSL to derive the AES key from the passphrase using PBKDF2, which combines the passphrase with a random salt and hashes it many times to produce a full-length 256-bit key. A passphrase is too short and predictable to be used as a key directly.

1.2

The checksums are different because each encryption generates a new random salt, which changes the derived key, so the same plaintext produces completely different ciphertext each time.

1.3

ECB had 3 distinct blocks, and the most common one repeated 24 times. CBC had 37 distinct blocks, each appearing once.

ECB leaked the pattern of the data, since identical blocks encrypt the same way. An attacker cannot read it, but can see repeats and tell when two records are the same.

I would ask what mode they use and how the IVs are generated, since ECB or reused IVs leak patterns.

Part 2

2.2

SHA-256 has no secret, so an attacker can change the file and just make a new matching hash. HMAC needs a secret key, so the attacker cannot make a valid tag and the change gets detected. With either one, the attacker can still read, block, or replay messages, but with HMAC they cannot fake a changed file.

Part 3

3.3

The email check only proves the uploader controls that inbox. It does not prove who they really are or that the account was not hacked.

I would compare all 40 fingerprint characters with my classmate in person or over a call. The fingerprint is a hash of the key, so a swapped key would have a different fingerprint, and the attacker cannot control both channels.

Part 4

4.2

The pubkey enc packet holds a random session key encrypted with my RSA public key. The encrypted data packet holds my message encrypted with AES using that session key. GPG does this because RSA is slow and only works on small data, while AES is fast. This is called hybrid encryption.

4.3

Signing: my private key.
Verifying: my public key.
Encryption: the recipient's public key.
Decryption: the recipient's private key.

Signing proves who sent the message and that it was not changed, which encryption does not.

Part 5

RSA can be attacked with factoring, which is much faster than brute force, so it needs huge keys. Ed25519 has no shortcut like that, so its 256 bit key is about as strong as RSA-4096.

Part 7

7.1

AI used: Claude
Prompt: "Write me a Python function that encrypts a file with AES."

7.2

1. Decrypted files can be read by other users on the computer, so they could read my plaintext. Violates confidentiality.
2. The temp file has a predictable name, so an attacker could plant a symlink and make the program overwrite another file. Violates integrity.
3. Weak passwords like one letter are allowed, so an attacker could guess it fast and decrypt the file. Violates key derivation, since a slow KDF only helps with a strong password.

7.3

1. Files are created owner-only. Fixes problem 1.
2. Files are created with O_EXCL so it will not write over an existing file or symlink. Fixes problem 2.
3. Passwords must be at least 12 characters. Fixes problem 3.
