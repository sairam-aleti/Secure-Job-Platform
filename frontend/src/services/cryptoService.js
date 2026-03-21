import forge from 'node-forge';

const cryptoService = {
  generateKeyPair: () => {
    const pair = forge.pki.rsa.generateKeyPair(2048);
    return {
      publicKey: forge.pki.publicKeyToPem(pair.publicKey),
      privateKey: forge.pki.privateKeyToPem(pair.privateKey)
    };
  },

  // SECURITY FIX: Random salt per encryption (not static)
  encryptPrivateKey: (privateKeyPem, password) => {
    const salt = forge.random.getBytesSync(16); // Random 16-byte salt
    const derivedKey = forge.pkcs5.pbkdf2(password, salt, 10000, 16);
    const cipher = forge.cipher.createCipher('AES-CBC', derivedKey);
    const iv = forge.random.getBytesSync(16);
    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(privateKeyPem));
    cipher.finish();
    return JSON.stringify({
      salt: forge.util.encode64(salt),  // Store salt alongside ciphertext
      iv: forge.util.encode64(iv),
      ciphertext: forge.util.encode64(cipher.output.getBytes())
    });
  },

  decryptPrivateKey: (encryptedDataJson, password) => {
    try {
      const data = JSON.parse(encryptedDataJson);
      // SECURITY FIX: Use stored random salt (backward compat with static salt)
      let salt;
      if (data.salt) {
        salt = forge.util.decode64(data.salt);
      } else {
        // Backward compatibility: old keys encrypted with static salt
        salt = 'fortknox_static_salt';
      }
      const derivedKey = forge.pkcs5.pbkdf2(password, salt, 10000, 16);
      const decipher = forge.cipher.createDecipher('AES-CBC', derivedKey);
      decipher.start({iv: forge.util.decode64(data.iv)});
      decipher.update(forge.util.createBuffer(forge.util.decode64(data.ciphertext)));
      if(!decipher.finish()) return null;
      return decipher.output.toString();
    } catch (e) { return null; }
  },

  getPublicKeyFromPrivate: (privateKeyPem) => {
    try {
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
      return forge.pki.publicKeyToPem(publicKey);
    } catch (e) { return null; }
  },

  // SECURITY FIX: Hybrid encryption (AES + RSA) for messages of any length
  encryptDouble: (message, recipientPublicKeyPem, myPublicKeyPem) => {
    try {
      // 1. Generate a random AES session key
      const aesKey = forge.random.getBytesSync(32); // 256-bit
      const iv = forge.random.getBytesSync(16);

      // 2. Encrypt the message with AES-CBC
      const cipher = forge.cipher.createCipher('AES-CBC', aesKey);
      cipher.start({iv: iv});
      cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(message)));
      cipher.finish();
      const encryptedMessage = cipher.output.getBytes();

      // 3. Encrypt the AES key with recipient's RSA public key
      const recipientKey = forge.pki.publicKeyFromPem(recipientPublicKeyPem);
      const encryptedKeyForRecipient = recipientKey.encrypt(aesKey, 'RSA-OAEP');

      // 4. Also encrypt AES key with sender's public key (so sender can read own messages)
      let encryptedKeyForSender = null;
      if (myPublicKeyPem) {
        const myKey = forge.pki.publicKeyFromPem(myPublicKeyPem);
        encryptedKeyForSender = forge.util.encode64(myKey.encrypt(aesKey, 'RSA-OAEP'));
      }

      return JSON.stringify({
        v: 2, // Version 2 = hybrid encryption
        iv: forge.util.encode64(iv),
        ct: forge.util.encode64(encryptedMessage),
        r: forge.util.encode64(encryptedKeyForRecipient),
        s: encryptedKeyForSender
      });
    } catch (e) {
      console.error("Encryption failed:", e);
      return null;
    }
  },

  decryptMessage: (ciphertextJson, privateKeyPem) => {
    try {
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      const data = JSON.parse(ciphertextJson);

      // Version 2: Hybrid encryption (AES + RSA)
      if (data.v === 2) {
        let aesKey = null;

        // Try recipient envelope first, then sender envelope
        try {
          aesKey = privateKey.decrypt(forge.util.decode64(data.r), 'RSA-OAEP');
        } catch (e) {
          if (data.s) {
            aesKey = privateKey.decrypt(forge.util.decode64(data.s), 'RSA-OAEP');
          }
        }

        if (!aesKey) return "[Unable to decrypt: Key mismatch]";

        // Decrypt the message with AES
        const decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
        decipher.start({iv: forge.util.decode64(data.iv)});
        decipher.update(forge.util.createBuffer(forge.util.decode64(data.ct)));
        if (!decipher.finish()) return "[Decryption integrity check failed]";
        return forge.util.decodeUtf8(decipher.output.toString());
      }

      // Version 1 / Legacy: Direct RSA encryption (backward compatibility)
      try {
        return privateKey.decrypt(forge.util.decode64(data.r), 'RSA-OAEP');
      } catch (e) {
        if (data.s) {
          return privateKey.decrypt(forge.util.decode64(data.s), 'RSA-OAEP');
        }
        return "[Unable to decrypt: Key mismatch]";
      }
    } catch (e) {
      return "[Unable to decrypt: Key mismatch]";
    }
  },

  // --- PKI DIGITAL SIGNATURES ---

  signMessage: (message, privateKeyPem) => {
    try {
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      const md = forge.md.sha256.create();
      md.update(message, 'utf8');
      const signature = privateKey.sign(md);
      return forge.util.encode64(signature);
    } catch (e) {
      console.error("Signing failed", e);
      return null;
    }
  },

  verifySignature: (message, signature64, publicKeyPem) => {
    try {
      const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
      const signature = forge.util.decode64(signature64);
      const md = forge.md.sha256.create();
      md.update(message, 'utf8');
      return publicKey.verify(md.digest().bytes(), signature);
    } catch (e) {
      return false;
    }
  }
};

export default cryptoService;