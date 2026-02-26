import forge from 'node-forge';

const cryptoService = {
  generateKeyPair: () => {
    const pair = forge.pki.rsa.generateKeyPair(2048);
    return {
      publicKey: forge.pki.publicKeyToPem(pair.publicKey),
      privateKey: forge.pki.privateKeyToPem(pair.privateKey)
    };
  },

  encryptPrivateKey: (privateKeyPem, password) => {
    const salt = 'fortknox_static_salt';
    const derivedKey = forge.pkcs5.pbkdf2(password, salt, 10000, 16);
    const cipher = forge.cipher.createCipher('AES-CBC', derivedKey);
    const iv = forge.random.getBytesSync(16);
    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(privateKeyPem));
    cipher.finish();
    return JSON.stringify({
      iv: forge.util.encode64(iv),
      ciphertext: forge.util.encode64(cipher.output.getBytes())
    });
  },

  decryptPrivateKey: (encryptedDataJson, password) => {
    try {
      const data = JSON.parse(encryptedDataJson);
      const salt = 'fortknox_static_salt';
      const derivedKey = forge.pkcs5.pbkdf2(password, salt, 10000, 16);
      const decipher = forge.cipher.createDecipher('AES-CBC', derivedKey);
      decipher.start({iv: forge.util.decode64(data.iv)});
      decipher.update(forge.util.createBuffer(forge.util.decode64(data.ciphertext)));
      if(!decipher.finish()) return null;
      return decipher.output.toString();
    } catch (e) { return null; }
  },

  // NEW: Helper to get public key from private key (avoids network call)
  getPublicKeyFromPrivate: (privateKeyPem) => {
    try {
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      const publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e);
      return forge.pki.publicKeyToPem(publicKey);
    } catch (e) { return null; }
  },

  encryptDouble: (message, recipientPublicKeyPem, myPublicKeyPem) => {
    try {
      const recipientKey = forge.pki.publicKeyFromPem(recipientPublicKeyPem);
      const forRecipient = forge.util.encode64(recipientKey.encrypt(message, 'RSA-OAEP'));
      
      let forSender = null;
      if (myPublicKeyPem) {
          const myKey = forge.pki.publicKeyFromPem(myPublicKeyPem);
          forSender = forge.util.encode64(myKey.encrypt(message, 'RSA-OAEP'));
      }

      return JSON.stringify({ r: forRecipient, s: forSender });
    } catch (e) {
      console.error("Encryption failed:", e);
      return null;
    }
  },

  decryptMessage: (ciphertextJson, privateKeyPem) => {
    try {
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
      const data = JSON.parse(ciphertextJson);
      
      // Try recipient envelope first
      try {
        return privateKey.decrypt(forge.util.decode64(data.r), 'RSA-OAEP');
      } catch (e) {
        // If that fails, try the sender envelope
        return privateKey.decrypt(forge.util.decode64(data.s), 'RSA-OAEP');
      }
    } catch (e) {
      return "[Unable to decrypt: Key mismatch]";
    }
  }
};

export default cryptoService;