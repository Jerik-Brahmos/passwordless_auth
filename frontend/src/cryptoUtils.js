import * as asn1js from 'asn1js';
export async function generateECDSAKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true, // extractable
      ["sign", "verify"]
  );
  const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  return { privateKey: keyPair.privateKey, publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey))) };
}

export async function signChallenge(privateKey, challenge) {
  const signature = await window.crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      new TextEncoder().encode(challenge)
  );
  const signatureArray = new Uint8Array(signature);

  // Split into R and S (assuming 64 bytes total for P-256: 32 bytes each)
  const r = signatureArray.slice(0, 32);
  const s = signatureArray.slice(32, 64);

  // Convert to DER format
  const der = new asn1js.Sequence({
      value: [
          new asn1js.Integer({ valueHex: r }),
          new asn1js.Integer({ valueHex: s })
      ]
  });
  const derEncoded = der.toBER(false);
  return btoa(String.fromCharCode(...new Uint8Array(derEncoded)));
}

export async function storePrivateKey(privateKey, email) {
  const exported = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  const keyData = btoa(String.fromCharCode(...new Uint8Array(exported)));
  await localStorage.setItem(`privateKey_${email}`, keyData); // Use IndexedDB in production
}

export async function retrievePrivateKey(email) {
  const keyData = localStorage.getItem(`privateKey_${email}`);
  if (!keyData) return null;
  const imported = await window.crypto.subtle.importKey(
      "pkcs8",
      Uint8Array.from(atob(keyData), c => c.charCodeAt(0)),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"]
  );
  return imported;
}