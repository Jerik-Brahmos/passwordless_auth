package com.crypto.passwordless_auth.util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Base64;

public class CryptoUtil {
    private static final KeyPair SERVER_KEY_PAIR = generateECDSAKeyPair();
    private static final String SERVER_PUBLIC_KEY = Base64.getEncoder().encodeToString(SERVER_KEY_PAIR.getPublic().getEncoded());

    public static KeyPair generateECDSAKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256, new SecureRandom()); // P-256 curve
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate ECDSA key pair", e);
        }
    }

    public static SecretKey generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // 256-bit AES
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate AES key", e);
        }
    }

    public static boolean verifyECDSASignature(String publicKey, String data, String signature) {
        try {
            PublicKey pubKey = KeyFactory.getInstance("EC").generatePublic(
                    new java.security.spec.X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)));
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(pubKey);
            sig.update(data.getBytes());
            boolean isValid = sig.verify(Base64.getDecoder().decode(signature));
            if (!isValid) {
                System.out.println("Signature invalid for data: " + data);
            }
            return isValid;
        } catch (Exception e) {
            System.err.println("Verification error: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public static String signPayload(String payload) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(SERVER_KEY_PAIR.getPrivate());
            sig.update(payload.getBytes());
            return Base64.getEncoder().encodeToString(sig.sign());
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign payload", e);
        }
    }

    public static String encryptAES(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted);
    }
}