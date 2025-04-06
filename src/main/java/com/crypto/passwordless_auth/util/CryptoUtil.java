package com.crypto.passwordless_auth.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtil {
    private static final BigInteger P = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
            16
    );
    private static final BigInteger G = BigInteger.valueOf(2);
    private static final SecureRandom random = new SecureRandom();

    public static class KeyPair {
        public BigInteger privateKey;
        public BigInteger publicKey;

        public KeyPair() {
            this.privateKey = new BigInteger(256, random);
            this.publicKey = G.modPow(this.privateKey, P);
        }

        public String getPrivateKeyAsString() {
            return privateKey.toString();
        }

        public String getPublicKeyAsString() {
            return publicKey.toString();
        }
    }

    public static BigInteger computeSharedSecret(BigInteger privateKey, BigInteger otherPublicKey) {
        return otherPublicKey.modPow(privateKey, P);
    }

    public static String encryptMessage(String message, BigInteger sharedSecret) {
        return Base64.getEncoder().encodeToString(message.getBytes());
    }

    public static String decryptMessage(String encrypted, BigInteger sharedSecret) {
        return new String(Base64.getDecoder().decode(encrypted));
    }
}