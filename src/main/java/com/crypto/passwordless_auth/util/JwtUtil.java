package com.crypto.passwordless_auth.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.util.Date;

public class JwtUtil {
    public static String generateToken(String email, String secret) {
        if (secret == null) {
            throw new IllegalArgumentException("JWT secret cannot be null. Please set the 'JWT_SECRET' environment variable.");
        }
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour
                .signWith(Keys.hmacShaKeyFor(secretBytes), SignatureAlgorithm.HS256) // Changed to HS256
                .compact();
    }

    public static boolean validateToken(String token, String email, String secret) {
        if (secret == null) {
            throw new IllegalArgumentException("JWT secret cannot be null.");
        }
        String extractedEmail = extractEmail(token, secret);
        return extractedEmail != null && extractedEmail.equals(email) && !isTokenExpired(token, secret);
    }

    public static String extractEmail(String token, String secret) {
        try {
            return Jwts.parser()
                    .setSigningKey(secret.getBytes(StandardCharsets.UTF_8))
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isTokenExpired(String token, String secret) {
        return Jwts.parser()
                .setSigningKey(secret.getBytes(StandardCharsets.UTF_8))
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration()
                .before(new Date());
    }
}