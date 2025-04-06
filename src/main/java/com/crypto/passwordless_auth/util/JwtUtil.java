package com.crypto.passwordless_auth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JwtUtil {

    private static final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512); // Generate a secure key

    // Method to generate a JWT token
    public static String generateToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) // 10 hours
                .signWith(key)
                .compact();
    }

    // Method to validate a token
    public static boolean validateToken(String token, String email) {
        final String extractedEmail = extractEmail(token);
        return (extractedEmail.equals(email) && !isTokenExpired(token));
    }

    // Method to extract email from token
    public static String extractEmail(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(getSignInKey()) // Corrected method name
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return claims.getSubject();
        } catch (Exception e) {
            return null;
        }
    }

    // Check if token is expired
    private static boolean isTokenExpired(String token) {
        final Date expiration = Jwts.parser()
                .setSigningKey(getSignInKey()) // Corrected method name
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
        return expiration.before(new Date());
    }

    // Method to get the signing key
    private static Key getSignInKey() { // Corrected method name
        return key;
    }
}