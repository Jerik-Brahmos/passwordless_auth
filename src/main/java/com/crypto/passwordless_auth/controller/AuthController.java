package com.crypto.passwordless_auth.controller;

import com.crypto.passwordless_auth.model.User;
import com.crypto.passwordless_auth.model.Device;
import com.crypto.passwordless_auth.repository.UserRepository;
import com.crypto.passwordless_auth.repository.DeviceRepository;
import com.crypto.passwordless_auth.util.CryptoUtil;
import com.crypto.passwordless_auth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = {"http://localhost:3000", "https://passwordless-auth-wheat.vercel.app"})
public class AuthController {

    @Autowired private UserRepository userRepository;
    @Autowired private DeviceRepository deviceRepository;
    @Autowired private RedisTemplate<String, QRSession> redisTemplate;
    @Autowired private Environment env;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final SecretKey aesKey = CryptoUtil.generateAESKey(); // For encrypting QR payloads if needed
    private static final SecureRandom secureRandom = new SecureRandom();

    private static class QRSession {
        String email;
        String challenge;
        String signedPayload;
        long expiryTime;
        String mobileToken;
        String laptopToken;
        String laptopDeviceId;

        // Constructor for simplicity (add getters/setters as needed)
        QRSession() {
            this.email = null;
            this.challenge = null;
            this.signedPayload = null;
            this.expiryTime = 0;
            this.mobileToken = null;
            this.laptopToken = null;
            this.laptopDeviceId = null;
        }
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String publicKey = request.get("publicKey"); // ECDSA public key
        User user = userRepository.findById(email).orElse(null);
        if (user != null) return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email already registered");

        user = new User();
        user.setEmail(email);
        user.setPublicKey(publicKey); // Store ECDSA public key
        userRepository.save(user);
        logger.info("User registered: {}", email);
        return ResponseEntity.ok("Registration successful");
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String deviceName = request.getOrDefault("deviceName", "Unknown");

        if ("Laptop".equalsIgnoreCase(deviceName)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Collections.singletonMap("error", "Laptops must use QR login"));
        }

        User user = userRepository.findById(email).orElse(null);
        if (user == null) return ResponseEntity.status(404).body(null);

        // Generate a 32-byte random challenge
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        String challenge = Base64.getEncoder().encodeToString(challengeBytes);

        user.setChallenge(challenge);
        userRepository.save(user);

        Map<String, String> response = new HashMap<>();
        response.put("challenge", challenge);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, String>> verify(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String signature = request.get("signature"); // ECDSA signature
        String deviceName = request.getOrDefault("deviceName", "Unknown");

        User user = userRepository.findById(email).orElse(null);
        if (user == null || "Laptop".equalsIgnoreCase(deviceName)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        }

        if (CryptoUtil.verifyECDSASignature(user.getPublicKey(), user.getChallenge(), signature)) {
            String jwt = JwtUtil.generateToken(email, env.getProperty("jwt.secret"));
            Device device = new Device();
            device.setUser(user);
            device.setDeviceName(deviceName);
            device.setSessionToken(jwt);
            device.setLastActive(System.currentTimeMillis());
            device.setPrimary(true);
            deviceRepository.save(device);

            Map<String, String> response = new HashMap<>();
            response.put("token", jwt);
            response.put("deviceId", device.getDeviceId().toString());
            logger.info("Mobile login successful: {}", email);
            return ResponseEntity.ok(response);
        }
        logger.warn("Signature verification failed for: {}", email);
        return ResponseEntity.status(401).body(null);
    }

    @PostMapping("/generate-qr")
    public ResponseEntity<Map<String, String>> generateQR(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String token = request.get("token");

        String qrToken = UUID.randomUUID().toString();
        // Generate a 32-byte random challenge
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        String challenge = Base64.getEncoder().encodeToString(challengeBytes);

        String payload = qrToken + "|" + challenge + "|" + email;
        String signedPayload = CryptoUtil.signPayload(payload); // Server signs with its private key

        QRSession session = new QRSession();
        session.email = email;
        session.challenge = challenge;
        session.signedPayload = signedPayload;
        session.expiryTime = System.currentTimeMillis() + 2 * 60 * 1000;

        redisTemplate.opsForValue().set(qrToken, session, 2, TimeUnit.MINUTES);

        Map<String, String> response = new HashMap<>();
        response.put("qrToken", qrToken);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/qr-verify")
    public ResponseEntity<Map<String, String>> qrVerify(@RequestBody Map<String, String> request) {
        String qrToken = request.get("qrToken");
        String mobileToken = request.get("mobileToken");

        QRSession session = redisTemplate.opsForValue().get(qrToken);
        if (session == null || System.currentTimeMillis() > session.expiryTime) {
            redisTemplate.delete(qrToken);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        String email = JwtUtil.extractEmail(mobileToken, env.getProperty("jwt.secret"));
        User user = userRepository.findById(email).orElse(null);
        if (user == null || !JwtUtil.validateToken(mobileToken, email, env.getProperty("jwt.secret"))) {
            return ResponseEntity.status(401).body(null);
        }

        String jwt = JwtUtil.generateToken(email, env.getProperty("jwt.secret"));
        Device laptop = new Device();
        laptop.setUser(user);
        laptop.setDeviceName("Laptop");
        laptop.setSessionToken(jwt);
        laptop.setLastActive(System.currentTimeMillis());
        laptop.setPrimary(false);
        deviceRepository.save(laptop);

        session.laptopToken = jwt;
        session.laptopDeviceId = laptop.getDeviceId().toString();
        redisTemplate.opsForValue().set(qrToken, session, 2, TimeUnit.MINUTES);

        Map<String, String> response = new HashMap<>();
        response.put("token", jwt);
        response.put("deviceId", laptop.getDeviceId().toString());
        return ResponseEntity.ok(response);
    }
}