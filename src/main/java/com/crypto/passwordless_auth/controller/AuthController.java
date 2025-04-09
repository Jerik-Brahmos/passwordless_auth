package com.crypto.passwordless_auth.controller;

import com.crypto.passwordless_auth.model.User;
import com.crypto.passwordless_auth.model.Device;
import com.crypto.passwordless_auth.repository.UserRepository;
import com.crypto.passwordless_auth.repository.DeviceRepository;
import com.crypto.passwordless_auth.util.CryptoUtil;
import com.crypto.passwordless_auth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = {"http://localhost:3000", "https://passwordless-auth-wheat.vercel.app"})
public class AuthController {

    @Autowired private UserRepository userRepository;
    @Autowired private DeviceRepository deviceRepository;
    @Autowired private Environment env;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final SecretKey aesKey = CryptoUtil.generateAESKey(); // For encrypting QR payloads if needed
    private static final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, QRSession> qrSessionStore = new ConcurrentHashMap<>(); // In-memory QR session store

    public static class QRSession {
        private String email;
        private String challenge;
        private String signedPayload;
        private long expiryTime;
        private String mobileToken;
        private String laptopToken;
        private String laptopDeviceId;

        // Default constructor
        public QRSession() {
            this.email = null;
            this.challenge = null;
            this.signedPayload = null;
            this.expiryTime = 0;
            this.mobileToken = null;
            this.laptopToken = null;
            this.laptopDeviceId = null;
        }

        // Getters and setters
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getChallenge() { return challenge; }
        public void setChallenge(String challenge) { this.challenge = challenge; }
        public String getSignedPayload() { return signedPayload; }
        public void setSignedPayload(String signedPayload) { this.signedPayload = signedPayload; }
        public long getExpiryTime() { return expiryTime; }
        public void setExpiryTime(long expiryTime) { this.expiryTime = expiryTime; }
        public String getMobileToken() { return mobileToken; }
        public void setMobileToken(String mobileToken) { this.mobileToken = mobileToken; }
        public String getLaptopToken() { return laptopToken; }
        public void setLaptopToken(String laptopToken) { this.laptopToken = laptopToken; }
        public String getLaptopDeviceId() { return laptopDeviceId; }
        public void setLaptopDeviceId(String laptopDeviceId) { this.laptopDeviceId = laptopDeviceId; }
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
        session.setEmail(email);
        session.setChallenge(challenge);
        session.setSignedPayload(signedPayload);
        session.setExpiryTime(System.currentTimeMillis() + 2 * 60 * 1000); // 2 minutes expiry

        qrSessionStore.put(qrToken, session);

        Map<String, String> response = new HashMap<>();
        response.put("qrToken", qrToken);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/qr-verify")
    public ResponseEntity<Map<String, String>> qrVerify(@RequestBody Map<String, String> request) {
        String qrToken = request.get("qrToken");
        String mobileToken = request.get("mobileToken");

        QRSession session = qrSessionStore.get(qrToken);
        if (session == null || System.currentTimeMillis() > session.getExpiryTime()) {
            qrSessionStore.remove(qrToken);
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

        session.setLaptopToken(jwt);
        session.setLaptopDeviceId(laptop.getDeviceId().toString());
        qrSessionStore.put(qrToken, session); // Update session in map

        Map<String, String> response = new HashMap<>();
        response.put("token", jwt);
        response.put("deviceId", laptop.getDeviceId().toString());
        return ResponseEntity.ok(response);
    }
    // Added endpoint for checking email existence
    @PostMapping("/check-email")
    public ResponseEntity<Map<String, Boolean>> checkEmail(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        User existingUser = userRepository.findById(email).orElse(null);
        Map<String, Boolean> response = new HashMap<>();
        response.put("exists", existingUser != null);
        return ResponseEntity.ok(response);
    }

    // Added endpoint for checking QR status
    @GetMapping("/check-qr-status")
    public ResponseEntity<Map<String, String>> checkQRStatus(@RequestParam String qrToken) {
        QRSession session = qrSessionStore.get(qrToken);
        if (session == null || System.currentTimeMillis() > session.getExpiryTime()) {
            qrSessionStore.remove(qrToken);
            return ResponseEntity.ok(Collections.singletonMap("status", "expired"));
        }

        if (session.getLaptopToken() != null && session.getLaptopDeviceId() != null) {
            Map<String, String> response = new HashMap<>();
            response.put("status", "authenticated");
            response.put("token", session.getLaptopToken());
            response.put("deviceId", session.getLaptopDeviceId());
            qrSessionStore.remove(qrToken); // Clean up after successful login
            return ResponseEntity.ok(response);
        }

        return ResponseEntity.ok(Collections.singletonMap("status", "pending"));
    }

}