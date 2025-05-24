// com.crypto.passwordless_auth.controller.AuthController.java
package com.crypto.passwordless_auth.controller;

import com.crypto.passwordless_auth.model.Note;
import com.crypto.passwordless_auth.model.User;
import com.crypto.passwordless_auth.model.Device;
import com.crypto.passwordless_auth.repository.NoteRepository;
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
    @Autowired private NoteRepository noteRepository;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private final SecretKey aesKey = CryptoUtil.generateAESKey(); // For legacy purposes, not used for notes
    private static final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, QRSession> qrSessionStore = new ConcurrentHashMap<>();
    private final Map<String, String> qrTokenStore = new HashMap<>();

    public static class QRSession {
        private String email;
        private String challenge;
        private String signedPayload;
        private long expiryTime;
        private String mobileToken;
        private String laptopToken;
        private String laptopDeviceId;

        public QRSession() {
            this.email = null;
            this.challenge = null;
            this.signedPayload = null;
            this.expiryTime = 0;
            this.mobileToken = null;
            this.laptopToken = null;
            this.laptopDeviceId = null;
        }

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
        String publicKey = request.get("publicKey");
        User user = userRepository.findById(email).orElse(null);
        if (user != null) return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email already registered");

        user = new User();
        user.setEmail(email);
        user.setPublicKey(publicKey);
        // Generate and store AES key for the user
        SecretKey aesKey = CryptoUtil.generateAESKey();
        user.setAesKey(Base64.getEncoder().encodeToString(aesKey.getEncoded()));
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

        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        String challenge = Base64.getEncoder().encodeToString(challengeBytes);
        logger.info("Generated challenge for {}: {}", email, challenge);

        user.setChallenge(challenge);
        userRepository.save(user);

        Map<String, String> response = new HashMap<>();
        response.put("challenge", challenge);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, String>> verify(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String signature = request.get("signature");
        String deviceName = request.getOrDefault("deviceName", "Unknown");

        User user = userRepository.findById(email).orElse(null);
        if (user == null || "Laptop".equalsIgnoreCase(deviceName)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
        }

        logger.info("Verifying for {} - Challenge: {}, Signature: {}", email, user.getChallenge(), signature);
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
        byte[] challengeBytes = new byte[32];
        secureRandom.nextBytes(challengeBytes);
        String challenge = Base64.getEncoder().encodeToString(challengeBytes);

        String payload = qrToken + "|" + challenge + "|" + email;
        String signedPayload = CryptoUtil.signPayload(payload);

        QRSession session = new QRSession();
        session.setEmail(email);
        session.setChallenge(challenge);
        session.setSignedPayload(signedPayload);
        session.setExpiryTime(System.currentTimeMillis() + 2 * 60 * 1000);

        qrSessionStore.put(qrToken, session);

        Map<String, String> response = new HashMap<>();
        response.put("qrToken", qrToken);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/qr-verify")
    public ResponseEntity<Map<String, String>> qrVerify(@RequestBody Map<String, String> request) {
        String qrToken = request.get("qrToken");
        String mobileToken = request.get("mobileToken");

        logger.info("Received qrToken: {}, mobileToken: {}", qrToken, mobileToken);

        QRSession session = qrSessionStore.get(qrToken);
        if (session == null || System.currentTimeMillis() > session.getExpiryTime()) {
            qrSessionStore.remove(qrToken);
            logger.warn("QR session not found or expired for qrToken: {}", qrToken);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "QR session expired or invalid"));
        }

        if (mobileToken == null || mobileToken.isEmpty()) {
            logger.warn("Mobile token is null or empty for qrToken: {}", qrToken);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Collections.singletonMap("error", "Mobile token is required"));
        }

        String email = JwtUtil.extractEmail(mobileToken, env.getProperty("jwt.secret"));
        if (email == null) {
            logger.warn("Failed to extract email from mobileToken: {}", mobileToken);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Invalid mobile token"));
        }

        User user = userRepository.findById(email).orElse(null);
        if (user == null || !JwtUtil.validateToken(mobileToken, email, env.getProperty("jwt.secret"))) {
            logger.warn("User not found or token invalid for email: {}", email);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("error", "Invalid user or token"));
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
        qrSessionStore.put(qrToken, session);

        logger.info("QR verification successful for email: {}", email);
        Map<String, String> response = new HashMap<>();
        response.put("token", jwt);
        response.put("deviceId", laptop.getDeviceId().toString());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/check-email")
    public ResponseEntity<Map<String, Boolean>> checkEmail(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        User existingUser = userRepository.findById(email).orElse(null);
        Map<String, Boolean> response = new HashMap<>();
        response.put("exists", existingUser != null);
        return ResponseEntity.ok(response);
    }

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
            qrSessionStore.remove(qrToken);
            return ResponseEntity.ok(response);
        }

        return ResponseEntity.ok(Collections.singletonMap("status", "pending"));
    }

    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("Spring Boot app is running");
    }

    // Note-related endpoints
    @PostMapping("/notes")
    public ResponseEntity<Note> createNote(
            @RequestHeader("Authorization") String token,
            @RequestBody Note note) {
        String email = JwtUtil.extractEmail(token.replace("Bearer ", ""), env.getProperty("jwt.secret"));
        User user = userRepository.findById(email).orElse(null);
        if (user == null || !JwtUtil.validateToken(token.replace("Bearer ", ""), email, env.getProperty("jwt.secret"))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            // Encrypt note content
            SecretKey aesKey = CryptoUtil.decodeAESKey(user.getAesKey());
            String encryptedContent = CryptoUtil.encryptAES(note.getContent(), aesKey);
            note.setContent(encryptedContent);
            note.setUser(user);
            Note savedNote = noteRepository.save(note);
            // Decrypt for response to maintain API compatibility
            savedNote.setContent(CryptoUtil.decryptAES(savedNote.getContent(), aesKey));
            return ResponseEntity.ok(savedNote);
        } catch (Exception e) {
            logger.error("Failed to encrypt note content: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/notes")
    public ResponseEntity<List<Note>> getNotes(
            @RequestHeader("Authorization") String token) {
        String email = JwtUtil.extractEmail(token.replace("Bearer ", ""), env.getProperty("jwt.secret"));
        User user = userRepository.findById(email).orElse(null);
        if (user == null || !JwtUtil.validateToken(token.replace("Bearer ", ""), email, env.getProperty("jwt.secret"))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            SecretKey aesKey = CryptoUtil.decodeAESKey(user.getAesKey());
            List<Note> notes = noteRepository.findByUser(user);
            // Decrypt content for each note
            for (Note note : notes) {
                note.setContent(CryptoUtil.decryptAES(note.getContent(), aesKey));
            }
            return ResponseEntity.ok(notes);
        } catch (Exception e) {
            logger.error("Failed to decrypt note content: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PutMapping("/notes/{id}")
    public ResponseEntity<Note> updateNote(
            @RequestHeader("Authorization") String token,
            @PathVariable Long id,
            @RequestBody Note updatedNote) {
        String email = JwtUtil.extractEmail(token.replace("Bearer ", ""), env.getProperty("jwt.secret"));
        User user = userRepository.findById(email).orElse(null);
        if (user == null || !JwtUtil.validateToken(token.replace("Bearer ", ""), email, env.getProperty("jwt.secret"))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Note note = noteRepository.findById(id).orElse(null);
        if (note == null || !note.getUser().getEmail().equals(email)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        try {
            SecretKey aesKey = CryptoUtil.decodeAESKey(user.getAesKey());
            // Encrypt updated content
            note.setTitle(updatedNote.getTitle());
            note.setContent(CryptoUtil.encryptAES(updatedNote.getContent(), aesKey));
            note.setUpdatedAt(System.currentTimeMillis());
            Note savedNote = noteRepository.save(note);
            // Decrypt for response
            savedNote.setContent(CryptoUtil.decryptAES(savedNote.getContent(), aesKey));
            return ResponseEntity.ok(savedNote);
        } catch (Exception e) {
            logger.error("Failed to encrypt/decrypt note content: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @DeleteMapping("/notes/{id}")
    public ResponseEntity<Void> deleteNote(
            @RequestHeader("Authorization") String token,
            @PathVariable Long id) {
        String email = JwtUtil.extractEmail(token.replace("Bearer ", ""), env.getProperty("jwt.secret"));
        User user = userRepository.findById(email).orElse(null);
        if (user == null || !JwtUtil.validateToken(token.replace("Bearer ", ""), email, env.getProperty("jwt.secret"))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        Note note = noteRepository.findById(id).orElse(null);
        if (note == null || !note.getUser().getEmail().equals(email)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        noteRepository.delete(note);
        return ResponseEntity.ok().build();
    }
}