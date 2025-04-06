package com.crypto.passwordless_auth.controller;

import com.crypto.passwordless_auth.model.User;
import com.crypto.passwordless_auth.model.Device;
import com.crypto.passwordless_auth.repository.UserRepository;
import com.crypto.passwordless_auth.repository.DeviceRepository;
import com.crypto.passwordless_auth.util.CryptoUtil;
import com.crypto.passwordless_auth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = {
        "http://localhost:3000",
        "https://passwordless-auth-wheat.vercel.app"
})
public class AuthController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private DeviceRepository deviceRepository;

    private final CryptoUtil.KeyPair serverKeyPair = new CryptoUtil.KeyPair();
    private final Map<String, QRSession> qrSessionStore = new ConcurrentHashMap<>();

    private static class QRSession {
        String email;
        String challenge;
        long expiryTime;
        String primaryDeviceToken; // Add this field

        public QRSession() {
            this.email = null;
            this.challenge = null;
            this.expiryTime = 0;
            this.primaryDeviceToken = null; // Initialize it
        }
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String publicKey = request.get("publicKey");
        try {
            User existingUser = userRepository.findById(email).orElse(null);
            if (existingUser != null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Email is already registered");
            }

            User user = new User();
            user.setEmail(email);
            user.setPublicKey(publicKey);
            userRepository.save(user);

            return ResponseEntity.ok("Registration successful");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Registration failed: " + e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String deviceName = request.getOrDefault("deviceName", "Unknown");

        User user = userRepository.findById(email).orElse(null);
        if (user == null) return ResponseEntity.status(404).body(null);

        // Reject non-QR login for mobile devices
        if ("Mobile".equalsIgnoreCase(deviceName)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Collections.singletonMap("error", "Mobile devices must use QR login"));
        }

        String challenge = String.valueOf(new SecureRandom().nextInt(10000));
        user.setChallenge(challenge);
        userRepository.save(user);

        Map<String, String> response = new HashMap<>();
        response.put("serverPublicKey", serverKeyPair.publicKey.toString());
        response.put("challenge", challenge);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    public ResponseEntity<Map<String, String>> verify(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String encryptedChallenge = request.get("encryptedChallenge");
        String deviceName = request.getOrDefault("deviceName", "Unknown");

        User user = userRepository.findById(email).orElse(null);
        if (user == null) return ResponseEntity.status(404).body(null);

        // Reject non-QR login for mobile devices
        if ("Mobile".equalsIgnoreCase(deviceName)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Collections.singletonMap("error", "Mobile devices must use QR login"));
        }

        BigInteger sharedSecret = CryptoUtil.computeSharedSecret(
                serverKeyPair.privateKey,
                new BigInteger(user.getPublicKey())
        );

        String decryptedChallenge = CryptoUtil.decryptMessage(encryptedChallenge, sharedSecret);
        if (decryptedChallenge.equals(user.getChallenge())) {
            List<Device> devices = deviceRepository.findByUser(user);
            devices.forEach(d -> {
                d.setPrimary(false);
                deviceRepository.save(d);
            });

            String jwt = JwtUtil.generateToken(email);
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
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.status(401).body(null);
    }
    @PostMapping("/generate-qr")
    public ResponseEntity<Map<String, String>> generateQR(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String token = request.get("token"); // Optional token

        // If no token is provided, generate a QR for unauthenticated device
        if (token == null || token.isEmpty()) {
            String qrToken = UUID.randomUUID().toString();
            String challenge = String.valueOf(new SecureRandom().nextInt(10000));

            QRSession session = new QRSession();
            session.email = email; // Can be empty or null for now
            session.challenge = challenge;
            session.expiryTime = System.currentTimeMillis() + 2 * 60 * 1000; // 2 minutes
            session.primaryDeviceToken = null; // Will be set when mobile authorizes

            qrSessionStore.put(qrToken, session);

            Map<String, String> response = new HashMap<>();
            response.put("qrToken", qrToken);
            return ResponseEntity.ok(response);
        }

        // If token is provided, validate it (for already logged-in devices)
        if (!JwtUtil.validateToken(token, email)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        User user = userRepository.findById(email).orElse(null);
        if (user == null) return ResponseEntity.status(404).body(null);

        // Find the primary mobile device (already logged in)
        List<Device> devices = deviceRepository.findByUserAndPrimary(user, true);
        if (devices.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Collections.singletonMap("error", "No primary device found."));
        }

        Device primaryDevice = devices.get(0); // Assume first primary device is mobile
        String primaryDeviceToken = primaryDevice.getSessionToken();

        String qrToken = UUID.randomUUID().toString();
        String challenge = String.valueOf(new SecureRandom().nextInt(10000));

        QRSession session = new QRSession();
        session.email = email;
        session.challenge = challenge;
        session.expiryTime = System.currentTimeMillis() + 2 * 60 * 1000; // 2 minutes
        session.primaryDeviceToken = primaryDeviceToken; // Set the primary device's token

        qrSessionStore.put(qrToken, session);

        Map<String, String> response = new HashMap<>();
        response.put("qrToken", qrToken);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/qr-details")
    public ResponseEntity<Map<String, String>> getQRDetails(@RequestBody Map<String, String> request) {
        String qrToken = request.get("qrToken");
        QRSession session = qrSessionStore.get(qrToken);
        if (session == null || System.currentTimeMillis() > session.expiryTime) {
            qrSessionStore.remove(qrToken);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        Map<String, String> response = new HashMap<>();
        response.put("serverPublicKey", serverKeyPair.publicKey.toString());
        response.put("challenge", session.challenge);
        response.put("email", session.email);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/qr-login")
    public ResponseEntity<Map<String, String>> qrLogin(@RequestBody Map<String, String> request) {
        String qrToken = request.get("qrToken");
        String encryptedChallenge = request.get("encryptedChallenge");
        String userPublicKey = request.get("userPublicKey");
        String deviceName = request.getOrDefault("deviceName", "Unknown");

        QRSession session = qrSessionStore.get(qrToken);
        if (session == null || System.currentTimeMillis() > session.expiryTime) {
            qrSessionStore.remove(qrToken);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        User user = userRepository.findById(session.email).orElse(null);
        if (user == null) return ResponseEntity.status(404).body(null);

        BigInteger sharedSecret = CryptoUtil.computeSharedSecret(
                serverKeyPair.privateKey,
                new BigInteger(userPublicKey)
        );

        String decryptedChallenge = CryptoUtil.decryptMessage(encryptedChallenge, sharedSecret);
        if (decryptedChallenge.equals(session.challenge)) {
            String jwt = JwtUtil.generateToken(session.email);
            Device device = new Device();
            device.setUser(user);
            device.setDeviceName(deviceName);
            device.setSessionToken(jwt);
            device.setLastActive(System.currentTimeMillis());
            device.setPrimary(false); // QR login is secondary
            deviceRepository.save(device);

            qrSessionStore.remove(qrToken);
            Map<String, String> response = new HashMap<>();
            response.put("token", jwt);
            response.put("deviceId", device.getDeviceId().toString());
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.status(401).body(null);
    }

    @PostMapping("/check-email")
    public ResponseEntity<Map<String, Boolean>> checkEmail(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        User existingUser = userRepository.findById(email).orElse(null);
        Map<String, Boolean> response = new HashMap<>();
        response.put("exists", existingUser != null);
        return ResponseEntity.ok(response);
    }
    @PostMapping("/qr-verify")
    public ResponseEntity<Map<String, String>> verifyQRFromMobile(@RequestBody Map<String, String> request) {
        String qrToken = request.get("qrToken");
        String mobileToken = request.get("mobileToken"); // Token from mobile

        QRSession session = qrSessionStore.get(qrToken);
        if (session == null || System.currentTimeMillis() > session.expiryTime) {
            qrSessionStore.remove(qrToken);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        // Validate mobile token to get email
        String email = JwtUtil.extractEmail(mobileToken); // Assume JwtUtil has this method
        if (email == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        User user = userRepository.findById(email).orElse(null);
        if (user == null) return ResponseEntity.status(404).body(null);

        // Link the mobile's user to the QR session
        session.email = email;
        session.primaryDeviceToken = mobileToken;

        // Generate token for laptop
        String laptopJwt = JwtUtil.generateToken(email);
        Device laptopDevice = new Device();
        laptopDevice.setUser(user);
        laptopDevice.setDeviceName("Laptop");
        laptopDevice.setSessionToken(laptopJwt);
        laptopDevice.setLastActive(System.currentTimeMillis());
        laptopDevice.setPrimary(false); // Laptop is secondary
        deviceRepository.save(laptopDevice);

        qrSessionStore.remove(qrToken);

        Map<String, String> response = new HashMap<>();
        response.put("token", laptopJwt);
        response.put("deviceId", laptopDevice.getDeviceId().toString());
        return ResponseEntity.ok(response);
    }
}