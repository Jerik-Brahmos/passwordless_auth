// com.crypto.passwordless_auth.model.User.java
package com.crypto.passwordless_auth.model;

import jakarta.persistence.*;
import java.util.List;

@Entity
@Table(name = "users") // Explicit table name to avoid reserved keyword 'user'
public class User {
    @Id
    private String email;

    @Column(columnDefinition = "TEXT")
    private String publicKey; // Use TEXT to handle long Base64-encoded keys

    private String challenge;

    @Column(columnDefinition = "TEXT")
    private String aesKey; // Store Base64-encoded AES key

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<Device> devices;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<Note> notes;

    // Constructors
    public User() {}

    // Getters and Setters
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }
    public String getChallenge() { return challenge; }
    public void setChallenge(String challenge) { this.challenge = challenge; }
    public String getAesKey() { return aesKey; }
    public void setAesKey(String aesKey) { this.aesKey = aesKey; }
    public List<Device> getDevices() { return devices; }
    public void setDevices(List<Device> devices) { this.devices = devices; }
    public List<Note> getNotes() { return notes; }
    public void setNotes(List<Note> notes) { this.notes = notes; }
}