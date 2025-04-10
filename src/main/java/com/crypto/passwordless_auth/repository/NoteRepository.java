// src/main/java/com/crypto/passwordless_auth/repository/NoteRepository.java
package com.crypto.passwordless_auth.repository;

import com.crypto.passwordless_auth.model.Note;
import com.crypto.passwordless_auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface NoteRepository extends JpaRepository<Note, Long> {
    List<Note> findByUser(User user);
}