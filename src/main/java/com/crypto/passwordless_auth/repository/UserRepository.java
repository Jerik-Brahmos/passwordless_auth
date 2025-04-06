package com.crypto.passwordless_auth.repository;

import com.crypto.passwordless_auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, String> {
}