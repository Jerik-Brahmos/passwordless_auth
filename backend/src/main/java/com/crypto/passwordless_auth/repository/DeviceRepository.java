package com.crypto.passwordless_auth.repository;

import com.crypto.passwordless_auth.model.Device;
import com.crypto.passwordless_auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface DeviceRepository extends JpaRepository<Device, UUID> {
    List<Device> findByUser(User user);

    // Use @Query to explicitly define the query, referencing the 'isPrimary' field
    @Query("SELECT d FROM Device d WHERE d.user = :user AND d.isPrimary = :isPrimary")
    List<Device> findByUserAndPrimary(User user, boolean isPrimary);
}