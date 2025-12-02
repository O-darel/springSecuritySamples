package org.authx.auth.authentication.repositories;

import org.authx.auth.authentication.models.Otp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface OtpRepository extends JpaRepository<Otp, Long> {
    Optional<Otp> findByEmailAndTypeAndUsedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
            String email, Otp.OtpType type, LocalDateTime now);

    @Modifying
    @Query("DELETE FROM Otp o WHERE o.expiresAt < :now")
    void deleteExpiredOtps(LocalDateTime now);

    @Modifying
    @Query("UPDATE Otp o SET o.used = true WHERE o.email = :email AND o.type = :type AND o.used = false")
    void invalidateOtps(String email, Otp.OtpType type);
}

