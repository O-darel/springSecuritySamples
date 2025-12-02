package org.authx.auth.authentication.services;

import org.authx.auth.authentication.models.Otp;
import org.authx.auth.authentication.repositories.OtpRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class OtpService {
    private static final int OTP_LENGTH = 6;
    private static final int OTP_EXPIRY_MINUTES = 10;
    private static final SecureRandom random = new SecureRandom();
    
    private final OtpRepository otpRepository;

    public OtpService(OtpRepository otpRepository) {
        this.otpRepository = otpRepository;
    }

    public String generateOtp() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < OTP_LENGTH; i++) {
            otp.append(random.nextInt(10));
        }
        return otp.toString();
    }

    @Transactional
    public String createAndSaveOtp(String email, Otp.OtpType type) {
        // Invalidate any existing unused OTPs for this email and type
        otpRepository.invalidateOtps(email, type);
        
        String code = generateOtp();
        Otp otp = new Otp();
        otp.setEmail(email);
        otp.setCode(code);
        otp.setType(type);
        otp.setExpiresAt(LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES));
        otp.setUsed(false);
        
        otpRepository.save(otp);
        
        // TODO: Send OTP via email/SMS - for now, just return the code
        // In production call an email /sms service to send otp
        System.out.println("OTP for " + email + " (" + type + "): " + code);
        
        return code;
    }

    @Transactional
    public boolean validateOtp(String email, String code, Otp.OtpType type) {
        Optional<Otp> otpOptional = otpRepository.findByEmailAndTypeAndUsedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
                email, type, LocalDateTime.now());
        
        if (otpOptional.isEmpty()) {
            return false;
        }
        
        Otp otp = otpOptional.get();
        if (otp.getCode().equals(code)) {
            otp.setUsed(true);
            otpRepository.save(otp);
            return true;
        }
        
        return false;
    }

    @Transactional
    public void cleanupExpiredOtps() {
        otpRepository.deleteExpiredOtps(LocalDateTime.now());
    }
}

