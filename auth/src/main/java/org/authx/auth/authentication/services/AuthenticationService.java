package org.authx.auth.authentication.services;

import org.authx.auth.authentication.dtos.RegisterRequest;
import org.authx.auth.authentication.models.Otp;
import org.authx.auth.authentication.models.User;
import org.authx.auth.authentication.repositories.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;

    public AuthenticationService(UserRepository userRepository, 
                                 PasswordEncoder passwordEncoder,
                                 OtpService otpService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.otpService = otpService;
    }

    @Transactional
    public User register(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already exists");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEnabled(true);

        return userRepository.save(user);
    }

    public void requestLoginOtp(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));
        
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("Invalid email or password");
        }
        
        otpService.createAndSaveOtp(email, Otp.OtpType.LOGIN);
    }
    
    @Deprecated
    public void requestLoginOtp(String email) {
        if (userRepository.findByEmail(email).isEmpty()) {
            throw new IllegalArgumentException("User not found with email: " + email);
        }
        otpService.createAndSaveOtp(email, Otp.OtpType.LOGIN);
    }

    public boolean verifyLoginOtp(String email, String otp) {
        return otpService.validateOtp(email, otp, Otp.OtpType.LOGIN);
    }

    public void requestPasswordResetOtp(String email) {
        if (userRepository.findByEmail(email).isEmpty()) {
            throw new IllegalArgumentException("User not found with email: " + email);
        }
        otpService.createAndSaveOtp(email, Otp.OtpType.PASSWORD_RESET);
    }

    @Transactional
    public void resetPassword(String email, String otp, String newPassword) {
        if (!otpService.validateOtp(email, otp, Otp.OtpType.PASSWORD_RESET)) {
            throw new IllegalArgumentException("Invalid or expired OTP");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }
}

