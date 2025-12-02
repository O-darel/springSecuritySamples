package org.authx.auth.authentication.controllers;

import jakarta.validation.Valid;
import org.authx.auth.authentication.dtos.LoginOtpRequest;
import org.authx.auth.authentication.dtos.LoginRequest;
import org.authx.auth.authentication.dtos.PasswordResetConfirm;
import org.authx.auth.authentication.dtos.PasswordResetRequest;
import org.authx.auth.authentication.dtos.RegisterRequest;
import org.authx.auth.authentication.models.ApiResponse;
import org.authx.auth.authentication.models.CustomUserDetails;
import org.authx.auth.authentication.models.User;
import org.authx.auth.authentication.services.AuthenticationService;
import org.authx.auth.authentication.services.CustomUserDetailsService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final CustomUserDetailsService userDetailsService;

    public AuthenticationController(AuthenticationService authenticationService,
                                    CustomUserDetailsService userDetailsService) {
        this.authenticationService = authenticationService;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<User>> register(@Valid @RequestBody RegisterRequest request) {
        try {
            User user = authenticationService.register(request);
            ApiResponse<User> response = new ApiResponse<>(
                    HttpStatus.CREATED.value(),
                    "User registered successfully",
                    user
            );
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (IllegalArgumentException e) {
            ApiResponse<User> response = new ApiResponse<>(
                    HttpStatus.BAD_REQUEST.value(),
                    e.getMessage(),
                    null
            );
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @PostMapping("/login/request-otp")
    public ResponseEntity<ApiResponse<Void>> requestLoginOtp(@Valid @RequestBody LoginOtpRequest request) {
        try {
            authenticationService.requestLoginOtp(request.getEmail(), request.getPassword());
            ApiResponse<Void> response = new ApiResponse<>(
                    HttpStatus.OK.value(),
                    "OTP sent to your email",
                    null
            );
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            ApiResponse<Void> response = new ApiResponse<>(
                    HttpStatus.BAD_REQUEST.value(),
                    e.getMessage(),
                    null
            );
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<String>> login(@Valid @RequestBody LoginRequest request) {
        try {
            boolean isValid = authenticationService.verifyLoginOtp(request.getEmail(), request.getOtp());
            
            if (!isValid) {
                ApiResponse<String> response = new ApiResponse<>(
                        HttpStatus.UNAUTHORIZED.value(),
                        "Invalid or expired OTP",
                        null
                );
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }

            // Create authentication and set it in security context
            CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(request.getEmail());
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            ApiResponse<String> response = new ApiResponse<>(
                    HttpStatus.OK.value(),
                    "Login successful",
                    "User authenticated"
            );
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            ApiResponse<String> response = new ApiResponse<>(
                    HttpStatus.BAD_REQUEST.value(),
                    e.getMessage(),
                    null
            );
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @PostMapping("/password-reset/request")
    public ResponseEntity<ApiResponse<Void>> requestPasswordReset(@Valid @RequestBody PasswordResetRequest request) {
        try {
            authenticationService.requestPasswordResetOtp(request.getEmail());
            ApiResponse<Void> response = new ApiResponse<>(
                    HttpStatus.OK.value(),
                    "Password reset OTP sent to your email",
                    null
            );
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            ApiResponse<Void> response = new ApiResponse<>(
                    HttpStatus.BAD_REQUEST.value(),
                    e.getMessage(),
                    null
            );
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @PostMapping("/password-reset/confirm")
    public ResponseEntity<ApiResponse<Void>> confirmPasswordReset(@Valid @RequestBody PasswordResetConfirm request) {
        try {
            authenticationService.resetPassword(request.getEmail(), request.getOtp(), request.getNewPassword());
            ApiResponse<Void> response = new ApiResponse<>(
                    HttpStatus.OK.value(),
                    "Password reset successfully",
                    null
            );
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            ApiResponse<Void> response = new ApiResponse<>(
                    HttpStatus.BAD_REQUEST.value(),
                    e.getMessage(),
                    null
            );
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }
}

