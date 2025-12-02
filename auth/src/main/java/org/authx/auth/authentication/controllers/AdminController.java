package org.authx.auth.authentication.controllers;

import jakarta.validation.Valid;
import org.authx.auth.authentication.dtos.CreateAdminRequest;
import org.authx.auth.authentication.dtos.UpdateUserPermissionsRequest;
import org.authx.auth.authentication.dtos.UpdateUserRolesRequest;
import org.authx.auth.authentication.models.ApiResponse;
import org.authx.auth.authentication.models.User;
import org.authx.auth.authentication.services.UserManagementService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {

    private final UserManagementService userManagementService;

    public AdminController(UserManagementService userManagementService) {
        this.userManagementService = userManagementService;
    }

    @PostMapping("/create")
    @PreAuthorize("hasAuthority('ADMIN_CREATE')")
    public ResponseEntity<ApiResponse<User>> createAdmin(@Valid @RequestBody CreateAdminRequest request) {
        try {
            User admin = userManagementService.createAdmin(request);
            ApiResponse<User> response = new ApiResponse<>(
                    HttpStatus.CREATED.value(),
                    "Admin created successfully",
                    admin
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

    @PutMapping("/users/{userId}/roles")
    @PreAuthorize("hasAuthority('USER_ROLE_UPDATE')")
    public ResponseEntity<ApiResponse<User>> updateUserRoles(
            @PathVariable Long userId,
            @Valid @RequestBody UpdateUserRolesRequest request) {
        try {
            User user = userManagementService.updateUserRoles(userId, request);
            ApiResponse<User> response = new ApiResponse<>(
                    HttpStatus.OK.value(),
                    "User roles updated successfully",
                    user
            );
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            ApiResponse<User> response = new ApiResponse<>(
                    HttpStatus.BAD_REQUEST.value(),
                    e.getMessage(),
                    null
            );
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @PutMapping("/users/{userId}/permissions")
    @PreAuthorize("hasAuthority('USER_PERMISSION_UPDATE')")
    public ResponseEntity<ApiResponse<User>> updateUserPermissions(
            @PathVariable Long userId,
            @Valid @RequestBody UpdateUserPermissionsRequest request) {
        try {
            User user = userManagementService.updateUserPermissions(userId, request);
            ApiResponse<User> response = new ApiResponse<>(
                    HttpStatus.OK.value(),
                    "User permissions updated successfully",
                    user
            );
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            ApiResponse<User> response = new ApiResponse<>(
                    HttpStatus.BAD_REQUEST.value(),
                    e.getMessage(),
                    null
            );
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }
}

