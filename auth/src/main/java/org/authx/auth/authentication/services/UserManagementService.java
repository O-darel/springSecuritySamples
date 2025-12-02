package org.authx.auth.authentication.services;

import org.authx.auth.authentication.dtos.CreateAdminRequest;
import org.authx.auth.authentication.dtos.UpdateUserPermissionsRequest;
import org.authx.auth.authentication.dtos.UpdateUserRolesRequest;
import org.authx.auth.authentication.models.Permission;
import org.authx.auth.authentication.models.Role;
import org.authx.auth.authentication.models.User;
import org.authx.auth.authentication.repositories.PermissionRepository;
import org.authx.auth.authentication.repositories.RoleRepository;
import org.authx.auth.authentication.repositories.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class UserManagementService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final PasswordEncoder passwordEncoder;

    public UserManagementService(UserRepository userRepository,
                                RoleRepository roleRepository,
                                PermissionRepository permissionRepository,
                                PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public User createAdmin(CreateAdminRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already exists");
        }

        User admin = new User();
        admin.setUsername(request.getUsername());
        admin.setEmail(request.getEmail());
        admin.setPassword(passwordEncoder.encode(request.getPassword()));
        admin.setEnabled(true);

        // Assign ROLE_ADMIN by default
        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseThrow(() -> new IllegalArgumentException("ROLE_ADMIN not found"));

        Set<Role> roles = new HashSet<>();
        roles.add(adminRole);
        admin.setRoles(roles);

        return userRepository.save(admin);
    }

    @Transactional
    public User updateUserRoles(Long userId, UpdateUserRolesRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        Set<Role> roles = request.getRoles().stream()
                .map(roleName -> roleRepository.findByName(roleName)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleName)))
                .collect(Collectors.toSet());

        user.setRoles(roles);
        return userRepository.save(user);
    }

    @Transactional
    public User updateUserPermissions(Long userId, UpdateUserPermissionsRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (request.getPermissions() == null || request.getPermissions().isEmpty()) {
            user.setPermissions(new HashSet<>());
        } else {
            Set<Permission> permissions = request.getPermissions().stream()
                    .map(permName -> permissionRepository.findByName(permName)
                            .orElseThrow(() -> new IllegalArgumentException("Permission not found: " + permName)))
                    .collect(Collectors.toSet());

            user.setPermissions(permissions);
        }

        return userRepository.save(user);
    }

    public User getUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }
}

