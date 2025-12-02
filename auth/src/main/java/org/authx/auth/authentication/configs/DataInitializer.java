package org.authx.auth.authentication.configs;

import org.authx.auth.authentication.models.Permission;
import org.authx.auth.authentication.models.Role;
import org.authx.auth.authentication.models.User;
import org.authx.auth.authentication.repositories.PermissionRepository;
import org.authx.auth.authentication.repositories.RoleRepository;
import org.authx.auth.authentication.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Component
@Order(1)
public class DataInitializer implements CommandLineRunner {

    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(PermissionRepository permissionRepository,
                          RoleRepository roleRepository,
                          UserRepository userRepository,
                          PasswordEncoder passwordEncoder) {
        this.permissionRepository = permissionRepository;
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(String... args) {
        initializePermissions();
        initializeRoles();
        initializeSuperAdmin();
    }

    private void initializePermissions() {
        // Student permissions
        createPermissionIfNotExists("STUDENT_READ", "Read student information");
        createPermissionIfNotExists("STUDENT_CREATE", "Create new students");
        createPermissionIfNotExists("STUDENT_UPDATE", "Update student information");
        createPermissionIfNotExists("STUDENT_DELETE", "Delete students");

        // Admin management permissions
        createPermissionIfNotExists("ADMIN_CREATE", "Create new admins");
        createPermissionIfNotExists("ADMIN_READ", "Read admin information");
        createPermissionIfNotExists("ADMIN_UPDATE", "Update admin information");
        createPermissionIfNotExists("ADMIN_DELETE", "Delete admins");

        // Teacher permissions (for future use)
        createPermissionIfNotExists("TEACHER_READ", "Read teacher information");
        createPermissionIfNotExists("TEACHER_CREATE", "Create new teachers");
        createPermissionIfNotExists("TEACHER_UPDATE", "Update teacher information");
        createPermissionIfNotExists("TEACHER_DELETE", "Delete teachers");

        // Course permissions (for future use)
        createPermissionIfNotExists("COURSE_READ", "Read course information");
        createPermissionIfNotExists("COURSE_CREATE", "Create new courses");
        createPermissionIfNotExists("COURSE_UPDATE", "Update course information");
        createPermissionIfNotExists("COURSE_DELETE", "Delete courses");

        // User role and permission management
        createPermissionIfNotExists("USER_ROLE_UPDATE", "Update user roles");
        createPermissionIfNotExists("USER_PERMISSION_UPDATE", "Update user permissions");
    }

    private void createPermissionIfNotExists(String name, String description) {
        permissionRepository.findByName(name).orElseGet(() -> {
            Permission permission = new Permission();
            permission.setName(name);
            permission.setDescription(description);
            return permissionRepository.save(permission);
        });
    }

    private void initializeRoles() {
        // Super Admin Role with all permissions
        Role superAdminRole = roleRepository.findByName("ROLE_SUPER_ADMIN").orElseGet(() -> {
            Role role = new Role();
            role.setName("ROLE_SUPER_ADMIN");
            role.setPermissions(new HashSet<>(permissionRepository.findAll()));
            return roleRepository.save(role);
        });

        // Update super admin role with all permissions (in case new permissions were added)
        Set<Permission> allPermissions = new HashSet<>(permissionRepository.findAll());
        superAdminRole.setPermissions(allPermissions);
        roleRepository.save(superAdminRole);

        // Admin Role with admin management and student permissions
        Role adminRole = roleRepository.findByName("ROLE_ADMIN").orElseGet(() -> {
            Role role = new Role();
            role.setName("ROLE_ADMIN");
            Set<Permission> adminPermissions = new HashSet<>();
            
            // Student permissions
            permissionRepository.findByName("STUDENT_READ").ifPresent(adminPermissions::add);
            permissionRepository.findByName("STUDENT_CREATE").ifPresent(adminPermissions::add);
            permissionRepository.findByName("STUDENT_UPDATE").ifPresent(adminPermissions::add);
            permissionRepository.findByName("STUDENT_DELETE").ifPresent(adminPermissions::add);
            
            // Admin management permissions
            permissionRepository.findByName("ADMIN_CREATE").ifPresent(adminPermissions::add);
            permissionRepository.findByName("ADMIN_READ").ifPresent(adminPermissions::add);
            permissionRepository.findByName("ADMIN_UPDATE").ifPresent(adminPermissions::add);
            permissionRepository.findByName("ADMIN_DELETE").ifPresent(adminPermissions::add);
            
            role.setPermissions(adminPermissions);
            return roleRepository.save(role);
        });
        
        // Update admin role permissions in case new permissions were added
        Set<Permission> adminPermissions = new HashSet<>();
        permissionRepository.findByName("STUDENT_READ").ifPresent(adminPermissions::add);
        permissionRepository.findByName("STUDENT_CREATE").ifPresent(adminPermissions::add);
        permissionRepository.findByName("STUDENT_UPDATE").ifPresent(adminPermissions::add);
        permissionRepository.findByName("STUDENT_DELETE").ifPresent(adminPermissions::add);
        permissionRepository.findByName("ADMIN_CREATE").ifPresent(adminPermissions::add);
        permissionRepository.findByName("ADMIN_READ").ifPresent(adminPermissions::add);
        permissionRepository.findByName("ADMIN_UPDATE").ifPresent(adminPermissions::add);
        permissionRepository.findByName("ADMIN_DELETE").ifPresent(adminPermissions::add);
        adminRole.setPermissions(adminPermissions);
        roleRepository.save(adminRole);
    }

    private void initializeSuperAdmin() {
        if (userRepository.findByEmail("superadmin@school.com").isEmpty()) {
            User superAdmin = new User();
            superAdmin.setUsername("superadmin");
            superAdmin.setEmail("superadmin@school.com");
            superAdmin.setPassword(passwordEncoder.encode("SuperAdmin@123"));
            superAdmin.setEnabled(true);

            Role superAdminRole = roleRepository.findByName("ROLE_SUPER_ADMIN")
                    .orElseThrow(() -> new RuntimeException("ROLE_SUPER_ADMIN not found"));

            Set<Role> roles = new HashSet<>();
            roles.add(superAdminRole);
            superAdmin.setRoles(roles);

            userRepository.save(superAdmin);
            System.out.println("Super Admin created: superadmin@school.com / SuperAdmin@123");
        }
    }
}

