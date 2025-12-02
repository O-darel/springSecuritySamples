package org.authx.auth.authentication.dtos;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class UpdateUserRolesRequest {
    @NotEmpty(message = "At least one role is required")
    private Set<String> roles; // Role names like "ROLE_ADMIN", "ROLE_TEACHER"
}

