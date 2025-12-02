package org.authx.auth.authentication.dtos;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class UpdateUserPermissionsRequest {
    private Set<String> permissions; // Permission names like "STUDENT_READ", "STUDENT_CREATE"
}

