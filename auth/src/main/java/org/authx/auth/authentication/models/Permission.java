package org.authx.auth.authentication.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "permissions")
@Setter
@Getter
public class Permission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Use uppercase constant-like names: STUDENT_READ, STUDENT_CREATE etc.
    @Column(unique = true, nullable = false)
    private String name;

    // Optional: description
    private String description;

}

