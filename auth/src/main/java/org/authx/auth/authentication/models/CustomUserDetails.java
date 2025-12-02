package org.authx.auth.authentication.models;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class CustomUserDetails implements UserDetails {

    private final User user;
    private final Set<GrantedAuthority> authorities;

    public CustomUserDetails(User user) {
        this.user = user;
        this.authorities = buildAuthorities(user);
    }

    private Set<GrantedAuthority> buildAuthorities(User user) {
        Set<GrantedAuthority> auths = new HashSet<>();

        // Add roles (as ROLE_...)
        for (Role role : user.getRoles()) {
            auths.add(new SimpleGrantedAuthority(role.getName()));
            // Add role's permissions
            for (Permission perm : role.getPermissions()) {
                auths.add(new SimpleGrantedAuthority(perm.getName()));
            }
        }

        // Add direct user permissions
        for (Permission perm : user.getPermissions()) {
            auths.add(new SimpleGrantedAuthority(perm.getName()));
        }

        return auths;
    }

    @Override public Collection<? extends GrantedAuthority> getAuthorities() { return authorities; }
    @Override public String getPassword() { return user.getPassword(); }
    @Override public String getUsername() { return user.getEmail(); }
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return user.isEnabled(); }
}
