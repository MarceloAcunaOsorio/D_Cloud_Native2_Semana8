package com.example.Backend.DTO;

import java.util.Set;

import com.example.Backend.Model.Rol;

public class UserDTO {
    
    private String username;
    private String password;
    private String email;
    private Set<Rol> roles;

    public UserDTO() {
    }

    public UserDTO(String username, String password, String email, Set<Rol> roles) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.roles = roles;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Set<Rol> getRoles() {
        return roles;
    }

    public void setRoles(Set<Rol> roles) {
        this.roles = roles;
    }
}
