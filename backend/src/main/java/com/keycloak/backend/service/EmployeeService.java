package com.keycloak.backend.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.keycloak.backend.dto.request.RegisterRequest;
import java.util.Map;

@Service
public class EmployeeService {

    @Autowired
    private KeycloakService keycloakService;

    public void registerEmployee(String username, String email, String firstName, String lastName,
            String password) {
        try {
            // ✅ Create user only in Keycloak (single source of truth)
            RegisterRequest registerRequest = new RegisterRequest();
            registerRequest.setUsername(username);
            registerRequest.setEmail(email);
            registerRequest.setFirstName(firstName);
            registerRequest.setLastName(lastName);
            registerRequest.setPassword(password);

            keycloakService.createKeycloakUser(registerRequest);

        } catch (Exception e) {
            throw new RuntimeException("Failed to create user: " + e.getMessage());
        }
    }

    public boolean validatePassword(String username, String rawPassword) {
        // ✅ Use Keycloak for authentication instead of local DB
        try {
            keycloakService.authenticateUser(username, rawPassword);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ✅ Get user data from Keycloak token
    public Map<String, Object> getUserFromToken(String token) {
        return keycloakService.parseJwtPayload(token);
    }
}