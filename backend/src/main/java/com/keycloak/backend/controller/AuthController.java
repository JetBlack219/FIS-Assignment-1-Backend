package com.keycloak.backend.controller;

import com.keycloak.backend.dto.request.LoginRequest;
import com.keycloak.backend.dto.request.LogoutRequest;
import com.keycloak.backend.dto.request.RefreshTokenRequest;
import com.keycloak.backend.dto.request.RegisterRequest;
import com.keycloak.backend.dto.response.ApiResponse;
import com.keycloak.backend.dto.response.AuthResponse;
import com.keycloak.backend.entity.EmployeeEntity;
import com.keycloak.backend.service.EmployeeService;
import com.keycloak.backend.service.KeycloakService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.validation.Valid;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    @Autowired
    private EmployeeService employeeService;

    @Autowired
    private KeycloakService keycloakService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<String>> register(@Valid @RequestBody RegisterRequest request) {
        try {
            employeeService.registerEmployee(
                    request.getUsername(),
                    request.getEmail(),
                    request.getFirstName(),
                    request.getLastName(),
                    request.getPassword());

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.success("User registered successfully in Keycloak",
                            "User " + request.getUsername() + " created successfully"));

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Registration failed: " + e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        try {
            // ✅ Authenticate directly with Keycloak (single source of truth)
            Map<String, Object> tokenData = keycloakService.authenticateUser(
                    request.getUsername(),
                    request.getPassword());

            // Parse user info from access token
            String accessToken = (String) tokenData.get("access_token");
            Map<String, Object> userInfo = keycloakService.parseJwtPayload(accessToken);

            AuthResponse authResponse = new AuthResponse();
            authResponse.setAccessToken(accessToken);
            authResponse.setRefreshToken((String) tokenData.get("refresh_token"));
            authResponse.setExpiresIn((Integer) tokenData.get("expires_in"));
            authResponse.setRefreshExpiresIn((Integer) tokenData.get("refresh_expires_in"));
            authResponse.setTokenType((String) tokenData.get("token_type"));

            AuthResponse.UserInfo user = new AuthResponse.UserInfo();
            user.setSub((String) userInfo.get("sub"));
            user.setUsername((String) userInfo.get("preferred_username"));
            user.setEmail((String) userInfo.get("email"));
            user.setFirstName((String) userInfo.get("given_name"));
            user.setLastName((String) userInfo.get("family_name"));
            authResponse.setUser(user);

            return ResponseEntity.ok(ApiResponse.success("Login successful", authResponse));

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error(e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Login failed: " + e.getMessage()));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        try {
            Map<String, Object> tokenData = keycloakService.refreshToken(request.getRefreshToken());

            AuthResponse authResponse = new AuthResponse();
            authResponse.setAccessToken((String) tokenData.get("access_token"));
            authResponse.setRefreshToken((String) tokenData.get("refresh_token"));
            authResponse.setExpiresIn((Integer) tokenData.get("expires_in"));
            authResponse.setRefreshExpiresIn((Integer) tokenData.get("refresh_expires_in"));
            authResponse.setTokenType((String) tokenData.get("token_type"));

            return ResponseEntity.ok(ApiResponse.success("Token refreshed successfully", authResponse));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Token refresh failed: " + e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@Valid @RequestBody LogoutRequest request) {
        try {
            keycloakService.logoutUser(request.getRefreshToken());
            return ResponseEntity.ok(ApiResponse.success("Logout successful", null));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Logout failed: " + e.getMessage()));
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<ApiResponse<Map<String, Object>>> verifyToken(
            @RequestHeader("Authorization") String authHeader) {
        try {
            if (!authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.error("Invalid authorization header"));
            }

            String token = authHeader.substring(7);
            Map<String, Object> userInfo = keycloakService.parseJwtPayload(token);

            return ResponseEntity.ok(ApiResponse.success("Token is valid", userInfo));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Invalid token: " + e.getMessage()));
        }
    }

    @GetMapping("/profile")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getProfile(
            @RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.error("Invalid authorization header"));
            }

            String token = authHeader.substring(7);
            Map<String, Object> userInfo = keycloakService.parseJwtPayload(token);

            // ✅ Return user info directly from Keycloak token
            Map<String, Object> profile = new HashMap<>();
            profile.put("username", userInfo.get("preferred_username"));
            profile.put("email", userInfo.get("email"));
            profile.put("firstName", userInfo.get("given_name"));
            profile.put("lastName", userInfo.get("family_name"));
            profile.put("sub", userInfo.get("sub"));

            return ResponseEntity.ok(ApiResponse.success("Profile fetched successfully", profile));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Failed to fetch profile: " + e.getMessage()));
        }
    }
}