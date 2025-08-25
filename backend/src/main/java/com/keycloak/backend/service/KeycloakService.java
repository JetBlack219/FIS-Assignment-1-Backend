package com.keycloak.backend.service;


import com.keycloak.backend.dto.request.LoginRequest;
import com.keycloak.backend.dto.request.RegisterRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class KeycloakService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @Value("${keycloak.auth-server-url}")
    private String keycloakUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    @Value("${keycloak.admin.username}")
    private String adminUsername;

    @Value("${keycloak.admin.password}")
    private String adminPassword;

    public String getAdminToken() {
        String url = keycloakUrl + "/realms/master/protocol/openid-connect/token";
        log.debug("Requesting admin token from: {}", url);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", "admin-cli");
        params.add("username", adminUsername);
        params.add("password", adminPassword);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);
            JsonNode jsonNode = objectMapper.readTree(response.getBody());
            String token = jsonNode.get("access_token").asText();
            log.info("Admin token obtained successfully");
            return token;
        } catch (HttpClientErrorException e) {
            log.error("Failed to get admin token: HTTP {} {}, Details: {}",
                    e.getStatusCode(), e.getStatusText(), e.getResponseBodyAsString());
            throw new RuntimeException("Failed to get admin token: " + e.getMessage());
        } catch (Exception e) {
            log.error("Failed to get admin token: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to get admin token: " + e.getMessage());
        }
    }

    public void createKeycloakUser(RegisterRequest request) {
        log.debug("Creating user: {}", request.getUsername());
        String adminToken = getAdminToken();
        String url = keycloakUrl + "/admin/realms/" + realm + "/users";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);

        Map<String, Object> userData = new HashMap<>();
        userData.put("username", request.getUsername());
        userData.put("email", request.getEmail());
        userData.put("firstName", request.getFirstName() != null ? request.getFirstName() : "");
        userData.put("lastName", request.getLastName() != null ? request.getLastName() : "");
        userData.put("enabled", true);
        userData.put("emailVerified", false);

        Map<String, Object> credential = new HashMap<>();
        credential.put("type", "password");
        credential.put("value", request.getPassword());
        credential.put("temporary", false);
        userData.put("credentials", new Object[] { credential });

        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(userData, headers);

        try {
            restTemplate.postForEntity(url, requestEntity, String.class);
            log.info("User {} created in Keycloak", request.getUsername());
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.CONFLICT) {
                throw new RuntimeException("User already exists in Keycloak");
            }
            throw new RuntimeException("Failed to create user in Keycloak: " + e.getMessage());
        }
    }

    public Map<String, Object> authenticateUser(LoginRequest request) {
        String url = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        log.debug("Authenticating user: {}, URL: {}", request.getUsername(), url);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("username", request.getUsername());
        params.add("password", request.getPassword());
        params.add("scope", "profile email");

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(url, requestEntity, String.class);
            Map<String, Object> tokenResponse = objectMapper.readValue(response.getBody(), Map.class);
            log.info("User {} authenticated successfully", request.getUsername());
            return tokenResponse;
        } catch (HttpClientErrorException e) {
            log.error("Authentication failed for user {}: HTTP {} {}, Details: {}",
                    request.getUsername(), e.getStatusCode(), e.getStatusText(), e.getResponseBodyAsString());
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new RuntimeException("Invalid credentials");
            }
            throw new RuntimeException("Authentication failed: " + e.getMessage());
        } catch (Exception e) {
            log.error("Authentication failed for user {}: {}", request.getUsername(), e.getMessage(), e);
            throw new RuntimeException("Authentication failed: " + e.getMessage());
        }
    }

    public Map<String, Object> refreshToken(String refreshToken) {
        String url = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        log.debug("Refreshing token");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);
            Map<String, Object> tokenResponse = objectMapper.readValue(response.getBody(), Map.class);
            log.info("Token refreshed successfully");
            return tokenResponse;
        } catch (HttpClientErrorException e) {
            log.error("Token refresh failed: HTTP {} {}, Details: {}",
                    e.getStatusCode(), e.getStatusText(), e.getResponseBodyAsString());
            throw new RuntimeException("Token refresh failed: " + e.getMessage());
        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage(), e);
            throw new RuntimeException("Token refresh failed: " + e.getMessage());
        }
    }

    public void logoutUser(String refreshToken) {
        String url = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/logout";
        log.debug("Logging out user");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        try {
            restTemplate.postForEntity(url, request, String.class);
            log.info("User logged out successfully");
        } catch (HttpClientErrorException e) {
            log.error("Logout failed: HTTP {} {}, Details: {}",
                    e.getStatusCode(), e.getStatusText(), e.getResponseBodyAsString());
            throw new RuntimeException("Logout failed: " + e.getMessage());
        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage(), e);
            throw new RuntimeException("Logout failed: " + e.getMessage());
        }
    }

    public Map<String, Object> parseJwtPayload(String token) {
        log.debug("Parsing JWT token");
        try {
            String[] chunks = token.split("\\.");
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String payload = new String(decoder.decode(chunks[1]));
            Map<String, Object> payloadMap = objectMapper.readValue(payload, Map.class);
            log.info("JWT token parsed successfully");
            return payloadMap;
        } catch (Exception e) {
            log.error("Failed to parse JWT token: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to parse JWT token: " + e.getMessage());
        }
    }

    public void createKeycloakUser(String username, String email, String firstName, String lastName, String password) {
        RegisterRequest request = new RegisterRequest();
        request.setUsername(username);
        request.setEmail(email);
        request.setFirstName(firstName);
        request.setLastName(lastName);
        request.setPassword(password);

        createKeycloakUser(request); // delegate
    }

    public Map<String, Object> authenticateUser(String username, String password) {
        LoginRequest req = new LoginRequest();
        req.setUsername(username);
        req.setPassword(password);
        return authenticateUser(req);
    }

}