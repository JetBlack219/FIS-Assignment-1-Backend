package com.keycloak.backend.dto.response;

import lombok.Data;

@Data
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private Integer expiresIn;
    private Integer refreshExpiresIn;
    private String tokenType;
    private UserInfo user;

    @Data
    public static class UserInfo {
        private String sub;
        private String username;
        private String email;
        private String firstName;
        private String lastName;
    }
}
