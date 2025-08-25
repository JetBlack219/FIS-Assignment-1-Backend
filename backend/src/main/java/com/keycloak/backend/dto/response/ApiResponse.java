package com.keycloak.backend.dto.response;

import lombok.Data;

@Data
public class ApiResponse<T> {
    private boolean success;
    private String message;
    private T data;
    private String error;

    public static <T> ApiResponse<T> success(String message, T data) {
        ApiResponse<T> response = new ApiResponse<>();
        response.success = true;
        response.message = message;
        response.data = data;
        return response;
    }

    public static <T> ApiResponse<T> error(String error) {
        ApiResponse<T> response = new ApiResponse<>();
        response.success = false;
        response.error = error;
        return response;
    }
}
