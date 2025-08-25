package com.keycloak.backend.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HealthController {

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = Map.of(
                "status", "OK",
                "timestamp", System.currentTimeMillis(),
                "service", "Keycloak Test API");
        return ResponseEntity.ok(response);
    }
}
