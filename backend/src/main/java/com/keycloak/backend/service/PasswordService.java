package com.keycloak.backend.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class PasswordService {

    private static final Logger logger = LoggerFactory.getLogger(PasswordService.class);
    private static final int SALT_LENGTH = 16;
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String ENCODING = "UTF-8";

    /**
     * Hashes a password with a randomly generated salt
     * 
     * @param rawPassword the plain text password
     * @return Base64 encoded string containing salt + hash
     * @throws IllegalArgumentException if rawPassword is null or empty
     */
    public String hashPassword(String rawPassword) {
        if (rawPassword == null || rawPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }

        try {
            // Generate a random salt
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[SALT_LENGTH];
            random.nextBytes(salt);

            // Hash the password with the salt using SHA-256
            MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
            md.update(salt);
            byte[] hashedPassword = md.digest(rawPassword.getBytes(ENCODING));

            // Combine salt and hash, then encode as Base64
            byte[] combined = new byte[salt.length + hashedPassword.length];
            System.arraycopy(salt, 0, combined, 0, salt.length);
            System.arraycopy(hashedPassword, 0, combined, salt.length, hashedPassword.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Hash algorithm not available: {}", HASH_ALGORITHM, e);
            throw new RuntimeException("Hash algorithm not available", e);
        } catch (Exception e) {
            logger.error("Error hashing password", e);
            throw new RuntimeException("Failed to hash password", e);
        }
    }

    /**
     * Verifies a password against its stored hash
     * 
     * @param rawPassword the plain text password to verify
     * @param storedHash  the stored hash to verify against
     * @return true if password matches, false otherwise
     */
    public boolean checkPassword(String rawPassword, String storedHash) {
        if (storedHash == null || rawPassword == null) {
            logger.warn("Null password or hash provided for verification");
            return false;
        }

        if (rawPassword.trim().isEmpty() || storedHash.trim().isEmpty()) {
            logger.warn("Empty password or hash provided for verification");
            return false;
        }

        try {
            // Decode the stored hash
            byte[] combined = Base64.getDecoder().decode(storedHash);

            // Validate the combined array length
            if (combined.length <= SALT_LENGTH) {
                logger.warn("Invalid stored hash format - too short");
                return false;
            }

            // Extract salt (first 16 bytes) and hash (remaining bytes)
            byte[] salt = new byte[SALT_LENGTH];
            byte[] storedPasswordHash = new byte[combined.length - SALT_LENGTH];
            System.arraycopy(combined, 0, salt, 0, SALT_LENGTH);
            System.arraycopy(combined, SALT_LENGTH, storedPasswordHash, 0, storedPasswordHash.length);

            // Hash the input password with the extracted salt
            MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
            md.update(salt);
            byte[] inputPasswordHash = md.digest(rawPassword.getBytes(ENCODING));

            // Compare the hashes using constant-time comparison
            return MessageDigest.isEqual(storedPasswordHash, inputPasswordHash);
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid Base64 encoding in stored hash", e);
            return false;
        } catch (NoSuchAlgorithmException e) {
            logger.error("Hash algorithm not available: {}", HASH_ALGORITHM, e);
            return false;
        } catch (Exception e) {
            logger.error("Error checking password", e);
            return false;
        }
    }
}