package org.keycloak.provider;

import org.jboss.logging.Logger;
import org.keycloak.adapter.EmployeeAdapter;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.entity.EmployeeEntity;
import org.keycloak.models.*;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

import org.keycloak.models.credential.PasswordCredentialModel;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.models.utils.KeycloakModelUtils;

public class EmployeeFederationStorageProvider implements UserStorageProvider, UserLookupProvider, UserRegistrationProvider, UserQueryProvider, CredentialInputValidator, CredentialInputUpdater {

    private static final Logger logger = Logger.getLogger(EmployeeFederationStorageProvider.class);
    public static final String PASSWORD = "password";
    private KeycloakSession session;
    private ComponentModel model;
    private Connection connection;

    public EmployeeFederationStorageProvider(KeycloakSession session, ComponentModel model, Connection connection) {
        this.session = session;
        this.model = model;
        this.connection = connection;
    }

    private String hashPassword(String rawPassword) {
    try {
        // Generate a random salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        
        // Hash the password with the salt using SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(salt);
        byte[] hashedPassword = md.digest(rawPassword.getBytes("UTF-8"));
        
        // Combine salt and hash, then encode as Base64
        byte[] combined = new byte[salt.length + hashedPassword.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(hashedPassword, 0, combined, salt.length, hashedPassword.length);
        
        return Base64.getEncoder().encodeToString(combined);
    } catch (Exception e) {
        logger.error("Error hashing password", e);
        throw new RuntimeException("Failed to hash password", e);
    }
}

    private boolean checkPassword(String rawPassword, String storedHash) {
        if (storedHash == null || rawPassword == null) {
            return false;
        }
        
        try {
            // Decode the stored hash
            byte[] combined = Base64.getDecoder().decode(storedHash);
            
            // Extract salt (first 16 bytes) and hash (remaining bytes)
            byte[] salt = new byte[16];
            byte[] storedPasswordHash = new byte[combined.length - 16];
            System.arraycopy(combined, 0, salt, 0, 16);
            System.arraycopy(combined, 16, storedPasswordHash, 0, storedPasswordHash.length);
            
            // Hash the input password with the extracted salt
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] inputPasswordHash = md.digest(rawPassword.getBytes("UTF-8"));
            
            // Compare the hashes
            return MessageDigest.isEqual(storedPasswordHash, inputPasswordHash);
        } catch (Exception e) {
            logger.error("Error checking password", e);
            return false;
        }
    }

    @Override
    public void close() {
        logger.info("Closing connection");
        try{
            if(connection!=null && !connection.isClosed()){
                connection.close();
                logger.info("Database connection closed successfully.");
            }
        }catch(SQLException e){
            logger.error(e);
        }
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        logger.info("Fetching user with id: " + id);
        String externalId = StorageId.externalId(id); // Extract the external ID

        try {
            // Parse the external ID to UUID
            UUID userId = UUID.fromString(externalId);

            String query = "SELECT * FROM employees WHERE id = ?";
            try (PreparedStatement stmt = connection.prepareStatement(query)) {
                // Use setObject with the UUID type
                stmt.setObject(1, userId);
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    logger.info("User with id: " + id + " found");
                    EmployeeEntity entity = mapRowToEmployee(rs);
                    return new EmployeeAdapter(session, realm, model, entity, connection);
                } else {
                    logger.info("User with id: " + id + " not found");
                }
            } catch (SQLException e) {
                logger.error("Error finding user by ID: " + id, e);
            }
        } catch (IllegalArgumentException e) {
            logger.error("Invalid UUID format for id: " + id, e);
        }
        return null;
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        logger.debug("Attempting to fetch user by username: " + username);
        String query = "SELECT * FROM employees WHERE username = ?";
        try(PreparedStatement stmt = connection.prepareStatement(query)){
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if(rs.next()){
                logger.info("User with username: " + username + " found.");
                EmployeeEntity entity = mapRowToEmployee(rs);
                return new EmployeeAdapter(session, realm, model, entity, connection);
            }
        }catch(SQLException e){
            logger.error("Error while fetching user by username: " + username, e);
        }
        return null;
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        logger.debug("Attempting to fetch user by email: " + email);
        String query = "SELECT * FROM employees WHERE email = ?";
        try(PreparedStatement stmt = connection.prepareStatement(query)){
            stmt.setString(1, email);
            ResultSet rs = stmt.executeQuery();
            if(rs.next()){
                logger.info("User with email: " + email + " found.");
                EmployeeEntity entity = mapRowToEmployee(rs);
                return new EmployeeAdapter(session, realm, model, entity, connection);
            }
        } catch (SQLException e) {
            logger.error("Error while fetching user by email: " + email, e);
        }
        return null;
    }

    private EmployeeEntity mapRowToEmployee(ResultSet rs) throws SQLException {
        logger.debug("Mapping ResultSet to EmployeeEntity");
        EmployeeEntity employee = new EmployeeEntity();
        employee.setId(UUID.fromString(rs.getString("id")));
        employee.setUsername(rs.getString("username"));
        employee.setEmail(rs.getString("email"));
        employee.setFirstName(rs.getString("firstname"));
        employee.setLastName(rs.getString("lastname"));
        employee.setPassword(rs.getString("password"));
        logger.debug("Mapped User: " + employee.getUsername());
        return employee;
    }

    @Override
    public UserModel addUser(RealmModel realmModel, String username) {
        logger.info("Adding user with username: " + username);

        String email = username + "@example.com"; // Placeholder; adjust as needed
        String firstName = "FirstName";
        String lastName = "LastName";
        UUID newId = UUID.randomUUID(); // Generate UUID

        String query = "INSERT INTO employees (id, username, email, password, firstname, lastname) " +
                "VALUES (?, ?, ?, ?, ?, ?)";

        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            // Change this line to use setObject with the UUID type
            stmt.setObject(1, newId, java.sql.Types.OTHER); // or use stmt.setObject(1, newId)
            stmt.setString(2, username);
            stmt.setString(3, email);
            stmt.setNull(4, Types.VARCHAR); // Set password to NULL
            stmt.setString(5, firstName);
            stmt.setString(6, lastName);

            int rowsAffected = stmt.executeUpdate();
            if (rowsAffected > 0) {
                logger.info("User with id " + newId + " added successfully.");

                EmployeeEntity entity = new EmployeeEntity();
                entity.setId(newId);
                entity.setUsername(username);
                entity.setEmail(email);
                entity.setPassword(null); // Explicitly set to null
                entity.setFirstName(firstName);
                entity.setLastName(lastName);

                return new EmployeeAdapter(session, realmModel, model, entity, connection);
            } else {
                logger.error("Failed to add user: " + username);
            }
        } catch (SQLException e) {
            logger.error("Error while adding user with username: " + username, e);
        }

        return null;
    }

    @Override
    public boolean removeUser(RealmModel realmModel, UserModel userModel) {
        logger.info("Removing user with id: " + userModel.getId());
        String externalId = StorageId.externalId(userModel.getId());

        try {
            UUID userId = UUID.fromString(externalId);

            String query = "DELETE FROM employees WHERE id = ?";
            try (PreparedStatement stmt = connection.prepareStatement(query)) {
                stmt.setObject(1, userId);
                int rowsAffected = stmt.executeUpdate();
                if (rowsAffected > 0) {
                    logger.info("User with id: " + userModel.getId() + " removed successfully.");
                    return true;
                } else {
                    logger.error("No user with id: " + userModel.getId() + " found for deletion.");
                }
            } catch (SQLException e) {
                logger.error("Error removing user", e);
            }
        } catch (IllegalArgumentException e) {
            logger.error("Invalid UUID format: " + userModel.getId(), e);
        }
        return false;
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realmModel, Map<String, String> map, Integer firstResult, Integer maxResults) {
        String searchParam = map.getOrDefault("email", map.getOrDefault("username", ""));
        logger.info("Searching for user with parameter: " + searchParam);

        List<EmployeeEntity> employees = new ArrayList<>();
        String query = "SELECT * FROM employees WHERE email LIKE ? OR username LIKE ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)){
            stmt.setString(1, "%" + searchParam + "%");
            stmt.setString(2, "%" + searchParam + "%");
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                employees.add(mapRowToEmployee(rs));
            }
            logger.info("Found " + employees.size() + " employees.");
        } catch (SQLException e) {
            logger.error("Error while searching for user with parameter: " + searchParam, e);
        }
        return employees.stream().map(employee -> new EmployeeAdapter(session, realmModel, model, employee, connection));
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realmModel, GroupModel groupModel, Integer firstResult, Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realmModel, String attribute, String value) {
        return Stream.empty();
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean updateCredential(RealmModel realmModel, UserModel userModel, CredentialInput credentialInput) {
        if (realmModel == null || userModel == null || credentialInput == null) {
            logger.warn("Null parameters provided to updateCredential");
            return false;
        }

        if (!supportsCredentialType(credentialInput.getType())) {
            logger.warn("Unsupported credential type: " + credentialInput.getType() + " for user: " + userModel.getUsername());
            return false;
        }

        if (credentialInput.getType().equals(PasswordCredentialModel.TYPE)) {
            String newPassword = credentialInput.getChallengeResponse();
            if (newPassword == null || newPassword.trim().isEmpty()) {
                logger.warn("Empty password provided for user: " + userModel.getUsername());
                return false;
            }

            String hashedPassword = hashPassword(newPassword);

            String query = "UPDATE employees SET password = ? WHERE username = ?";
            try (PreparedStatement stmt = connection.prepareStatement(query)){
                stmt.setString(1, hashedPassword);
                stmt.setString(2, userModel.getUsername());
                int rowsUpdated = stmt.executeUpdate();
                if (rowsUpdated > 0) {
                    logger.info("Password updated successfully for user: " + userModel.getUsername());
                    return true;
                } else  {
                    logger.warn("No user found to update password for username: " + userModel.getUsername());
                    return false;
                }
            } catch (SQLException e) {
                logger.error("Error while updating password for user: " + userModel.getUsername(), e);
                return false;
            }
        }

        logger.warn("Unsupported credential input type for user: " + userModel.getUsername());
        return false;
    }

    @Override
    public void disableCredentialType(RealmModel realmModel, UserModel userModel, String credentialType) {
        if(PasswordCredentialModel.TYPE.equals(credentialType)){
            logger.info("Disabling credential type for user: " + userModel.getUsername());
            throw new IllegalArgumentException("Disabling password credentials is not supported.");
        }
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realmModel, UserModel userModel) {
        return Stream.empty();
    }

    @Override
    public boolean isConfiguredFor(RealmModel realmModel, UserModel userModel, String credentialType) {
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realmModel, UserModel userModel, CredentialInput credentialInput) {
        logger.info("Validating user: " + userModel.getUsername());
        if (!supportsCredentialType(credentialInput.getType())) {
            logger.warn("Invalid credentials for user: " + userModel.getUsername());
            return false;
        }
        String query = "SELECT password FROM employees WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, userModel.getUsername());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String storedPassword = rs.getString("password");
                boolean isValid = checkPassword(credentialInput.getChallengeResponse(), storedPassword);
                logger.info("User: " + userModel.getUsername() + " password: " + isValid);
                return isValid;
            } else {
                logger.error("User: " + userModel.getUsername() + " password does not match");
            }
        } catch (SQLException e) {
            logger.error("Error validating credentials for user", e);
        }
        return false;
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        logger.info("Counting users for realm: " + realm.getName());

        String query = "SELECT COUNT(*) FROM employees";
        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int count = rs.getInt(1);
                logger.info("Found " + count + " users in employees table.");
                return count;
            }
        } catch (SQLException e) {
            logger.error("Error counting users", e);
        }
        return 0; // Fallback if query fails
    }

    public void setModel(ComponentModel componentModel) {
        this.model = componentModel;
    }

    public void setSession(KeycloakSession keycloakSession) {
        this.session = keycloakSession;
    }

    public void setConnection(Connection connection) {
        this.connection = connection;
    }
}
