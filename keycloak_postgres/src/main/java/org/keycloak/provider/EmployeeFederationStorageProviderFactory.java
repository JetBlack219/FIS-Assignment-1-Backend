package org.keycloak.provider;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserProvider;
import org.keycloak.storage.UserStorageProviderFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class EmployeeFederationStorageProviderFactory implements UserStorageProviderFactory<EmployeeFederationStorageProvider> {

    private Connection connection;
    private static final Logger logger = Logger.getLogger(EmployeeFederationStorageProviderFactory.class);
    private static final String URL = "jdbc:postgresql://localhost:5432/postgres";
    private static final String USER = "postgres";
    private static final String PASS = "nguyen";
    @Override
    public EmployeeFederationStorageProvider create(KeycloakSession keycloakSession, ComponentModel componentModel) {
        try{
            EmployeeFederationStorageProvider employeeProvider = new EmployeeFederationStorageProvider(keycloakSession, componentModel, connection);
            employeeProvider.setModel(componentModel);
            employeeProvider.setSession(keycloakSession);
            employeeProvider.setConnection(getConnection());
            return employeeProvider;
        } catch (Exception e) {
            logger.error("Error while creating EmployeeFederationStorageProvider", e);
            throw new RuntimeException("Failed to create EmployeeFederationStorageProvider", e);
        }
    }

    private synchronized Connection getConnection() throws SQLException {
        if (connection == null || !isConnectionValid()) {
            int attempts = 0;
            SQLException lastException = null;
            while (attempts < 3) {
                try {
                    connection = DriverManager.getConnection(URL, USER, PASS);
                    logger.info("Connected to the PostgreSQL Database at: " + connection.getMetaData().getURL());
                    return connection;
                } catch (SQLException e) {
                    attempts++;
                    lastException = e;
                    logger.error("Failed to connect to the PostgreSQL Database at: " + connection.getMetaData().getURL(), e);
                }
            }
            throw new RuntimeException("Unable to connect to the PostgreSQL Database after 3 attempt at: " + connection.getMetaData().getURL());
        }
        return connection;
    }

    private boolean isConnectionValid() {
        try {
            return connection != null && !connection.isClosed() && connection.isValid(2);
        } catch (SQLException e) {
            return false;
        }
    }

    @Override
    public String getId() {
        return "custom-user-provider";
    }

    @Override
    public void close() {
        try{
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        } catch (SQLException e) {
            logger.error("Error while closing connection", e);
        }
    }
}
