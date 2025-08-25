package org.keycloak.adapter;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.entity.EmployeeEntity;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.List;

public class EmployeeAdapter extends AbstractUserAdapterFederatedStorage {
    private static final Logger logger = Logger.getLogger(EmployeeAdapter.class);
    private final EmployeeEntity entity;
    private final String id;
    private final Connection connection;

    public EmployeeAdapter(KeycloakSession session, RealmModel realm, ComponentModel model, EmployeeEntity entity, Connection connection) {
        super(session, realm, model);
        this.entity = entity;
        this.id = StorageId.keycloakId(model, String.valueOf(entity.getId()));
        this.connection = connection;
    }


    @Override
    public String getUsername() {
        return entity.getUsername();
    }

    @Override
    public void setUsername(String s) {
        entity.setUsername(s);
    }

    @Override
    public String getId(){
        return id;
    }

    @Override
    public String getEmail() {
        return entity.getEmail();
    }
    @Override
    public void setEmail(String email) {
        super.setEmail(email);
        updateDatabase("email", email);
    }

    @Override
    public void setFirstName(String firstName) {
        super.setFirstName(firstName);
        updateDatabase("firstname", firstName);
    }

    @Override
    public void setLastName(String lastName) {
        super.setLastName(lastName);
        updateDatabase("lastname", lastName);
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        super.setAttribute(name, values);
        if ("firstName".equals(name)) {
            updateDatabase("firstname", values.getFirst());
        } else if ("lastName".equals(name)) {
            updateDatabase("lastname", values.getFirst());
        } else if ("email".equals(name)) {
            updateDatabase("email", values.getFirst());
        }
    }

    private void updateDatabase(String columnName, String value) {
        String sql = "UPDATE employees SET " + columnName + " = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, value);
            stmt.setObject(2, entity.getId()); // UUID type
            stmt.executeUpdate();
        } catch (SQLException e) {
            logger.error("Error updating database for user " + entity.getId(), e);
        }
    }
}
