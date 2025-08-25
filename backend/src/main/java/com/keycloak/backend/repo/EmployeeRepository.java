package com.keycloak.backend.repo;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.keycloak.backend.entity.EmployeeEntity;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface EmployeeRepository extends JpaRepository<EmployeeEntity, UUID> {
    Optional<EmployeeEntity> findByUsername(String username);

    Optional<EmployeeEntity> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);
}
