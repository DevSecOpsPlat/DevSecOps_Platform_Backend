package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, Long> {

    /* L'ID de l'entité est un UUID alors que le générique du repository est Long :
       méthode dérivée explicite pour chercher par UUID. */
    Optional<User> findOneById(UUID id);

    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);

    Optional<User> findByActivationToken(String activationToken);
}
