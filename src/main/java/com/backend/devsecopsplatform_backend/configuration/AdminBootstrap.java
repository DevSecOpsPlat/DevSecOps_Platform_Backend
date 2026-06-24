package com.backend.devsecopsplatform_backend.configuration;

import com.backend.devsecopsplatform_backend.entity.AccountStatus;
import com.backend.devsecopsplatform_backend.entity.Role;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class AdminBootstrap {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Crée un compte admin par défaut si aucun admin n'existe.
     */
    @Bean
    public CommandLineRunner seedDefaultAdmin() {
        return args -> {
            boolean adminExists = userRepository.findAll().stream()
                    .anyMatch(u -> u.getRoles() != null && u.getRoles().contains(Role.ROLE_ADMIN));
            if (adminExists) {
                return;
            }

            User admin = new User();
            admin.setUsername("admin");
            admin.setEmail("admin@devsecops.com");
            admin.setPassword(passwordEncoder.encode("Admin@123")); // à changer en prod
            admin.setRoles(List.of(Role.ROLE_ADMIN));
            admin.setAccountStatus(AccountStatus.ACTIVE);

            userRepository.save(admin);
            log.info("✅ Compte administrateur par défaut créé (username=admin, password=admin123)");
        };
    }
}

