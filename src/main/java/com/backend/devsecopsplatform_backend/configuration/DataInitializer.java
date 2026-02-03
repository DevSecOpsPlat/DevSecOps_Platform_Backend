package com.backend.devsecopsplatform_backend.configuration;

import com.backend.devsecopsplatform_backend.entity.Role;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;


@Component
@RequiredArgsConstructor
public class DataInitializer {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @PostConstruct
    public void createAdmin() {
        if (userRepository.findByUsername("admin").isEmpty()) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setEmail("admin@devsecops.com");
            admin.setPassword(passwordEncoder.encode("Admin@123"));
            admin.setRoles(List.of(Role.ROLE_ADMIN));


            userRepository.save(admin);
            System.out.println("Admin created");
        }
    }
}
