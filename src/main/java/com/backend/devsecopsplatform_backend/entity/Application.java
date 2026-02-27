package com.backend.devsecopsplatform_backend.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;


@Entity
@Table(name = "applications", indexes = {
        @Index(name = "idx_app_created_by", columnList = "created_by"),
        @Index(name = "idx_app_name", columnList = "name")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Application {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "name", nullable = false, length = 200)
    private String name;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "git_repository_url", nullable = false, length = 500)
    private String gitRepositoryUrl;

    @Column(name = "dockerfile_path", length = 255)
    private String dockerfilePath = "./Dockerfile";


    @Column(name = "encrypted_github_token")
    private String encryptedGithubToken;


    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "created_by", nullable = false)
    @JsonIgnoreProperties({"applications", "ephemeralEnvironments", "password"})
    private User createdBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime createdAt;


    @OneToMany(mappedBy = "application", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference("app-env") // Parent
    private List<EphemeralEnvironment> ephemeralEnvironments = new ArrayList<>();

    public void addEphemeralEnvironment(EphemeralEnvironment environment) {
        ephemeralEnvironments.add(environment);
        environment.setApplication(this);
    }

    public void removeEphemeralEnvironment(EphemeralEnvironment environment) {
        ephemeralEnvironments.remove(environment);
        environment.setApplication(null);
    }
}