package com.backend.devsecopsplatform_backend.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Journal d'activité d'un compte : création, changements d'e-mail / mot de passe,
 * activation / désactivation — avec l'auteur de l'action (utilisateur ou admin).
 */
@Entity
@Table(name = "user_activity_log", indexes = {
        @Index(name = "idx_activity_user", columnList = "user_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserActivityLog {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonIgnore
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false, length = 50)
    private UserActivityType action;

    @Column(name = "detail", length = 500)
    private String detail;

    /** Username de l'auteur de l'action (l'utilisateur lui-même ou un admin). */
    @Column(name = "performed_by", length = 100)
    private String performedBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    public static UserActivityLog of(User user, UserActivityType action, String detail, String performedBy) {
        UserActivityLog log = new UserActivityLog();
        log.setUser(user);
        log.setAction(action);
        log.setDetail(detail);
        log.setPerformedBy(performedBy);
        return log;
    }
}
