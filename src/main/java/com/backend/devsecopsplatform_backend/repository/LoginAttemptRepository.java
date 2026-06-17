package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.LoginAttempt;
import com.backend.devsecopsplatform_backend.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, UUID> {

    Optional<LoginAttempt> findTopByUserAndSuccessTrueOrderByAttemptedAtDesc(User user);

    List<LoginAttempt> findByUserAndSuccessFalseAndAttemptedAtAfterOrderByAttemptedAtAsc(
            User user, LocalDateTime after);

    List<LoginAttempt> findByUser(User user);

    long countBySuccessFalseAndAttemptedAtAfter(LocalDateTime after);

    long countBySuccessFalseAndIpAddressAndAttemptedAtAfter(String ipAddress, LocalDateTime after);

    @Query("""
            SELECT l FROM LoginAttempt l JOIN FETCH l.user u
            WHERE l.success = false AND l.attemptedAt >= :since
            ORDER BY l.attemptedAt DESC
            """)
    List<LoginAttempt> findFailedSinceWithUser(@Param("since") LocalDateTime since);

    @Query("""
            SELECT l FROM LoginAttempt l JOIN FETCH l.user u
            WHERE l.attemptedAt >= :since
            ORDER BY l.attemptedAt ASC
            """)
    List<LoginAttempt> findAllSinceWithUser(@Param("since") LocalDateTime since);

    @Query(value = """
            SELECT CAST(l.attempted_at AS date) AS day, l.success, COUNT(*)
            FROM login_attempts l
            INNER JOIN users u ON u.id = l.user_id
            WHERE l.attempted_at >= :since
              AND NOT EXISTS (
                  SELECT 1 FROM user_roles ur
                  WHERE ur.user_id = u.id AND ur.roles = 'ROLE_ADMIN'
              )
            GROUP BY CAST(l.attempted_at AS date), l.success
            ORDER BY day
            """, nativeQuery = true)
    List<Object[]> countByDaySinceNonAdmin(@Param("since") LocalDateTime since);
}
