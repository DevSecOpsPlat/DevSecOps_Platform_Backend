package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.UserActivityLog;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface UserActivityLogRepository extends JpaRepository<UserActivityLog, UUID> {

    List<UserActivityLog> findByUserOrderByCreatedAtDesc(User user);

    /** Fil d'activité admin-wide (tous comptes), pour AdminActivityService — fetch du user
     * associé nécessaire : la relation est @JsonIgnore/lazy et le nom du compte doit être lu
     * pendant que la session est encore ouverte. */
    @Query("SELECT a FROM UserActivityLog a JOIN FETCH a.user ORDER BY a.createdAt DESC")
    List<UserActivityLog> findAllWithUserOrderByCreatedAtDesc(Pageable pageable);
}
