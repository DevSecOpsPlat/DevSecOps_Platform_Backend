package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.entity.UserActivityLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface UserActivityLogRepository extends JpaRepository<UserActivityLog, UUID> {

    List<UserActivityLog> findByUserOrderByCreatedAtDesc(User user);
}
