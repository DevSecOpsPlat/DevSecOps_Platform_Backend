package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.AiRemediationCache;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AiRemediationCacheRepository extends JpaRepository<AiRemediationCache, UUID> {
    Optional<AiRemediationCache> findByCacheKey(String cacheKey);
}
