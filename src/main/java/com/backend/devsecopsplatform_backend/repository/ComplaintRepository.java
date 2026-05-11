package com.backend.devsecopsplatform_backend.repository;

import com.backend.devsecopsplatform_backend.entity.Complaint;
import com.backend.devsecopsplatform_backend.entity.ComplaintStatus;
import com.backend.devsecopsplatform_backend.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ComplaintRepository extends JpaRepository<Complaint, UUID> {

    @Query("SELECT DISTINCT c FROM Complaint c JOIN FETCH c.author a LEFT JOIN FETCH c.messages m LEFT JOIN FETCH m.author WHERE a = :author ORDER BY c.createdAt DESC")
    List<Complaint> findByAuthorWithMessages(@Param("author") User author);

    @Query("SELECT DISTINCT c FROM Complaint c JOIN FETCH c.author a LEFT JOIN FETCH c.messages m LEFT JOIN FETCH m.author ORDER BY c.createdAt DESC")
    List<Complaint> findAllWithMessages();

    @Query("SELECT DISTINCT c FROM Complaint c JOIN FETCH c.author a LEFT JOIN FETCH c.messages m LEFT JOIN FETCH m.author WHERE c.status = :status ORDER BY c.createdAt DESC")
    List<Complaint> findByStatusWithMessages(@Param("status") ComplaintStatus status);

    @Query("SELECT DISTINCT c FROM Complaint c JOIN FETCH c.author a LEFT JOIN FETCH c.messages m LEFT JOIN FETCH m.author WHERE c.id = :id")
    Optional<Complaint> findByIdWithMessages(@Param("id") UUID id);
}
