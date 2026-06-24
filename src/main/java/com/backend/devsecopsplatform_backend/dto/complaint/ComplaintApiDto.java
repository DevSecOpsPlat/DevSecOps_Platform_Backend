package com.backend.devsecopsplatform_backend.dto.complaint;

import com.backend.devsecopsplatform_backend.entity.Complaint;
import com.backend.devsecopsplatform_backend.entity.ComplaintMessage;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;

public final class ComplaintApiDto {

    public record MessageDto(UUID id, String authorUsername, boolean fromAdmin, String body, String createdAt) {}

    public record ThreadDto(
            UUID id,
            String authorUsername,
            String authorEmail,
            String subject,
            String status,
            String createdAt,
            String updatedAt,
            List<MessageDto> messages
    ) {}

    public static ThreadDto toThread(Complaint c) {
        List<MessageDto> messages = c.getMessages() == null ? List.of() : c.getMessages().stream()
                .sorted(Comparator.comparing(ComplaintMessage::getCreatedAt, Comparator.nullsLast(Comparator.naturalOrder())))
                .map(m -> new MessageDto(
                        m.getId(),
                        m.getAuthor() != null ? m.getAuthor().getUsername() : null,
                        m.getAuthor() != null && m.getAuthor().isAdmin(),
                        m.getBody(),
                        m.getCreatedAt() != null ? m.getCreatedAt().toString() : null
                ))
                .toList();
        return new ThreadDto(
                c.getId(),
                c.getAuthor() != null ? c.getAuthor().getUsername() : null,
                c.getAuthor() != null ? c.getAuthor().getEmail() : null,
                c.getSubject(),
                c.getStatus() != null ? c.getStatus().name() : null,
                c.getCreatedAt() != null ? c.getCreatedAt().toString() : null,
                c.getUpdatedAt() != null ? c.getUpdatedAt().toString() : null,
                messages
        );
    }

    private ComplaintApiDto() {}
}
