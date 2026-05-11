package com.backend.devsecopsplatform_backend.controller.admin;

import com.backend.devsecopsplatform_backend.dto.complaint.ComplaintApiDto;
import com.backend.devsecopsplatform_backend.entity.Complaint;
import com.backend.devsecopsplatform_backend.entity.ComplaintStatus;
import com.backend.devsecopsplatform_backend.service.complaint.ComplaintService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/admin/complaints")
@RequiredArgsConstructor
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class AdminComplaintController {

    private final ComplaintService complaintService;

    public record AddMessageRequest(String message) {}

    @GetMapping
    public ResponseEntity<List<ComplaintApiDto.ThreadDto>> list(@RequestParam(required = false) String status) {
        ComplaintStatus filter = null;
        if (status != null && !status.isBlank()) {
            try {
                filter = ComplaintStatus.valueOf(status.trim().toUpperCase());
            } catch (IllegalArgumentException ignored) {
                // filtre ignoré si valeur inconnue
            }
        }
        return ResponseEntity.ok(complaintService.listAllForAdmin(filter).stream().map(ComplaintApiDto::toThread).toList());
    }

    @PostMapping("/{id}/messages")
    public ResponseEntity<ComplaintApiDto.ThreadDto> addMessage(@PathVariable("id") UUID id,
                                                                @RequestBody(required = false) AddMessageRequest body) {
        String text = body != null ? body.message() : null;
        Complaint c = complaintService.addMessageAsAdmin(id, text);
        return ResponseEntity.ok(ComplaintApiDto.toThread(c));
    }

    @PostMapping("/{id}/close")
    public ResponseEntity<ComplaintApiDto.ThreadDto> close(@PathVariable("id") UUID id) {
        Complaint c = complaintService.closeAsAdmin(id);
        return ResponseEntity.ok(ComplaintApiDto.toThread(c));
    }
}
