package com.backend.devsecopsplatform_backend.controller.complaint;

import com.backend.devsecopsplatform_backend.dto.complaint.ComplaintApiDto;
import com.backend.devsecopsplatform_backend.entity.Complaint;
import com.backend.devsecopsplatform_backend.service.complaint.ComplaintService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/complaints")
@RequiredArgsConstructor
@CrossOrigin(origins = {"http://localhost:4200", "http://envirotest.local", "http://envirotest.local:4200"})
public class ComplaintController {

    private final ComplaintService complaintService;

    public record CreateComplaintRequest(String subject, String message) {}

    public record AddMessageRequest(String message) {}

    @PostMapping
    public ResponseEntity<ComplaintApiDto.ThreadDto> create(@RequestBody(required = false) CreateComplaintRequest body) {
        if (body == null) {
            throw new IllegalArgumentException("Corps de requête attendu (subject, message).");
        }
        Complaint c = complaintService.create(body.subject(), body.message());
        return ResponseEntity.ok(ComplaintApiDto.toThread(c));
    }

    @GetMapping("/mine")
    public ResponseEntity<List<ComplaintApiDto.ThreadDto>> mine() {
        return ResponseEntity.ok(complaintService.listMine().stream().map(ComplaintApiDto::toThread).toList());
    }

    @PostMapping("/{id}/messages")
    public ResponseEntity<ComplaintApiDto.ThreadDto> addMessage(@PathVariable("id") UUID id,
                                                                 @RequestBody(required = false) AddMessageRequest body) {
        String text = body != null ? body.message() : null;
        Complaint c = complaintService.addMessageAsAuthor(id, text);
        return ResponseEntity.ok(ComplaintApiDto.toThread(c));
    }

    @PostMapping("/{id}/close")
    public ResponseEntity<ComplaintApiDto.ThreadDto> close(@PathVariable("id") UUID id) {
        Complaint c = complaintService.closeAsAuthor(id);
        return ResponseEntity.ok(ComplaintApiDto.toThread(c));
    }
}
