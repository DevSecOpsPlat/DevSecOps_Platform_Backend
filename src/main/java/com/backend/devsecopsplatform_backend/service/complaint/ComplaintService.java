package com.backend.devsecopsplatform_backend.service.complaint;

import com.backend.devsecopsplatform_backend.entity.Complaint;
import com.backend.devsecopsplatform_backend.entity.ComplaintMessage;
import com.backend.devsecopsplatform_backend.entity.ComplaintStatus;
import com.backend.devsecopsplatform_backend.entity.User;
import com.backend.devsecopsplatform_backend.repository.ComplaintRepository;
import com.backend.devsecopsplatform_backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ComplaintService {

    private static final int MAX_SUBJECT = 200;
    private static final int MAX_MESSAGE = 5000;

    private final ComplaintRepository complaintRepository;
    private final UserRepository userRepository;

    @Transactional
    public Complaint create(String subject, String message) {
        User author = currentUser();
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("Le sujet est obligatoire.");
        }
        if (message == null || message.isBlank()) {
            throw new IllegalArgumentException("Le message est obligatoire.");
        }
        String s = subject.trim();
        String m = message.trim();
        if (s.length() > MAX_SUBJECT) {
            throw new IllegalArgumentException("Le sujet ne doit pas dépasser " + MAX_SUBJECT + " caractères.");
        }
        if (m.length() > MAX_MESSAGE) {
            throw new IllegalArgumentException("Le message ne doit pas dépasser " + MAX_MESSAGE + " caractères.");
        }
        Complaint c = new Complaint();
        c.setAuthor(author);
        c.setSubject(s);
        c.setStatus(ComplaintStatus.OPEN);
        ComplaintMessage first = new ComplaintMessage();
        first.setComplaint(c);
        first.setAuthor(author);
        first.setBody(m);
        c.getMessages().add(first);
        complaintRepository.save(c);
        return complaintRepository.findByIdWithMessages(c.getId())
                .orElseThrow(() -> new IllegalStateException("Réclamation introuvable après création."));
    }

    @Transactional(readOnly = true)
    public List<Complaint> listMine() {
        User author = currentUser();
        return complaintRepository.findByAuthorWithMessages(author);
    }

    @Transactional(readOnly = true)
    public List<Complaint> listAllForAdmin(ComplaintStatus filter) {
        if (filter == null) {
            return complaintRepository.findAllWithMessages();
        }
        return complaintRepository.findByStatusWithMessages(filter);
    }

    @Transactional
    public Complaint addMessageAsAuthor(UUID complaintId, String text) {
        User user = currentUser();
        Complaint c = complaintRepository.findByIdWithMessages(complaintId)
                .orElseThrow(() -> new IllegalArgumentException("Réclamation introuvable."));
        if (!c.getAuthor().getId().equals(user.getId())) {
            throw new SecurityException("Vous ne pouvez pas répondre à cette réclamation.");
        }
        ensureOpenForNewMessage(c);
        appendMessage(c, user, text);
        complaintRepository.save(c);
        return complaintRepository.findByIdWithMessages(complaintId)
                .orElseThrow(() -> new IllegalStateException("Réclamation introuvable."));
    }

    @Transactional
    public Complaint addMessageAsAdmin(UUID complaintId, String text) {
        User admin = currentUser();
        if (!admin.isAdmin()) {
            throw new SecurityException("Action réservée aux administrateurs.");
        }
        Complaint c = complaintRepository.findByIdWithMessages(complaintId)
                .orElseThrow(() -> new IllegalArgumentException("Réclamation introuvable."));
        ensureOpenForNewMessage(c);
        appendMessage(c, admin, text);
        complaintRepository.save(c);
        return complaintRepository.findByIdWithMessages(complaintId)
                .orElseThrow(() -> new IllegalStateException("Réclamation introuvable."));
    }

    @Transactional
    public Complaint closeAsAuthor(UUID complaintId) {
        User user = currentUser();
        Complaint c = complaintRepository.findById(complaintId)
                .orElseThrow(() -> new IllegalArgumentException("Réclamation introuvable."));
        if (!c.getAuthor().getId().equals(user.getId())) {
            throw new SecurityException("Vous ne pouvez pas fermer cette réclamation.");
        }
        c.setStatus(ComplaintStatus.CLOSED);
        complaintRepository.save(c);
        return complaintRepository.findByIdWithMessages(complaintId)
                .orElseThrow(() -> new IllegalStateException("Réclamation introuvable."));
    }

    @Transactional
    public Complaint closeAsAdmin(UUID complaintId) {
        User admin = currentUser();
        if (!admin.isAdmin()) {
            throw new SecurityException("Action réservée aux administrateurs.");
        }
        Complaint c = complaintRepository.findById(complaintId)
                .orElseThrow(() -> new IllegalArgumentException("Réclamation introuvable."));
        c.setStatus(ComplaintStatus.CLOSED);
        complaintRepository.save(c);
        return complaintRepository.findByIdWithMessages(complaintId)
                .orElseThrow(() -> new IllegalStateException("Réclamation introuvable."));
    }

    private static void ensureOpenForNewMessage(Complaint c) {
        if (c.getStatus() != ComplaintStatus.OPEN) {
            throw new IllegalStateException("Cette réclamation est fermée ; vous ne pouvez plus envoyer de message.");
        }
    }

    private static void appendMessage(Complaint c, User author, String text) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("Le message ne peut pas être vide.");
        }
        String body = text.trim();
        if (body.length() > MAX_MESSAGE) {
            throw new IllegalArgumentException("Le message ne doit pas dépasser " + MAX_MESSAGE + " caractères.");
        }
        ComplaintMessage m = new ComplaintMessage();
        m.setComplaint(c);
        m.setAuthor(author);
        m.setBody(body);
        c.getMessages().add(m);
    }

    private User currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            throw new IllegalStateException("Utilisateur non authentifié.");
        }
        return userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new IllegalStateException("Utilisateur introuvable."));
    }
}
