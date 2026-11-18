package com.backend.devsecopsplatform_backend.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DisplayTimeTest {

    private final ObjectMapper mapper = new GitLabConfig().objectMapper();
    private final LocalDateTime created = LocalDateTime.of(2026, 11, 18, 9, 50, 36);

    @Test
    void localDateTimeIsSentWithItsOffset() throws Exception {
        String json = mapper.writeValueAsString(Map.of("createdAt", created));
        String value = mapper.readTree(json).get("createdAt").asText();
        // Le navigateur reçoit un instant non ambigu, quel que soit le fuseau de la JVM.
        assertEquals(created.atZone(ZoneId.systemDefault()).toInstant(), OffsetDateTime.parse(value).toInstant());
    }

    @Test
    void bothFormatsAreReadBack() throws Exception {
        LocalDateTime withOffset = mapper.readValue(
                "\"" + created.atZone(ZoneId.systemDefault()).toOffsetDateTime() + "\"", LocalDateTime.class);
        LocalDateTime withoutOffset = mapper.readValue("\"2026-11-18T09:50:36\"", LocalDateTime.class);
        assertEquals(created, withOffset);
        assertEquals(created, withoutOffset);
    }

    @Test
    void serverSideTextUsesTheUsersTimeZone() {
        String expected = created.atZone(ZoneId.systemDefault())
                .withZoneSameInstant(ZoneId.of("Africa/Tunis"))
                .format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm"));
        assertEquals(expected, DisplayTime.format(created, DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")));
        assertEquals("—", DisplayTime.format(null, DateTimeFormatter.ISO_LOCAL_DATE_TIME));
    }
}
