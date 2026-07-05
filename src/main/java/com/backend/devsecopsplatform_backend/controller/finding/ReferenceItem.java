package com.backend.devsecopsplatform_backend.controller.finding;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/** Référence officielle (CWE, CVE, OWASP, doc) associée à une remédiation IA. */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ReferenceItem {
    /** CWE | CVE | OWASP | DOC */
    private String type;
    /** Ex: CWE-79, CVE-2024-1234, A03:2021 */
    private String id;
    private String url;
}
