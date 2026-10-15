package com.backend.devsecopsplatform_backend.controller.appmgmt;

import lombok.Data;

/**
 * Corps du callback de résumé de scan container (Grype), envoyé par le job
 * {@code deploy:grype-scan} du pipeline de déploiement — audit-deploiement.md, chantier #9.
 */
@Data
public class ContainerScanCallbackRequest {
    private Integer critical;
    private Integer high;
    private Integer medium;
    private Integer low;
    private String imageName;
}
