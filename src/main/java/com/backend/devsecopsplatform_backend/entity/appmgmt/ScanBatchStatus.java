package com.backend.devsecopsplatform_backend.entity.appmgmt;

/**
 * Cycle de vie d'un lot de scan application ({@link ScanBatch}).
 *
 * <p>Terminal : {@link #PARTIAL}, {@link #COMPLETE}, {@link #FAILED}.
 * Non-terminal : {@link #PENDING}, {@link #RUNNING}.
 */
public enum ScanBatchStatus {
    /** Lot créé, pipeline pas encore démarré / confirmé. Non-terminal. */
    PENDING,
    /**
     * Pipeline en cours : au moins une exécution non terminée.
     * Non-terminal. Ne pas confondre avec {@link #PARTIAL}.
     */
    RUNNING,
    /**
     * <strong>Terminal :</strong> pipeline terminé, au moins un service sans résultat
     * (parmi les {@code expectedServiceCount} prévus). Jamais un verdict positif (D5).
     * Ne pas confondre avec {@link #RUNNING} (non-terminal, exécutions encore en cours).
     */
    PARTIAL,
    /**
     * <strong>Terminal.</strong> Tous les services prévus ont un résultat terminal
     * (succès ou échec métier/tech). Verdict application figé.
     */
    COMPLETE,
    /**
     * <strong>Terminal.</strong> Échec technique global (déclenchement GitLab impossible)
     * ou lot abandonné.
     */
    FAILED
}
