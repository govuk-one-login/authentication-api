package uk.gov.di.orchestration.identity.entity;

import uk.gov.di.orchestration.shared.entity.CrossBrowserEntity;

public class CrossBrowserException extends Exception {
    private final transient CrossBrowserEntity entity;

    public CrossBrowserException(CrossBrowserEntity entity) {
        this.entity = entity;
    }

    public CrossBrowserEntity getEntity() {
        return entity;
    }
}
