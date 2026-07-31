package uk.gov.di.orchestration.identity.entity;

import uk.gov.di.orchestration.shared.entity.CrossBrowserEntity;

public class CrossBrowserNoSessionException extends CrossBrowserException {
    public CrossBrowserNoSessionException(CrossBrowserEntity entity) {
        super(entity);
    }
}
