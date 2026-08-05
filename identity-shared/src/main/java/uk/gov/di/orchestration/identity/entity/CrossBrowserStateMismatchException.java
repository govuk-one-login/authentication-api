package uk.gov.di.orchestration.identity.entity;

import uk.gov.di.orchestration.shared.entity.CrossBrowserEntity;

public class CrossBrowserStateMismatchException extends CrossBrowserException {
    public CrossBrowserStateMismatchException(CrossBrowserEntity entity) {
        super(entity);
    }
}
