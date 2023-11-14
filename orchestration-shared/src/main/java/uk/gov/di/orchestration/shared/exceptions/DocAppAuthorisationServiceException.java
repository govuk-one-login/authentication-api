package uk.gov.di.orchestration.shared.exceptions;

public class DocAppAuthorisationServiceException extends RuntimeException {
    public DocAppAuthorisationServiceException(Exception e) {
        super(e.getMessage());
    }
}
