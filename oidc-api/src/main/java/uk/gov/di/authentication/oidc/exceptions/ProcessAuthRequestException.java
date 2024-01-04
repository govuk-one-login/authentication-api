package uk.gov.di.authentication.oidc.exceptions;

import uk.gov.di.orchestration.shared.entity.ErrorResponse;

public class ProcessAuthRequestException extends Exception {
    final int statusCode;
    final ErrorResponse errorResponse;

    public ProcessAuthRequestException(int statusCode, ErrorResponse errorResponse) {
        this.statusCode = statusCode;
        this.errorResponse = errorResponse;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public ErrorResponse getErrorResponse() {
        return errorResponse;
    }
}
