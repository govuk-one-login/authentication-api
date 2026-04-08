package uk.gov.di.authentication.frontendapi.errormapper;

import uk.gov.di.authentication.shared.entity.ErrorResponse;

public record ErrorResponseWithStatus(int statusCode, ErrorResponse errorResponse) {}
