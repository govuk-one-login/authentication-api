package uk.gov.di.authentication.frontendapi.entity;

public enum JwksServiceFailureReason {
    IO_FAILURE,
    INTERRUPTED_FAILURE,
    PARSE_FAILURE,
    NO_MATCHING_KEY
}
