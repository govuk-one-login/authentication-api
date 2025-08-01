package uk.gov.di.orchestration.shared.entity;

import com.nimbusds.oauth2.sdk.ErrorObject;

public record CrossBrowserEntity(
        String clientSessionId, ErrorObject errorObject, OrchClientSessionItem orchClientSession) {}
