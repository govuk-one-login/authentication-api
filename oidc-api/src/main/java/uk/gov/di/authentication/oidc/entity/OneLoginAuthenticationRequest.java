package uk.gov.di.authentication.oidc.entity;

import java.time.ZonedDateTime;

public record OneLoginAuthenticationRequest(
        String clientId,
        ZonedDateTime time
) {
}
