package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.AMCScope;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class AMCAuthorizationService {
    private final ConfigurationService configurationService;
    private final NowHelper.NowClock nowClock;
    private static final Logger LOG = LogManager.getLogger(AMCAuthorizationService.class);

    public AMCAuthorizationService(
            ConfigurationService configurationService, NowHelper.NowClock nowClock) {
        this.configurationService = configurationService;
        this.nowClock = nowClock;
    }

    JWTClaimsSet createAccessTokenClaims(
            Subject internalPairwiseSubject, AMCScope[] scope, AuthSessionItem authSessionItem) {
        LOG.info("Generating access token");
        Date issueTime = nowClock.now();
        Date expiryDate =
                nowClock.nowPlus(configurationService.getSessionExpiry(), ChronoUnit.SECONDS);
        List<String> scopeValues = Arrays.stream(scope).map(AMCScope::getValue).toList();

        return new JWTClaimsSet.Builder()
                .claim("scope", scopeValues)
                .issuer(configurationService.getAuthIssuerClaim())
                .audience(configurationService.getAuthToAuthAudience())
                .expirationTime(expiryDate)
                .issueTime(issueTime)
                .notBeforeTime(issueTime)
                .subject(internalPairwiseSubject.getValue())
                .claim("client_id", authSessionItem.getClientId())
                .claim("sid", authSessionItem.getSessionId())
                .jwtID(UUID.randomUUID().toString())
                .build();
    }
}
