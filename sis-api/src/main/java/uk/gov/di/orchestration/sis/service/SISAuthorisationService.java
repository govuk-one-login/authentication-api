package uk.gov.di.orchestration.sis.service;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.JwksCacheService;
import uk.gov.di.orchestration.shared.services.OrchJwtService;

import java.security.interfaces.RSAPublicKey;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static uk.gov.di.orchestration.shared.helpers.RsaKeyHelper.getRsaPublicKeyFromJwksCacheItem;

public class SISAuthorisationService {
    private static final Logger LOG = LogManager.getLogger(SISAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final JwksCacheService jwksCacheService;
    private final OrchJwtService orchJwtService;
    private final NowHelper.NowClock nowClock;

    public SISAuthorisationService(
            ConfigurationService configurationService,
            JwksCacheService jwksCacheService,
            OrchJwtService orchJwtService,
            NowHelper.NowClock nowClock) {
        this.configurationService = configurationService;
        this.jwksCacheService = jwksCacheService;
        this.orchJwtService = orchJwtService;
        this.nowClock = nowClock;
    }

    public EncryptedJWT constructRequestJWT(
            State state,
            Scope scope,
            Subject subject,
            ClaimsSetRequest claims,
            String clientSessionId,
            String emailAddress,
            List<String> vtr,
            Boolean reproveIdentity) {
        LOG.info("Generating request JWT");
        var jwtID = IdGenerator.generate();
        var expiryDate = nowClock.nowPlus(3, ChronoUnit.MINUTES);
        var claimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claims);
        var claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(configurationService.getSISAuthorisationClientId())
                        .audience(configurationService.getSISAudience())
                        .expirationTime(expiryDate)
                        .subject(subject.getValue())
                        .issueTime(nowClock.now())
                        .jwtID(jwtID)
                        .notBeforeTime(nowClock.now())
                        .claim("state", state.getValue())
                        .claim("govuk_signin_journey_id", clientSessionId)
                        .claim("email_address", emailAddress)
                        .claim(
                                "redirect_uri",
                                configurationService.getSISAuthorisationCallbackURI().toString())
                        .claim("client_id", configurationService.getSISAuthorisationClientId())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("vtr", vtr);
        if (configurationService.isAccountInterventionServiceActionEnabled()
                && reproveIdentity != null) {
            claimsBuilder.claim("reprove_identity", reproveIdentity);
        }
        claimsBuilder.claim("claims", claimsRequest.toJSONObject());
        LOG.info("Encrypted request JWT has been generated");
        return orchJwtService.signAndEncryptJWT(
                claimsBuilder.build(),
                configurationService.getSISTokenSigningKeyAlias(),
                getPublicEncryptionKey());
    }

    private RSAPublicKey getPublicEncryptionKey() {
        LOG.info("Getting SIS Encryption JWK via JWKS endpoint");
        return getRsaPublicKeyFromJwksCacheItem(jwksCacheService.getOrGenerateSISJwksCacheItem());
    }
}
