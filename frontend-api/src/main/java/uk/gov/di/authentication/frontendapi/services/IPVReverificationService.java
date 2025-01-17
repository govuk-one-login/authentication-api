package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.exceptions.IPVReverificationServiceException;
import uk.gov.di.authentication.frontendapi.exceptions.JwtServiceException;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.exceptions.MissingEnvVariableException;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper.NowClock;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.TokenService;

import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

public class IPVReverificationService {
    private static final Logger LOG = LogManager.getLogger(IPVReverificationService.class);
    private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.ES256;
    private static final String MFA_RESET_SCOPE = "reverification";
    private static final String STATE_STORAGE_PREFIX = "mfaReset:state:";
    private final ConfigurationService configurationService;
    private final JwtService jwtService;
    private final NowClock nowClock;
    private final TokenService tokenService;
    private final RedisConnectionService redisConnectionService;
    private final Json objectMapper = SerializationService.getInstance();

    public IPVReverificationService(
            ConfigurationService configurationService,
            JwtService jwtService,
            TokenService tokenService,
            RedisConnectionService redisConnectionService) {
        this(
                configurationService,
                new NowClock(Clock.systemUTC()),
                jwtService,
                tokenService,
                redisConnectionService);
    }

    public IPVReverificationService(
            ConfigurationService configurationService,
            NowClock nowClock,
            JwtService jwtService,
            TokenService tokenService,
            RedisConnectionService redisConnectionService) {
        this.configurationService = configurationService;
        this.nowClock = nowClock;
        this.jwtService = jwtService;
        this.tokenService = tokenService;
        this.redisConnectionService = redisConnectionService;
    }

    public String buildIpvReverificationRedirectUri(
            Subject subject, String clientSessionId, Session session, State state)
            throws JwtServiceException {
        ClaimsSetRequest claims = buildMfaResetClaimsRequest(subject);
        EncryptedJWT requestJWT =
                constructMfaResetAuthorizationJWT(state, subject, claims, clientSessionId);

        AuthorizationRequest.Builder authRequestBuilder =
                new AuthorizationRequest.Builder(
                                new ResponseType(ResponseType.Value.CODE),
                                new ClientID(configurationService.getIPVAuthorisationClientId()))
                        .endpointURI(configurationService.getIPVAuthorisationURI())
                        .requestObject(requestJWT);

        AuthorizationRequest ipvAuthorisationRequest = authRequestBuilder.build();
        String ipvReverificationRequestURI = ipvAuthorisationRequest.toURI().toString();

        storeState(session.getSessionId(), state);

        LOG.info("IPV reverification JAR created, redirect URI {}", ipvReverificationRequestURI);

        return ipvReverificationRequestURI;
    }

    private EncryptedJWT constructMfaResetAuthorizationJWT(
            State state, Subject subject, ClaimsSetRequest claims, String clientSessionId) {
        LOG.info("Generating MFA Reset request JWT");
        JWTClaimsSet mfaResetAuthorizationClaims =
                createMfaResetAuthorizationClaims(state, subject, claims, clientSessionId);

        LOG.info("Claim set: {}", mfaResetAuthorizationClaims);

        SignedJWT signedJWT =
                jwtService.signJWT(
                        SIGNING_ALGORITHM,
                        mfaResetAuthorizationClaims,
                        configurationService.getMfaResetJarSigningKeyId());
        LOG.info("Created Signed MFA Reset JWT");

        EncryptedJWT encryptedJWT = jwtService.encryptJWT(signedJWT, getPublicKey());
        LOG.info("Created encrypted MFA Reset request JWT");
        return encryptedJWT;
    }

    private JWTClaimsSet createMfaResetAuthorizationClaims(
            State state, Subject subject, ClaimsSetRequest claims, String clientSessionId) {
        LOG.info("Creating MFA Reset Authorization claims");
        String jwtID = IdGenerator.generate();
        Date issueTime = nowClock.now();
        Date expiryDate = nowClock.nowPlus(3, ChronoUnit.MINUTES);
        OIDCClaimsRequest claimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claims);
        JWTClaimsSet.Builder claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(configurationService.getAuthIssuerClaimForIPV())
                        .audience(configurationService.getIPVAudience())
                        .expirationTime(expiryDate)
                        .subject(subject.getValue())
                        .issueTime(issueTime)
                        .jwtID(jwtID)
                        .notBeforeTime(issueTime)
                        .claim("state", state.getValue())
                        .claim("govuk_signin_journey_id", clientSessionId)
                        .claim(
                                "redirect_uri",
                                configurationService.getMfaResetCallbackURI().toString())
                        .claim("client_id", configurationService.getIPVAuthorisationClientId())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", MFA_RESET_SCOPE)
                        .claim("claims", claimsRequest.toJSONObject());
        return claimsBuilder.build();
    }

    private ClaimsSetRequest buildMfaResetClaimsRequest(Subject internalPairwiseSubject) {
        AccessToken storageToken =
                tokenService.generateStorageTokenForMfaReset(internalPairwiseSubject);
        return new ClaimsSetRequest()
                .add(
                        new ClaimsSetRequest.Entry(configurationService.getStorageTokenClaimName())
                                .withValues(List.of(storageToken.getValue())));
    }

    private RSAPublicKey getPublicKey() {
        try {
            LOG.info("Getting IPV Auth Encryption Public Key");
            String ipvAuthEncryptionPublicKey =
                    configurationService.getIPVAuthEncryptionPublicKey();
            return new RSAKey.Builder(
                            (RSAKey) JWK.parseFromPEMEncodedObjects(ipvAuthEncryptionPublicKey))
                    .build()
                    .toRSAPublicKey();
        } catch (JOSEException e) {
            LOG.error("Error parsing the public key to RSAPublicKey", e);
            throw new IPVReverificationServiceException(e.getMessage());
        } catch (MissingEnvVariableException e) {
            LOG.error("Missing environment variable IPV Auth Encryption Public Key");
            throw new IPVReverificationServiceException(e.getMessage());
        }
    }

    private void storeState(String sessionId, State state) {
        try {
            redisConnectionService.saveWithExpiry(
                    STATE_STORAGE_PREFIX + sessionId,
                    objectMapper.writeValueAsString(state),
                    configurationService.getSessionExpiry());
        } catch (Json.JsonException e) {
            LOG.error("Unable to save state to Redis");
            throw new IPVReverificationServiceException(e.getMessage());
        }
    }
}
