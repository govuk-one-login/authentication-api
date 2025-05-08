package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
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
import uk.gov.di.authentication.shared.exceptions.MissingEnvVariableException;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper.NowClock;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.TokenService;

import java.net.MalformedURLException;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

public class IPVReverificationService {
    private static final Logger LOG = LogManager.getLogger(IPVReverificationService.class);
    private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.ES256;
    private static final String MFA_RESET_SCOPE = "reverification";
    private final ConfigurationService configurationService;
    private final JwtService jwtService;
    private final NowClock nowClock;
    private final TokenService tokenService;
    private final JWKSource<SecurityContext> jwkSource;

    /**
     * Constructs the IPVReverificationService with all necessary services required to create, sign
     * and encrypt the JWT sent over to IPV in the MfaResetAuthorizeHandler.
     *
     * @param configurationService the service used to get environment variables for each
     *     environment.
     */
    public IPVReverificationService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        try {
            RedisConnectionService redisConnectionService =
                    new RedisConnectionService(configurationService);
            KmsConnectionService kmsConnectionService =
                    new KmsConnectionService(configurationService);
            this.jwtService = new JwtService(kmsConnectionService);
            this.tokenService =
                    new TokenService(
                            configurationService, redisConnectionService, kmsConnectionService);
            this.nowClock = new NowClock(Clock.systemUTC());

            this.jwkSource =
                    configurationService.isIpvJwksCallEnabled()
                            ? JWKSourceBuilder.create(configurationService.getIpvJwksUrl())
                                    .retrying(true)
                                    .refreshAheadCache(false)
                                    .cache(true)
                                    .rateLimited(false)
                                    .build()
                            : null;
        } catch (Exception e) {
            LOG.error("Error while initializing IPVReverificationService", e);
            throw new IPVReverificationServiceException(
                    "Failed to initialize IPVReverificationService");
        }
    }

    public IPVReverificationService(
            ConfigurationService configurationService,
            JwtService jwtService,
            TokenService tokenService)
            throws MalformedURLException {
        this(configurationService, new NowClock(Clock.systemUTC()), jwtService, tokenService);
    }

    public IPVReverificationService(
            ConfigurationService configurationService,
            NowClock nowClock,
            JwtService jwtService,
            TokenService tokenService)
            throws MalformedURLException {
        this.configurationService = configurationService;
        this.nowClock = nowClock;
        this.jwtService = jwtService;
        this.tokenService = tokenService;
        this.jwkSource =
                configurationService.isIpvJwksCallEnabled()
                        ? JWKSourceBuilder.create(configurationService.getIpvJwksUrl())
                                .retrying(true)
                                .refreshAheadCache(false)
                                .cache(true)
                                .rateLimited(false)
                                .build()
                        : null;
    }

    public String buildIpvReverificationRedirectUri(
            Subject subject, String clientSessionId, State state) throws JwtServiceException {
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

        LOG.info("IPV reverification JAR created, redirect URI {}", ipvReverificationRequestURI);

        return ipvReverificationRequestURI;
    }

    private EncryptedJWT constructMfaResetAuthorizationJWT(
            State state, Subject subject, ClaimsSetRequest claims, String clientSessionId) {
        LOG.info("Generating MFA Reset request JWT");
        JWTClaimsSet mfaResetAuthorizationClaims =
                createMfaResetAuthorizationClaims(state, subject, claims, clientSessionId);

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
                        .issuer(configurationService.getAuthIssuerClaim())
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
        RSAPublicKey publicKey;
        try {
            LOG.info("Getting IPV Auth Encryption Public Key");

            if (configurationService.isIpvJwksCallEnabled()) {
                RSAKey rsaKey =
                        this.jwkSource
                                .get(new JWKSelector(new JWKMatcher.Builder().build()), null)
                                .stream()
                                .filter(jwk -> jwk instanceof RSAKey)
                                .map(jwk -> (RSAKey) jwk)
                                .findFirst()
                                .orElseThrow(() -> new KeySourceException("No RSA key found"));

                publicKey = rsaKey.toRSAPublicKey();

            } else {
                String ipvAuthEncryptionPublicKey =
                        configurationService.getIPVAuthEncryptionPublicKey();
                publicKey =
                        new RSAKey.Builder(
                                        (RSAKey)
                                                JWK.parseFromPEMEncodedObjects(
                                                        ipvAuthEncryptionPublicKey))
                                .build()
                                .toRSAPublicKey();
            }

            return publicKey;

        } catch (JOSEException e) {
            LOG.error("Error retrieving or parsing public key", e);
            throw new IPVReverificationServiceException(e.getMessage());
        } catch (MissingEnvVariableException e) {
            LOG.error("Missing environment variable IPV Auth Encryption Public Key", e);
            throw new IPVReverificationServiceException(e.getMessage());
        }
    }
}
