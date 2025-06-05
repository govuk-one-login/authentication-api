package uk.gov.di.authentication.ipv.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper.NowClock;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.RedisConnectionService;
import uk.gov.di.orchestration.shared.services.SerializationService;
import uk.gov.di.orchestration.shared.services.StateStorageService;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class IPVAuthorisationService {

    private static final Logger LOG = LogManager.getLogger(IPVAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;
    private final KmsConnectionService kmsConnectionService;
    private final StateStorageService stateStorageService;
    private final JwksService jwksService;
    private final NowClock nowClock;
    public static final String STATE_STORAGE_PREFIX = "state:";
    private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.ES256;
    private static final Json objectMapper = SerializationService.getInstance();

    public IPVAuthorisationService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService,
            KmsConnectionService kmsConnectionService,
            StateStorageService stateStorageService) {
        this(
                configurationService,
                redisConnectionService,
                kmsConnectionService,
                new JwksService(configurationService, kmsConnectionService),
                new NowClock(Clock.systemUTC()),
                stateStorageService);
    }

    public IPVAuthorisationService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService,
            KmsConnectionService kmsConnectionService,
            JwksService jwksService,
            NowClock nowClock,
            StateStorageService stateStorageService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
        this.kmsConnectionService = kmsConnectionService;
        this.jwksService = jwksService;
        this.nowClock = nowClock;
        this.stateStorageService = stateStorageService;
    }

    public Optional<ErrorObject> validateResponse(Map<String, String> headers, String sessionId) {
        if (headers == null || headers.isEmpty()) {
            LOG.warn("No Query parameters in IPV Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present"));
        }
        if (headers.containsKey("error")) {
            LOG.warn("Error response found in IPV Authorisation response");
            return Optional.of(new ErrorObject(headers.get("error")));
        }
        if (!headers.containsKey("state") || headers.get("state").isEmpty()) {
            LOG.warn("No state param in IPV Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No state param present in Authorisation response"));
        }
        if (!isStateValid(sessionId, headers.get("state"))) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid state param present in Authorisation response"));
        }
        if (!headers.containsKey("code") || headers.get("code").isEmpty()) {
            LOG.warn("No code param in IPV Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No code param present in Authorisation response"));
        }

        return Optional.empty();
    }

    public void storeState(String sessionId, State state) {
        try {
            redisConnectionService.saveWithExpiry(
                    STATE_STORAGE_PREFIX + sessionId,
                    objectMapper.writeValueAsString(state),
                    configurationService.getSessionExpiry());

            stateStorageService.storeState(STATE_STORAGE_PREFIX + sessionId, state);
        } catch (JsonException e) {
            LOG.error("Unable to save state to Redis");
            throw new RuntimeException(e);
        }
    }

    private boolean isStateValid(String sessionId, String responseState) {
        var value =
                Optional.ofNullable(
                        redisConnectionService.getValue(STATE_STORAGE_PREFIX + sessionId));
        if (value.isEmpty()) {
            LOG.info("No state found in Redis");
            return false;
        }
        State storedState;
        try {
            storedState = objectMapper.readValue(value.get(), State.class);
        } catch (JsonException e) {
            LOG.info("Error when deserializing state from redis");
            return false;
        }
        LOG.info(
                "Response state: {} and Stored state: {}. Are equal: {}",
                responseState,
                storedState.getValue(),
                responseState.equals(storedState.getValue()));
        return responseState.equals(storedState.getValue());
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
        var signingKeyJwt = jwksService.getPublicIpvTokenJwkWithOpaqueId();
        var jwsHeader =
                new JWSHeader.Builder(SIGNING_ALGORITHM).keyID(signingKeyJwt.getKeyID()).build();
        var jwtID = IdGenerator.generate();
        var expiryDate = nowClock.nowPlus(3, ChronoUnit.MINUTES);
        var claimsRequest = new OIDCClaimsRequest().withUserInfoClaimsRequest(claims);
        var claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(configurationService.getIPVAuthorisationClientId())
                        .audience(configurationService.getIPVAudience())
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
                                configurationService.getIPVAuthorisationCallbackURI().toString())
                        .claim("client_id", configurationService.getIPVAuthorisationClientId())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString())
                        .claim("vtr", vtr);
        if (configurationService.isAccountInterventionServiceActionEnabled()
                && reproveIdentity != null) {
            claimsBuilder.claim("reprove_identity", reproveIdentity);
        }
        claimsBuilder.claim("claims", claimsRequest.toJSONObject());

        var encodedHeader = jwsHeader.toBase64URL();
        var encodedClaims = Base64URL.encode(claimsBuilder.build().toString());
        var message = encodedHeader + "." + encodedClaims;
        var signRequest =
                SignRequest.builder()
                        .message(SdkBytes.fromByteArray(message.getBytes(StandardCharsets.UTF_8)))
                        .keyId(configurationService.getIPVTokenSigningKeyAlias())
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();
        try {
            LOG.info("Signing request JWT");
            var signResult = kmsConnectionService.sign(signRequest);
            LOG.info("Request JWT has been signed successfully");
            var signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.signature().asByteArray(),
                                            ECDSA.getSignatureByteArrayLength(SIGNING_ALGORITHM)))
                            .toString();
            var signedJWT = SignedJWT.parse(message + "." + signature);
            var encryptedJWT = encryptJWT(signedJWT);
            LOG.info("Encrypted request JWT has been generated");
            return encryptedJWT;
        } catch (ParseException | JOSEException e) {
            LOG.error("Error when generating SignedJWT", e);
            throw new RuntimeException(e);
        }
    }

    private EncryptedJWT encryptJWT(SignedJWT signedJWT) {
        try {
            LOG.info("Encrypting SignedJWT");
            String keyId = null;
            RSAPublicKey publicEncryptionKey;
            if (configurationService.isUseIPVJwksEndpointEnabled()) {
                JWK publicEncryptionJwk = getJwkFromJwksEndpoint();
                keyId = publicEncryptionJwk.getKeyID();
                publicEncryptionKey = getRsaPublicKeyFromJwk(publicEncryptionJwk);
            } else {
                publicEncryptionKey = getPublicKeyFromSSM();
            }
            var jweObject =
                    new JWEObject(
                            new JWEHeader.Builder(
                                            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                    .contentType("JWT")
                                    .keyID(keyId)
                                    .build(),
                            new Payload(signedJWT));
            jweObject.encrypt(new RSAEncrypter(publicEncryptionKey));
            LOG.info("SignedJWT has been successfully encrypted");
            return EncryptedJWT.parse(jweObject.serialize());
        } catch (JOSEException e) {
            LOG.error("Error when encrypting SignedJWT", e);
            throw new RuntimeException(e);
        } catch (ParseException e) {
            LOG.error("Error when parsing JWE object to EncryptedJWT", e);
            throw new RuntimeException(e);
        }
    }

    private RSAPublicKey getPublicKeyFromSSM() {
        try {
            LOG.info("Getting IPV Encryption Public Key via SSM");
            var ipvAuthEncryptionPublicKey = configurationService.getIPVAuthEncryptionPublicKey();
            return new RSAKey.Builder(
                            (RSAKey) JWK.parseFromPEMEncodedObjects(ipvAuthEncryptionPublicKey))
                    .build()
                    .toRSAPublicKey();
        } catch (JOSEException e) {
            LOG.error("Error parsing the public key to RSAPublicKey", e);
            throw new RuntimeException(e);
        }
    }

    private JWK getJwkFromJwksEndpoint() {
        LOG.info("Getting IPV Encryption JWK via JWKS endpoint");
        return jwksService.getIpvJwk();
    }

    private RSAPublicKey getRsaPublicKeyFromJwk(JWK ipvAuthEncryptionPublicKey) {
        try {
            LOG.info("Converting JWK to RSAPublicKey");
            return new RSAKey.Builder((RSAKey) ipvAuthEncryptionPublicKey).build().toRSAPublicKey();
        } catch (JOSEException e) {
            LOG.error("Error parsing the public key to RSAPublicKey", e);
            throw new RuntimeException(e);
        }
    }
}
