package uk.gov.di.orchestration.shared.services;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
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
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.State;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.exceptions.DocAppAuthorisationServiceException;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.serialization.Json.JsonException;

import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;

public class DocAppAuthorisationService {

    private static final Logger LOG = LogManager.getLogger(DocAppAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;
    private final KmsConnectionService kmsConnectionService;
    private final JwksService jwksService;
    public static final String STATE_STORAGE_PREFIX = "state:";

    public static final String STATE_PARAM = "state";
    private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.ES256;

    private final Json objectMapper = SerializationService.getInstance();

    public DocAppAuthorisationService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService,
            KmsConnectionService kmsConnectionService,
            JwksService jwksService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
        this.kmsConnectionService = kmsConnectionService;
        this.jwksService = jwksService;
    }

    public Optional<ErrorObject> validateResponse(Map<String, String> headers, String sessionId) {
        LOG.info("Validating AuthorisationResponse");
        if (headers == null || headers.isEmpty()) {
            LOG.warn("No Query parameters in Doc Checking App Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "No query parameters present"));
        }
        if (headers.containsKey("error")) {
            LOG.warn("Error response found in Doc Checking App Authorisation response");
            return Optional.of(new ErrorObject(headers.get("error")));
        }
        if (!headers.containsKey(STATE_PARAM) || headers.get(STATE_PARAM).isEmpty()) {
            LOG.warn("No state param in Doc Checking App Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No state param present in Authorisation response"));
        }
        if (!isStateValid(sessionId, headers.get(STATE_PARAM))) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid state param present in Authorisation response"));
        }
        if (!headers.containsKey("code") || headers.get("code").isEmpty()) {
            LOG.warn("No code param in Doc Checking App Authorisation response");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "No code param present in Authorisation response"));
        }
        LOG.info("AuthorisationResponse passed validation");
        return Optional.empty();
    }

    public void storeState(String sessionId, State state) {
        try {
            LOG.info("Storing state");
            redisConnectionService.saveWithExpiry(
                    STATE_STORAGE_PREFIX + sessionId,
                    objectMapper.writeValueAsString(state),
                    configurationService.getSessionExpiry());
        } catch (JsonException e) {
            LOG.error("Unable to save state to Redis");
            throw new DocAppAuthorisationServiceException(e);
        }
    }

    private boolean isStateValid(String sessionId, String responseState) {
        var value =
                Optional.ofNullable(
                        redisConnectionService.getValue(STATE_STORAGE_PREFIX + sessionId));
        if (value.isEmpty()) {
            LOG.info("No Doc Checking App state found in Redis");
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
            String subjectValue,
            ClientRegistry clientRegistry,
            String clientSessionId) {
        LOG.info("Generating request JWT");
        var docAppTokenSigningKeyAlias = configurationService.getDocAppTokenSigningKeyAlias();
        var signingKeyId =
                kmsConnectionService
                        .getPublicKey(
                                GetPublicKeyRequest.builder()
                                        .keyId(docAppTokenSigningKeyAlias)
                                        .build())
                        .keyId();
        var jwsHeader =
                new JWSHeader.Builder(SIGNING_ALGORITHM)
                        .keyID(hashSha256String(signingKeyId))
                        .build();
        var jwtID = IdGenerator.generate();
        var expiryDate =
                clientRegistry.isTestClient()
                        ? NowHelper.nowPlus(5, ChronoUnit.DAYS)
                        : NowHelper.nowPlus(3, ChronoUnit.MINUTES);
        var audience =
                configurationService.isDocAppNewAudClaimEnabled()
                        ? configurationService.getDocAppAudClaim()
                        : new Audience(configurationService.getDocAppAuthorisationURI());
        var claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(configurationService.getDocAppAuthorisationClientId())
                        .audience(audience.getValue())
                        .expirationTime(expiryDate)
                        .subject(subjectValue)
                        .issueTime(NowHelper.now())
                        .notBeforeTime(NowHelper.now())
                        .jwtID(jwtID)
                        .claim(STATE_PARAM, state.getValue())
                        .claim(
                                "redirect_uri",
                                configurationService.getDocAppAuthorisationCallbackURI().toString())
                        .claim("client_id", configurationService.getDocAppAuthorisationClientId())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("govuk_signin_journey_id", clientSessionId);
        if (clientRegistry.isTestClient()) {
            claimsBuilder.claim("test_client", true);
        }
        var encodedHeader = jwsHeader.toBase64URL();
        var encodedClaims = Base64URL.encode(claimsBuilder.build().toString());
        var message = encodedHeader + "." + encodedClaims;
        var signRequest =
                SignRequest.builder()
                        .message(SdkBytes.fromByteArray(message.getBytes(StandardCharsets.UTF_8)))
                        .keyId(docAppTokenSigningKeyAlias)
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                        .build();
        try {
            LOG.info("Signing request JWT");
            var signResponse = kmsConnectionService.sign(signRequest);
            LOG.info("Request JWT has been signed successfully");
            var signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResponse.signature().asByteArray(),
                                            ECDSA.getSignatureByteArrayLength(SIGNING_ALGORITHM)))
                            .toString();
            var signedJWT = SignedJWT.parse(message + "." + signature);
            var encryptedJWT = encryptJWT(signedJWT);
            LOG.info("Encrypted request JWT has been generated");
            return encryptedJWT;
        } catch (ParseException | JOSEException e) {
            LOG.error("Error when generating SignedJWT", e);
            throw new DocAppAuthorisationServiceException(e);
        }
    }

    private EncryptedJWT encryptJWT(SignedJWT signedJWT) {
        try {
            LOG.info("Encrypting SignedJWT");
            var publicEncryptionKey = getPublicEncryptionKey();
            var rsaKey = new RSAKey.Builder((RSAKey) publicEncryptionKey).build().toRSAPublicKey();
            var jweObject =
                    new JWEObject(
                            new JWEHeader.Builder(
                                            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                    .contentType("JWT")
                                    .keyID(publicEncryptionKey.getKeyID())
                                    .build(),
                            new Payload(signedJWT));
            jweObject.encrypt(new RSAEncrypter(rsaKey));
            LOG.info("SignedJWT has been successfully encrypted");
            return EncryptedJWT.parse(jweObject.serialize());
        } catch (JOSEException e) {
            LOG.error("Error when encrypting SignedJWT", e);
            throw new DocAppAuthorisationServiceException(e);
        } catch (ParseException e) {
            LOG.error("Error when parsing JWE object to EncryptedJWT", e);
            throw new DocAppAuthorisationServiceException(e);
        }
    }

    private JWK getPublicEncryptionKey() {
        try {
            LOG.info("Getting Doc App Auth Encryption Public Key via JWKS endpoint");
            JWK encryptionJWK;
            // TODO: ATO-1755 - Remove feature flag once this has been turned on in all environments
            if (configurationService.isUseAnyKeyFromDocAppJwks()) {
                encryptionJWK = jwksService.getDocAppJwk();
            } else {
                encryptionJWK =
                        jwksService.retrieveJwkFromURLWithKeyId(
                                configurationService.getDocAppJwksURI().toURL(),
                                configurationService.getDocAppEncryptionKeyID());
            }
            return encryptionJWK;
        } catch (KeySourceException e) {
            LOG.error("Could not find key with provided key ID", e);
            throw new RuntimeException(e);
        } catch (MalformedURLException e) {
            LOG.error("Invalid JWKs URL", e);
            throw new DocAppAuthorisationServiceException(e);
        }
    }
}
