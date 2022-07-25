package uk.gov.di.authentication.app.services;

import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
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
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.JwksService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.net.MalformedURLException;
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;

public class DocAppAuthorisationService {

    private static final Logger LOG = LogManager.getLogger(DocAppAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;
    private final KmsConnectionService kmsConnectionService;
    private final JwksService jwksService;
    public static final String STATE_STORAGE_PREFIX = "state:";
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
        if (!headers.containsKey("state") || headers.get("state").isEmpty()) {
            LOG.warn("No state param in Doc Checking App Authorisation response");
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
            throw new RuntimeException(e);
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
            State state, Subject subject, ClientRegistry clientRegistry) {
        LOG.info("Generating request JWT");
        var docAppTokenSigningKeyAlias = configurationService.getDocAppTokenSigningKeyAlias();
        var signingKeyId =
                kmsConnectionService
                        .getPublicKey(
                                new GetPublicKeyRequest().withKeyId(docAppTokenSigningKeyAlias))
                        .getKeyId();
        var jwsHeader =
                new JWSHeader.Builder(SIGNING_ALGORITHM)
                        .keyID(hashSha256String(signingKeyId))
                        .build();
        var jwtID = IdGenerator.generate();
        var expiryDate =
                clientRegistry.isTestClient()
                        ? NowHelper.nowPlus(5, ChronoUnit.DAYS)
                        : NowHelper.nowPlus(3, ChronoUnit.MINUTES);
        var claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(configurationService.getDocAppAuthorisationClientId())
                        .audience(configurationService.getDocAppAuthorisationURI().toString())
                        .expirationTime(expiryDate)
                        .subject(subject.getValue())
                        .issueTime(NowHelper.now())
                        .notBeforeTime(NowHelper.now())
                        .jwtID(jwtID)
                        .claim("state", state.getValue())
                        .claim(
                                "redirect_uri",
                                configurationService.getDocAppAuthorisationCallbackURI().toString())
                        .claim("client_id", configurationService.getDocAppAuthorisationClientId())
                        .claim("response_type", ResponseType.CODE.toString());
        if (clientRegistry.isTestClient()) {
            claimsBuilder.claim("test_client", true);
        }
        var encodedHeader = jwsHeader.toBase64URL();
        var encodedClaims = Base64URL.encode(claimsBuilder.build().toString());
        var message = encodedHeader + "." + encodedClaims;
        var signRequest = new SignRequest();
        signRequest.setMessage(ByteBuffer.wrap(message.getBytes()));
        signRequest.setKeyId(docAppTokenSigningKeyAlias);
        signRequest.setSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString());
        try {
            LOG.info("Signing request JWT");
            var signResult = kmsConnectionService.sign(signRequest);
            LOG.info("Request JWT has been signed successfully");
            var signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.getSignature().array(),
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
            var publicEncryptionKey = getPublicEncryptionKey();
            var jweObject =
                    new JWEObject(
                            new JWEHeader.Builder(
                                            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                    .contentType("JWT")
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

    private RSAPublicKey getPublicEncryptionKey() {
        try {
            LOG.info("Getting Doc App Auth Encryption Public Key via JWKS endpoint");
            var publicJwkSet =
                    jwksService.retrieveJwkSetFromURL(
                            configurationService.getDocAppJwksUri().toURL());
            var encryptionJWK =
                    publicJwkSet.getKeyByKeyId(configurationService.getDocAppEncryptionKeyID());
            return new RSAKey.Builder((RSAKey) encryptionJWK).build().toRSAPublicKey();
        } catch (JOSEException e) {
            LOG.error("Error parsing the public key to RSAPublicKey", e);
            throw new RuntimeException();
        } catch (MalformedURLException e) {
            LOG.error("Invalid JWKs URL", e);
            throw new RuntimeException(e);
        }
    }
}
