package uk.gov.di.authentication.app.services;

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
import com.nimbusds.jose.jwk.JWK;
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
import com.nimbusds.openid.connect.sdk.Nonce;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.nio.ByteBuffer;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

public class DocAppAuthorisationService {

    private static final Logger LOG = LogManager.getLogger(DocAppAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;
    private final KmsConnectionService kmsConnectionService;
    public static final String STATE_STORAGE_PREFIX = "state:";
    private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.ES256;

    private final Json objectMapper = SerializationService.getInstance();

    public DocAppAuthorisationService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService,
            KmsConnectionService kmsConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
        this.kmsConnectionService = kmsConnectionService;
    }

    public Optional<ErrorObject> validateResponse(Map<String, String> headers, String sessionId) {
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

        return Optional.empty();
    }

    public void storeState(String sessionId, State state) {
        try {
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

    public EncryptedJWT constructRequestJWT(State state, Subject subject) {
        LOG.info("Generating request JWT");
        var jwsHeader = new JWSHeader(SIGNING_ALGORITHM);
        var jwtID = IdGenerator.generate();
        var expiryDate = NowHelper.nowPlus(3, ChronoUnit.MINUTES);
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
                        .claim("nonce", new Nonce(IdGenerator.generate()).getValue())
                        .claim(
                                "redirect_uri",
                                configurationService.getDocAppAuthorisationCallbackURI().toString())
                        .claim("client_id", configurationService.getDocAppAuthorisationClientId())
                        .claim("response_type", ResponseType.CODE.toString());
        var encodedHeader = jwsHeader.toBase64URL();
        var encodedClaims = Base64URL.encode(claimsBuilder.build().toString());
        var message = encodedHeader + "." + encodedClaims;
        var signRequest = new SignRequest();
        signRequest.setMessage(ByteBuffer.wrap(message.getBytes()));
        signRequest.setKeyId(configurationService.getDocAppTokenSigningKeyAlias());
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
            LOG.info("Getting Doc App Auth Encryption Public Key");
            var docAppAuthEncryptionPublicKey =
                    configurationService.getDocAppAuthEncryptionPublicKey();
            return new RSAKey.Builder(
                            (RSAKey) JWK.parseFromPEMEncodedObjects(docAppAuthEncryptionPublicKey))
                    .build()
                    .toRSAPublicKey();
        } catch (JOSEException e) {
            LOG.error("Error parsing the public key to RSAPublicKey", e);
            throw new RuntimeException();
        }
    }
}
