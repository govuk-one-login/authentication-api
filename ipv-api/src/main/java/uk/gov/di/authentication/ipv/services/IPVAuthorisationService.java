package uk.gov.di.authentication.ipv.services;

import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import com.nimbusds.openid.connect.sdk.Nonce;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;
import uk.gov.di.authentication.shared.services.RedisConnectionService;

import java.nio.ByteBuffer;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class IPVAuthorisationService {

    private static final Logger LOG = LogManager.getLogger(IPVAuthorisationService.class);
    private final ConfigurationService configurationService;
    private final RedisConnectionService redisConnectionService;
    private final KmsConnectionService kmsConnectionService;
    public static final String STATE_STORAGE_PREFIX = "state:";
    private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.ES256;

    public IPVAuthorisationService(
            ConfigurationService configurationService,
            RedisConnectionService redisConnectionService,
            KmsConnectionService kmsConnectionService) {
        this.configurationService = configurationService;
        this.redisConnectionService = redisConnectionService;
        this.kmsConnectionService = kmsConnectionService;
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
                    new ObjectMapper().writeValueAsString(state),
                    configurationService.getSessionExpiry());
        } catch (JsonProcessingException e) {
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
            storedState = new ObjectMapper().readValue(value.get(), State.class);
        } catch (JsonProcessingException e) {
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
            State state, Nonce nonce, Scope scope, Subject subject, String claims) {
        var jwsHeader = new JWSHeader(SIGNING_ALGORITHM);
        var jwtID = IdGenerator.generate();
        var expiryDate =
                Date.from(LocalDateTime.now().plusMinutes(3).atZone(ZoneId.of("UTC")).toInstant());
        var claimsBuilder =
                new JWTClaimsSet.Builder()
                        .issuer(configurationService.getIPVAuthorisationClientId())
                        .audience(configurationService.getIPVAuthorisationURI().toString())
                        .expirationTime(expiryDate)
                        .subject(subject.getValue())
                        .issueTime(
                                Date.from(LocalDateTime.now().atZone(ZoneId.of("UTC")).toInstant()))
                        .jwtID(jwtID)
                        .claim("state", state.getValue())
                        .claim("nonce", nonce.getValue())
                        .claim(
                                "redirect_uri",
                                configurationService.getIPVAuthorisationCallbackURI().toString())
                        .claim("client_id", configurationService.getIPVAuthorisationClientId())
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", scope.toString());
        if (Objects.nonNull(claims)) {
            claimsBuilder.claim("claims", claims);
        }
        var encodedHeader = jwsHeader.toBase64URL();
        var encodedClaims = Base64URL.encode(claimsBuilder.build().toString());
        var message = encodedHeader + "." + encodedClaims;
        var signRequest = new SignRequest();
        signRequest.setMessage(ByteBuffer.wrap(message.getBytes()));
        signRequest.setKeyId(configurationService.getIPVTokenSigningKeyAlias());
        signRequest.setSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString());
        try {
            var signResult = kmsConnectionService.sign(signRequest);
            LOG.info("Token has been signed successfully");
            var signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.getSignature().array(),
                                            ECDSA.getSignatureByteArrayLength(SIGNING_ALGORITHM)))
                            .toString();
            var signedJWT = SignedJWT.parse(message + "." + signature);
            return encryptJWT(signedJWT);
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    private EncryptedJWT encryptJWT(SignedJWT signedJWT) {
        try {
            var getPublicKeyRequest = new GetPublicKeyRequest();
            getPublicKeyRequest.setKeyId(configurationService.getIPVAuthEncryptionKeyAlias());
            var publicEncryptionKey = getPublicKey();
            var jweObject =
                    new JWEObject(
                            new JWEHeader.Builder(
                                            JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                                    .contentType("JWT")
                                    .build(),
                            new Payload(signedJWT));
            jweObject.encrypt(new RSAEncrypter(publicEncryptionKey));

            return EncryptedJWT.parse(jweObject.serialize());
        } catch (JOSEException | ParseException e) {
            LOG.error("Error when encrypting SignedJWT", e);
            throw new RuntimeException(e);
        }
    }

    private RSAPublicKey getPublicKey() {
        try {
            var ipvAuthEncryptionPublicKey = configurationService.getIPVAuthEncryptionPublicKey();
            return new RSAKey.Builder(
                            (RSAKey) JWK.parseFromPEMEncodedObjects(ipvAuthEncryptionPublicKey))
                    .build()
                    .toRSAPublicKey();
        } catch (JOSEException e) {
            LOG.error("Error parsing the public key to RSAPublicKey", e);
            throw new RuntimeException();
        }
    }
}
