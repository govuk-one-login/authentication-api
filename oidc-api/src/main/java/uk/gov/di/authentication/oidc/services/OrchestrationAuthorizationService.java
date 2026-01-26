package uk.gov.di.authentication.oidc.services;

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
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.oidc.exceptions.InvalidJWEException;
import uk.gov.di.authentication.oidc.exceptions.InvalidPublicKeyException;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.helpers.PersistentIdHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.CrossBrowserOrchestrationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.JwksService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.services.StateStorageService;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class OrchestrationAuthorizationService {
    public static final String VTR_PARAM = "vtr";
    public static final String AUTHENTICATION_STATE_STORAGE_PREFIX = "auth-state:";
    private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.ES256;
    private final ConfigurationService configurationService;
    private final DynamoClientService dynamoClientService;
    private final KmsConnectionService kmsConnectionService;
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;
    private final StateStorageService stateStorageService;
    private final JwksService jwksService;
    private static final Logger LOG = LogManager.getLogger(OrchestrationAuthorizationService.class);

    public OrchestrationAuthorizationService(
            ConfigurationService configurationService,
            DynamoClientService dynamoClientService,
            KmsConnectionService kmsConnectionService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            StateStorageService stateStorageService,
            JwksService jwksService) {
        this.configurationService = configurationService;
        this.dynamoClientService = dynamoClientService;
        this.kmsConnectionService = kmsConnectionService;
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
        this.stateStorageService = stateStorageService;
        this.jwksService = jwksService;
    }

    public OrchestrationAuthorizationService(ConfigurationService configurationService) {
        this(
                configurationService,
                new DynamoClientService(configurationService),
                new KmsConnectionService(configurationService),
                new CrossBrowserOrchestrationService(configurationService),
                new StateStorageService(configurationService),
                new JwksService(
                        configurationService, new KmsConnectionService(configurationService)));
    }

    public OrchestrationAuthorizationService(
            ConfigurationService configurationService,
            KmsConnectionService kmsConnectionService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            StateStorageService stateStorageService) {
        this(
                configurationService,
                new DynamoClientService(configurationService),
                kmsConnectionService,
                crossBrowserOrchestrationService,
                stateStorageService,
                new JwksService(configurationService, kmsConnectionService));
    }

    public boolean isClientRedirectUriValid(ClientID clientID, URI redirectURI)
            throws ClientNotFoundException {
        Optional<ClientRegistry> client = dynamoClientService.getClient(clientID.toString());
        if (client.isEmpty()) {
            throw new ClientNotFoundException(clientID.toString());
        }
        return isClientRedirectUriValid(client.get(), redirectURI);
    }

    public boolean isClientRedirectUriValid(ClientRegistry client, URI redirectURI) {
        return client.getRedirectUrls().contains(redirectURI.toString());
    }

    public AuthenticationSuccessResponse generateSuccessfulAuthResponse(
            AuthenticationRequest authRequest,
            AuthorizationCode authorizationCode,
            URI redirectUri,
            State state) {

        LOG.info("Generating Successful Auth Response");
        return new AuthenticationSuccessResponse(
                redirectUri,
                authorizationCode,
                null,
                null,
                state,
                null,
                authRequest.getResponseMode());
    }

    public EncryptedJWT getSignedAndEncryptedJWT(JWTClaimsSet jwtClaimsSet) {
        var signedJwt = getSignedJWT(jwtClaimsSet);
        return encryptJWT(signedJwt);
    }

    public SignedJWT getSignedJWT(JWTClaimsSet jwtClaimsSet) {
        LOG.info("Generating signed and encrypted JWT");
        var signingKey = jwksService.getPublicAuthSigningJwkWithOpaqueId();
        var jwsHeader =
                new JWSHeader.Builder(SIGNING_ALGORITHM).keyID(signingKey.getKeyID()).build();

        var encodedHeader = jwsHeader.toBase64URL();
        var encodedClaims = Base64URL.encode(jwtClaimsSet.toString());
        var message = encodedHeader + "." + encodedClaims;

        var signRequestBuilder =
                SignRequest.builder()
                        .keyId(
                                configurationService
                                        .getOrchestrationToAuthenticationTokenSigningKeyAlias())
                        .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256);

        SignRequest signRequest =
                isMessageHashSignRequired(message)
                        ? signRequestBuilder
                                .message(SdkBytes.fromByteArray(getMessageHashDigest(message)))
                                .messageType(MessageType.DIGEST)
                                .build()
                        : signRequestBuilder
                                .message(
                                        SdkBytes.fromByteArray(
                                                message.getBytes(StandardCharsets.UTF_8)))
                                .messageType(MessageType.RAW)
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
            return SignedJWT.parse(message + "." + signature);
        } catch (ParseException | JOSEException e) {
            LOG.error("Error when generating SignedJWT", e);
            throw new InvalidJWEException("Error when generating SignedJWT", e);
        }
    }

    private EncryptedJWT encryptJWT(SignedJWT signedJWT) {
        try {
            LOG.info("Encrypting SignedJWT");
            var publicEncryptionKey = getPublicKey();
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
            throw new InvalidJWEException("Error when encrypting SignedJWT", e);
        } catch (ParseException e) {
            LOG.error("Error when parsing JWE object to EncryptedJWT", e);
            throw new InvalidJWEException("Error when parsing JWE object to EncryptedJWT", e);
        }
    }

    private RSAPublicKey getPublicKey() {
        try {
            LOG.info("Getting Orchestration to Authentication Encryption Public Key");
            var orchToAuthEncryptionPublicKey =
                    configurationService.getOrchestrationToAuthenticationEncryptionPublicKey();
            return new RSAKey.Builder(
                            (RSAKey) JWK.parseFromPEMEncodedObjects(orchToAuthEncryptionPublicKey))
                    .build()
                    .toRSAPublicKey();
        } catch (JOSEException e) {
            LOG.error("Error parsing the public key to RSAPublicKey", e);
            throw new InvalidPublicKeyException("Error parsing the public key to RSAPublicKey", e);
        }
    }

    public AuthenticationErrorResponse generateAuthenticationErrorResponse(
            AuthenticationRequest authRequest,
            ErrorObject errorObject,
            URI redirectUri,
            State state) {

        return generateAuthenticationErrorResponse(
                redirectUri, state, authRequest.getResponseMode(), errorObject);
    }

    public AuthenticationErrorResponse generateAuthenticationErrorResponse(
            URI redirectUri, State state, ResponseMode responseMode, ErrorObject errorObject) {
        LOG.info("Generating Authentication Error Response");
        return new AuthenticationErrorResponse(redirectUri, errorObject, state, responseMode);
    }

    public List<VectorOfTrust> getVtrList(AuthenticationRequest authenticationRequest) {
        return VectorOfTrust.parseFromAuthRequestAttribute(
                authenticationRequest.getCustomParameter(VTR_PARAM));
    }

    public String getExistingOrCreateNewPersistentSessionId(Map<String, String> headers) {
        return PersistentIdHelper.getExistingOrCreateNewPersistentSessionId(headers);
    }

    public void storeState(String sessionId, String clientSessionId, State state) {
        LOG.info("Storing state");
        stateStorageService.storeState(
                AUTHENTICATION_STATE_STORAGE_PREFIX + sessionId, state.getValue());
        crossBrowserOrchestrationService.storeClientSessionIdAgainstState(clientSessionId, state);
    }

    public boolean isJarValidationRequired(ClientRegistry client) {
        return client.getScopes().contains(CustomScopeValue.DOC_CHECKING_APP.getValue())
                || client.isJarValidationRequired();
    }

    private boolean isMessageHashSignRequired(String jwtMessage) {
        return jwtMessage.getBytes(StandardCharsets.UTF_8).length >= 4096;
    }

    private byte[] getMessageHashDigest(String jwtMessage) {
        byte[] signingInputHash;
        try {
            signingInputHash =
                    MessageDigest.getInstance("SHA-256")
                            .digest(jwtMessage.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }
        return signingInputHash;
    }
}
