package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
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
import uk.gov.di.orchestration.shared.services.OrchJwtService;
import uk.gov.di.orchestration.shared.services.StateStorageService;

import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class OrchestrationAuthorizationService {
    public static final String VTR_PARAM = "vtr";
    public static final String AUTHENTICATION_STATE_STORAGE_PREFIX = "auth-state:";
    private final ConfigurationService configurationService;
    private final DynamoClientService dynamoClientService;
    private final CrossBrowserOrchestrationService crossBrowserOrchestrationService;
    private final StateStorageService stateStorageService;
    private final OrchJwtService orchJwtService;
    private static final Logger LOG = LogManager.getLogger(OrchestrationAuthorizationService.class);

    public OrchestrationAuthorizationService(
            ConfigurationService configurationService,
            DynamoClientService dynamoClientService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            StateStorageService stateStorageService,
            OrchJwtService orchJwtService) {
        this.configurationService = configurationService;
        this.dynamoClientService = dynamoClientService;
        this.crossBrowserOrchestrationService = crossBrowserOrchestrationService;
        this.stateStorageService = stateStorageService;
        this.orchJwtService = orchJwtService;
    }

    public OrchestrationAuthorizationService(ConfigurationService configurationService) {
        this(
                configurationService,
                new DynamoClientService(configurationService),
                new CrossBrowserOrchestrationService(configurationService),
                new StateStorageService(configurationService),
                new OrchJwtService(configurationService));
    }

    public OrchestrationAuthorizationService(
            ConfigurationService configurationService,
            KmsConnectionService kmsConnectionService,
            CrossBrowserOrchestrationService crossBrowserOrchestrationService,
            StateStorageService stateStorageService) {
        this(
                configurationService,
                new DynamoClientService(configurationService),
                crossBrowserOrchestrationService,
                stateStorageService,
                new OrchJwtService(
                        kmsConnectionService,
                        new JwksService(configurationService, kmsConnectionService)));
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
        return orchJwtService.signAndEncryptJWT(
                jwtClaimsSet, configurationService.getAuthSigningKeyAlias(), getPublicKey());
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
}
