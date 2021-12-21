package uk.gov.di.authentication.shared.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.ClientSession;
import uk.gov.di.authentication.shared.entity.Session;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.state.UserContext;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.lang.String.format;

public class AuthorizationService {

    public static final String VTR = "vtr";
    private static final String CLIENT_ID = "client_id";
    private final DynamoClientService dynamoClientService;
    private final DynamoService dynamoService;
    public static final String COOKIE_CONSENT_ACCEPT = "accept";
    public static final String COOKIE_CONSENT_REJECT = "reject";
    public static final String COOKIE_CONSENT_NOT_ENGAGED = "not-engaged";

    private static final Logger LOG = LogManager.getLogger(AuthorizationService.class);

    public AuthorizationService(
            DynamoClientService dynamoClientService, DynamoService dynamoService) {
        this.dynamoClientService = dynamoClientService;
        this.dynamoService = dynamoService;
    }

    public AuthorizationService(ConfigurationService configurationService) {
        this(
                new DynamoClientService(
                        configurationService.getAwsRegion(),
                        configurationService.getEnvironment(),
                        configurationService.getDynamoEndpointUri()),
                new DynamoService(configurationService));
    }

    public boolean isClientRedirectUriValid(ClientID clientID, URI redirectURI)
            throws ClientNotFoundException {
        Optional<ClientRegistry> client = dynamoClientService.getClient(clientID.toString());
        if (client.isEmpty()) {
            throw new ClientNotFoundException(clientID.toString());
        }
        return client.get().getRedirectUrls().contains(redirectURI.toString());
    }

    public boolean isClientCookieConsentShared(ClientID clientID) throws ClientNotFoundException {
        return dynamoClientService
                .getClient(clientID.toString())
                .map(ClientRegistry::isCookieConsentShared)
                .orElseThrow();
    }

    public AuthenticationSuccessResponse generateSuccessfulAuthResponse(
            AuthenticationRequest authRequest,
            AuthorizationCode authorizationCode,
            List<NameValuePair> additionalParams)
            throws URISyntaxException {

        URIBuilder redirectUri = new URIBuilder(authRequest.getRedirectionURI());

        if (additionalParams != null && !additionalParams.isEmpty()) {
            redirectUri.addParameters(additionalParams);
        }

        return new AuthenticationSuccessResponse(
                redirectUri.build(),
                authorizationCode,
                null,
                null,
                authRequest.getState(),
                null,
                authRequest.getResponseMode());
    }

    public Optional<ErrorObject> validateAuthRequest(AuthenticationRequest authRequest) {
        Optional<ClientRegistry> client =
                dynamoClientService.getClient(authRequest.getClientID().toString());
        if (client.isEmpty()) {
            LOG.warn("Invalid client: {}", authRequest.getClientID());
            return Optional.of(OAuth2Error.UNAUTHORIZED_CLIENT);
        }
        if (!client.get().getRedirectUrls().contains(authRequest.getRedirectionURI().toString())) {
            LOG.warn(
                    "Invalid Redirect URI for Client {}. Redirect URI in request {}",
                    client.get().getClientID(),
                    authRequest.getRedirectionURI().toString());
            throw new RuntimeException(
                    format(
                            "Invalid Redirect in request %s",
                            authRequest.getRedirectionURI().toString()));
        }
        if (!authRequest.getResponseType().toString().equals("code")) {
            LOG.warn("Unsupported responseType included in request. Expected responseType of code");
            return Optional.of(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE);
        }
        if (!areScopesValid(authRequest.getScope().toStringList())
                || !client.get().getScopes().containsAll(authRequest.getScope().toStringList())) {
            LOG.warn(
                    "Invalid scopes in authRequest. Scopes in request: {}",
                    authRequest.getScope().toStringList());
            return Optional.of(OAuth2Error.INVALID_SCOPE);
        }
        if (!areClaimsValid(authRequest.getOIDCClaims())) {
            LOG.warn(
                    "Invalid claims in authRequest. Claims in request: {}",
                    authRequest.getOIDCClaims().toJSONString());
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "Request contains invalid claims"));
        }
        if (authRequest.getNonce() == null) {
            LOG.warn("Nonce is missing from authRequest");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Request is missing nonce parameter"));
        }
        if (authRequest.getState() == null) {
            LOG.warn("State is missing from authRequest");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Request is missing state parameter"));
        }
        List<String> authRequestVtr = authRequest.getCustomParameter(VTR);
        try {
            VectorOfTrust.parseFromAuthRequestAttribute(authRequestVtr);
        } catch (IllegalArgumentException e) {
            LOG.warn(
                    "vtr in AuthRequest is not valid. vtr in request: {}. IllegalArgumentException: {}",
                    authRequestVtr,
                    e);
            return Optional.of(
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid"));
        }
        return Optional.empty();
    }

    public AuthenticationErrorResponse generateAuthenticationErrorResponse(
            AuthenticationRequest authRequest, ErrorObject errorObject) {

        return generateAuthenticationErrorResponse(
                authRequest.getRedirectionURI(),
                authRequest.getState(),
                authRequest.getResponseMode(),
                errorObject);
    }

    public AuthenticationErrorResponse generateAuthenticationErrorResponse(
            URI redirectUri, State state, ResponseMode responseMode, ErrorObject errorObject) {
        return new AuthenticationErrorResponse(redirectUri, errorObject, state, responseMode);
    }

    public VectorOfTrust getEffectiveVectorOfTrust(AuthenticationRequest authenticationRequest) {
        return VectorOfTrust.parseFromAuthRequestAttribute(
                authenticationRequest.getCustomParameter(VTR));
    }

    public UserContext buildUserContext(Session session, ClientSession clientSession) {
        UserContext.Builder builder = UserContext.builder(session).withClientSession(clientSession);
        UserContext userContext;
        try {
            String clientId =
                    clientSession.getAuthRequestParams().get(CLIENT_ID).stream()
                            .findFirst()
                            .orElseThrow();
            ClientRegistry clientRegistry = dynamoClientService.getClient(clientId).orElseThrow();
            if (session.getEmailAddress() != null) {
                UserProfile userProfile =
                        dynamoService.getUserProfileByEmail(session.getEmailAddress());
                if (userProfile != null) {
                    builder.withUserProfile(userProfile);
                }
            }
            userContext = builder.withClient(clientRegistry).build();
        } catch (NoSuchElementException e) {
            LOG.error("Error creating UserContext");
            throw new RuntimeException("Error when creating UserContext", e);
        }
        return userContext;
    }

    private boolean areScopesValid(List<String> scopes) {
        for (String scope : scopes) {
            if (ValidScopes.getAllValidScopes().stream().noneMatch((t) -> t.equals(scope))) {
                return false;
            }
        }
        return true;
    }

    private boolean areClaimsValid(OIDCClaimsRequest claimsRequest) {
        if (claimsRequest == null) {
            return true;
        }
        List<String> claimNames =
                claimsRequest.getUserInfoClaimsRequest().getEntries().stream()
                        .map(ClaimsSetRequest.Entry::getClaimName)
                        .collect(Collectors.toList());
        for (String claim : claimNames) {
            if (ValidClaims.getAllowedClaimNames().stream().noneMatch(t -> t.equals(claim))) {
                return false;
            }
        }
        return true;
    }

    public String getExistingOrCreateNewPersistentSessionId(Map<String, String> headers) {
        return PersistentIdHelper.getExistingOrCreateNewPersistentSessionId(headers);
    }

    public boolean isValidCookieConsentValue(String cookieConsent) {
        return List.of(COOKIE_CONSENT_ACCEPT, COOKIE_CONSENT_REJECT, COOKIE_CONSENT_NOT_ENGAGED)
                .contains(cookieConsent);
    }
}
