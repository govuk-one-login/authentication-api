package uk.gov.di.authentication.shared.services;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.InvocationType;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientRegistry;
import uk.gov.di.authentication.shared.entity.RequestUriPayload;
import uk.gov.di.authentication.shared.entity.RequestUriResponsePayload;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.entity.VectorOfTrust;
import uk.gov.di.authentication.shared.exceptions.ClientNotFoundException;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class AuthorizationService {

    public static final String VTR_PARAM = "vtr";
    private final DynamoClientService dynamoClientService;
    private final AWSLambda awsLambda;
    private final ConfigurationService configurationService;

    private static final Logger LOG = LogManager.getLogger(AuthorizationService.class);

    public AuthorizationService(
            DynamoClientService dynamoClientService,
            AWSLambda awsLambda,
            ConfigurationService configurationService) {
        this.dynamoClientService = dynamoClientService;
        this.awsLambda = awsLambda;
        this.configurationService = configurationService;
    }

    public AuthorizationService(ConfigurationService configurationService) {
        this(
                new DynamoClientService(configurationService),
                configurationService
                        .getInvokedLambdaEndpoint()
                        .map(
                                t ->
                                        AWSLambdaClientBuilder.standard()
                                                .withEndpointConfiguration(
                                                        new AwsClientBuilder.EndpointConfiguration(
                                                                t,
                                                                configurationService
                                                                        .getAwsRegion())))
                        .orElse(
                                AWSLambdaClientBuilder.standard()
                                        .withRegion(configurationService.getAwsRegion()))
                        .build(),
                configurationService);
    }

    public boolean isClientRedirectUriValid(ClientID clientID, URI redirectURI)
            throws ClientNotFoundException {
        Optional<ClientRegistry> client = dynamoClientService.getClient(clientID.toString());
        if (client.isEmpty()) {
            throw new ClientNotFoundException(clientID.toString());
        }
        return client.get().getRedirectUrls().contains(redirectURI.toString());
    }

    public AuthenticationSuccessResponse generateSuccessfulAuthResponse(
            AuthenticationRequest authRequest, AuthorizationCode authorizationCode)
            throws URISyntaxException {

        URIBuilder redirectUri = new URIBuilder(authRequest.getRedirectionURI());

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
        var clientId = authRequest.getClientID().toString();
        var isRequestUri = authRequest.getRequestURI() != null;

        attachLogFieldToLogs(CLIENT_ID, clientId);

        Optional<ClientRegistry> client = dynamoClientService.getClient(clientId);

        if (client.isEmpty()) {
            LOG.warn("Invalid client");
            return Optional.of(OAuth2Error.UNAUTHORIZED_CLIENT);
        }

        if (!client.get().getRedirectUrls().contains(authRequest.getRedirectionURI().toString())) {
            LOG.warn(
                    "Invalid Redirect URI in request {}",
                    authRequest.getRedirectionURI().toString());
            throw new RuntimeException(
                    format(
                            "Invalid Redirect in request %s",
                            authRequest.getRedirectionURI().toString()));
        }
        if (isRequestUri && !configurationService.isRequestUriParamSupported()) {
            return Optional.of(OAuth2Error.REQUEST_URI_NOT_SUPPORTED);
        }
        if (!authRequest.getResponseType().toString().equals(ResponseType.CODE.toString())) {
            LOG.warn("Unsupported responseType included in request. Expected responseType of code");
            return Optional.of(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE);
        }
        if (!areScopesValid(authRequest.getScope().toStringList(), client.get())) {
            LOG.warn(
                    "Invalid scopes in authRequest. Scopes in request: {}",
                    authRequest.getScope().toStringList());
            return Optional.of(OAuth2Error.INVALID_SCOPE);
        }
        if (!areClaimsValid(authRequest.getOIDCClaims(), client.get())) {
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
        if (isRequestUri) {
            if (!client.get().getRequestUris().contains(authRequest.getRequestURI().toString())) {
                return Optional.of(
                        new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Invalid request URI"));
            }
            return invokeAuthorizeRequestUriLambda(authRequest, client.get());
        }
        List<String> authRequestVtr = authRequest.getCustomParameter(VTR_PARAM);
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

    public Optional<ErrorObject> invokeAuthorizeRequestUriLambda(
            AuthenticationRequest authenticationRequest, ClientRegistry clientRegistry) {
        var lambdaArn = configurationService.getAuthorizeRequestLambdaArn();
        try {
            var invokeRequest =
                    new InvokeRequest()
                            .withFunctionName(lambdaArn)
                            .withQualifier(
                                    configurationService.getAuthorizeRequestLambdaQualifier())
                            .withPayload(
                                    new ObjectMapper()
                                            .writeValueAsString(
                                                    new RequestUriPayload(
                                                            clientRegistry, authenticationRequest)))
                            .withInvocationType(InvocationType.RequestResponse);
            LOG.info("About to invoke the AuthorizeRequestUriHandler");
            var invokeResult = awsLambda.invoke(invokeRequest);
            var ans = new String(invokeResult.getPayload().array(), StandardCharsets.UTF_8);
            var requestUriResponsePayload =
                    new ObjectMapper().readValue(ans, RequestUriResponsePayload.class);
            if (requestUriResponsePayload.isSuccessfulRequest()) {
                LOG.info("Received successful response from AuthorizeRequestUriHandler");
                return Optional.empty();
            } else {
                LOG.warn("Received unsuccessful response from AuthorizeRequestUriHandler");
                return Optional.of(ErrorObject.parse(requestUriResponsePayload.getErrorObject()));
            }
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public AuthenticationErrorResponse generateAuthenticationErrorResponse(
            URI redirectUri, State state, ResponseMode responseMode, ErrorObject errorObject) {
        return new AuthenticationErrorResponse(redirectUri, errorObject, state, responseMode);
    }

    public VectorOfTrust getEffectiveVectorOfTrust(AuthenticationRequest authenticationRequest) {
        return VectorOfTrust.parseFromAuthRequestAttribute(
                authenticationRequest.getCustomParameter(VTR_PARAM));
    }

    private boolean areScopesValid(List<String> scopes, ClientRegistry clientRegistry) {
        for (String scope : scopes) {
            if (ValidScopes.getAllValidScopes().stream().noneMatch((t) -> t.equals(scope))) {
                return false;
            }
        }
        return clientRegistry.getScopes().containsAll(scopes);
    }

    private boolean areClaimsValid(OIDCClaimsRequest claimsRequest, ClientRegistry clientRegistry) {
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
        if (!clientRegistry.getClaims().containsAll(claimNames)) {
            return false;
        }

        return true;
    }

    public String getExistingOrCreateNewPersistentSessionId(Map<String, String> headers) {
        return PersistentIdHelper.getExistingOrCreateNewPersistentSessionId(headers);
    }
}
