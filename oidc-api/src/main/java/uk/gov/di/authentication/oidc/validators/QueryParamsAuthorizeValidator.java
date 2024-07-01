package uk.gov.di.authentication.oidc.validators;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.services.IPVCapacityService;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.LevelOfConfidence;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.entity.ValidScopes;
import uk.gov.di.orchestration.shared.entity.VtrList;
import uk.gov.di.orchestration.shared.exceptions.ClientRegistryValidationException;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;

import java.util.List;
import java.util.Optional;

import static java.lang.String.format;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class QueryParamsAuthorizeValidator extends BaseAuthorizeValidator {

    public QueryParamsAuthorizeValidator(
            ConfigurationService configurationService,
            DynamoClientService dynamoClientService,
            IPVCapacityService ipvCapacityService) {
        super(configurationService, dynamoClientService, ipvCapacityService);
    }

    public QueryParamsAuthorizeValidator(ConfigurationService configurationService) {
        this(
                configurationService,
                new DynamoClientService(configurationService),
                new IPVCapacityService(configurationService));
    }

    @Override
    public Optional<AuthRequestError> validate(AuthenticationRequest authRequest) {

        var clientId = authRequest.getClientID().toString();
        attachLogFieldToLogs(CLIENT_ID, clientId);
        ClientRegistry client = getClientFromDynamo(clientId);

        if (!client.getRedirectUrls().contains(authRequest.getRedirectionURI().toString())) {
            LOG.warn("Invalid Redirect URI in request {}", authRequest.getRedirectionURI());
            throw new ClientRegistryValidationException(
                    format(
                            "Invalid Redirect in request %s",
                            authRequest.getRedirectionURI().toString()));
        }
        var redirectURI = authRequest.getRedirectionURI();

        if (authRequest.getState() == null) {
            LOG.error("State is missing from authRequest");
            return Optional.of(
                    new AuthRequestError(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "Request is missing state parameter"),
                            redirectURI,
                            null));
        }
        var state = authRequest.getState();

        if (authRequest.getRequestURI() != null) {
            LOG.error("Request URI is not supported");
            return Optional.of(
                    new AuthRequestError(
                            OAuth2Error.REQUEST_URI_NOT_SUPPORTED, redirectURI, state));
        }
        if (!authRequest.getResponseType().toString().equals(ResponseType.CODE.toString())) {
            LOG.error(
                    "Unsupported responseType included in request. Expected responseType of code");
            return Optional.of(
                    new AuthRequestError(
                            OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, redirectURI, state));
        }
        if (!areScopesValid(authRequest.getScope().toStringList(), client)) {
            return Optional.of(new AuthRequestError(OAuth2Error.INVALID_SCOPE, redirectURI, state));
        }
        if (!areClaimsValid(authRequest.getOIDCClaims(), client)) {
            return Optional.of(
                    new AuthRequestError(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "Request contains invalid claims"),
                            redirectURI,
                            state));
        }
        if (authRequest.getNonce() == null) {
            LOG.error("Nonce is missing from authRequest");
            return Optional.of(
                    new AuthRequestError(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "Request is missing nonce parameter"),
                            redirectURI,
                            state));
        }
        List<String> authRequestVtr = authRequest.getCustomParameter(VTR_PARAM);
        try {
            var vtrList = VtrList.parseFromAuthRequestAttribute(authRequestVtr);
            var levelOfConfidenceValues = vtrList.getLevelsOfConfidence();
            if (!client.getClientLoCs()
                    .containsAll(
                            levelOfConfidenceValues.stream()
                                    .map(LevelOfConfidence::getValue)
                                    .toList())) {
                LOG.error(
                        "Level of confidence values have been requested which this client is not permitted to request. Level of confidence values in request: {}",
                        levelOfConfidenceValues);
                return Optional.of(
                        new AuthRequestError(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request vtr is not permitted"),
                                redirectURI,
                                state));
            }
            if (vtrList.identityRequired()
                    && !ipvCapacityService.isIPVCapacityAvailable()
                    && !client.isTestClient()) {
                return Optional.of(
                        new AuthRequestError(
                                OAuth2Error.TEMPORARILY_UNAVAILABLE, redirectURI, state));
            }
        } catch (IllegalArgumentException e) {
            LOG.error(
                    "vtr in AuthRequest is not valid. vtr in request: {}. IllegalArgumentException: {}",
                    authRequestVtr,
                    e);
            return Optional.of(
                    new AuthRequestError(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid"),
                            redirectURI,
                            state));
        }
        return Optional.empty();
    }

    private boolean areScopesValid(List<String> scopes, ClientRegistry clientRegistry) {
        for (String scope : scopes) {
            if (ValidScopes.getAllValidScopes().stream().noneMatch(t -> t.equals(scope))) {
                LOG.error(
                        "Scopes have been requested which are not yet supported. Scopes in request: {}",
                        scopes);
                return false;
            }
        }
        if (!clientRegistry.getScopes().containsAll(scopes)) {
            LOG.error(
                    "Scopes have been requested which this client is not supported to request. Scopes in request: {}",
                    scopes);
            return false;
        }
        return true;
    }

    private boolean areClaimsValid(OIDCClaimsRequest claimsRequest, ClientRegistry clientRegistry) {
        if (claimsRequest == null || claimsRequest.getUserInfoClaimsRequest() == null) {
            LOG.info("No claims present in auth request");
            return true;
        }
        List<String> claimNames =
                claimsRequest.getUserInfoClaimsRequest().getEntries().stream()
                        .map(ClaimsSetRequest.Entry::getClaimName)
                        .toList();

        boolean containsUnsupportedClaims =
                claimNames.stream()
                        .anyMatch(
                                claim ->
                                        ValidClaims.getAllValidClaims().stream()
                                                .noneMatch(t -> t.equals(claim)));
        if (containsUnsupportedClaims) {
            LOG.error(
                    () ->
                            "Claims have been requested which are not yet supported. Claims in request: "
                                    + claimsRequest.toJSONString());
            return false;
        }

        boolean hasUnsupportedClaims = !clientRegistry.getClaims().containsAll(claimNames);
        if (hasUnsupportedClaims) {
            LOG.error(
                    () ->
                            "Claims have been requested which this client is not supported to request. Claims in request: {}"
                                    + claimsRequest.toJSONString());
            return false;
        }
        LOG.info("Claims are present AND valid in auth request");
        return true;
    }
}
