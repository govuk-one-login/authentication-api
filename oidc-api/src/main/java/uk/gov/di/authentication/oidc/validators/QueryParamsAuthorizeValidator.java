package uk.gov.di.authentication.oidc.validators;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.Identifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.services.IPVCapacityService;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ValidScopes;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.ClientRedirectUriValidationException;
import uk.gov.di.orchestration.shared.exceptions.InvalidResponseModeException;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

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
    public Optional<AuthRequestError> validate(AuthenticationRequest authRequest)
            throws InvalidResponseModeException {

        var clientId = authRequest.getClientID().toString();
        attachLogFieldToLogs(CLIENT_ID, clientId);
        ClientRegistry client = getClientFromDynamo(clientId);

        if (!client.getRedirectUrls().contains(authRequest.getRedirectionURI().toString())) {
            logErrorInProdElseWarn(
                    String.format(
                            "Invalid Redirect URI in request %s", authRequest.getRedirectionURI()));
            throw new ClientRedirectUriValidationException(
                    format(
                            "Invalid Redirect in request %s",
                            authRequest.getRedirectionURI().toString()));
        }
        var redirectURI = authRequest.getRedirectionURI();

        var responseMode = Optional.ofNullable(authRequest.getResponseMode());
        responseMode.ifPresent(mode -> validateResponseMode(mode.getValue()));

        if (authRequest.getState() == null) {
            logErrorInProdElseWarn("State is missing from authRequest");
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
            logErrorInProdElseWarn("Request URI is not supported");
            return Optional.of(
                    new AuthRequestError(
                            OAuth2Error.REQUEST_URI_NOT_SUPPORTED, redirectURI, state));
        }
        if (!authRequest.getResponseType().toString().equals(ResponseType.CODE.toString())) {
            logErrorInProdElseWarn(
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
        if (authRequest.getNonce() == null && !client.permitMissingNonce()) {
            logErrorInProdElseWarn("Nonce is missing from authRequest");
            return Optional.of(
                    new AuthRequestError(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "Request is missing nonce parameter"),
                            redirectURI,
                            state));
        }

        var codeChallenge =
                Optional.ofNullable(authRequest.getCodeChallenge())
                        .map(Identifier::getValue)
                        .orElse(null);
        var codeChallengeMethod =
                Optional.ofNullable(authRequest.getCodeChallengeMethod())
                        .map(Identifier::getValue)
                        .orElse(null);

        var codeChallengeError =
                validateCodeChallengeAndMethod(
                        codeChallenge, codeChallengeMethod, client.getPKCEEnforced());
        if (codeChallengeError.isPresent()) {
            return Optional.of(new AuthRequestError(codeChallengeError.get(), redirectURI, state));
        }

        List<String> authRequestVtr = authRequest.getCustomParameter(VTR_PARAM);
        try {
            var vtrList = VectorOfTrust.parseFromAuthRequestAttribute(authRequestVtr);
            var levelOfConfidenceValues = VectorOfTrust.getRequestedLevelsOfConfidence(vtrList);
            if (!client.getClientLoCs().containsAll(levelOfConfidenceValues)) {
                logErrorInProdElseWarn(
                        String.format(
                                "Level of confidence values have been requested which this client is not permitted to request. Level of confidence values in request: %s",
                                levelOfConfidenceValues));
                return Optional.of(
                        new AuthRequestError(
                                new ErrorObject(
                                        OAuth2Error.INVALID_REQUEST_CODE,
                                        "Request vtr is not permitted"),
                                redirectURI,
                                state));
            }
            if (vtrList.get(0).containsLevelOfConfidence()
                    && !ipvCapacityService.isIPVCapacityAvailable()
                    && !client.isTestClient()) {
                return Optional.of(
                        new AuthRequestError(
                                OAuth2Error.TEMPORARILY_UNAVAILABLE, redirectURI, state));
            }
        } catch (IllegalArgumentException e) {
            logErrorInProdElseWarn(
                    String.format(
                            "vtr in AuthRequest is not valid. vtr in request: %s. IllegalArgumentException: %s",
                            authRequestVtr, e));
            return Optional.of(
                    new AuthRequestError(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid"),
                            redirectURI,
                            state));
        }
        if (!client.getMaxAgeEnabled() && authRequest.getMaxAge() != -1) {
            LOG.warn(
                    "Max age present in auth request but not enabled for client. Client ID: {}",
                    client.getClientID());
        }
        if (authRequest.getMaxAge() < -1) {
            LOG.warn("Max age is negative in query params");
            return Optional.of(
                    new AuthRequestError(
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "Max age is negative in query params"),
                            redirectURI,
                            state));
        }

        var loginHint = Optional.ofNullable(authRequest.getLoginHint());
        if (loginHint.isPresent()) {
            LOG.info("login_hint attached to query params");
        }

        var channelOpt =
                Optional.ofNullable(authRequest.getCustomParameter("channel"))
                        .map(List::stream)
                        .flatMap(Stream::findFirst);
        if (channelOpt.isPresent()) {
            var channelError = validateChannel(channelOpt.get());
            if (channelError.isPresent()) {
                return Optional.of(new AuthRequestError(channelError.get(), redirectURI, state));
            }
        }

        return Optional.empty();
    }

    private boolean areScopesValid(List<String> scopes, ClientRegistry clientRegistry) {
        if (!ValidScopes.areScopesValid(scopes)) {
            logErrorInProdElseWarn(
                    String.format(
                            "Scopes have been requested which are not yet supported. Scopes in request: %s",
                            scopes));
            return false;
        }
        if (!clientRegistry.getScopes().containsAll(scopes)) {
            logErrorInProdElseWarn(
                    String.format(
                            "Scopes have been requested which this client is not supported to request. Scopes in request: %s",
                            scopes));
            return false;
        }
        return true;
    }
}
