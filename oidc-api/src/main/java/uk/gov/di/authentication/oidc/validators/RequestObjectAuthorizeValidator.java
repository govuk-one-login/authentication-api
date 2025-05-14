package uk.gov.di.authentication.oidc.validators;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.langtag.LangTagUtils;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.services.IPVCapacityService;
import uk.gov.di.orchestration.shared.api.OidcAPI;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ClientType;
import uk.gov.di.orchestration.shared.entity.ValidScopes;
import uk.gov.di.orchestration.shared.entity.VectorOfTrust;
import uk.gov.di.orchestration.shared.exceptions.ClientRedirectUriValidationException;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.exceptions.JwksException;
import uk.gov.di.orchestration.shared.serialization.Json;
import uk.gov.di.orchestration.shared.services.ClientSignatureValidationService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;
import uk.gov.di.orchestration.shared.services.SerializationService;

import java.net.URI;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.ResponseType.CODE;
import static java.lang.String.format;
import static java.util.Collections.emptyList;
import static uk.gov.di.authentication.oidc.helpers.RequestObjectToAuthRequestHelper.parseOidcClaims;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.orchestration.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class RequestObjectAuthorizeValidator extends BaseAuthorizeValidator {

    private static final Json objectMapper = SerializationService.getInstance();

    private final OidcAPI oidcApi;
    private final ClientSignatureValidationService clientSignatureValidationService;

    public RequestObjectAuthorizeValidator(
            ConfigurationService configurationService,
            DynamoClientService dynamoClientService,
            IPVCapacityService ipvCapacityService,
            OidcAPI oidcApi,
            ClientSignatureValidationService clientSignatureValidationService) {
        super(configurationService, dynamoClientService, ipvCapacityService);
        this.clientSignatureValidationService = clientSignatureValidationService;
        this.oidcApi = oidcApi;
    }

    public RequestObjectAuthorizeValidator(ConfigurationService configurationService) {
        super(
                configurationService,
                new DynamoClientService(configurationService),
                new IPVCapacityService(configurationService));
        this.oidcApi = new OidcAPI(configurationService);
        this.clientSignatureValidationService =
                new ClientSignatureValidationService(configurationService);
    }

    @Override
    public Optional<AuthRequestError> validate(AuthenticationRequest authRequest)
            throws ClientSignatureValidationException, JwksException {

        var clientId = authRequest.getClientID().toString();
        attachLogFieldToLogs(CLIENT_ID, clientId);
        ClientRegistry client = getClientFromDynamo(clientId);

        var signedJWT = (SignedJWT) authRequest.getRequestObject();
        clientSignatureValidationService.validate(signedJWT, client);

        try {
            var jwtClaimsSet = signedJWT.getJWTClaimsSet();

            if (jwtClaimsSet.getStringClaim("redirect_uri") == null
                    || !client.getRedirectUrls()
                            .contains(jwtClaimsSet.getStringClaim("redirect_uri"))) {
                logErrorInProdElseWarn(
                        String.format(
                                "Invalid Redirect URI in request %s",
                                jwtClaimsSet.getStringClaim("redirect_uri")));
                throw new ClientRedirectUriValidationException(
                        format(
                                "Invalid Redirect in request %s",
                                jwtClaimsSet.getStringClaim("redirect_uri")));
            }

            var redirectURI = URI.create((String) jwtClaimsSet.getClaim("redirect_uri"));

            var responseMode = jwtClaimsSet.getStringClaim("response_mode");

            if (Objects.nonNull(responseMode)) {
                validateResponseMode(responseMode);
            }

            if (Objects.isNull(jwtClaimsSet.getClaim("state"))) {
                logErrorInProdElseWarn("State is missing from authRequest");
                return errorResponse(
                        redirectURI,
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing state parameter"),
                        null);
            }

            State state = new State(jwtClaimsSet.getStringClaim("state"));

            if (Arrays.stream(ClientType.values())
                    .noneMatch(type -> type.getValue().equals(client.getClientType()))) {
                logErrorInProdElseWarn(
                        String.format(
                                "ClientType value of %s is not recognised",
                                client.getClientType()));
                return errorResponse(redirectURI, OAuth2Error.UNAUTHORIZED_CLIENT, state);
            }

            if (!CODE.toString().equals(authRequest.getResponseType().toString())) {
                logErrorInProdElseWarn(
                        "Unsupported responseType included in request. Expected responseType of code");
                return errorResponse(redirectURI, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, state);
            }

            if (requestContainsInvalidScopes(authRequest.getScope(), client)) {
                logErrorInProdElseWarn(
                        String.format(
                                "Invalid scopes in authRequest. Scopes in request: %s",
                                authRequest.getScope().toStringList()));
                return errorResponse(redirectURI, OAuth2Error.INVALID_SCOPE, state);
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("client_id"))
                    || !jwtClaimsSet
                            .getClaim("client_id")
                            .toString()
                            .equals(authRequest.getClientID().getValue())) {
                return errorResponse(redirectURI, OAuth2Error.UNAUTHORIZED_CLIENT, state);
            }
            if (Objects.nonNull(jwtClaimsSet.getClaim("request"))
                    || Objects.nonNull(jwtClaimsSet.getClaim("request_uri"))) {
                logErrorInProdElseWarn(
                        "request or request_uri claim should not be included in request JWT");
                return errorResponse(redirectURI, OAuth2Error.INVALID_REQUEST, state);
            }
            if (Objects.isNull(jwtClaimsSet.getAudience())
                    || !jwtClaimsSet.getAudience().contains(oidcApi.authorizeURI().toString())) {
                logErrorInProdElseWarn("Invalid or missing audience");
                return errorResponse(redirectURI, OAuth2Error.ACCESS_DENIED, state);
            }
            if (Objects.isNull(jwtClaimsSet.getIssuer())
                    || !jwtClaimsSet.getIssuer().equals(client.getClientID())) {
                logErrorInProdElseWarn("Invalid or missing issuer");
                return errorResponse(redirectURI, OAuth2Error.UNAUTHORIZED_CLIENT, state);
            }

            if (!CODE.toString().equals(jwtClaimsSet.getClaim("response_type"))) {
                logErrorInProdElseWarn(
                        "Unsupported responseType included in request JWT. Expected responseType of code");
                return errorResponse(redirectURI, OAuth2Error.UNSUPPORTED_RESPONSE_TYPE, state);
            }
            if (Objects.isNull(jwtClaimsSet.getClaim("scope"))
                    || requestContainsInvalidScopes(
                            Scope.parse(jwtClaimsSet.getClaim("scope").toString()), client)) {
                logErrorInProdElseWarn("Invalid scopes in request JWT");
                return errorResponse(redirectURI, OAuth2Error.INVALID_SCOPE, state);
            }

            if (Objects.nonNull((jwtClaimsSet.getClaim("claims")))
                    && !areClaimsValid(parseOidcClaims(jwtClaimsSet), client)) {
                logErrorInProdElseWarn("Invalid claims in request object");
                return errorResponse(
                        redirectURI,
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request contains invalid claims"),
                        state);
            }

            if (Objects.isNull(jwtClaimsSet.getClaim("nonce")) && !client.permitMissingNonce()) {
                logErrorInProdElseWarn("Nonce is missing from authRequest");
                return errorResponse(
                        redirectURI,
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing nonce parameter"),
                        state);
            }

            if (configurationService.isPkceEnabled()) {
                var codeChallenge = jwtClaimsSet.getStringClaim("code_challenge");
                var codeChallengeMethod = jwtClaimsSet.getStringClaim("code_challenge_method");

                var codeChallengeError =
                        validateCodeChallengeAndMethod(
                                codeChallenge, codeChallengeMethod, client.getPKCEEnforced());
                if (codeChallengeError.isPresent()) {
                    return errorResponse(redirectURI, codeChallengeError.get(), state);
                }
            }

            var vtrError = validateVtr(jwtClaimsSet, client);
            if (vtrError.isPresent()) {
                return errorResponse(redirectURI, vtrError.get(), state);
            }
            if (Objects.nonNull(jwtClaimsSet.getClaim("ui_locales"))) {
                try {
                    String uiLocales = (String) jwtClaimsSet.getClaim("ui_locales");
                    LangTagUtils.parseLangTagList(uiLocales.split(" "));
                } catch (ClassCastException | LangTagException e) {
                    logErrorInProdElseWarn(
                            String.format("ui_locales parameter is invalid: %s", e.getMessage()));
                    return errorResponse(
                            redirectURI,
                            new ErrorObject(
                                    OAuth2Error.INVALID_REQUEST_CODE,
                                    "ui_locales parameter is invalid"),
                            state);
                }
            }

            var maxAgeError = validateMaxAge(jwtClaimsSet, client);

            if (maxAgeError.isPresent()) {
                return errorResponse(redirectURI, maxAgeError.get(), state);
            }

            var loginHint = Optional.ofNullable(jwtClaimsSet.getStringClaim("login_hint"));
            loginHint.ifPresent(
                    hint ->
                            LOG.info(
                                    "login_hint present in request object, length: {}",
                                    hint.length()));

            LOG.info("RequestObject has passed initial validation");
            return Optional.empty();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean requestContainsInvalidScopes(Scope scopes, ClientRegistry clientRegistry) {

        for (String scope : scopes.toStringList()) {
            if (!ValidScopes.getAllValidScopes().contains(scope)) {
                return true;
            }

            if (!clientRegistry.getScopes().contains(scope)) {
                return true;
            }
        }

        return false;
    }

    private Optional<ErrorObject> validateVtr(JWTClaimsSet jwtClaimsSet, ClientRegistry client) {
        List<String> authRequestVtr = new ArrayList<>();
        try {
            authRequestVtr = getRequestObjectVtrAsList(jwtClaimsSet);
            var vtrList = VectorOfTrust.parseFromAuthRequestAttribute(authRequestVtr);
            var levelOfConfidenceValues = VectorOfTrust.getRequestedLevelsOfConfidence(vtrList);
            if (!client.getClientLoCs().containsAll(levelOfConfidenceValues)) {
                logErrorInProdElseWarn(
                        String.format(
                                "Level of confidence values have been requested which this client is not permitted to request. Level of confidence values in request: %s",
                                levelOfConfidenceValues));
                return Optional.of(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE, "Request vtr is not permitted"));
            }
            if (vtrList.get(0).containsLevelOfConfidence()
                    && !ipvCapacityService.isIPVCapacityAvailable()) {
                return Optional.of(OAuth2Error.TEMPORARILY_UNAVAILABLE);
            }
        } catch (IllegalArgumentException e) {
            logErrorInProdElseWarn(
                    String.format(
                            "vtr in AuthRequest is not valid. vtr in request: %s. IllegalArgumentException: %s",
                            authRequestVtr, e));
            return Optional.of(
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid"));
        } catch (ParseException | Json.JsonException e) {
            logErrorInProdElseWarn(
                    String.format("Parse exception thrown when validating vtr: %s", e));
            return Optional.of(
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Request vtr not valid"));
        }
        return Optional.empty();
    }

    private Optional<ErrorObject> validateMaxAge(JWTClaimsSet jwtClaimsSet, ClientRegistry client)
            throws ParseException {
        if (Objects.isNull(jwtClaimsSet.getClaim("max_age"))) {
            return Optional.empty();
        }

        if (!client.getMaxAgeEnabled()) {
            LOG.warn(
                    "Max age present in request object but not enabled for client. Client ID: {}",
                    client.getClientID());
        }

        try {
            var maxAgeAsInt = jwtClaimsSet.getIntegerClaim("max_age");
            if (maxAgeAsInt < 0) {
                LOG.warn("Max age is negative in request object");
                return Optional.of(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Max age is negative in request object"));
            } else return Optional.empty();
        } catch (ParseException e) {
            return validateStringMaxAge(jwtClaimsSet);
        }
    }

    private Optional<ErrorObject> validateStringMaxAge(JWTClaimsSet jwtClaimsSet) {
        try {
            var maxAgeAsString = jwtClaimsSet.getStringClaim("max_age");
            if (Integer.parseInt(maxAgeAsString) < 0) {
                LOG.warn("Max age is negative in request object");
                return Optional.of(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Max age is negative in request object"));
            }
        } catch (ParseException | NumberFormatException e) {
            LOG.warn("Max age could not be parsed to an integer");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Max age could not be parsed to an integer"));
        }
        return Optional.empty();
    }

    private List<String> getRequestObjectVtrAsList(JWTClaimsSet jwtClaimsSet)
            throws ParseException, Json.JsonException {
        var vtrClaim = jwtClaimsSet.getClaim("vtr");
        if (vtrClaim == null) {
            return emptyList();
        } else if (vtrClaim instanceof String vtr) {
            return List.of(vtr);
        } else if (vtrClaim instanceof List<?> vtrList
                && vtrList.stream().allMatch(String.class::isInstance)) {
            return List.of(
                    objectMapper.writeValueAsString(jwtClaimsSet.getStringArrayClaim("vtr")));
        }

        throw new ParseException("vtr is in an invalid format. Could not be parsed.", 0);
    }

    private static Optional<AuthRequestError> errorResponse(
            URI uri, ErrorObject error, State state) {
        return Optional.of(new AuthRequestError(error, uri, state));
    }
}
