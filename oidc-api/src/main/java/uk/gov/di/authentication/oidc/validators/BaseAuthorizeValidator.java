package uk.gov.di.authentication.oidc.validators;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.oidc.entity.AuthRequestError;
import uk.gov.di.authentication.oidc.services.IPVCapacityService;
import uk.gov.di.orchestration.shared.entity.Channel;
import uk.gov.di.orchestration.shared.entity.ClientRegistry;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.ClientSignatureValidationException;
import uk.gov.di.orchestration.shared.exceptions.InvalidResponseModeException;
import uk.gov.di.orchestration.shared.exceptions.JwksException;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.DynamoClientService;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

public abstract class BaseAuthorizeValidator {

    protected static final String VTR_PARAM = "vtr";
    protected final ConfigurationService configurationService;
    protected final DynamoClientService dynamoClientService;
    protected final IPVCapacityService ipvCapacityService;
    protected static final Logger LOG = LogManager.getLogger(BaseAuthorizeValidator.class);

    protected BaseAuthorizeValidator(
            ConfigurationService configurationService,
            DynamoClientService dynamoClientService,
            IPVCapacityService ipvCapacityService) {
        this.configurationService = configurationService;
        this.dynamoClientService = dynamoClientService;
        this.ipvCapacityService = ipvCapacityService;
    }

    public abstract Optional<AuthRequestError> validate(AuthenticationRequest authRequest)
            throws ClientSignatureValidationException, JwksException;

    ClientRegistry getClientFromDynamo(String clientId) {
        var client = dynamoClientService.getClient(clientId).orElse(null);

        if (Objects.isNull(client)) {
            var errorMsg = "No Client found with given ClientID";
            LOG.warn(errorMsg);
            throw new RuntimeException(errorMsg);
        }
        return client;
    }

    protected void logErrorInProdElseWarn(String logMessage) {
        if (configurationService.getEnvironment().equals("production")) {
            LOG.error(logMessage);
        } else {
            LOG.warn(logMessage);
        }
    }

    protected boolean areClaimsValid(
            OIDCClaimsRequest claimsRequest, ClientRegistry clientRegistry) {
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
            logErrorInProdElseWarn(
                    String.format(
                            "Claims have been requested which are not yet supported. Claims in request: %s",
                            claimsRequest.toJSONString()));
            return false;
        }

        boolean hasUnsupportedClaims = !clientRegistry.getClaims().containsAll(claimNames);
        if (hasUnsupportedClaims) {
            logErrorInProdElseWarn(
                    String.format(
                            "Claims have been requested which this client is not supported to request. Claims in request: %s",
                            claimsRequest.toJSONString()));
            return false;
        }
        LOG.info("Claims are present AND valid in auth request");
        return true;
    }

    protected Optional<ErrorObject> validateCodeChallengeAndMethod(
            String codeChallenge, String codeChallengeMethod, boolean isPKCEEnforced) {
        if (codeChallenge == null) {
            if (isPKCEEnforced) {
                logErrorInProdElseWarn("PKCE is enforced but code_challenge is missing.");
                return Optional.of(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing code_challenge parameter, but PKCE is enforced."));
            }
            return Optional.empty();
        }

        if (codeChallenge.isBlank()) {
            logErrorInProdElseWarn("code_challenge is blank (empty or contains only white space).");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid value for code_challenge parameter."));
        }

        if (codeChallengeMethod == null) {
            logErrorInProdElseWarn(
                    "code_challenge_method is missing from authRequest, but is required as code_challenge is present.");
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Request is missing code_challenge_method parameter. code_challenge_method is required when code_challenge is present."));
        }

        var isValidCodeChallengeMethod =
                codeChallengeMethod.equals(CodeChallengeMethod.S256.getValue());

        if (!isValidCodeChallengeMethod) {
            logErrorInProdElseWarn(
                    String.format(
                            "Invalid value for code_challenge_method - only '%s' is supported. code_challenge_method value in request: %s",
                            CodeChallengeMethod.S256.getValue(), codeChallengeMethod));
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid value for code_challenge_method parameter."));
        }

        return Optional.empty();
    }

    protected void validateResponseMode(String responseMode) throws InvalidResponseModeException {
        if (!responseMode.equals(ResponseMode.QUERY.getValue())
                && !responseMode.equals(ResponseMode.FRAGMENT.getValue())) {
            var errorMessage =
                    String.format("Invalid response mode included in request: %s", responseMode);

            logErrorInProdElseWarn(errorMessage);
            throw new InvalidResponseModeException(errorMessage);
        }
    }

    protected Optional<ErrorObject> validateChannel(String channel) {
        if (!Channel.WEB.getValue().equals(channel)
                && !Channel.GENERIC_APP.getValue().equals(channel)) {
            var errorMessage = String.format("Invalid channel included in request: %s", channel);

            logErrorInProdElseWarn(errorMessage);
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Invalid value for channel parameter."));
        }
        return Optional.empty();
    }
}
