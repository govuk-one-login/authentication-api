package uk.gov.di.authentication.external.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.id.Audience;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.external.exceptions.AuthCodeStoreRetreivalException;
import uk.gov.di.authentication.external.services.TokenService;
import uk.gov.di.authentication.external.validators.TokenRequestValidator;
import uk.gov.di.authentication.shared.entity.AuthCodeStore;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.TokenAuthInvalidException;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.RequestBodyHelper;
import uk.gov.di.authentication.shared.services.AccessTokenService;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAuthCodeService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SystemService;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static uk.gov.di.authentication.external.domain.AuthExternalApiAuditableEvent.AUTH_TOKEN_SENT_TO_ORCHESTRATION;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachTraceId;

public class TokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(TokenHandler.class);
    private final ConfigurationService configurationService;
    private final DynamoAuthCodeService authorisationCodeService;
    private final AccessTokenService accessTokenStoreService;
    private final TokenService tokenUtilityService;
    private final TokenRequestValidator tokenRequestValidator;
    private final AuditService auditService;
    private final DynamoService dynamoService;

    public TokenHandler(
            ConfigurationService configurationService,
            DynamoAuthCodeService authorisationCodeService,
            AccessTokenService accessTokenService,
            TokenService tokenUtilityService,
            TokenRequestValidator tokenRequestValidator,
            AuditService auditService,
            DynamoService dynamoService) {
        this.configurationService = configurationService;
        this.authorisationCodeService = authorisationCodeService;
        this.accessTokenStoreService = accessTokenService;
        this.tokenUtilityService = tokenUtilityService;
        this.tokenRequestValidator = tokenRequestValidator;
        this.auditService = auditService;
        this.dynamoService = dynamoService;
    }

    public TokenHandler() {
        this(ConfigurationService.getInstance());
        this.configurationService.setSystemService(new SystemService());
    }

    public TokenHandler(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.authorisationCodeService = new DynamoAuthCodeService(configurationService);
        this.accessTokenStoreService = new AccessTokenService(configurationService);
        this.tokenUtilityService = new TokenService();

        String orchestratorCallbackRedirectUri =
                configurationService.getAuthenticationAuthCallbackURI().toString();
        String orchestratorClientId = configurationService.getOrchestrationClientId();
        this.tokenRequestValidator =
                new TokenRequestValidator(orchestratorCallbackRedirectUri, orchestratorClientId);
        this.auditService = new AuditService(configurationService);
        this.dynamoService = new DynamoService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            return segmentedFunctionCall(
                    "auth-external-api::" + getClass().getSimpleName(),
                    () -> tokenRequestHandler(input));
        } catch (Exception e) {
            LOG.error("Unexpected exception: {}", e.getMessage());
            return generateApiGatewayProxyResponse(500, "server_error");
        }
    }

    public APIGatewayProxyResponseEvent tokenRequestHandler(APIGatewayProxyRequestEvent input) {
        attachTraceId();
        LOG.info("Request received to the TokenHandler");

        Map<String, String> requestBody = RequestBodyHelper.parseRequestBody(input.getBody());
        Optional<ErrorObject> invalidRequestParamError =
                tokenRequestValidator.validatePlaintextParams(requestBody);

        if (invalidRequestParamError.isPresent()) {
            LOG.warn(
                    "Invalid Token Request. ErrorCode: {}. ErrorDescription: {}",
                    invalidRequestParamError.get().getCode(),
                    invalidRequestParamError.get().getDescription());
            return generateApiGatewayProxyResponse(
                    400, invalidRequestParamError.get().toJSONObject().toJSONString());
        }

        try {
            var authenticationBackendURI = configurationService.getAuthenticationBackendURI();
            var authExternalApiTokenEndpoint =
                    buildURI(authenticationBackendURI.toString(), "token");

            var orchestrationBackendURI = configurationService.getOrchestrationBackendURI();
            var orchAuthExternalApiTokenEndpoint =
                    buildURI(orchestrationBackendURI.toString(), "token");

            var expectedAudience =
                    Set.of(
                            new Audience(authExternalApiTokenEndpoint),
                            new Audience(orchAuthExternalApiTokenEndpoint));
            var validPublicKeys =
                    configurationService.getOrchestrationToAuthenticationSigningPublicKeys();
            tokenRequestValidator.validatePrivateKeyJwtClientAuth(
                    input.getBody(), expectedAudience, validPublicKeys);

            String suppliedAuthCode = requestBody.get("code");

            AuthCodeStore authCodeStore =
                    authorisationCodeService
                            .getAuthCodeStore(suppliedAuthCode)
                            .orElseThrow(
                                    () -> {
                                        String errorMessage =
                                                String.format(
                                                        "No auth code store found for %s",
                                                        suppliedAuthCode);
                                        LOG.warn(errorMessage);
                                        return new AuthCodeStoreRetreivalException(
                                                errorMessage, OAuth2Error.INVALID_REQUEST);
                                    });

            if (!isCodeStoreValid(authCodeStore)) {
                var tokenErrorResponse =
                        tokenUtilityService.generateTokenErrorResponse(OAuth2Error.INVALID_REQUEST);
                return generateApiGatewayProxyResponse(
                        tokenErrorResponse.getStatusCode(), tokenErrorResponse.getContent());
            }

            LOG.info(
                    "Auth code has been found and validated. Generating bearer token and sending response");
            AccessTokenResponse tokenResponse =
                    tokenUtilityService.generateNewBearerTokenAndTokenResponse();

            accessTokenStoreService.addAccessTokenStore(
                    tokenResponse.getTokens().getAccessToken().getValue(),
                    authCodeStore.getSubjectID(),
                    authCodeStore.getClaims(),
                    authCodeStore.getIsNewAccount(),
                    authCodeStore.getSectorIdentifier(),
                    authCodeStore.getPasswordResetTime());

            authorisationCodeService.updateHasBeenUsed(authCodeStore.getAuthCode(), true);

            String subjectID = authCodeStore.getSubjectID();
            UserProfile userProfile = dynamoService.getUserProfileFromSubject(subjectID);
            String internalPairwiseId =
                    userProfile.getSalt() == null
                            ? AuditService.UNKNOWN
                            : ClientSubjectHelper.calculatePairwiseIdentifier(
                                    subjectID,
                                    URI.create(configurationService.getInternalSectorUri()),
                                    SdkBytes.fromByteBuffer(userProfile.getSalt()).asByteArray());

            var auditContext =
                    AuditContext.emptyAuditContext()
                            .withClientId(
                                    Optional.ofNullable(requestBody.get("client_id"))
                                            .orElse(AuditService.UNKNOWN))
                            .withSubjectId(
                                    Optional.ofNullable(internalPairwiseId)
                                            .orElse(AuditService.UNKNOWN))
                            .withClientSessionId(authCodeStore.getJourneyID());

            auditService.submitAuditEvent(AUTH_TOKEN_SENT_TO_ORCHESTRATION, auditContext);

            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            return generateApiGatewayProxyResponse(
                    200, tokenResponse.toJSONObject().toJSONString(), headers, null);

        } catch (TokenAuthInvalidException e) {
            LOG.warn("Unable to validate token auth method", e);
            var tokenErrorResponse =
                    tokenUtilityService.generateTokenErrorResponse(e.getErrorObject());
            return generateApiGatewayProxyResponse(
                    tokenErrorResponse.getStatusCode(), tokenErrorResponse.getContent());
        } catch (AuthCodeStoreRetreivalException e) {
            var tokenErrorResponse =
                    tokenUtilityService.generateTokenErrorResponse(e.getOAuth2Error());
            return generateApiGatewayProxyResponse(
                    tokenErrorResponse.getStatusCode(), tokenErrorResponse.getContent());
        }
    }

    private boolean isCodeStoreValid(AuthCodeStore authCodeStore) {
        if (authCodeStore.isHasBeenUsed()) {
            LOG.warn("Auth code already used");
            return false;
        }
        if (authCodeStore.getTimeToExist() < NowHelper.now().toInstant().getEpochSecond()) {
            LOG.error(
                    "Auth code expired - this should not have been returned from the database service");
            return false;
        }
        return true;
    }
}
