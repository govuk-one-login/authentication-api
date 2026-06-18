package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionFailureReason;
import uk.gov.di.authentication.frontendapi.entity.FinishPasskeyAssertionRequest;
import uk.gov.di.authentication.frontendapi.services.webauthn.DefaultPasskeyJsonParser;
import uk.gov.di.authentication.frontendapi.services.webauthn.PasskeyAssertionService;
import uk.gov.di.authentication.frontendapi.services.webauthn.PasskeyJsonParser;
import uk.gov.di.authentication.frontendapi.services.webauthn.RelyingPartyProvider;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;
import uk.gov.di.authentication.userpermissions.UserActionsManager;
import uk.gov.di.authentication.userpermissions.entity.PermissionContext;

import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;

public class FinishPasskeyAssertionHandler
        extends BaseFrontendHandler<FinishPasskeyAssertionRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOG = LogManager.getLogger(FinishPasskeyAssertionHandler.class);
    private final PasskeyAssertionService passkeyAssertionService;
    private final UserActionsManager userActionsManager;
    private final StructuredAuditService structuredAuditService;
    private final PasskeyJsonParser passkeyJsonParser;

    public FinishPasskeyAssertionHandler() {
        this(ConfigurationService.getInstance());
    }

    public FinishPasskeyAssertionHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            PasskeyAssertionService passkeyAssertionService,
            UserActionsManager userActionsManager,
            StructuredAuditService structuredAuditService,
            PasskeyJsonParser passkeyJsonParser) {
        super(
                FinishPasskeyAssertionRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.passkeyAssertionService = passkeyAssertionService;
        this.userActionsManager = userActionsManager;
        this.structuredAuditService = structuredAuditService;
        this.passkeyJsonParser = passkeyJsonParser;
    }

    public FinishPasskeyAssertionHandler(ConfigurationService configurationService) {
        super(FinishPasskeyAssertionRequest.class, configurationService);
        this.passkeyAssertionService =
                new PasskeyAssertionService(RelyingPartyProvider.provide(configurationService));
        this.userActionsManager = new UserActionsManager(configurationService);
        this.structuredAuditService = new StructuredAuditService(configurationService);
        this.passkeyJsonParser = new DefaultPasskeyJsonParser();
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        return super.handleRequest(input, context);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequestWithUserContext(
            APIGatewayProxyRequestEvent input,
            Context context,
            FinishPasskeyAssertionRequest request,
            UserContext userContext) {

        LOG.info("FinishPasskeyAssertionHandler called");

        var requestContextResult = parseAssertionRequest(userContext, request.pkc());
        if (requestContextResult.isFailure()) {
            return requestContextResult.getFailure();
        }
        var requestContext = requestContextResult.getSuccess();

        return verifyPasskeyAssertion(requestContext)
                .flatMap(this::updatePasskeyRecord)
                .map(success -> reportCorrectPasskeyReceived(userContext))
                .fold(
                        failure -> {
                            reportIncorrectPasskeyReceived(userContext);
                            return switch (failure) {
                                case ASSERTION_FAILED_ERROR -> generateApiGatewayProxyErrorResponse(
                                        401, ErrorResponse.PASSKEY_ASSERTION_FAILED);
                            };
                        },
                        success -> generateApiGatewayProxyResponse(200, ""));
    }

    private record FinishAssertionRequestContext(
            AssertionRequest assertionRequest,
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                    publicKeyCredential) {}

    private Result<APIGatewayProxyResponseEvent, FinishAssertionRequestContext>
            parseAssertionRequest(UserContext userContext, String publicKeyCredentialJson) {
        AssertionRequest assertionRequest;
        try {
            assertionRequest =
                    passkeyJsonParser.parseAssertionRequest(
                            userContext.getAuthSession().getPasskeyAssertionRequest());
        } catch (JsonProcessingException e) {
            LOG.error("Error processing assertion {}", e.getMessage());
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(
                            500, ErrorResponse.UNEXPECTED_INTERNAL_API_ERROR));
        }

        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
                credential;
        try {
            credential = passkeyJsonParser.parsePublicKeyCredential(publicKeyCredentialJson);
        } catch (Exception e) {
            LOG.warn("Error parsing public key credentials json {}", e);
            return Result.failure(
                    generateApiGatewayProxyErrorResponse(
                            400, ErrorResponse.PASSKEY_ASSERTION_INVALID_PKC));
        }

        return Result.success(new FinishAssertionRequestContext(assertionRequest, credential));
    }

    private Result<FinishPasskeyAssertionFailureReason, AssertionResult> verifyPasskeyAssertion(
            FinishAssertionRequestContext requestContext) {
        return passkeyAssertionService.finishAssertion(
                requestContext.assertionRequest, requestContext.publicKeyCredential);
    }

    private Result<FinishPasskeyAssertionFailureReason, Void> updatePasskeyRecord(
            AssertionResult assertionResult) {
        // TODO - AUT-4938 - Update database with latest passkey values
        return Result.success(null);
    }

    private Void reportCorrectPasskeyReceived(UserContext userContext) {
        PermissionContext permissionContext =
                PermissionContext.builder()
                        .withAuthSessionItem(userContext.getAuthSession())
                        .build();
        userActionsManager.correctPasskeyReceived(null, permissionContext);

        return null;
    }

    private Void reportIncorrectPasskeyReceived(UserContext userContext) {
        PermissionContext permissionContext =
                PermissionContext.builder()
                        .withAuthSessionItem(userContext.getAuthSession())
                        .build();
        userActionsManager.incorrectPasskeyReceived(null, permissionContext);

        return null;
    }
}
