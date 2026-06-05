package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.entity.StartPasskeyAssertionRequest;
import uk.gov.di.authentication.frontendapi.entity.passkeys.audit.PasskeyAuthenticationAuditExtension;
import uk.gov.di.authentication.frontendapi.services.webauthn.DefaultPasskeyJsonParser;
import uk.gov.di.authentication.frontendapi.services.webauthn.PasskeyAssertionService;
import uk.gov.di.authentication.frontendapi.services.webauthn.RelyingPartyProvider;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.helpers.IpAddressHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.lambda.BaseFrontendHandler;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PASSKEY_AUTHENTICATION_GENERATED;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EXTENSIONS_PASSKEY;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class StartPasskeyAssertionHandler extends BaseFrontendHandler<StartPasskeyAssertionRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(StartPasskeyAssertionHandler.class);
    private final AuditService auditService;
    private final PasskeyAssertionService passkeyAssertionService;

    public StartPasskeyAssertionHandler() {
        this(ConfigurationService.getInstance());
    }

    public StartPasskeyAssertionHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            PasskeyAssertionService passkeyAssertionService,
            AuditService auditService) {
        super(
                StartPasskeyAssertionRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.passkeyAssertionService = passkeyAssertionService;
        this.auditService = auditService;
    }

    public StartPasskeyAssertionHandler(ConfigurationService configurationService) {
        super(StartPasskeyAssertionRequest.class, configurationService);
        this.passkeyAssertionService =
                new PasskeyAssertionService(
                        RelyingPartyProvider.provide(configurationService),
                        new DefaultPasskeyJsonParser());
        this.auditService = new AuditService(configurationService);
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
            StartPasskeyAssertionRequest request,
            UserContext userContext) {
        LOG.info("StartPasskeyAssertionHandler called");
        var emailAddress = userContext.getAuthSession().getEmailAddress();
        if (emailAddress == null || emailAddress.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.EMAIL_ADDRESS_EMPTY);
        }
        var maybeUserProfile = authenticationService.getUserProfileByEmailMaybe(emailAddress);
        if (maybeUserProfile.isEmpty()) {
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.USER_NOT_FOUND);
        }
        var userProfile = maybeUserProfile.get();
        var publicSubjectId = userProfile.getPublicSubjectID();

        var assertionRequest = passkeyAssertionService.startAssertion(publicSubjectId);

        String credentialsJson;
        String assertionRequestJsonToStore;
        try {
            credentialsJson = assertionRequest.toCredentialsGetJson();
            assertionRequestJsonToStore = assertionRequest.toJson();
        } catch (JsonProcessingException e) {
            LOG.error("Error serializing assertion request", e);
            return generateApiGatewayProxyErrorResponse(
                    500, ErrorResponse.UNEXPECTED_INTERNAL_API_ERROR);
        }

        authSessionService.updateSession(
                userContext
                        .getAuthSession()
                        .withPasskeyAssertionRequest(assertionRequestJsonToStore));

        emitAuthPasskeyAuthenticationGeneratedAuditEvent(userContext, input, emailAddress);
        return generateApiGatewayProxyResponse(200, credentialsJson);
    }

    private void emitAuthPasskeyAuthenticationGeneratedAuditEvent(
            UserContext userContext, APIGatewayProxyRequestEvent input, String emailAddress) {
        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getAuthSession().getInternalCommonSubjectId(),
                        emailAddress,
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        var journeyTypePair = pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, JourneyType.SIGN_IN);
        // TODO work out how to derive this user verification value
        var passkeyUnrestrictedPair =
                pair(
                        AUDIT_EXTENSIONS_PASSKEY,
                        PasskeyAuthenticationAuditExtension.fromUserVerification("required"));

        auditService.submitAuditEvent(
                AUTH_PASSKEY_AUTHENTICATION_GENERATED,
                auditContext,
                journeyTypePair,
                passkeyUnrestrictedPair);
    }
}
