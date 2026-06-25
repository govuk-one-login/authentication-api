package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserVerificationRequirement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.auditevents.services.StructuredAuditService;
import uk.gov.di.authentication.frontendapi.entity.StartPasskeyAssertionRequest;
import uk.gov.di.authentication.frontendapi.entity.passkeys.audit.PasskeyAuthenticationAuditExtension;
import uk.gov.di.authentication.frontendapi.entity.passkeys.audit.PasskeyAuthenticationAuditRestricted;
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
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Comparator;
import java.util.List;
import java.util.Map;

import static uk.gov.di.audit.AuditContext.auditContextFromUserContext;
import static uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent.AUTH_PASSKEY_AUTHENTICATION_GENERATED;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_PASSKEY;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetricDimensions.PASSKEY_AUTHENTICATION_GENERATION_FAILURE_REASON;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.PASSKEY_AUTHENTICATION_GENERATED;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.PASSKEY_AUTHENTICATION_GENERATION_FAILED;
import static uk.gov.di.authentication.shared.domain.CloudwatchMetrics.PASSKEY_AUTHENTICATION_REQUESTED;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyErrorResponse;
import static uk.gov.di.authentication.shared.helpers.ApiGatewayResponseHelper.generateApiGatewayProxyResponse;
import static uk.gov.di.authentication.shared.services.AuditService.MetadataPair.pair;

public class StartPasskeyAssertionHandler extends BaseFrontendHandler<StartPasskeyAssertionRequest>
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOG = LogManager.getLogger(StartPasskeyAssertionHandler.class);
    private final AuditService auditService;
    private final PasskeyAssertionService passkeyAssertionService;
    private final CloudwatchMetricsService cloudwatchMetricsService;

    public StartPasskeyAssertionHandler() {
        this(ConfigurationService.getInstance());
    }

    public StartPasskeyAssertionHandler(
            ConfigurationService configurationService,
            AuthenticationService authenticationService,
            AuthSessionService authSessionService,
            PasskeyAssertionService passkeyAssertionService,
            AuditService auditService,
            CloudwatchMetricsService cloudwatchMetricsService) {
        super(
                StartPasskeyAssertionRequest.class,
                configurationService,
                authenticationService,
                authSessionService);
        this.passkeyAssertionService = passkeyAssertionService;
        this.auditService = auditService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
    }

    public StartPasskeyAssertionHandler(ConfigurationService configurationService) {
        super(StartPasskeyAssertionRequest.class, configurationService);
        this.passkeyAssertionService =
                new PasskeyAssertionService(
                        RelyingPartyProvider.provide(configurationService),
                        new DefaultPasskeyJsonParser(),
                        new StructuredAuditService(configurationService));
        this.auditService = new AuditService(configurationService);
        this.cloudwatchMetricsService = new CloudwatchMetricsService(configurationService);
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

        incrementAuthenticationRequestedMetric();

        var emailAddress = userContext.getAuthSession().getEmailAddress();
        if (emailAddress == null || emailAddress.isEmpty()) {
            incrementAuthenticationGenerationFailedMetric("emailAddressNotFound");
            return generateApiGatewayProxyErrorResponse(400, ErrorResponse.EMAIL_ADDRESS_EMPTY);
        }
        var maybeUserProfile = authenticationService.getUserProfileByEmailMaybe(emailAddress);
        if (maybeUserProfile.isEmpty()) {
            incrementAuthenticationGenerationFailedMetric("userProfileNotFound");
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
            incrementAuthenticationGenerationFailedMetric("serialisationFailure");
            return generateApiGatewayProxyErrorResponse(
                    500, ErrorResponse.UNEXPECTED_INTERNAL_API_ERROR);
        }

        authSessionService.updateSession(
                userContext
                        .getAuthSession()
                        .withPasskeyAssertionRequest(assertionRequestJsonToStore));

        incrementAuthenticationGeneratedMetric();
        emitAuthPasskeyAuthenticationGeneratedAuditEvent(
                userContext, input, emailAddress, assertionRequest);
        return generateApiGatewayProxyResponse(200, credentialsJson);
    }

    private void emitAuthPasskeyAuthenticationGeneratedAuditEvent(
            UserContext userContext,
            APIGatewayProxyRequestEvent input,
            String emailAddress,
            AssertionRequest assertionRequest) {
        var auditContext =
                auditContextFromUserContext(
                        userContext,
                        userContext.getAuthSession().getInternalCommonSubjectId(),
                        emailAddress,
                        IpAddressHelper.extractIpAddress(input),
                        AuditService.UNKNOWN,
                        PersistentIdHelper.extractPersistentIdFromHeaders(input.getHeaders()));

        var journeyTypePair =
                pair(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE, JourneyType.SIGN_IN.getValue());

        var maybeUserVerification =
                assertionRequest
                        .getPublicKeyCredentialRequestOptions()
                        .getUserVerification()
                        .map(UserVerificationRequirement::getValue);
        var passkeyUnrestrictedPair =
                pair(
                        AUDIT_EVENT_EXTENSIONS_PASSKEY,
                        PasskeyAuthenticationAuditExtension.fromUserVerification(
                                maybeUserVerification.orElse(AuditService.UNKNOWN)));

        var allowedCredentials =
                assertionRequest
                        .getPublicKeyCredentialRequestOptions()
                        .getAllowCredentials()
                        .map(
                                allowCredentials ->
                                        allowCredentials.stream()
                                                .map(
                                                        StartPasskeyAssertionHandler
                                                                ::allowCredentialFrom)
                                                .sorted(
                                                        Comparator.comparing(
                                                                PasskeyAuthenticationAuditRestricted
                                                                                .PasskeyAllowedCredential
                                                                        ::passkeyCredentialId))
                                                .toList())
                        .orElse(List.of());
        var restrictedPasskeyPair =
                pair(
                        AUDIT_EVENT_EXTENSIONS_PASSKEY,
                        new PasskeyAuthenticationAuditRestricted(allowedCredentials),
                        true);

        auditService.submitAuditEvent(
                AUTH_PASSKEY_AUTHENTICATION_GENERATED,
                auditContext,
                journeyTypePair,
                passkeyUnrestrictedPair,
                restrictedPasskeyPair);
    }

    private static PasskeyAuthenticationAuditRestricted.PasskeyAllowedCredential
            allowCredentialFrom(PublicKeyCredentialDescriptor credentialDescriptor) {
        return new PasskeyAuthenticationAuditRestricted.PasskeyAllowedCredential(
                credentialDescriptor.getId().getBase64Url(),
                credentialDescriptor
                        .getTransports()
                        .map(set -> set.stream().map(AuthenticatorTransport::getId).toList())
                        .orElse(List.of()));
    }

    private void incrementAuthenticationRequestedMetric() {
        cloudwatchMetricsService.incrementCounter(
                PASSKEY_AUTHENTICATION_REQUESTED, metricDimensions());
    }

    private void incrementAuthenticationGenerationFailedMetric(String failureReason) {
        cloudwatchMetricsService.incrementCounter(
                PASSKEY_AUTHENTICATION_GENERATION_FAILED, metricDimensions(failureReason));
    }

    private void incrementAuthenticationGeneratedMetric() {
        cloudwatchMetricsService.incrementCounter(
                PASSKEY_AUTHENTICATION_GENERATED, metricDimensions());
    }

    private Map<String, String> metricDimensions() {
        return Map.of(ENVIRONMENT.getValue(), configurationService.getEnvironment());
    }

    private Map<String, String> metricDimensions(String failureReason) {
        return Map.ofEntries(
                Map.entry(ENVIRONMENT.getValue(), configurationService.getEnvironment()),
                Map.entry(
                        PASSKEY_AUTHENTICATION_GENERATION_FAILURE_REASON.getValue(),
                        failureReason));
    }
}
