package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import uk.gov.di.accountmanagement.entity.NotificationType;
import uk.gov.di.accountmanagement.entity.NotifyRequest;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.LocaleHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.SerializationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.services.mfa.MfaDeleteFailureReason;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.domain.AccountManagementAuditableEvent.AUTH_MFA_METHOD_DELETE_COMPLETED;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE;
import static uk.gov.di.authentication.shared.domain.AuditableEvent.AUDIT_EVENT_EXTENSIONS_MFA_TYPE;
import static uk.gov.di.authentication.shared.entity.JourneyType.ACCOUNT_MANAGEMENT;
import static uk.gov.di.authentication.shared.entity.PriorityIdentifier.DEFAULT;
import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.SMS;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsDeleteHandlerTest {

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final Context context = mock(Context.class);
    private static final String MFA_IDENTIFIER_TO_DELETE = "8e18b315-995e-434e-a236-4fbfb72d6ce0";
    private static final String TEST_PUBLIC_SUBJECT = new Subject().getValue();
    private static final String TEST_CLIENT = "test-client";
    private static final byte[] TEST_SALT = SaltHelper.generateNewSalt();
    private static final String TEST_EMAIL = "test@test.com";
    private static final String TEST_PHONE_NUMBER = "01234567890";

    private static final UserProfile userProfile =
            new UserProfile().withSubjectID(TEST_PUBLIC_SUBJECT).withEmail(TEST_EMAIL);
    private static final String TEST_INTERNAL_SUBJECT =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    TEST_PUBLIC_SUBJECT, "test.account.gov.uk", TEST_SALT);
    private final Json objectMapper = SerializationService.getInstance();

    private static final MFAMethodsService mfaMethodsService = mock(MFAMethodsService.class);
    private static final DynamoService dynamoService = mock(DynamoService.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final AuditService auditService = mock(AuditService.class);
    private static final MFAMethod SMS_MFA_METHOD =
            new MFAMethod()
                    .withPriority(DEFAULT.name())
                    .withDestination(TEST_PHONE_NUMBER)
                    .withMfaMethodType(SMS.getValue())
                    .withMethodVerified(true)
                    .withEnabled(true)
                    .withMfaIdentifier(MFA_IDENTIFIER_TO_DELETE);
    private static final MFAMethod AUTH_APP_MFA_METHOD =
            new MFAMethod()
                    .withPriority(DEFAULT.name())
                    .withMfaMethodType(MFAMethodType.AUTH_APP.getValue())
                    .withMethodVerified(true)
                    .withEnabled(true);

    private MFAMethodsDeleteHandler handler;

    @BeforeEach
    void setUp() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        handler =
                new MFAMethodsDeleteHandler(
                        configurationService,
                        mfaMethodsService,
                        dynamoService,
                        sqsClient,
                        auditService);
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(dynamoService.getOrGenerateSalt(userProfile)).thenReturn(TEST_SALT);
    }

    @Nested
    class SuccessfulRequest {
        @Test
        void shouldReturn204WhenFeatureFlagEnabled() throws Json.JsonException {
            when(mfaMethodsService.deleteMfaMethod(MFA_IDENTIFIER_TO_DELETE, userProfile))
                    .thenReturn(Result.success(SMS_MFA_METHOD));
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));

            var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

            var result = handler.handleRequest(event, context);
            assertEquals(204, result.getStatusCode());

            verify(sqsClient)
                    .send(
                            objectMapper.writeValueAsString(
                                    new NotifyRequest(
                                            TEST_EMAIL,
                                            NotificationType.BACKUP_METHOD_REMOVED,
                                            LocaleHelper.SupportedLanguage.EN)));

            ArgumentCaptor<AuditContext> auditContextCaptor =
                    ArgumentCaptor.forClass(AuditContext.class);

            verify(auditService)
                    .submitAuditEvent(
                            eq(AUTH_MFA_METHOD_DELETE_COMPLETED), auditContextCaptor.capture());

            AuditContext capturedContext = auditContextCaptor.getValue();

            assertEquals(SMS_MFA_METHOD.getDestination(), capturedContext.phoneNumber());

            assertTrue(
                    capturedContext
                            .getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_MFA_TYPE)
                            .isPresent());
            assertEquals(
                    SMS.name(),
                    capturedContext
                            .getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_MFA_TYPE)
                            .get()
                            .value());

            assertTrue(
                    capturedContext
                            .getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE)
                            .isPresent());
            assertEquals(
                    ACCOUNT_MANAGEMENT.name(),
                    capturedContext
                            .getMetadataItemByKey(AUDIT_EVENT_EXTENSIONS_JOURNEY_TYPE)
                            .get()
                            .value());
        }

        @Test
        void userDeletesBackupAuthApp() throws Json.JsonException {
            when(mfaMethodsService.deleteMfaMethod(MFA_IDENTIFIER_TO_DELETE, userProfile))
                    .thenReturn(Result.success(AUTH_APP_MFA_METHOD));
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));

            var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

            var result = handler.handleRequest(event, context);
            assertEquals(204, result.getStatusCode());

            verify(sqsClient)
                    .send(
                            objectMapper.writeValueAsString(
                                    new NotifyRequest(
                                            TEST_EMAIL,
                                            NotificationType.BACKUP_METHOD_REMOVED,
                                            LocaleHelper.SupportedLanguage.EN)));
        }
    }

    @Nested
    class FailedRequest {

        private static Stream<Arguments> failureReasonsToResponseCodes() {
            return Stream.of(
                    Arguments.of(
                            MfaDeleteFailureReason.CANNOT_DELETE_DEFAULT_METHOD,
                            409,
                            ErrorResponse.ERROR_1066),
                    Arguments.of(
                            MfaDeleteFailureReason.CANNOT_DELETE_MFA_METHOD_FOR_NON_MIGRATED_USER,
                            400,
                            ErrorResponse.ERROR_1067),
                    Arguments.of(
                            MfaDeleteFailureReason.MFA_METHOD_WITH_IDENTIFIER_DOES_NOT_EXIST,
                            404,
                            ErrorResponse.ERROR_1065));
        }

        @ParameterizedTest
        @MethodSource("failureReasonsToResponseCodes")
        void shouldReturnAppropriateResponseWhenMfaMethodsServiceIndicatesMethodCouldNotBeDeleted(
                MfaDeleteFailureReason failureReason,
                int expectedStatusCode,
                ErrorResponse expectedErrorResponse) {
            when(mfaMethodsService.deleteMfaMethod(MFA_IDENTIFIER_TO_DELETE, userProfile))
                    .thenReturn(Result.failure(failureReason));
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));

            var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

            var result = handler.handleRequest(event, context);
            assertEquals(expectedStatusCode, result.getStatusCode());
            assertThat(result, hasJsonBody(expectedErrorResponse));

            verifyNoInteractions(sqsClient);
        }

        @Test
        void shouldReturn400IfPublicSubjectIdNotIncludedInPath() {
            var eventWithoutPublicSubjectId =
                    new APIGatewayProxyRequestEvent()
                            .withPathParameters(
                                    (Map.of(
                                            "publicSubjectId",
                                            "",
                                            "mfaIdentifier",
                                            MFA_IDENTIFIER_TO_DELETE)))
                            .withHeaders(VALID_HEADERS);

            var result = handler.handleRequest(eventWithoutPublicSubjectId, context);

            assertThat(result, hasStatus(400));

            verifyNoInteractions(sqsClient);
        }

        @Test
        void shouldReturn400IfMfaIdentifierNotIncludedInPath() {
            var eventWithoutMfaIdentifier =
                    new APIGatewayProxyRequestEvent()
                            .withPathParameters(
                                    (Map.of(
                                            "publicSubjectId",
                                            TEST_PUBLIC_SUBJECT,
                                            "mfaIdentifier",
                                            "")))
                            .withHeaders(VALID_HEADERS);

            var result = handler.handleRequest(eventWithoutMfaIdentifier, context);

            assertThat(result, hasStatus(400));

            verifyNoInteractions(sqsClient);
        }

        @Test
        void shouldReturn400WhenFeatureFlagDisabled() {
            when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(false);

            var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);

            var result = handler.handleRequest(event, context);
            assertEquals(400, result.getStatusCode());

            verifyNoInteractions(sqsClient);
        }

        @Test
        void shouldReturn401WhenPrincipalIsInvalid() {
            var event = generateApiGatewayEvent("invalid-principal");
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.of(userProfile));

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(401));
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1079));

            verifyNoInteractions(sqsClient);
        }

        @Test
        void shouldReturn404WhenUserProfileIsNotFoundForPublicSubject() {
            var event = generateApiGatewayEvent(TEST_INTERNAL_SUBJECT);
            when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                    .thenReturn(Optional.empty());

            var result = handler.handleRequest(event, context);

            assertThat(result, hasStatus(404));
            assertThat(result, hasJsonBody(ErrorResponse.ERROR_1056));

            verifyNoInteractions(sqsClient);
        }
    }

    private static APIGatewayProxyRequestEvent generateApiGatewayEvent(String principal) {
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", principal);
        authorizerParams.put("clientId", TEST_CLIENT);
        proxyRequestContext.setAuthorizer(authorizerParams);
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));

        return new APIGatewayProxyRequestEvent()
                .withPathParameters(
                        (Map.of(
                                "publicSubjectId",
                                TEST_PUBLIC_SUBJECT,
                                "mfaIdentifier",
                                MFAMethodsDeleteHandlerTest.MFA_IDENTIFIER_TO_DELETE)))
                .withHeaders(VALID_HEADERS)
                .withRequestContext(proxyRequestContext);
    }
}
