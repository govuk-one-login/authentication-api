package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.authentication.entity.MfaMethodCreateRequest;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.MfaMethodData;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.SmsMfaDetail;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.exceptions.InvalidPriorityIdentifierException;
import uk.gov.di.authentication.shared.helpers.ClientSessionIdHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoMfaMethodsService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.sharedtest.logging.CaptureLoggingExtension;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.services.DynamoMfaMethodsService.HARDCODED_SMS_MFA_ID;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.logging.LogEventMatcher.withMessageContaining;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsCreateHandlerTest {
    @RegisterExtension
    private final CaptureLoggingExtension logging =
            new CaptureLoggingExtension(MFAMethodsCreateHandler.class);

    private final Context context = mock(Context.class);
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final String SESSION_ID = "some-session-id";
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";
    private static final String TEST_PHONE_NUMBER = "07123123123";
    private static final String TEST_PUBLIC_SUBJECT = "test-public-subject";
    private static final String TEST_EMAIL = "test@test.com";
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final DynamoMfaMethodsService mfaMethodsService =
            mock(DynamoMfaMethodsService.class);
    private static final DynamoService dynamoService = mock(DynamoService.class);
    private static final UserProfile userProfile = mock(UserProfile.class);

    private MFAMethodsCreateHandler handler;

    @BeforeEach
    void setUp() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        handler =
                new MFAMethodsCreateHandler(configurationService, mfaMethodsService, dynamoService);
        when(configurationService.getAwsRegion()).thenReturn("eu-west-2");
    }

    @Test
    void shouldReturn200AndCreateMfaSmsMfaMethod() throws InvalidPriorityIdentifierException {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.of(userProfile));
        when(userProfile.getEmail()).thenReturn(TEST_EMAIL);
        when(mfaMethodsService.postMfaMethod(any(), any()))
                .thenReturn(
                        new MfaMethodData(
                                HARDCODED_SMS_MFA_ID,
                                PriorityIdentifier.BACKUP,
                                true,
                                new SmsMfaDetail(MFAMethodType.SMS, TEST_PHONE_NUMBER)));

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        MFAMethodType.SMS,
                        TEST_PHONE_NUMBER,
                        TEST_PUBLIC_SUBJECT);

        var result = handler.handleRequest(event, context);

        ArgumentCaptor<MfaMethodCreateRequest> requestCaptor =
                ArgumentCaptor.forClass(MfaMethodCreateRequest.class);

        verify(mfaMethodsService).postMfaMethod(eq(TEST_EMAIL), requestCaptor.capture());
        var capturedRequest = requestCaptor.getValue();

        assertEquals(
                new SmsMfaDetail(MFAMethodType.SMS, TEST_PHONE_NUMBER),
                capturedRequest.mfaMethod().method());
        assertEquals(PriorityIdentifier.BACKUP, capturedRequest.mfaMethod().priorityIdentifier());

        assertThat(result, hasStatus(200));
        var expectedResponse =
                format(
                        """
                {
                  "mfaIdentifier": "%s",
                  "priorityIdentifier": "BACKUP",
                  "methodVerified": true,
                  "method": {
                    "mfaMethodType": "SMS",
                    "phoneNumber": "%s"
                  }
                }
                """,
                        HARDCODED_SMS_MFA_ID, TEST_PHONE_NUMBER);
        var expectedResponseParsedToString =
                JsonParser.parseString(expectedResponse).getAsJsonObject().toString();
        assertEquals(expectedResponseParsedToString, result.getBody());
    }

    @Test
    void shouldReturn400IfRequestIsMadeInEnvWhereApiNotEnabled() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(false);

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        MFAMethodType.AUTH_APP,
                        TEST_PHONE_NUMBER,
                        TEST_PUBLIC_SUBJECT);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn400WhenPathParameterIsIncorrect() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.empty());

        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        MFAMethodType.AUTH_APP,
                        TEST_PHONE_NUMBER,
                        "incorrect-subject");
        event.setPathParameters(Map.of());

        when(dynamoService.getOptionalUserProfileFromPublicSubject(TEST_PUBLIC_SUBJECT))
                .thenReturn(Optional.empty());

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
        assertThat(
                logging.events(),
                hasItem(
                        withMessageContaining(
                                "Subject missing from request prevents request being handled.")));
    }

    @Test
    void shouldReturn400WhenJsonIsInvalid() {
        var event =
                generateApiGatewayEvent(
                        PriorityIdentifier.BACKUP,
                        MFAMethodType.AUTH_APP,
                        TEST_PHONE_NUMBER,
                        TEST_PUBLIC_SUBJECT);
        event.setBody("Invalid JSON");

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1001));
    }

    private APIGatewayProxyRequestEvent generateApiGatewayEvent(
            PriorityIdentifier priorityIdentifier,
            MFAMethodType mfaMethodType,
            String phoneNumber,
            String publicSubject) {
        var event = new APIGatewayProxyRequestEvent();

        event.setPathParameters(Map.of("publicSubjectId", publicSubject));
        event.setBody(
                format(
                        """
                                        { "mfaMethod": {
                                            "priorityIdentifier": "%s",
                                            "method": {
                                                "mfaMethodType": "%s",
                                                "phoneNumber": "%s" }
                                            }
                                        }
                                       """,
                        priorityIdentifier, mfaMethodType, phoneNumber));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));
        event.setRequestContext(proxyRequestContext);
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_ID,
                        ClientSessionIdHelper.SESSION_ID_HEADER_NAME,
                        SESSION_ID,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));

        return event;
    }
}
