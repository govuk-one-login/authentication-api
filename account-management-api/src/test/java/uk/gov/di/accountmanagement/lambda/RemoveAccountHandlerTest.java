package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.accountmanagement.entity.AccountDeletionReason;
import uk.gov.di.accountmanagement.exceptions.InvalidPrincipalException;
import uk.gov.di.accountmanagement.helpers.AuditHelper;
import uk.gov.di.accountmanagement.services.AccountDeletionService;
import uk.gov.di.accountmanagement.services.AwsSqsClient;
import uk.gov.di.accountmanagement.services.DynamoDeleteService;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.identityWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class RemoveAccountHandlerTest {

    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final Subject PUBLIC_SUBJECT = new Subject();
    private static final Subject INTERNAL_SUBJECT = new Subject();
    private static final String PERSISTENT_ID = "some-persistent-session-id";
    private static final byte[] SALT = SaltHelper.generateNewSalt();
    private final String expectedCommonSubject =
            ClientSubjectHelper.calculatePairwiseIdentifier(
                    INTERNAL_SUBJECT.getValue(), "test.account.gov.uk", SALT);
    private static final String TXMA_ENCODED_HEADER_VALUE = "txma-test-value";

    private RemoveAccountHandler handler;
    private final Context context = mock(Context.class);
    private final AwsSqsClient sqsClient = mock(AwsSqsClient.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final DynamoDeleteService dynamoDeleteService = mock(DynamoDeleteService.class);
    private final AccountDeletionService accountDeletionService =
            mock(AccountDeletionService.class);

    @BeforeEach
    public void setUp() {
        handler =
                new RemoveAccountHandler(
                        authenticationService,
                        sqsClient,
                        auditService,
                        configurationService,
                        dynamoDeleteService,
                        accountDeletionService);
        when(configurationService.getInternalSectorUri()).thenReturn("https://test.account.gov.uk");
        when(authenticationService.getOrGenerateSalt(any(UserProfile.class))).thenReturn(SALT);
    }

    @Test
    void shouldReturn204IfAccountRemovalIsSuccessfulAndPrincipalContainsInternalPairwiseSubjectId()
            throws Json.JsonException {
        var userProfile =
                new UserProfile()
                        .withPublicSubjectID(PUBLIC_SUBJECT.getValue())
                        .withSubjectID(INTERNAL_SUBJECT.getValue());
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        var event = generateApiGatewayEvent(expectedCommonSubject);
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(accountDeletionService)
                .removeAccount(
                        Optional.of(event),
                        userProfile,
                        Optional.of(TXMA_ENCODED_HEADER_VALUE),
                        AccountDeletionReason.USER_INITIATED);
    }

    @Test
    void shouldNotSendEncodedAuditDataIfHeaderNotPresent() throws Json.JsonException {
        var userProfile =
                new UserProfile()
                        .withPublicSubjectID(PUBLIC_SUBJECT.getValue())
                        .withSubjectID(INTERNAL_SUBJECT.getValue());
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));

        var event = generateApiGatewayEvent(expectedCommonSubject);
        event.setHeaders(Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID));
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(accountDeletionService)
                .removeAccount(
                        Optional.of(event),
                        userProfile,
                        Optional.empty(),
                        AccountDeletionReason.USER_INITIATED);
    }

    @Test
    void shouldThrowIfPrincipalIdIsInvalid() {
        var userProfile =
                new UserProfile()
                        .withPublicSubjectID(new Subject().getValue())
                        .withSubjectID(new Subject().getValue());
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(authenticationService.getOrGenerateSalt(userProfile))
                .thenReturn(SaltHelper.generateNewSalt());

        var event = generateApiGatewayEvent(PUBLIC_SUBJECT.getValue());

        var expectedException =
                assertThrows(
                        InvalidPrincipalException.class,
                        () -> handler.handleRequest(event, context),
                        "Expected to throw exception");

        assertThat(expectedException.getMessage(), equalTo("Invalid Principal in request"));
        verifyNoInteractions(sqsClient);
        verifyNoInteractions(auditService);
    }

    @Test
    void shouldReturn400IfUserAccountDoesNotExist() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());

        var event = generateApiGatewayEvent(PUBLIC_SUBJECT.getValue());
        var result = handler.handleRequest(event, context);

        verifyNoInteractions(dynamoDeleteService);
        verifyNoInteractions(auditService);
        assertThat(result, hasStatus(400));
        assertThat(result, hasJsonBody(ErrorResponse.ACCT_DOES_NOT_EXIST));
    }

    private APIGatewayProxyRequestEvent generateApiGatewayEvent(String principalId) {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{\"email\": \"%s\" }", EMAIL));
        APIGatewayProxyRequestEvent.ProxyRequestContext proxyRequestContext =
                new APIGatewayProxyRequestEvent.ProxyRequestContext();
        Map<String, Object> authorizerParams = new HashMap<>();
        authorizerParams.put("principalId", principalId);
        proxyRequestContext.setAuthorizer(authorizerParams);
        proxyRequestContext.setIdentity(identityWithSourceIp("123.123.123.123"));
        event.setRequestContext(proxyRequestContext);
        event.setHeaders(
                Map.of(
                        PersistentIdHelper.PERSISTENT_ID_HEADER_NAME,
                        PERSISTENT_ID,
                        AuditHelper.TXMA_ENCODED_HEADER_NAME,
                        TXMA_ENCODED_HEADER_VALUE));

        return event;
    }
}
