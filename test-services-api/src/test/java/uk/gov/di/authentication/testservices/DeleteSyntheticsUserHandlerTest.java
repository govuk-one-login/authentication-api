package uk.gov.di.authentication.testservices;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.audit.AuditContext;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.testservices.domain.TestServicesAuditableEvent;
import uk.gov.di.authentication.testservices.lambda.DeleteSyntheticsUserHandler;

import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.sharedtest.helper.RequestEventHelper.contextWithSourceIp;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasJsonBody;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class DeleteSyntheticsUserHandlerTest {

    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final Subject PUBLIC_SUBJECT = new Subject();
    private static final String PERSISTENT_ID = "some-persistent-session-id";

    private DeleteSyntheticsUserHandler handler;
    private final Context context = mock(Context.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuditService auditService = mock(AuditService.class);

    private final AuditContext auditContext =
            new AuditContext(
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    EMAIL,
                    "123.123.123.123",
                    AuditService.UNKNOWN,
                    AuditService.UNKNOWN,
                    Optional.empty(),
                    new ArrayList<>());

    @BeforeEach
    public void setUp() {
        handler =
                new DeleteSyntheticsUserHandler(
                        authenticationService, configurationService, auditService);
    }

    @Test
    void shouldReturn204IfAccountRemovalIsSuccessfulAndPrincipalContainsPublicSubjectId()
            throws Json.JsonException {
        var userProfile =
                new UserProfile().withEmail(EMAIL).withPublicSubjectID(PUBLIC_SUBJECT.getValue());
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(configurationService.getSyntheticsUsers()).thenReturn(EMAIL);

        var event = generateApiGatewayEvent();
        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(204));
        verify(authenticationService).removeAccount(EMAIL);
        verify(auditService)
                .submitAuditEvent(
                        TestServicesAuditableEvent.AUTH_SYNTHETICS_USER_DELETED, auditContext);
    }

    @Test
    void shouldReturn404IfUserAccountNotConfigured() {
        var event = generateApiGatewayEvent();
        var result = handler.handleRequest(event, context);

        verify(authenticationService, never()).removeAccount(EMAIL);
        assertThat(result, hasStatus(404));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1010));
    }

    @Test
    void shouldReturn404IfUserAccountDoesNotExist() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());
        when(configurationService.getSyntheticsUsers()).thenReturn(EMAIL);

        var event = generateApiGatewayEvent();
        var result = handler.handleRequest(event, context);

        verify(authenticationService, never()).removeAccount(EMAIL);
        assertThat(result, hasStatus(404));
        assertThat(result, hasJsonBody(ErrorResponse.ERROR_1010));

        verify(auditService)
                .submitAuditEvent(
                        TestServicesAuditableEvent.AUTH_SYNTHETICS_USER_NOT_FOUND_FOR_DELETION,
                        auditContext);
    }

    private APIGatewayProxyRequestEvent generateApiGatewayEvent() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setRequestContext(contextWithSourceIp("123.123.123.123"));
        event.setBody(format("{\"email\": \"%s\" }", EMAIL));
        event.setHeaders(Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID));

        return event;
    }
}
