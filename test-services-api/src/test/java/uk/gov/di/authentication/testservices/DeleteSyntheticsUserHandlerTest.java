package uk.gov.di.authentication.testservices;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.PersistentIdHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.testservices.lambda.DeleteSyntheticsUserHandler;

import java.util.Map;
import java.util.Optional;

import static java.lang.String.format;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
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

    @BeforeEach
    public void setUp() {
        handler = new DeleteSyntheticsUserHandler(authenticationService, configurationService);
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
    }

    private APIGatewayProxyRequestEvent generateApiGatewayEvent() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(format("{\"email\": \"%s\" }", EMAIL));
        event.setHeaders(Map.of(PersistentIdHelper.PERSISTENT_ID_HEADER_NAME, PERSISTENT_ID));

        return event;
    }
}
