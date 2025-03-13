package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import io.vavr.control.Either;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.MfaMethodsService;

import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsDeleteHandlerTest {

    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final Context context = mock(Context.class);
    private static final String PUBLIC_SUBJECT_ID = "some-subject-id";
    private static final String MFA_IDENTIFIER_TO_DELETE = "8e18b315-995e-434e-a236-4fbfb72d6ce0";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final DynamoService dynamoService = mock(DynamoService.class);
    private static final UserProfile userProfile = mock(UserProfile.class);
    private static final MfaMethodsService mfaMethodsService = mock(MfaMethodsService.class);

    private final APIGatewayProxyRequestEvent event =
            new APIGatewayProxyRequestEvent()
                    .withPathParameters(
                            Map.ofEntries(
                                    Map.entry("publicSubjectId", PUBLIC_SUBJECT_ID),
                                    Map.entry("mfaIdentifier", MFA_IDENTIFIER_TO_DELETE)))
                    .withHeaders(VALID_HEADERS);

    private MFAMethodsDeleteHandler handler;

    @BeforeEach
    void setUp() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(true);
        handler =
                new MFAMethodsDeleteHandler(configurationService, dynamoService, mfaMethodsService);
    }

    @Test
    void shouldReturn204WhenFeatureFlagEnabled() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.of(userProfile));
        when(userProfile.getEmail()).thenReturn(EMAIL);
        when(mfaMethodsService.deleteMfaMethod(EMAIL, MFA_IDENTIFIER_TO_DELETE))
                .thenReturn(Either.right(MFA_IDENTIFIER_TO_DELETE));
        var result = handler.handleRequest(event, context);
        assertEquals(204, result.getStatusCode());
    }

    @Test
    void shouldReturn404WhenFeatureFlagEnabledButUserDoesNotExist() {
        when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.empty());
        var result = handler.handleRequest(event, context);
        assertEquals(404, result.getStatusCode());
    }

    @Test
    void shouldReturn400IfPublicSubjectIdNotIncludedInPath() {
        var event =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters((Map.of("publicSubjectId", "")))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn400WhenFeatureFlagDisabled() {
        when(configurationService.isMfaMethodManagementApiEnabled()).thenReturn(false);

        var result = handler.handleRequest(event, context);
        assertEquals(400, result.getStatusCode());
    }
}
