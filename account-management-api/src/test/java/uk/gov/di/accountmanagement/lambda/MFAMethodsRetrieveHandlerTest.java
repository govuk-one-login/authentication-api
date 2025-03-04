package uk.gov.di.accountmanagement.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.entity.MfaMethodData;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.SmsMfaDetail;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoService;
import uk.gov.di.authentication.shared.services.MfaMethodsService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.accountmanagement.helpers.CommonTestVariables.VALID_HEADERS;
import static uk.gov.di.authentication.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class MFAMethodsRetrieveHandlerTest {
    private final Context context = mock(Context.class);
    private static final String PUBLIC_SUBJECT_ID = "some-subject-id";
    private static final String EMAIL = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final ConfigurationService configurationService =
            mock(ConfigurationService.class);
    private static final DynamoService dynamoService = mock(DynamoService.class);
    private static final UserProfile userProfile = mock(UserProfile.class);
    private static final MfaMethodsService mfaMethodsService = mock(MfaMethodsService.class);

    private MFAMethodsRetrieveHandler handler;

    @BeforeEach
    void setUp() {
        when(userProfile.getEmail()).thenReturn(EMAIL);
        handler =
                new MFAMethodsRetrieveHandler(
                        configurationService, dynamoService, mfaMethodsService);
    }

    @Test
    void shouldReturn200WithTheMethodReturnedByTheMfaMethodsService() {
        when(configurationService.getEnvironment()).thenReturn("test-environment");
        when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.of(userProfile));

        var method =
                new MfaMethodData(
                        1,
                        PriorityIdentifier.DEFAULT,
                        true,
                        new SmsMfaDetail(MFAMethodType.SMS, "+44123456789"));
        when(mfaMethodsService.getMfaMethods(EMAIL)).thenReturn(List.of(method));

        var event =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters((Map.of("publicSubjectId", PUBLIC_SUBJECT_ID)))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        assertEquals(
                "[{\"mfaIdentifier\":1,\"priorityIdentifier\":\"DEFAULT\",\"methodVerified\":true,\"method\":{\"mfaMethodType\":\"SMS\",\"phoneNumber\":\"+44123456789\"}}]",
                result.getBody());
    }

    @Test
    void shouldReturn400IfPublicSubjectIdNotIncludedInPath() {
        when(configurationService.getEnvironment()).thenReturn("test-environment");
        var event =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters((Map.of("publicSubjectId", "")))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @ParameterizedTest
    @ValueSource(strings = {"production", "integration"})
    void shouldReturn400IfRequestIsMadeInProductionOrIntegration(String environment) {
        when(configurationService.getEnvironment()).thenReturn(environment);
        var event =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters((Map.of("publicSubjectId", PUBLIC_SUBJECT_ID)))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(400));
    }

    @Test
    void shouldReturn404IfNoUserProfileForPublicSubjectId() {
        when(configurationService.getEnvironment()).thenReturn("test-environment");
        when(dynamoService.getOptionalUserProfileFromPublicSubject(PUBLIC_SUBJECT_ID))
                .thenReturn(Optional.empty());
        var event =
                new APIGatewayProxyRequestEvent()
                        .withPathParameters((Map.of("publicSubjectId", PUBLIC_SUBJECT_ID)))
                        .withHeaders(VALID_HEADERS);

        var result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(404));
    }
}
