package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.authentication.frontendapi.anticorruptionlayer.AMCFailureAntiCorruption;
import uk.gov.di.authentication.frontendapi.entity.AMCAuthorizeFailureReason;
import uk.gov.di.authentication.frontendapi.entity.AMCAuthorizeRequest;
import uk.gov.di.authentication.frontendapi.entity.AMCJourneyType;
import uk.gov.di.authentication.frontendapi.entity.AMCScope;
import uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper;
import uk.gov.di.authentication.frontendapi.services.AMCAuthorizationService;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.state.UserContext;

import java.util.Optional;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_SESSION_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.PUBLIC_SUBJECT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;

class AMCAuthorizeHandlerTest {
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private final AMCAuthorizationService amcAuthorizationService =
            mock(AMCAuthorizationService.class);
    private AMCAuthorizeHandler handler;
    private final Context context = mock(Context.class);
    private final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID)
                    .withClientId(CLIENT_ID)
                    .withEmailAddress(EMAIL);
    private final UserProfile userProfile =
            new UserProfile().withEmail(EMAIL).withPublicSubjectID(PUBLIC_SUBJECT_ID);
    private final UserContext userContext = mock(UserContext.class);

    @BeforeEach
    void setUp() {
        handler =
                new AMCAuthorizeHandler(
                        configurationService,
                        authenticationService,
                        authSessionService,
                        amcAuthorizationService);

        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
        when(userContext.getAuthSession()).thenReturn(authSession);
        when(userContext.getClientSessionId()).thenReturn(CLIENT_SESSION_ID);
    }

    @Test
    void shouldReturnAuthorizationUrlOnSuccess() {
        String expectedUrl = "https://example.com/authorize";
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(amcAuthorizationService.buildAuthorizationUrl(
                        eq(INTERNAL_COMMON_SUBJECT_ID),
                        eq(new AMCScope[] {AMCScope.ACCOUNT_DELETE}),
                        eq(authSession),
                        eq(CLIENT_SESSION_ID),
                        eq(PUBLIC_SUBJECT_ID)))
                .thenReturn(Result.success(expectedUrl));

        var event =
                ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody(
                        CommonTestVariables.VALID_HEADERS,
                        format(
                                "{\"email\":\"%s\",\"journeyType\":\"%s\"}",
                                EMAIL, AMCJourneyType.SFAD));

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        event, context, new AMCAuthorizeRequest(AMCJourneyType.SFAD), userContext);

        assertEquals(200, result.getStatusCode());
        assertTrue(result.getBody().contains(expectedUrl));
        verify(amcAuthorizationService)
                .buildAuthorizationUrl(
                        INTERNAL_COMMON_SUBJECT_ID,
                        new AMCScope[] {AMCScope.ACCOUNT_DELETE},
                        authSession,
                        CLIENT_SESSION_ID,
                        PUBLIC_SUBJECT_ID);
    }

    @Test
    void shouldReturn400WhenUserProfileNotFound() {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL)).thenReturn(Optional.empty());

        var event =
                ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody(
                        CommonTestVariables.VALID_HEADERS,
                        format(
                                "{\"email\":\"%s\",\"journeyType\":\"%s\"}",
                                EMAIL, AMCJourneyType.SFAD));

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        event, context, new AMCAuthorizeRequest(AMCJourneyType.SFAD), userContext);

        assertEquals(400, result.getStatusCode());
        assertTrue(result.getBody().contains(ErrorResponse.EMAIL_HAS_NO_USER_PROFILE.getMessage()));
    }

    @ParameterizedTest
    @EnumSource(AMCAuthorizeFailureReason.class)
    void shouldHandleAllFailureReasons(AMCAuthorizeFailureReason failureReason) {
        when(authenticationService.getUserProfileByEmailMaybe(EMAIL))
                .thenReturn(Optional.of(userProfile));
        when(amcAuthorizationService.buildAuthorizationUrl(
                        anyString(), any(), any(), anyString(), anyString()))
                .thenReturn(Result.failure(failureReason));

        var event =
                ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody(
                        CommonTestVariables.VALID_HEADERS,
                        format(
                                "{\"email\":\"%s\",\"journeyType\":\"%s\"}",
                                EMAIL, AMCJourneyType.SFAD));

        APIGatewayProxyResponseEvent result =
                handler.handleRequestWithUserContext(
                        event, context, new AMCAuthorizeRequest(AMCJourneyType.SFAD), userContext);

        var httpResponse = AMCFailureAntiCorruption.toHttpResponse(failureReason);
        int expectedStatusCode = httpResponse.statusCode();
        ErrorResponse expectedError = httpResponse.errorResponse();

        assertEquals(expectedStatusCode, result.getStatusCode());
        assertTrue(result.getBody().contains(expectedError.getMessage()));
    }
}
