package uk.gov.di.authentication.oidc.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.domain.OidcAuditableEvent;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.oidc.services.AccessTokenService;
import uk.gov.di.authentication.oidc.services.UserInfoService;
import uk.gov.di.orchestration.audit.TxmaAuditUser;
import uk.gov.di.orchestration.shared.entity.AccessTokenStore;
import uk.gov.di.orchestration.shared.entity.ValidClaims;
import uk.gov.di.orchestration.shared.exceptions.AccessTokenException;
import uk.gov.di.orchestration.shared.exceptions.ClientNotFoundException;
import uk.gov.di.orchestration.shared.services.AuditService;
import uk.gov.di.orchestration.shared.services.CloudwatchMetricsService;
import uk.gov.di.orchestration.shared.services.ConfigurationService;

import java.util.List;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.token.BearerTokenError.INVALID_TOKEN;
import static com.nimbusds.oauth2.sdk.token.BearerTokenError.MISSING_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.CLIENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetricDimensions.ENVIRONMENT;
import static uk.gov.di.orchestration.shared.domain.CloudwatchMetrics.USER_INFO_RETURNED;
import static uk.gov.di.orchestration.sharedtest.helper.IdentityTestData.RETURN_CODE;
import static uk.gov.di.orchestration.sharedtest.matchers.APIGatewayProxyResponseEventMatcher.hasStatus;

class UserInfoHandlerTest {

    private static final String EMAIL_ADDRESS = "joe.bloggs@digital.cabinet-office.gov.uk";
    private static final String PHONE_NUMBER = "01234567890";
    private static final Subject SUBJECT = new Subject();
    private static final String TOKEN = "token";
    private static final String TEST_INTERNAL_COMMON_SUBJECT_ID = "internal-common-subject-id";
    private static final String JOURNEY_ID = "client-session-id";
    private static final Subject AUDIT_SUBJECT_ID = new Subject();
    private final Context context = mock(Context.class);
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private final UserInfoService userInfoService = mock(UserInfoService.class);
    private final AccessTokenInfo accessTokenInfo = mock(AccessTokenInfo.class);
    private final AccessTokenService accessTokenService = mock(AccessTokenService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final CloudwatchMetricsService cloudwatchMetricsService =
            mock(CloudwatchMetricsService.class);

    private static final Map<String, List<String>> INVALID_TOKEN_RESPONSE =
            new UserInfoErrorResponse(INVALID_TOKEN).toHTTPResponse().getHeaderMap();
    private UserInfoHandler handler;

    @BeforeEach
    void setUp() {
        handler =
                new UserInfoHandler(
                        configurationService,
                        userInfoService,
                        accessTokenService,
                        auditService,
                        cloudwatchMetricsService);
        when(context.getAwsRequestId()).thenReturn("aws-request-id");
        when(accessTokenInfo.getClientID()).thenReturn("client-id");
        when(accessTokenInfo.getSubject()).thenReturn(SUBJECT.getValue());
        when(accessTokenInfo.getAccessTokenStore())
                .thenReturn(
                        new AccessTokenStore(TOKEN, TEST_INTERNAL_COMMON_SUBJECT_ID, JOURNEY_ID));
        when(configurationService.getEnvironment()).thenReturn("test");
    }

    @Test
    void shouldReturn200WithUserInfoBasedOnScopesForSuccessfulRequest()
            throws ParseException, AccessTokenException, ClientNotFoundException {
        AccessToken accessToken = new BearerAccessToken();
        UserInfo userInfo = new UserInfo(SUBJECT);
        userInfo.setEmailVerified(true);
        userInfo.setPhoneNumberVerified(true);
        userInfo.setPhoneNumber(PHONE_NUMBER);
        userInfo.setEmailAddress(EMAIL_ADDRESS);
        when(accessTokenService.parse(accessToken.toAuthorizationHeader(), false))
                .thenReturn(accessTokenInfo);
        when(userInfoService.populateUserInfo(accessTokenInfo)).thenReturn(userInfo);
        when(userInfoService.calculateSubjectForAudit(accessTokenInfo))
                .thenReturn(AUDIT_SUBJECT_ID.getValue());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", accessToken.toAuthorizationHeader()));
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(200));
        UserInfo parsedResultBody = UserInfo.parse(result.getBody());
        assertThat(parsedResultBody.getSubject(), equalTo(SUBJECT));
        assertThat(parsedResultBody.getEmailAddress(), equalTo(EMAIL_ADDRESS));
        assertTrue(parsedResultBody.getEmailVerified());
        assertThat(parsedResultBody.getPhoneNumber(), equalTo(PHONE_NUMBER));
        assertTrue(parsedResultBody.getPhoneNumberVerified());

        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.USER_INFO_RETURNED,
                        "client-id",
                        TxmaAuditUser.user()
                                .withUserId(AUDIT_SUBJECT_ID.getValue())
                                .withGovukSigninJourneyId(JOURNEY_ID),
                        List.of());

        verify(cloudwatchMetricsService)
                .incrementCounter(
                        USER_INFO_RETURNED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                "client-id"));
    }

    @Test
    void shouldAuditReturnCodeWhenReturnCodeClaimIsPresent()
            throws AccessTokenException, ClientNotFoundException {
        AccessToken accessToken = new BearerAccessToken();
        UserInfo userInfo = new UserInfo(SUBJECT);
        userInfo.setClaim(ValidClaims.RETURN_CODE.getValue(), RETURN_CODE);
        when(accessTokenService.parse(accessToken.toAuthorizationHeader(), false))
                .thenReturn(accessTokenInfo);
        when(userInfoService.populateUserInfo(accessTokenInfo)).thenReturn(userInfo);
        when(userInfoService.calculateSubjectForAudit(accessTokenInfo))
                .thenReturn(AUDIT_SUBJECT_ID.getValue());

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", accessToken.toAuthorizationHeader()));
        handler.handleRequest(event, context);

        verify(auditService)
                .submitAuditEvent(
                        OidcAuditableEvent.USER_INFO_RETURNED,
                        "client-id",
                        TxmaAuditUser.user()
                                .withUserId(AUDIT_SUBJECT_ID.getValue())
                                .withGovukSigninJourneyId(JOURNEY_ID),
                        List.of(AuditService.MetadataPair.pair("return-code", RETURN_CODE)));
    }

    @Test
    void shouldReturn401WhenBearerTokenIsNotParseable() throws AccessTokenException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("Authorization", "this-is-not-a-valid-token"));
        AccessTokenException accessTokenException =
                new AccessTokenException("Unable to parse AccessToken", INVALID_TOKEN);
        when(accessTokenService.parse("this-is-not-a-valid-token", false))
                .thenThrow(accessTokenException);

        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        assertEquals(INVALID_TOKEN_RESPONSE, result.getMultiValueHeaders());

        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        USER_INFO_RETURNED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                "client-id"));
    }

    @Test
    void shouldReturn401WhenAuthorizationHeaderIsMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent result = handler.handleRequest(event, context);

        assertThat(result, hasStatus(401));
        Map<String, List<String>> missingTokenExpectedResponse =
                new UserInfoErrorResponse(MISSING_TOKEN).toHTTPResponse().getHeaderMap();
        assertEquals(missingTokenExpectedResponse, result.getMultiValueHeaders());

        verify(cloudwatchMetricsService, never())
                .incrementCounter(
                        USER_INFO_RETURNED.getValue(),
                        Map.of(
                                ENVIRONMENT.getValue(),
                                configurationService.getEnvironment(),
                                CLIENT.getValue(),
                                "client-id"));
    }
}
