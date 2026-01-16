package uk.gov.di.authentication.frontendapi.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.frontendapi.entity.AMCJourneyType;
import uk.gov.di.authentication.frontendapi.helpers.ApiGatewayProxyRequestHelper;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.helpers.CommonTestVariables;
import uk.gov.di.authentication.shared.services.AuthSessionService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.Optional;

import static java.lang.String.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.EMAIL;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.INTERNAL_COMMON_SUBJECT_ID;
import static uk.gov.di.authentication.shared.helpers.CommonTestVariables.SESSION_ID;

class AMCAuthorizeHandlerTest {

    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private static final AuthenticationService authenticationService =
            mock(AuthenticationService.class);
    private static final AuthSessionService authSessionService = mock(AuthSessionService.class);
    private AMCAuthorizeHandler handler;
    private final Context context = mock(Context.class);
    private static final AuthSessionItem authSession =
            new AuthSessionItem()
                    .withSessionId(SESSION_ID)
                    .withInternalCommonSubjectId(INTERNAL_COMMON_SUBJECT_ID)
                    .withClientId(CLIENT_ID)
                    .withRpSectorIdentifierHost("gov.uk");

    @BeforeAll
    static void globalSetup() {
        when(authSessionService.getSessionFromRequestHeaders(anyMap()))
                .thenReturn(Optional.of(authSession));
    }

    @BeforeEach
    void testSetup() {
        handler =
                new AMCAuthorizeHandler(
                        configurationService, authenticationService, authSessionService);
    }

    @Test
    void testAMCAuthorizeHandler() {
        var event =
                ApiGatewayProxyRequestHelper.apiRequestEventWithHeadersAndBody(
                        CommonTestVariables.VALID_HEADERS,
                        format(
                                "{ \"email\": \"%s\", \"journeyType\": \"%s\"}",
                                EMAIL, AMCJourneyType.SFAD));

        var result = handler.handleRequest(event, context);

        assertEquals(200, result.getStatusCode());
    }
}
