package uk.gov.di.authentication.frontendapi.services;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;

class ResetPasswordServiceTest {

    private static final String FRONTEND_BASE_URL = "https://localhost:8080/frontend";
    private static final String RESET_PASSWORD_PATH = "reset-password?code=";
    private static final long CODE_EXPIRY_TIME = 900;
    private static final String CODE = "123456";
    private static final String SESSION_ID = "some-session-id";
    private static final String PERSISTENT_SESSION_ID = "persistent-session-id";
    private final ConfigurationService configurationService = mock(ConfigurationService.class);
    private ResetPasswordService resetPasswordService =
            new ResetPasswordService(configurationService);

    @BeforeEach
    void setup() {
        when(configurationService.getCodeExpiry()).thenReturn(CODE_EXPIRY_TIME);
        when(configurationService.getFrontendBaseUrl()).thenReturn(FRONTEND_BASE_URL);
        when(configurationService.getResetPasswordRoute()).thenReturn(RESET_PASSWORD_PATH);
    }

    @Test
    void shouldReturnPasswordResetLink() {
        String passwordResetLink =
                resetPasswordService.buildResetPasswordLink(
                        CODE, SESSION_ID, PERSISTENT_SESSION_ID);
        String[] splitPasswordLink = passwordResetLink.split("\\.");

        assertThat(splitPasswordLink.length, equalTo(4));
        assertThat(
                splitPasswordLink[0],
                equalTo(buildURI(FRONTEND_BASE_URL, RESET_PASSWORD_PATH + CODE).toString()));
        assertNotNull(splitPasswordLink[1]);
        assertThat(splitPasswordLink[2], equalTo(SESSION_ID));
        assertThat(splitPasswordLink[3], equalTo(PERSISTENT_SESSION_ID));
    }
}
