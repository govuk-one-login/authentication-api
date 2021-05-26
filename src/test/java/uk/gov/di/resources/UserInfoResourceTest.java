package uk.gov.di.resources;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import org.eclipse.jetty.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.services.TokenService;
import uk.gov.di.services.UserService;

import javax.ws.rs.core.Response;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(DropwizardExtensionsSupport.class)
class UserInfoResourceTest {

    private static final TokenService tokenService = mock(TokenService.class);
    private static final UserService userService = mock(UserService.class);
    private static final ResourceExtension userInfoExtension =
            ResourceExtension.builder()
                    .addResource(new UserInfoResource(tokenService, userService))
                    .build();

    @Test
    void shouldReturnUnauthorisedIfNoHeaderPresent() {
        final Response response = userInfoExtension.target("/userinfo").request().get();

        assertEquals(HttpStatus.UNAUTHORIZED_401, response.getStatus());
    }

    @Test
    void shouldReturnUserDataIfAuthorisationHeaderPresent() throws ParseException {
        var email = "joe.bloggs@digital.cabinet-office.gov.uk";

        var expectedUserInfo = new UserInfo(new Subject());
        expectedUserInfo.setGivenName("Joe");

        when(tokenService.getEmailForToken(any())).thenReturn(email);
        when(userService.getInfoForEmail(email)).thenReturn(expectedUserInfo);

        final Response response =
                userInfoExtension
                        .target("/userinfo")
                        .request()
                        .header("Authorization", "Bearer sometoken")
                        .get();

        assertEquals(HttpStatus.OK_200, response.getStatus());

        var actualUserInfo = UserInfo.parse(response.readEntity(String.class));
        assertEquals(expectedUserInfo.getGivenName(), actualUserInfo.getGivenName());
    }
}
