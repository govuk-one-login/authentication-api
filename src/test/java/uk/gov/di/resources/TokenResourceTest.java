package uk.gov.di.resources;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import org.eclipse.jetty.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.services.AuthenticationService;
import uk.gov.di.services.AuthorizationCodeService;
import uk.gov.di.services.ClientService;
import uk.gov.di.services.TokenService;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(DropwizardExtensionsSupport.class)
public class TokenResourceTest {

    private static final TokenService tokenService = mock(TokenService.class);
    private static final AuthorizationCodeService authCodeService =
            mock(AuthorizationCodeService.class);
    private static final ClientService clientService = mock(ClientService.class);
    private static final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private static final SignedJWT signedJWT = mock(SignedJWT.class);
    private static final ResourceExtension tokenResourceExtension =
            ResourceExtension.builder()
                    .addResource(new TokenResource(tokenService, clientService, authenticationService, authCodeService))
                    .build();

    @Test
    public void testTokenResource() {
        var email = "joe.bloggs@digital.cabinet-office.gov.uk";

        when(tokenService.generateIDToken(anyString(), any())).thenReturn(signedJWT);
        when(tokenService.issueToken(email)).thenReturn(new BearerAccessToken());
        when(authCodeService.getEmailForCode(eq(new AuthorizationCode("123"))))
                .thenReturn(Optional.of(email));
        when(clientService.isValidClient(anyString(), anyString())).thenReturn(true);
        when(authenticationService.getInfoForEmail(anyString())).thenReturn(new UserInfo(new Subject()));

        MultivaluedMap<String, String> tokenResourceFormParams = new MultivaluedHashMap<>();
        tokenResourceFormParams.add("code", "123");
        tokenResourceFormParams.add("client_id", "123");
        tokenResourceFormParams.add("client_secret", "123");

        final Response response =
                tokenResourceExtension
                        .target("/token")
                        .request()
                        .post(Entity.form(tokenResourceFormParams));

        assertEquals(HttpStatus.OK_200, response.getStatus());
    }

    @Test
    public void shouldReturnForbiddenIfAuthorizationNotRecognised() {
        when(authCodeService.getEmailForCode(eq(new AuthorizationCode("123"))))
                .thenReturn(Optional.empty());
        when(clientService.isValidClient(anyString(), anyString())).thenReturn(true);

        MultivaluedMap<String, String> tokenResourceFormParams = new MultivaluedHashMap<>();
        tokenResourceFormParams.add("code", "123");
        tokenResourceFormParams.add("client_id", "123");
        tokenResourceFormParams.add("client_secret", "123");

        final Response response =
                tokenResourceExtension
                        .target("/token")
                        .request()
                        .post(Entity.form(tokenResourceFormParams));

        assertEquals(HttpStatus.FORBIDDEN_403, response.getStatus());
    }

    @Test
    public void shouldValidateClientCredentials() {
        when(clientService.isValidClient(anyString(), anyString())).thenReturn(false);

        MultivaluedMap<String, String> tokenResourceFormParams = new MultivaluedHashMap<>();
        tokenResourceFormParams.add("code", "123");
        tokenResourceFormParams.add("client_id", "123");
        tokenResourceFormParams.add("client_secret", "123");

        final Response response =
                tokenResourceExtension
                        .target("/token")
                        .request()
                        .post(Entity.form(tokenResourceFormParams));

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR_500, response.getStatus());
    }
}
