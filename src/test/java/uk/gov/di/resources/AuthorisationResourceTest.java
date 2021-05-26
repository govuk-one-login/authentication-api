package uk.gov.di.resources;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import org.eclipse.jetty.http.HttpStatus;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.helpers.AuthenticationResponseHelper;
import uk.gov.di.services.ClientService;

import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(DropwizardExtensionsSupport.class)
public class AuthorisationResourceTest {

    private static final ClientService clientService = mock(ClientService.class);

    private static final ResourceExtension authorizationResource =
            ResourceExtension.builder()
                    .addResource(new AuthorisationResource(clientService))
                    .setClientConfigurator(
                            clientConfig -> {
                                clientConfig.property(ClientProperties.FOLLOW_REDIRECTS, false);
                            }).build();

    @BeforeAll
    public static void setUp() {
        when(clientService.getErrorForAuthorizationRequest(any())).thenReturn(Optional.empty());
    }

    @Test
    public void shouldProvideCodeAuthenticationRequestWhenLoggedIn() {
        when(clientService.getSuccessfulResponse(any(), anyString()))
                .thenReturn(
                        AuthenticationResponseHelper.generateSuccessfulAuthResponse(
                                new AuthenticationRequest.Builder(
                                                new ResponseType("code"),
                                                new Scope("openid"),
                                                new ClientID("test"),
                                                URI.create("http://example.com/login-code"))
                                        .build(),
                                new AuthorizationCode()));
        Response response = authorisationRequestBuilder().cookie("userCookie", "dummy-value").get();

        assertEquals(HttpStatus.FOUND_302, response.getStatus());
        assertEquals("example.com", response.getLocation().getHost());
        assertEquals("/login-code", response.getLocation().getPath());
        assertTrue(response.getLocation().getQuery().startsWith("code="));
    }

    @Test
    public void shouldRedirectAuthenticationRequestToLoginPageIfNotLoggedIn() {
        Response response = authorisationRequestBuilder().get();

        assertEquals(HttpStatus.FOUND_302, response.getStatus());
        assertEquals("localhost", response.getLocation().getHost());
        assertEquals("/login", response.getLocation().getPath());
    }

    @Test
    public void shouldReturnErrorResponseWhenReceivingInvalidAuthRequest() {
        when(clientService.getErrorForAuthorizationRequest(any()))
                .thenReturn(Optional.of(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS));
        Response response = authorisationRequestBuilder().get();

        assertEquals(HttpStatus.FOUND_302, response.getStatus());
        assertEquals("example.com", response.getLocation().getHost());
        assertEquals("/login-code", response.getLocation().getPath());
        assertTrue(
                response.getLocation()
                        .getQuery()
                        .contains("error=unmet_authentication_requirements"));
    }

    private Invocation.Builder authorisationRequestBuilder() {
        return authorizationResource
                .target("/authorize")
                .queryParam("client_id", "test")
                .queryParam("scope", "openid")
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", "http://example.com/login-code")
                .request();
    }
}
