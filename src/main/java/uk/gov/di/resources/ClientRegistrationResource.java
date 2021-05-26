package uk.gov.di.resources;

import org.eclipse.jetty.http.HttpStatus;
import uk.gov.di.configuration.AuthenticationApiConfiguration;
import uk.gov.di.entity.Client;
import uk.gov.di.entity.ClientRegistrationRequest;
import uk.gov.di.services.ClientService;

import javax.validation.constraints.NotEmpty;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.List;
import java.util.Optional;

@Path("/connect")
public class ClientRegistrationResource {

    private ClientService clientService;
    private AuthenticationApiConfiguration config;

    public ClientRegistrationResource(ClientService clientService, AuthenticationApiConfiguration config) {
        this.clientService = clientService;
        this.config = config;
    }

    @POST
    @Path("/register")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response clientRegistrationJson(ClientRegistrationRequest clientRegistrationRequest) {
        Client client = clientService.addClient(
                clientRegistrationRequest.clientName(),
                clientRegistrationRequest.redirectUris(),
                clientRegistrationRequest.contacts());
        return Response.ok(client).build();
    }

    @POST
    @Path("/logout")
    public Response logout() {
        return Response.status(HttpStatus.MOVED_TEMPORARILY_302).location(URI.create("/logout?redirectUri=/connect/register")).cookie(new NewCookie(
                "clientRegistrationCookie",
                null,
                "/",
                null,
                Cookie.DEFAULT_VERSION,
                null,
                0,
                false))
                .build();
    }
}
