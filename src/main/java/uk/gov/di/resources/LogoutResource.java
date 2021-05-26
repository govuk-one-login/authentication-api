package uk.gov.di.resources;

import javax.validation.constraints.NotNull;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import java.net.URI;

@Path("/logout")
public class LogoutResource {

    @GET
    public Response logout(@QueryParam("redirectUri") @NotNull String redirectUri) {
        URI destination = UriBuilder.fromUri(URI.create(redirectUri)).build();

        return Response.status(302)
                .location(destination)
                .cookie(
                        new NewCookie(
                                "userCookie",
                                "",
                                "/",
                                null,
                                Cookie.DEFAULT_VERSION,
                                null,
                                0,
                                false))
                .build();
    }
}
