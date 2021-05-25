package uk.gov.di.resources;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

@Path("/authorize")
public class AuthorisationResource {

    @GET
    public String helloWorld() {
        return "Hello world";
    }
}
