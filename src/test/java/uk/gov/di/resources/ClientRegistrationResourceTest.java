package uk.gov.di.resources;

import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import org.eclipse.jetty.http.HttpStatus;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.configuration.AuthenticationApiConfiguration;
import uk.gov.di.entity.Client;
import uk.gov.di.entity.ClientRegistrationRequest;
import uk.gov.di.services.ClientService;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(DropwizardExtensionsSupport.class)
class ClientRegistrationResourceTest {

    private static final AuthenticationApiConfiguration configuration = mock(AuthenticationApiConfiguration.class);
    private static final ClientService CLIENT_SERVICE = new ClientService(new ArrayList<>(), null);
    private static final ResourceExtension CLIENT_REGISTRATION_RESOURCE =
            ResourceExtension.builder()
                    .addResource(new ClientRegistrationResource(CLIENT_SERVICE, configuration))
                    .setClientConfigurator(
                            clientConfig -> {
                                clientConfig.property(ClientProperties.FOLLOW_REDIRECTS, false);
                            })
                    .build();

    @Test
    void shouldReturnSuccessfulRestfulResponse() {
        ClientRegistrationRequest request = new ClientRegistrationRequest(
                "restful_test_client",
                List.of("http://example.com"),
                List.of("contact@example.com")
        );
        final Response response = CLIENT_REGISTRATION_RESOURCE
                .target("/connect/register")
                .request()
                .post(Entity.json(request));

        assertEquals(HttpStatus.OK_200, response.getStatus());
        Client client = response.readEntity(Client.class);
        assertEquals("restful_test_client", client.clientName());
        assertNotNull(client.clientId());
        assertNotNull(client.clientSecret());
    }
}