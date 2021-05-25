package uk.gov.di.services;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.configuration.AuthenticationApiConfiguration;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class TokenServiceTest {

    private final AuthenticationApiConfiguration configuration = mock(AuthenticationApiConfiguration.class);
    private TokenService tokenService;

    @BeforeEach
    public void setup() {
        when(configuration.getBaseUrl()).thenReturn(URI.create("https://example.com"));
        tokenService = new TokenService(configuration);
    }

    @Test
    public void shouldAssociateCreatedTokenWithEmailAddress() {
        AccessToken token = tokenService.issueToken("test@digital.cabinet-office.gov.uk");

        assertEquals("test@digital.cabinet-office.gov.uk", tokenService.getEmailForToken(token));
    }
}
