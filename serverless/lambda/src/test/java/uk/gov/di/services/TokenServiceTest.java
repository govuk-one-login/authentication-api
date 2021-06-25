package uk.gov.di.services;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TokenServiceTest {

    private ConfigurationService configurationService = mock(ConfigurationService.class);
    private final TokenService tokenService = new TokenService(configurationService);
    private static final Subject SUBJECT = new Subject("some-subject");
    private static final String BASE_URL = "http://example.com";

    @Test
    public void shouldAssociateCreatedTokenWithEmailAddress() {
        AccessToken token = tokenService.issueToken("test@digital.cabinet-office.gov.uk");

        assertEquals(
                "test@digital.cabinet-office.gov.uk", tokenService.getEmailForToken(token).get());
    }

    @Test
    public void shouldSuccessfullyGenerateIDtoken() throws ParseException {
        Optional<String> baseUrl = Optional.of(BASE_URL);
        when(configurationService.getBaseURL()).thenReturn(baseUrl);

        SignedJWT signedJWT = tokenService.generateIDToken("client-id", SUBJECT);

        assertEquals(BASE_URL, signedJWT.getJWTClaimsSet().getIssuer());
        assertEquals(SUBJECT.getValue(), signedJWT.getJWTClaimsSet().getClaim("sub"));
    }
}
