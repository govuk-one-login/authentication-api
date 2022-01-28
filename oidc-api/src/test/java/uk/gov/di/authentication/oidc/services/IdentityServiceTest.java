package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.oidc.entity.IdentityResponse;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.SPOTCredential;
import uk.gov.di.authentication.shared.exceptions.AccessTokenException;
import uk.gov.di.authentication.shared.services.DynamoSpotService;
import uk.gov.di.authentication.sharedtest.helper.SignedCredentialHelper;
import uk.gov.di.authentication.sharedtest.helper.TokenGeneratorHelper;

import java.util.List;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IdentityServiceTest {

    private final DynamoSpotService dynamoSpotService = mock(DynamoSpotService.class);
    private IdentityService identityService;
    private static final Subject INTERNAL_SUBJECT = new Subject("internal-subject");
    private static final Subject SUBJECT = new Subject("some-subject");
    private static final List<String> SCOPES =
            List.of(
                    OIDCScopeValue.OPENID.getValue(),
                    OIDCScopeValue.EMAIL.getValue(),
                    OIDCScopeValue.PHONE.getValue());
    private static final String CLIENT_ID = "client-id";
    private static final String BASE_URL = "http://example.com";
    private String serializedCredential = SignedCredentialHelper.generateCredential().serialize();
    private SPOTCredential spotCredential =
            new SPOTCredential()
                    .setSubjectID(SUBJECT.getValue())
                    .setSerializedCredential(serializedCredential);
    private AccessToken accessToken;

    @BeforeEach
    void setUp() throws JOSEException {
        identityService = new IdentityService(dynamoSpotService);
        accessToken =
                new BearerAccessToken(
                        TokenGeneratorHelper.generateSignedTokenWithGeneratedKey(
                                        CLIENT_ID, BASE_URL, SCOPES, SUBJECT)
                                .serialize());
    }

    @Test
    void shouldReturnIdentityResponseAndDeleteSpotCredential() throws AccessTokenException {
        AccessTokenStore accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        AccessTokenInfo accessTokenInfo =
                new AccessTokenInfo(accessTokenStore, SUBJECT.getValue(), SCOPES);

        when(dynamoSpotService.getSpotCredential(accessTokenInfo.getPublicSubject()))
                .thenReturn(Optional.of(spotCredential));

        IdentityResponse identityResponse =
                identityService.populateIdentityResponse(accessTokenInfo);

        verify(dynamoSpotService).removeSpotCredential(accessTokenInfo.getPublicSubject());
        assertThat(identityResponse.getSub(), equalTo(accessTokenInfo.getPublicSubject()));
        assertThat(identityResponse.getIdentityCredential(), equalTo(serializedCredential));
    }

    @Test
    void shouldThrowExceptionWhenSpotCredentialIsNotFound() {
        AccessTokenStore accessTokenStore =
                new AccessTokenStore(accessToken.getValue(), INTERNAL_SUBJECT.getValue());
        AccessTokenInfo accessTokenInfo =
                new AccessTokenInfo(accessTokenStore, SUBJECT.getValue(), SCOPES);
        when(dynamoSpotService.getSpotCredential(accessTokenInfo.getPublicSubject()))
                .thenReturn(Optional.empty());

        AccessTokenException accessTokenException =
                assertThrows(
                        AccessTokenException.class,
                        () -> identityService.populateIdentityResponse(accessTokenInfo));

        assertThat(accessTokenException.getError(), equalTo(BearerTokenError.INVALID_TOKEN));
        assertThat(accessTokenException.getMessage(), equalTo("Invalid Access Token"));
        verify(dynamoSpotService, never()).removeSpotCredential(accessTokenInfo.getPublicSubject());
    }
}
