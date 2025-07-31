package uk.gov.di.orchestration.shared.helpers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import org.junit.jupiter.api.Test;
import uk.gov.di.orchestration.shared.entity.CustomScopeValue;
import uk.gov.di.orchestration.sharedtest.utils.KeyPairUtils;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DocAppSubjectIdHelperTest {

    private static final String REDIRECT_URI = "https://localhost:8080";
    private static final Scope SCOPE =
            new Scope(OIDCScopeValue.OPENID, CustomScopeValue.DOC_CHECKING_APP);
    private static final State STATE = new State();
    private static final Nonce NONCE = new Nonce();
    private static final ClientID CLIENT_ID = new ClientID("test-id");
    private static final URI DOC_APP_DOMAIN = URI.create("https://doc-app-domain.gov.uk");
    private static final String AUDIENCE = "https://localhost/authorize";

    @Test
    void shouldUseSubjectFromRequestObjectWhenPresent() throws JOSEException {
        var expectedSubject = new Subject();
        var authRequestParams = generateAuthRequestParams(expectedSubject);

        var docAppSubjectId =
                DocAppSubjectIdHelper.calculateDocAppSubjectId(authRequestParams, DOC_APP_DOMAIN);

        assertThat(docAppSubjectId, equalTo(expectedSubject));
    }

    @Test
    void shouldUsePairwiseSubjectWhenSubjectNotPresentInRequestObject() throws JOSEException {
        var authRequestParams = generateAuthRequestParams(null);

        var docAppSubjectId =
                DocAppSubjectIdHelper.calculateDocAppSubjectId(authRequestParams, DOC_APP_DOMAIN);

        assertTrue(docAppSubjectId.getValue().startsWith("urn:fdc:gov.uk:2022:"));
    }

    private Map<String, List<String>> generateAuthRequestParams(Subject subject)
            throws JOSEException {
        var jwtClaimsSetBuilder =
                new JWTClaimsSet.Builder()
                        .audience(AUDIENCE)
                        .claim("redirect_uri", REDIRECT_URI)
                        .claim("response_type", ResponseType.CODE.toString())
                        .claim("scope", SCOPE.toString())
                        .claim("nonce", NONCE)
                        .claim("state", STATE)
                        .claim("client_id", CLIENT_ID)
                        .issuer(new ClientID("test-id").getValue());
        if (Objects.nonNull(subject)) {
            jwtClaimsSetBuilder.subject(subject.getValue());
        }
        var jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        var signedJWT = new SignedJWT(jwsHeader, jwtClaimsSetBuilder.build());
        var signer = new RSASSASigner(KeyPairUtils.generateRsaKeyPair().getPrivate());
        signedJWT.sign(signer);
        var authRequest =
                new AuthenticationRequest.Builder(
                                ResponseType.CODE, SCOPE, CLIENT_ID, URI.create(REDIRECT_URI))
                        .state(STATE)
                        .nonce(new Nonce())
                        .requestObject(signedJWT)
                        .build();
        return authRequest.toParameters();
    }
}
