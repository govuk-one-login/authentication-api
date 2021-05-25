package uk.gov.di.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import uk.gov.di.configuration.AuthenticationApiConfiguration;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class TokenService {

    private final RSAKey signingKey;
    private final JWSSigner signer;
    private final Issuer issuer;

    private AuthenticationApiConfiguration config;
    private final Map<AccessToken, String> tokensMap = new HashMap<>();

    public TokenService(AuthenticationApiConfiguration config) {
        this.config = config;
        this.issuer = new Issuer(config.getBaseUrl().toString());
        try {
            signingKey = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
            signer = new RSASSASigner(signingKey);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public SignedJWT generateIDToken(String clientId, Subject subject) {
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());

        IDTokenClaimsSet idTokenClaims =
                new IDTokenClaimsSet(
                        issuer,
                        subject,
                        List.of(new Audience(clientId)),
                        expiryDate,
                        new Date());

        JWTClaimsSet jwtClaimsSet;
        try {
            jwtClaimsSet = idTokenClaims.toJWTClaimsSet();
        } catch (ParseException e) {
            throw new RuntimeException("Can't convert IDTokenClaimsSet to JWTClaimsSet");
        }
        JWSHeader jwsHeader =
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build();
        SignedJWT idToken;

        try {
            idToken = new SignedJWT(jwsHeader, jwtClaimsSet);
            idToken.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return idToken;
    }

    public AccessToken issueToken(String email) {
        AccessToken accessToken = new BearerAccessToken();
        tokensMap.put(accessToken, email);

        return accessToken;
    }

    public String getEmailForToken(AccessToken token) {
        return tokensMap.get(token);
    }

    public JWK getSigningKey() {
        return signingKey;
    }
}
