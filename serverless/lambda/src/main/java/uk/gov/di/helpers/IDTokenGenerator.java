package uk.gov.di.helpers;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

public class IDTokenGenerator {

    public static SignedJWT generateIDToken(
            String clientId, Subject subject, String issuerUrl, RSAKey signingKey) {
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
        IDTokenClaimsSet idTokenClaims =
                new IDTokenClaimsSet(
                        new Issuer(issuerUrl),
                        subject,
                        List.of(new Audience(clientId)),
                        expiryDate,
                        new Date());
        JWSHeader jwsHeader =
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build();
        SignedJWT idToken;

        try {
            RSASSASigner signer = new RSASSASigner(signingKey);
            idToken = new SignedJWT(jwsHeader, idTokenClaims.toJWTClaimsSet());
            idToken.sign(signer);
        } catch (JOSEException | ParseException e) {
            throw new RuntimeException(e);
        }
        return idToken;
    }
}
