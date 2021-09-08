package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.GetPublicKeyResult;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.authentication.shared.helpers.RequestBodyHelper;

import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class TokenService {

    private final ConfigurationService configService;
    private final RedisConnectionService redisConnectionService;
    private final KmsConnectionService kmsConnectionService;
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenService.class);

    public TokenService(
            ConfigurationService configService,
            RedisConnectionService redisConnectionService,
            KmsConnectionService kmsConnectionService) {
        this.configService = configService;
        this.redisConnectionService = redisConnectionService;
        this.kmsConnectionService = kmsConnectionService;
    }

    public OIDCTokenResponse generateTokenResponse(
            String clientID,
            Subject subject,
            List<String> scopes,
            Map<String, Object> additionalTokenClaims) {
        AccessToken accessToken = generateAndStoreAccessToken(clientID, subject, scopes);
        SignedJWT idToken = generateIDToken(clientID, subject, additionalTokenClaims);
        return new OIDCTokenResponse(new OIDCTokens(idToken, accessToken, null));
    }

    public Optional<String> getSubjectWithAccessToken(AccessToken token) {
        return Optional.ofNullable(redisConnectionService.getValue(token.toJSONString()));
    }

    public boolean validateIdTokenSignature(String idTokenHint) {
        try {
            LOGGER.info("Validating ID token signature");
            LOGGER.info("IDTokenHint: " + idTokenHint);
            LOGGER.info("TokenSigningKeyID: " + configService.getTokenSigningKeyAlias());
            SignedJWT idToken = SignedJWT.parse(idTokenHint);
            LOGGER.info("ClientID:" + idToken.getJWTClaimsSet().getAudience().get(0));
            LOGGER.info("Issuer: " + configService.getBaseURL().get());
            JWK publicJwk = getPublicJwk();
            LOGGER.info("PublicJWK: " + publicJwk.toString());
            JWKSet jwkSet = new JWKSet(publicJwk);
            LOGGER.info("JWKSET: " + jwkSet);
            IDTokenValidator validator =
                    new IDTokenValidator(
                            new Issuer(configService.getBaseURL().get()),
                            new ClientID(idToken.getJWTClaimsSet().getAudience().get(0)),
                            JWSAlgorithm.ES256,
                            jwkSet);
            JWSKeySelector jwsKeySelector = validator.getJWSKeySelector();
            LOGGER.info("KEYSELECTOR: " + jwsKeySelector.selectJWSKeys(idToken.getHeader(), null));
            validator.validate(idToken, null);
        } catch (java.text.ParseException | JOSEException | BadJOSEException e) {
            LOGGER.error("Unable to validate Signature of ID token", e);
            return false;
        }
        return true;
    }

    public boolean validateAccessTokenSignature(AccessToken accessToken) {
        boolean isVerified;
        try {
            LOGGER.info("Validating Access Token signature");
            LOGGER.info("TokenSigningKeyID: " + configService.getTokenSigningKeyAlias());
            SignedJWT signedJwt = SignedJWT.parse(accessToken.getValue());
            JWSVerifier verifier = new ECDSAVerifier(getPublicJwk().toECKey());
            isVerified = signedJwt.verify(verifier);
        } catch (JOSEException | java.text.ParseException e) {
            LOGGER.error("Unable to validate Signature of Access token", e);
            return false;
        }
        return isVerified;
    }

    public PublicKey getPublicKey() {
        LOGGER.info("Creating GetPublicKeyRequest to retrieve PublicKey from KMS");
        Provider bcProvider = new BouncyCastleProvider();
        GetPublicKeyRequest getPublicKeyRequest = new GetPublicKeyRequest();
        getPublicKeyRequest.setKeyId(configService.getTokenSigningKeyAlias());
        GetPublicKeyResult publicKeyResult = kmsConnectionService.getPublicKey(getPublicKeyRequest);
        try {
            LOGGER.info("PUBLICKEYRESULT: " + publicKeyResult.toString());
            SubjectPublicKeyInfo subjectKeyInfo =
                    SubjectPublicKeyInfo.getInstance(publicKeyResult.getPublicKey().array());
            return new JcaPEMKeyConverter().setProvider(bcProvider).getPublicKey(subjectKeyInfo);
        } catch (PEMException e) {
            LOGGER.error("Error getting the PublicKey using the JcaPEMKeyConverter", e);
            throw new RuntimeException();
        }
    }

    public JWK getPublicJwk() {
        try {
            PublicKey publicKey = getPublicKey();
            ECKey jwk =
                    new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                            .keyID(configService.getTokenSigningKeyAlias())
                            .keyUse(KeyUse.SIGNATURE)
                            .algorithm(new Algorithm(JWSAlgorithm.ES256.getName()))
                            .build();
            LOGGER.info("ECKey: " + jwk.toJSONString());
            LOGGER.info("ECKey KeyID: " + jwk.getKeyID());
            return JWK.parse(jwk.toJSONObject());
        } catch (java.text.ParseException e) {
            LOGGER.error("Error parsing the ECKey to JWK", e);
            throw new RuntimeException(e);
        }
    }

    public Optional<ErrorObject> validateTokenRequestParams(String tokenRequestBody) {
        Map<String, String> requestBody = RequestBodyHelper.parseRequestBody(tokenRequestBody);
        if (!requestBody.containsKey("client_id")) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Request is missing client_id parameter"));
        }
        if (!requestBody.containsKey("redirect_uri")) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Request is missing redirect_uri parameter"));
        }
        if (!requestBody.containsKey("grant_type")) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Request is missing grant_type parameter"));
        }
        if (!requestBody.get("grant_type").equals(GrantType.AUTHORIZATION_CODE.getValue())) {
            return Optional.of(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
        }
        if (!requestBody.containsKey("code")) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "Request is missing code parameter"));
        }
        return Optional.empty();
    }

    public Optional<ErrorObject> validatePrivateKeyJWT(
            String requestString, String publicKey, String tokenUrl) {
        PrivateKeyJWT privateKeyJWT;
        try {
            privateKeyJWT = PrivateKeyJWT.parse(requestString);
        } catch (ParseException e) {
            LOGGER.error("Couldn't parse Private Key JWT", e);
            return Optional.of(OAuth2Error.INVALID_CLIENT);
        }
        ClientAuthenticationVerifier<?> authenticationVerifier =
                new ClientAuthenticationVerifier<>(
                        generateClientCredentialsSelector(publicKey),
                        Collections.singleton(new Audience(tokenUrl)));
        try {
            authenticationVerifier.verify(privateKeyJWT, null, null);
        } catch (InvalidClientException | JOSEException e) {
            LOGGER.error("Unable to Verify Signature of Private Key JWT", e);
            return Optional.of(OAuth2Error.INVALID_CLIENT);
        }
        return Optional.empty();
    }

    private SignedJWT generateIDToken(
            String clientId, Subject subject, Map<String, Object> additionalTokenClaims) {
        LOGGER.info("Generating IdToken for ClientId: {}", clientId);
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
        IDTokenClaimsSet idTokenClaims =
                new IDTokenClaimsSet(
                        new Issuer(configService.getBaseURL().get()),
                        subject,
                        List.of(new Audience(clientId)),
                        expiryDate,
                        new Date());
        idTokenClaims.putAll(additionalTokenClaims);
        try {
            return generateSignedJWT(idTokenClaims.toJWTClaimsSet());
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOGGER.error("Error when trying to parse IDTokenClaims to JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }

    private AccessToken generateAndStoreAccessToken(
            String clientId, Subject subject, List<String> scopes) {
        LOGGER.info("Generating AccessToken for ClientId: {}", clientId);
        LocalDateTime localDateTime = LocalDateTime.now().plusMinutes(2);
        Date expiryDate = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());

        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer(configService.getBaseURL().get())
                        .expirationTime(expiryDate)
                        .issueTime(
                                Date.from(
                                        LocalDateTime.now()
                                                .atZone(ZoneId.systemDefault())
                                                .toInstant()))
                        .claim("client_id", clientId)
                        .subject(subject.getValue())
                        .jwtID(UUID.randomUUID().toString())
                        .build();
        SignedJWT signedJWT = generateSignedJWT(claimsSet);
        AccessToken accessToken = new BearerAccessToken(signedJWT.serialize());

        redisConnectionService.saveWithExpiry(
                accessToken.toJSONString(),
                subject.toString(),
                configService.getAccessTokenExpiry());
        return accessToken;
    }

    private SignedJWT generateSignedJWT(JWTClaimsSet claimsSet) {
        try {
            JWSHeader jwsHeader =
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(configService.getTokenSigningKeyAlias())
                            .build();
            Base64URL encodedHeader = jwsHeader.toBase64URL();
            Base64URL encodedClaims = Base64URL.encode(claimsSet.toString());
            String message = encodedHeader + "." + encodedClaims;
            ByteBuffer messageToSign = ByteBuffer.wrap(message.getBytes());
            SignRequest signRequest = new SignRequest();
            signRequest.setMessage(messageToSign);
            signRequest.setKeyId(configService.getTokenSigningKeyAlias());
            signRequest.setSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString());
            SignResult signResult = kmsConnectionService.sign(signRequest);
            LOGGER.info("Token has been signed successfully");
            String signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.getSignature().array(),
                                            ECDSA.getSignatureByteArrayLength(JWSAlgorithm.ES256)))
                            .toString();
            return SignedJWT.parse(message + "." + signature);
        } catch (java.text.ParseException | JOSEException e) {
            LOGGER.error("Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }

    private ClientCredentialsSelector<?> generateClientCredentialsSelector(String publicKey) {
        return new ClientCredentialsSelector<>() {
            @Override
            public List<Secret> selectClientSecrets(
                    ClientID claimedClientID,
                    ClientAuthenticationMethod authMethod,
                    com.nimbusds.oauth2.sdk.auth.verifier.Context context) {
                return null;
            }

            @Override
            public List<PublicKey> selectPublicKeys(
                    ClientID claimedClientID,
                    ClientAuthenticationMethod authMethod,
                    JWSHeader jwsHeader,
                    boolean forceRefresh,
                    com.nimbusds.oauth2.sdk.auth.verifier.Context context) {

                byte[] decodedKey = Base64.getMimeDecoder().decode(publicKey);
                try {
                    X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(decodedKey);
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    return Collections.singletonList(kf.generatePublic(x509publicKey));
                } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }
}
