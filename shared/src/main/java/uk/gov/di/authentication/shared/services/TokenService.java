package uk.gov.di.authentication.shared.services;

import com.amazonaws.services.kms.model.GetPublicKeyRequest;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SignResult;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
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
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.AccessTokenStore;
import uk.gov.di.authentication.shared.entity.ClientConsent;
import uk.gov.di.authentication.shared.entity.RefreshTokenStore;
import uk.gov.di.authentication.shared.entity.ValidScopes;
import uk.gov.di.authentication.shared.helpers.IdGenerator;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.helpers.RequestBodyHelper;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.serialization.Json.JsonException;

import java.net.URI;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static uk.gov.di.authentication.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.authentication.shared.helpers.HashHelper.hashSha256String;
import static uk.gov.di.authentication.shared.helpers.InstrumentationHelper.segmentedFunctionCall;

public class TokenService {

    private final ConfigurationService configService;
    private final RedisConnectionService redisConnectionService;
    private final KmsConnectionService kmsConnectionService;
    private static final JWSAlgorithm TOKEN_ALGORITHM = JWSAlgorithm.ES256;
    private static final Logger LOG = LogManager.getLogger(TokenService.class);
    private static final String REFRESH_TOKEN_PREFIX = "REFRESH_TOKEN:";
    private static final String ACCESS_TOKEN_PREFIX = "ACCESS_TOKEN:";
    private static final List<String> ALLOWED_GRANTS =
            List.of(GrantType.AUTHORIZATION_CODE.getValue(), GrantType.REFRESH_TOKEN.getValue());

    private final Json objectMapper = SerializationService.getInstance();

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
            Subject internalSubject,
            Scope authRequestScopes,
            Map<String, Object> additionalTokenClaims,
            Subject subject,
            String vot,
            List<ClientConsent> clientConsents,
            boolean isConsentRequired,
            OIDCClaimsRequest claimsRequest,
            boolean isDocAppJourney) {
        List<String> scopesForToken;
        if (isConsentRequired) {
            scopesForToken = calculateScopesForToken(clientConsents, clientID, authRequestScopes);
        } else {
            scopesForToken = authRequestScopes.toStringList();
        }
        AccessToken accessToken =
                segmentedFunctionCall(
                        "generateAndStoreAccessToken",
                        () ->
                                generateAndStoreAccessToken(
                                        clientID,
                                        internalSubject,
                                        scopesForToken,
                                        subject,
                                        claimsRequest));
        AccessTokenHash accessTokenHash =
                segmentedFunctionCall(
                        "AccessTokenHash.compute",
                        () -> AccessTokenHash.compute(accessToken, TOKEN_ALGORITHM, null));
        SignedJWT idToken =
                segmentedFunctionCall(
                        "generateIDToken",
                        () ->
                                generateIDToken(
                                        clientID,
                                        subject,
                                        additionalTokenClaims,
                                        accessTokenHash,
                                        vot,
                                        isDocAppJourney));
        if (scopesForToken.contains(OIDCScopeValue.OFFLINE_ACCESS.getValue())) {
            RefreshToken refreshToken =
                    segmentedFunctionCall(
                            "generateAndStoreRefreshToken",
                            () ->
                                    generateAndStoreRefreshToken(
                                            clientID, internalSubject, scopesForToken, subject));
            return new OIDCTokenResponse(new OIDCTokens(idToken, accessToken, refreshToken));
        } else {
            return new OIDCTokenResponse(new OIDCTokens(idToken, accessToken, null));
        }
    }

    public OIDCTokenResponse generateRefreshTokenResponse(
            String clientID, Subject internalSubject, List<String> scopes, Subject subject) {
        AccessToken accessToken =
                generateAndStoreAccessToken(clientID, internalSubject, scopes, subject, null);
        RefreshToken refreshToken =
                generateAndStoreRefreshToken(clientID, internalSubject, scopes, subject);
        return new OIDCTokenResponse(new OIDCTokens(accessToken, refreshToken));
    }

    public Optional<ErrorObject> validateTokenRequestParams(String tokenRequestBody) {
        Map<String, String> requestBody = RequestBodyHelper.parseRequestBody(tokenRequestBody);
        if (!requestBody.containsKey("grant_type")) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE,
                            "Request is missing grant_type parameter"));
        }
        if (!ALLOWED_GRANTS.contains(requestBody.get("grant_type"))) {
            return Optional.of(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
        }
        if (requestBody.get("grant_type").equals(GrantType.AUTHORIZATION_CODE.getValue())) {
            if (!requestBody.containsKey("redirect_uri")) {
                return Optional.of(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing redirect_uri parameter"));
            }
            if (!requestBody.containsKey("code")) {
                return Optional.of(
                        new ErrorObject(
                                OAuth2Error.INVALID_REQUEST_CODE,
                                "Request is missing code parameter"));
            }
        } else if (requestBody.get("grant_type").equals(GrantType.REFRESH_TOKEN.getValue())) {
            return validateRefreshRequestParams(requestBody);
        }
        return Optional.empty();
    }

    public Optional<ErrorObject> validatePrivateKeyJWT(
            String requestString, String publicKey, String tokenUrl, String clientID) {
        PrivateKeyJWT privateKeyJWT;
        try {
            privateKeyJWT = PrivateKeyJWT.parse(requestString);
        } catch (ParseException e) {
            LOG.warn("Could not parse Private Key JWT");
            return Optional.of(OAuth2Error.INVALID_CLIENT);
        }
        if (hasPrivateKeyJwtExpired(privateKeyJWT.getClientAssertion())) {
            LOG.warn("PrivateKeyJWT has expired");
            return Optional.of(OAuth2Error.INVALID_GRANT);
        }
        if (Objects.isNull(privateKeyJWT.getClientID())
                || !privateKeyJWT.getClientID().toString().equals(clientID)) {
            LOG.warn("Invalid ClientID in PrivateKeyJWT");
            return Optional.of(OAuth2Error.INVALID_CLIENT);
        }
        ClientAuthenticationVerifier<?> authenticationVerifier =
                new ClientAuthenticationVerifier<>(
                        generateClientCredentialsSelector(publicKey),
                        Collections.singleton(new Audience(tokenUrl)));
        try {
            authenticationVerifier.verify(privateKeyJWT, null, null);
        } catch (InvalidClientException | JOSEException e) {
            LOG.warn("Unable to Verify Signature of Private Key JWT", e);
            return Optional.of(OAuth2Error.INVALID_CLIENT);
        }
        return Optional.empty();
    }

    public Optional<String> getClientIDFromPrivateKeyJWT(String requestString) {
        PrivateKeyJWT privateKeyJWT;
        try {
            privateKeyJWT = PrivateKeyJWT.parse(requestString);
        } catch (ParseException e) {
            LOG.warn("Could not parse Private Key JWT");
            return Optional.empty();
        }
        if (Objects.isNull(privateKeyJWT.getClientID())) {
            LOG.warn("Invalid ClientID in PrivateKeyJWT");
            return Optional.empty();
        }
        return Optional.of(privateKeyJWT.getClientID().toString());
    }

    private List<String> calculateScopesForToken(
            List<ClientConsent> clientConsents, String clientID, Scope authRequestScopes) {
        ClientConsent clientConsent =
                clientConsents.stream()
                        .filter(consent -> consent.getClientId().equals(clientID))
                        .findFirst()
                        .orElse(null);
        if (clientConsent == null) {
            LOG.warn("Client consent is empty for user");
            throw new RuntimeException("Client consent is empty for user");
        }
        Set<String> claimsFromAuthnRequest =
                ValidScopes.getClaimsForListOfScopes(authRequestScopes.toStringList());
        Set<String> claims =
                clientConsent.getClaims().stream()
                        .filter(t -> claimsFromAuthnRequest.stream().anyMatch(t::equals))
                        .collect(Collectors.toSet());
        List<String> scopesForIdToken = ValidScopes.getScopesForListOfClaims(claims);
        if (authRequestScopes.contains(OIDCScopeValue.OFFLINE_ACCESS.getValue())) {
            scopesForIdToken.add(OIDCScopeValue.OFFLINE_ACCESS.getValue());
        }
        return scopesForIdToken;
    }

    private Optional<ErrorObject> validateRefreshRequestParams(Map<String, String> requestBody) {
        if (!requestBody.containsKey("refresh_token")) {
            return Optional.of(
                    new ErrorObject(
                            OAuth2Error.INVALID_REQUEST_CODE, "Request is missing refresh token"));
        }
        try {
            RefreshToken refreshToken = new RefreshToken(requestBody.get("refresh_token"));
        } catch (IllegalArgumentException e) {
            LOG.warn("Invalid RefreshToken", e);
            return Optional.of(
                    new ErrorObject(OAuth2Error.INVALID_REQUEST_CODE, "Invalid refresh token"));
        }
        return Optional.empty();
    }

    private SignedJWT generateIDToken(
            String clientId,
            Subject subject,
            Map<String, Object> additionalTokenClaims,
            AccessTokenHash accessTokenHash,
            String vot,
            boolean isDocAppJourney) {

        LOG.info("Generating IdToken");
        URI trustMarkUri = buildURI(configService.getOidcApiBaseURL().get(), "/trustmark");
        Date expiryDate = NowHelper.nowPlus(configService.getIDTokenExpiry(), ChronoUnit.SECONDS);
        IDTokenClaimsSet idTokenClaims =
                new IDTokenClaimsSet(
                        new Issuer(configService.getOidcApiBaseURL().get()),
                        subject,
                        List.of(new Audience(clientId)),
                        expiryDate,
                        NowHelper.now());
        idTokenClaims.setAccessTokenHash(accessTokenHash);
        idTokenClaims.putAll(additionalTokenClaims);
        if (!isDocAppJourney) {
            idTokenClaims.setClaim("vot", vot);
        }
        idTokenClaims.setClaim("vtm", trustMarkUri.toString());
        try {
            return generateSignedJWT(idTokenClaims.toJWTClaimsSet(), Optional.empty());
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            LOG.error("Error when trying to parse IDTokenClaims to JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }

    private AccessToken generateAndStoreAccessToken(
            String clientId,
            Subject internalSubject,
            List<String> scopes,
            Subject subject,
            OIDCClaimsRequest claimsRequest) {

        LOG.info("Generating AccessToken");
        Date expiryDate =
                NowHelper.nowPlus(configService.getAccessTokenExpiry(), ChronoUnit.SECONDS);
        var jwtID = UUID.randomUUID().toString();

        LOG.info("AccessToken being created with JWTID: {}", jwtID);

        JWTClaimsSet.Builder claimSetBuilder =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer(configService.getOidcApiBaseURL().get())
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .claim("client_id", clientId)
                        .subject(subject.getValue())
                        .jwtID(jwtID);

        if (Objects.nonNull(claimsRequest)) {
            claimSetBuilder.claim(
                    "claims",
                    claimsRequest.getUserInfoClaimsRequest().getEntries().stream()
                            .map(ClaimsSetRequest.Entry::getClaimName)
                            .collect(Collectors.toList()));
        }

        SignedJWT signedJWT = generateSignedJWT(claimSetBuilder.build(), Optional.empty());
        AccessToken accessToken = new BearerAccessToken(signedJWT.serialize());

        try {
            redisConnectionService.saveWithExpiry(
                    ACCESS_TOKEN_PREFIX + clientId + "." + subject.getValue(),
                    objectMapper.writeValueAsString(
                            new AccessTokenStore(
                                    accessToken.getValue(), internalSubject.getValue())),
                    configService.getAccessTokenExpiry());
        } catch (JsonException e) {
            LOG.error("Unable to save access token to Redis");
            throw new RuntimeException(e);
        }
        return accessToken;
    }

    private RefreshToken generateAndStoreRefreshToken(
            String clientId, Subject internalSubject, List<String> scopes, Subject subject) {
        LOG.info("Generating RefreshToken");
        Date expiryDate = NowHelper.nowPlus(configService.getSessionExpiry(), ChronoUnit.SECONDS);
        var jwtId = IdGenerator.generate();
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopes)
                        .issuer(configService.getOidcApiBaseURL().get())
                        .expirationTime(expiryDate)
                        .issueTime(NowHelper.now())
                        .claim("client_id", clientId)
                        .subject(subject.getValue())
                        .jwtID(jwtId)
                        .build();
        SignedJWT signedJWT = generateSignedJWT(claimsSet, Optional.empty());
        RefreshToken refreshToken = new RefreshToken(signedJWT.serialize());

        String redisKey = REFRESH_TOKEN_PREFIX + jwtId;
        var store = new RefreshTokenStore(refreshToken.getValue(), internalSubject.toString());
        try {
            redisConnectionService.saveWithExpiry(
                    redisKey,
                    objectMapper.writeValueAsString(store),
                    configService.getSessionExpiry());
        } catch (JsonException e) {
            throw new RuntimeException("Error serializing refresh token store", e);
        }

        return refreshToken;
    }

    public SignedJWT generateSignedJWT(JWTClaimsSet claimsSet, Optional<String> type) {

        var signingKeyId =
                kmsConnectionService
                        .getPublicKey(
                                new GetPublicKeyRequest()
                                        .withKeyId(configService.getTokenSigningKeyAlias()))
                        .getKeyId();

        try {
            var jwsHeader =
                    new JWSHeader.Builder(TOKEN_ALGORITHM).keyID(hashSha256String(signingKeyId));

            type.map(JOSEObjectType::new).ifPresent(jwsHeader::type);

            Base64URL encodedHeader = jwsHeader.build().toBase64URL();
            Base64URL encodedClaims = Base64URL.encode(claimsSet.toString());
            String message = encodedHeader + "." + encodedClaims;
            ByteBuffer messageToSign = ByteBuffer.wrap(message.getBytes());
            SignRequest signRequest = new SignRequest();
            signRequest.setMessage(messageToSign);
            signRequest.setKeyId(configService.getTokenSigningKeyAlias());
            signRequest.setSigningAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256.toString());
            SignResult signResult = kmsConnectionService.sign(signRequest);
            LOG.info("Token has been signed successfully");
            String signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResult.getSignature().array(),
                                            ECDSA.getSignatureByteArrayLength(TOKEN_ALGORITHM)))
                            .toString();
            return SignedJWT.parse(message + "." + signature);
        } catch (java.text.ParseException | JOSEException e) {
            LOG.error("Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
            throw new RuntimeException(e);
        }
    }

    private boolean hasPrivateKeyJwtExpired(SignedJWT signedJWT) {
        try {
            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Date currentDateTime = NowHelper.now();
            if (DateUtils.isBefore(claimsSet.getExpirationTime(), currentDateTime, 30)) {
                return true;
            }
        } catch (java.text.ParseException e) {
            LOG.warn("Unable to parse PrivateKeyJwt when checking if expired", e);
            return true;
        }
        return false;
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
