package uk.gov.di.authentication.oidc.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.orchestration.shared.exceptions.JwtParseException;
import uk.gov.di.orchestration.shared.exceptions.TokenRequestException;
import uk.gov.di.orchestration.shared.exceptions.TokenResponseException;
import uk.gov.di.orchestration.shared.exceptions.UnsuccessfulCredentialResponseException;
import uk.gov.di.orchestration.shared.helpers.NowHelper;
import uk.gov.di.orchestration.shared.services.ConfigurationService;
import uk.gov.di.orchestration.shared.services.KmsConnectionService;
import uk.gov.di.orchestration.shared.tracing.JavaHttpRequestSender;
import uk.gov.di.orchestration.shared.tracing.TracingHttpClient;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static uk.gov.di.orchestration.shared.helpers.ConstructUriHelper.buildURI;
import static uk.gov.di.orchestration.shared.helpers.HashHelper.hashSha256String;

public class AuthenticationTokenService {
    private final ConfigurationService configurationService;
    private final KmsConnectionService kmsService;
    private static final JWSAlgorithm TOKEN_ALGORITHM = JWSAlgorithm.ES256;
    private static final Long PRIVATE_KEY_JWT_EXPIRY = 5L;
    private static final Logger LOG = LogManager.getLogger(AuthenticationTokenService.class);

    public AuthenticationTokenService(
            ConfigurationService configurationService, KmsConnectionService kmsService) {
        this.configurationService = configurationService;
        this.kmsService = kmsService;
    }

    public TokenRequest constructTokenRequest(String authCode) {
        LOG.info("Constructing token request");
        var codeGrant =
                new AuthorizationCodeGrant(
                        new AuthorizationCode(authCode),
                        configurationService.getAuthenticationAuthCallbackURI());
        var authenticationBackendURI = configurationService.getAuthenticationBackendURI();
        var tokenURI = buildURI(authenticationBackendURI.toString(), "token");
        var claimsSet =
                new JWTAuthenticationClaimsSet(
                        new ClientID(configurationService.getOrchestrationClientId()),
                        singletonList(new Audience(tokenURI)),
                        NowHelper.nowPlus(PRIVATE_KEY_JWT_EXPIRY, ChronoUnit.MINUTES),
                        NowHelper.now(),
                        NowHelper.now(),
                        new JWTID());
        return new TokenRequest(
                tokenURI,
                generatePrivateKeyJwt(claimsSet),
                codeGrant,
                null,
                singletonList(tokenURI),
                Map.of(
                        "client_id",
                        singletonList(configurationService.getOrchestrationClientId())));
    }

    public TokenResponse sendTokenRequest(TokenRequest tokenRequest) {
        var tracingHttpClient = new JavaHttpRequestSender(TracingHttpClient.newHttpClient());
        try {
            LOG.info("Sending TokenRequest");
            int count = 0;
            int maxTries = 2;
            TokenResponse tokenResponse;
            do {
                if (count > 0) LOG.warn("Retrying Authentication token request");
                count++;
                tokenResponse =
                        TokenResponse.parse(tokenRequest.toHTTPRequest().send(tracingHttpClient));
                if (!tokenResponse.indicatesSuccess()) {
                    HTTPResponse response = tokenResponse.toHTTPResponse();
                    LOG.warn(
                            format(
                                    "Unsuccessful %s response from Authentication token endpoint on attempt %d: %s ",
                                    response.getStatusCode(), count, response.getContent()));
                }
            } while (!tokenResponse.indicatesSuccess() && count < maxTries);
            return tokenResponse;
        } catch (IOException e) {
            LOG.error("Error whilst sending TokenRequest", e);
            throw new TokenRequestException("Error whilst sending TokenRequest", e);
        } catch (ParseException e) {
            LOG.error("Error whilst parsing TokenResponse", e);
            throw new TokenResponseException("Error whilst parsing TokenResponse", e);
        }
    }

    public UserInfo sendUserInfoDataRequest(HTTPRequest request)
            throws UnsuccessfulCredentialResponseException {
        var tracingHttpClient = new JavaHttpRequestSender(TracingHttpClient.newHttpClient());
        try {
            LOG.info("Sending userinfo request");
            int count = 0;
            int maxTries = 2;
            HTTPResponse response;
            do {
                if (count > 0) LOG.warn("Retrying Authentication userinfo request");
                count++;
                response = request.send(tracingHttpClient);
                if (!response.indicatesSuccess()) {
                    LOG.warn(
                            format(
                                    "Unsuccessful %s response from Authentication userinfo endpoint on attempt %d: %s ",
                                    response.getStatusCode(), count, response.getContent()));
                }
            } while (!response.indicatesSuccess() && count < maxTries);
            if (!response.indicatesSuccess()) {
                throw new UnsuccessfulCredentialResponseException(
                        format(
                                "Error %s when attempting to call Authentication userinfo endpoint: %s",
                                response.getStatusCode(), response.getContent()));
            }

            LOG.info("Received successful userinfo response");
            return parseUserInfoFromResponse(response);
        } catch (IOException e) {
            throw new UnsuccessfulCredentialResponseException(
                    "Error when attempting to call Authentication userinfo endpoint", e);
        }
    }

    UserInfo parseUserInfoFromResponse(HTTPResponse response)
            throws UnsuccessfulCredentialResponseException {
        try {
            String content = response.getContent();
            if (content == null) {
                throw new UnsuccessfulCredentialResponseException("No content in HTTP response");
            }
            return UserInfo.parse(content);
        } catch (ParseException e) {
            LOG.warn("Unable to parse userinfo response as UserInfo object");
            throw new UnsuccessfulCredentialResponseException(
                    "Error parsing authentication userinfo response as JSON", e);
        }
    }

    private PrivateKeyJWT generatePrivateKeyJwt(JWTAuthenticationClaimsSet claimsSet) {
        try {
            LOG.info("Generating PrivateKeyJWT");
            var tokenSigningKeyAlias =
                    configurationService.getOrchestrationToAuthenticationTokenSigningKeyAlias();
            var signingKeyId =
                    kmsService
                            .getPublicKey(
                                    GetPublicKeyRequest.builder()
                                            .keyId(tokenSigningKeyAlias)
                                            .build())
                            .keyId();
            var jwsHeader =
                    new JWSHeader.Builder(TOKEN_ALGORITHM)
                            .keyID(hashSha256String(signingKeyId))
                            .build();
            var encodedHeader = jwsHeader.toBase64URL();
            var encodedClaims = Base64URL.encode(claimsSet.toJWTClaimsSet().toString());
            var message = encodedHeader + "." + encodedClaims;
            var messageToSign = ByteBuffer.wrap(message.getBytes(StandardCharsets.UTF_8));
            var signRequest =
                    SignRequest.builder()
                            .message(SdkBytes.fromByteBuffer(messageToSign))
                            .keyId(tokenSigningKeyAlias)
                            .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                            .build();
            var signResponse = kmsService.sign(signRequest);
            LOG.info("PrivateKeyJWT has been signed successfully");
            var signature =
                    Base64URL.encode(
                                    ECDSA.transcodeSignatureToConcat(
                                            signResponse.signature().asByteArray(),
                                            ECDSA.getSignatureByteArrayLength(TOKEN_ALGORITHM)))
                            .toString();
            return new PrivateKeyJWT(SignedJWT.parse(message + "." + signature));
        } catch (JOSEException | java.text.ParseException e) {
            LOG.error("Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
            throw new JwtParseException(
                    "Exception thrown when trying to parse SignedJWT or JWTClaimSet", e);
        }
    }
}
