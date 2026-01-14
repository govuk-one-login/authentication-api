package uk.gov.di.authentication.frontendapi.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;
import uk.gov.di.authentication.frontendapi.entity.AMCAuthorizeFailureReason;
import uk.gov.di.authentication.frontendapi.entity.AMCScope;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.Result;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.KmsConnectionService;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public class AMCAuthorizationService {
    private final ConfigurationService configurationService;
    private final NowHelper.NowClock nowClock;
    private final KmsConnectionService kmsConnectionService;
    private static final Logger LOG = LogManager.getLogger(AMCAuthorizationService.class);
    private static final int ECDSA_P256_SIGNATURE_LENGTH = 64; // 32 bytes R + 32 bytes S for ES256

    public AMCAuthorizationService(
            ConfigurationService configurationService,
            NowHelper.NowClock nowClock,
            KmsConnectionService kmsConnectionService) {
        this.configurationService = configurationService;
        this.nowClock = nowClock;
        this.kmsConnectionService = kmsConnectionService;
    }

    Result<AMCAuthorizeFailureReason, BearerAccessToken> createAccessToken(
            Subject internalPairwiseSubject, AMCScope[] scope, AuthSessionItem authSessionItem) {
        LOG.info("Generating access token");
        Date issueTime = nowClock.now();
        Date expiryDate =
                nowClock.nowPlus(configurationService.getSessionExpiry(), ChronoUnit.SECONDS);
        List<String> scopeValues = Arrays.stream(scope).map(AMCScope::getValue).toList();

        var claims =
                new JWTClaimsSet.Builder()
                        .claim("scope", scopeValues)
                        .issuer(configurationService.getAuthIssuerClaim())
                        .audience(configurationService.getAuthToAuthAudience())
                        .expirationTime(expiryDate)
                        .issueTime(issueTime)
                        .notBeforeTime(issueTime)
                        .subject(internalPairwiseSubject.getValue())
                        .claim("client_id", authSessionItem.getClientId())
                        .claim("sid", authSessionItem.getSessionId())
                        .jwtID(UUID.randomUUID().toString())
                        .build();

        Result<AMCAuthorizeFailureReason, SignedJWT> signJWTResult =
                signJWT(
                        claims,
                        configurationService.getAuthToAccountManagementPrivateSigningKeyAlias());

        if (signJWTResult.isFailure()) {
            return Result.failure(signJWTResult.getFailure());
        }

        Scope oauthScope = new Scope(scopeValues.toArray(new String[0]));
        BearerAccessToken bearerToken =
                new BearerAccessToken(
                        signJWTResult.getSuccess().serialize(),
                        configurationService.getSessionExpiry(),
                        oauthScope);

        return Result.success(bearerToken);
    }

    private Result<AMCAuthorizeFailureReason, SignedJWT> signJWT(
            JWTClaimsSet claims, String keyId) {
        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();

        Base64URL encodedHeader = header.toBase64URL();
        Base64URL encodedClaims = claims.toPayload().toBase64URL();
        String signingInput = encodedHeader + "." + encodedClaims;

        SignResponse signResponse;
        try {
            SignRequest signRequest =
                    SignRequest.builder()
                            .keyId(keyId)
                            .message(
                                    SdkBytes.fromByteArray(
                                            signingInput.getBytes(StandardCharsets.UTF_8)))
                            .messageType(MessageType.RAW)
                            .signingAlgorithm(SigningAlgorithmSpec.ECDSA_SHA_256)
                            .build();

            signResponse = kmsConnectionService.sign(signRequest);
        } catch (SdkException e) {
            LOG.error("Failed to sign token via AWS KMS", e);
            return Result.failure(AMCAuthorizeFailureReason.KMS_ERROR);
        }

        Base64URL signature;
        try {
            // AWS KMS returns ECDSA signatures in ASN.1 DER format.
            // However, the JWS specification (RFC 7515) requires the signature to be in
            // raw "R + S" concatenated format (IEEE P1363).
            // We must transcode the bytes to ensure the JWT is valid and verifiable.
            byte[] derSignature = signResponse.signature().asByteArray();
            byte[] joseSignature =
                    ECDSA.transcodeSignatureToConcat(derSignature, ECDSA_P256_SIGNATURE_LENGTH);
            signature = Base64URL.encode(joseSignature);
        } catch (JOSEException e) {
            LOG.error("Failed to transcode KMS signature from DER to JOSE format", e);
            return Result.failure(AMCAuthorizeFailureReason.TRANSCODING_ERROR);
        }

        try {
            return Result.success(new SignedJWT(encodedHeader, encodedClaims, signature));
        } catch (ParseException e) {
            LOG.error("Failed to construct final SignedJWT object", e);
            return Result.failure(AMCAuthorizeFailureReason.JWT_CONSTRUCTION_ERROR);
        }
    }
}
