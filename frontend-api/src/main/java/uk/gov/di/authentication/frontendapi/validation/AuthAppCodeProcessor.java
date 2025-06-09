package uk.gov.di.authentication.frontendapi.validation;

import org.apache.commons.codec.CodecPolicy;
import org.apache.commons.codec.binary.Base32;
import uk.gov.di.authentication.entity.CodeRequest;
import uk.gov.di.authentication.frontendapi.domain.FrontendAuditableEvent;
import uk.gov.di.authentication.shared.entity.CodeRequestType;
import uk.gov.di.authentication.shared.entity.ErrorResponse;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethod;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.helpers.NowHelper;
import uk.gov.di.authentication.shared.services.AuditService;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CodeStorageService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoAccountModifiersService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;
import uk.gov.di.authentication.shared.state.UserContext;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static uk.gov.di.authentication.shared.entity.mfa.MFAMethodType.AUTH_APP;
import static uk.gov.di.authentication.shared.services.CodeStorageService.CODE_BLOCKED_KEY_PREFIX;

public class AuthAppCodeProcessor extends MfaCodeProcessor {

    private final int windowTime;
    private final int allowedWindows;
    private final CodeRequest codeRequest;
    private static final Base32 base32 = new Base32(0, null, false, (byte) '=', CodecPolicy.STRICT);

    public AuthAppCodeProcessor(
            UserContext userContext,
            CodeStorageService codeStorageService,
            ConfigurationService configurationService,
            AuthenticationService dynamoService,
            int maxRetries,
            CodeRequest codeRequest,
            AuditService auditService,
            DynamoAccountModifiersService accountModifiersService,
            MFAMethodsService mfaMethodsService) {
        super(
                userContext,
                codeStorageService,
                maxRetries,
                dynamoService,
                auditService,
                accountModifiersService,
                mfaMethodsService);
        this.windowTime = configurationService.getAuthAppCodeWindowLength();
        this.allowedWindows = configurationService.getAuthAppCodeAllowedWindows();
        this.codeRequest = codeRequest;
    }

    @Override
    public Optional<ErrorResponse> validateCode() {
        var codeRequestType =
                CodeRequestType.getCodeRequestType(AUTH_APP, codeRequest.getJourneyType());
        var codeBlockedKeyPrefix = CODE_BLOCKED_KEY_PREFIX + codeRequestType;

        var nonRegistrationJourneyTypes =
                List.of(
                        JourneyType.SIGN_IN,
                        JourneyType.PASSWORD_RESET_MFA,
                        JourneyType.REAUTHENTICATION);

        if (isCodeBlockedForSession(codeBlockedKeyPrefix)) {
            LOG.info("Code blocked for session");
            return Optional.of(ErrorResponse.ERROR_1042);
        }

        if (codeRequestType.getJourneyType() != JourneyType.REAUTHENTICATION) {
            incrementRetryCount();
        }

        if (hasExceededRetryLimit()) {
            LOG.info("Exceeded code retry limit");
            return Optional.of(ErrorResponse.ERROR_1042);
        }

        var authAppSecret =
                nonRegistrationJourneyTypes.contains(codeRequest.getJourneyType())
                        ? getMfaCredentialValue().orElse(null)
                        : codeRequest.getProfileInformation();

        if (Objects.isNull(authAppSecret)) {
            LOG.info("No auth app secret found");
            return Optional.of(ErrorResponse.ERROR_1081);
        }

        if (!nonRegistrationJourneyTypes.contains(codeRequest.getJourneyType())
                && !base32.isInAlphabet(codeRequest.getProfileInformation())) {
            return Optional.of(ErrorResponse.ERROR_1041);
        }

        if (!isCodeValid(codeRequest.getCode(), authAppSecret)) {
            LOG.info("Auth code is not valid");
            return Optional.of(ErrorResponse.ERROR_1043);
        }
        LOG.info("Auth code valid. Resetting code request count");
        resetCodeIncorrectEntryCount();

        return Optional.empty();
    }

    @Override
    public void processSuccessfulCodeRequest(String ipAddress, String persistentSessionId) {
        switch (codeRequest.getJourneyType()) {
            case REGISTRATION:
                dynamoService.setAuthAppAndAccountVerified(
                        emailAddress, codeRequest.getProfileInformation());
                submitAuditEvent(
                        FrontendAuditableEvent.AUTH_UPDATE_PROFILE_AUTH_APP,
                        AUTH_APP,
                        AuditService.UNKNOWN,
                        ipAddress,
                        persistentSessionId,
                        false);
                break;
            case ACCOUNT_RECOVERY:
                dynamoService.setVerifiedAuthAppAndRemoveExistingMfaMethod(
                        emailAddress, codeRequest.getProfileInformation());
                submitAuditEvent(
                        FrontendAuditableEvent.AUTH_UPDATE_PROFILE_AUTH_APP,
                        AUTH_APP,
                        AuditService.UNKNOWN,
                        ipAddress,
                        persistentSessionId,
                        true);
                break;
            case SIGN_IN:
            case PASSWORD_RESET_MFA:
                clearAccountRecoveryBlockIfPresent(AUTH_APP, ipAddress, persistentSessionId);
        }
    }

    public boolean isCodeValid(String code, String secret) {
        if (code.isEmpty() || code.length() > 6) {
            return false;
        }

        int codeToCheck = Integer.parseInt(code);

        if (secret == null) {
            throw new IllegalArgumentException("Secret cannot be null.");
        }

        if (codeToCheck <= 0 || codeToCheck >= (int) Math.pow(10, 6)) {
            return false;
        }

        return checkCode(secret, codeToCheck, NowHelper.now().getTime());
    }

    private Optional<String> getMfaCredentialValue() {
        var userCredentials = dynamoService.getUserCredentialsFromEmail(emailAddress);
        var userProfile = dynamoService.getUserProfileByEmail(emailAddress);

        if (userCredentials == null) {
            LOG.info("User credentials not found");
            return Optional.empty();
        }

        if (userProfile.isMfaMethodsMigrated()) {
            var maybeAuthAppMfaMethod =
                    userCredentials.getMfaMethods().stream()
                            .filter(
                                    mfaMethod ->
                                            mfaMethod
                                                    .getMfaMethodType()
                                                    .equals(AUTH_APP.getValue()))
                            .findFirst();
            if (maybeAuthAppMfaMethod.isEmpty()) {
                LOG.error("No auth app method found for migrated user");
                return Optional.empty();
            }
            return Optional.of(maybeAuthAppMfaMethod.get().getCredentialValue());
        } else {
            var mfaMethod =
                    userCredentials.getMfaMethods().stream()
                            .filter(
                                    method ->
                                            method.getMfaMethodType()
                                                    .equals(MFAMethodType.AUTH_APP.getValue()))
                            .filter(MFAMethod::isEnabled)
                            .findAny();

            return mfaMethod.map(MFAMethod::getCredentialValue);
        }
    }

    private boolean checkCode(String secret, long code, long timestamp) {
        byte[] decodedKey = decodeSecret(secret);

        final long timeWindow = getTimeWindowFromTime(timestamp);

        for (int i = -((allowedWindows - 1) / 2); i <= allowedWindows / 2; ++i) {
            try {
                int calculatedCodeHash = calculateCode(decodedKey, timeWindow + i);
                if (calculatedCodeHash == code) {
                    return true;
                }
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                LOG.error("Error calculating TOTP hash from decoded secret", e);
                return false;
            }
        }
        return false;
    }

    private byte[] decodeSecret(String secret) {
        Base32 codec32 = new Base32();
        return codec32.decode(secret.toUpperCase());
    }

    private int calculateCode(byte[] key, long time)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];

        for (int i = 8; i-- > 0; time >>>= 8) {
            data[i] = (byte) time;
        }

        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");

        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);

        byte[] hash = mac.doFinal(data);

        int offset = hash[hash.length - 1] & 0xF;

        long truncatedHash = 0;

        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;

            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= (int) Math.pow(10, 6);

        return (int) truncatedHash;
    }

    private long getTimeWindowFromTime(long time) {
        return time / TimeUnit.SECONDS.toMillis(windowTime);
    }
}
