package uk.gov.di.authentication.external.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkBytes;
import uk.gov.di.authentication.external.entity.AuthUserInfoClaims;
import uk.gov.di.authentication.shared.entity.AuthSessionItem;
import uk.gov.di.authentication.shared.entity.PriorityIdentifier;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.entity.mfa.MFAMethodType;
import uk.gov.di.authentication.shared.entity.token.AccessTokenStore;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.mfa.MFAMethodsService;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Objects;

public class UserInfoService {

    private final AuthenticationService authenticationService;
    private final MFAMethodsService mfaMethodsService;
    private final ConfigurationService configurationService;
    private static final Logger LOG = LogManager.getLogger(UserInfoService.class);

    public UserInfoService(
            AuthenticationService authenticationService,
            MFAMethodsService mfaMethodsService,
            ConfigurationService configurationService) {
        this.authenticationService = authenticationService;
        this.mfaMethodsService = mfaMethodsService;
        this.configurationService = configurationService;
    }

    public UserInfo populateUserInfo(
            AccessTokenStore accessTokenInfo, AuthSessionItem authSession) {
        LOG.info("Populating Authentication UserInfo");
        String internalSubjectId = accessTokenInfo.getSubjectID();
        var userProfile = authenticationService.getUserProfileFromSubject(internalSubjectId);

        Subject internalPairwiseId =
                ClientSubjectHelper.getSubjectWithSectorIdentifier(
                        userProfile,
                        configurationService.getInternalSectorUri(),
                        authenticationService);

        var userInfo = new UserInfo(internalPairwiseId);
        addClaimsFromToken(accessTokenInfo, internalSubjectId, userProfile, userInfo);
        addClaimsFromSession(accessTokenInfo, authSession, userInfo);
        return userInfo;
    }

    private void addClaimsFromToken(
            AccessTokenStore accessTokenInfo,
            String internalSubjectId,
            UserProfile userProfile,
            UserInfo userInfo) {
        var rpPairwiseId =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        internalSubjectId,
                        accessTokenInfo.getSectorIdentifier(),
                        SdkBytes.fromByteBuffer(userProfile.getSalt()).asByteArray());

        userInfo.setClaim("rp_pairwise_id", rpPairwiseId);
        userInfo.setClaim(
                AuthUserInfoClaims.NEW_ACCOUNT.getValue(), accessTokenInfo.getIsNewAccount());
        userInfo.setClaim("password_reset_time", accessTokenInfo.getPasswordResetTime());

        if (accessTokenInfo.getClaims().contains(AuthUserInfoClaims.LEGACY_SUBJECT_ID.getValue())) {
            userInfo.setClaim("legacy_subject_id", userProfile.getLegacySubjectID());
        }
        if (accessTokenInfo.getClaims().contains(AuthUserInfoClaims.PUBLIC_SUBJECT_ID.getValue())) {
            userInfo.setClaim("public_subject_id", userProfile.getPublicSubjectID());
        }
        if (accessTokenInfo.getClaims().contains(AuthUserInfoClaims.LOCAL_ACCOUNT_ID.getValue())) {
            userInfo.setClaim("local_account_id", userProfile.getSubjectID());
        }
        if (accessTokenInfo.getClaims().contains(AuthUserInfoClaims.EMAIL.getValue())) {
            userInfo.setEmailAddress(userProfile.getEmail());
        }
        if (accessTokenInfo.getClaims().contains(AuthUserInfoClaims.EMAIL_VERIFIED.getValue())) {
            userInfo.setEmailVerified(userProfile.isEmailVerified());
        }
        if (accessTokenInfo.getClaims().contains(AuthUserInfoClaims.SALT.getValue())) {
            String base64StringFromSalt = bytesToBase64(userProfile.getSalt());
            LOG.info("is salt from UserProfile defined: {}", base64StringFromSalt != null);
            userInfo.setClaim("salt", base64StringFromSalt);
        }

        var phoneData = getPhoneDataIfSMSIsDefault(userProfile);
        if (accessTokenInfo.getClaims().contains(AuthUserInfoClaims.PHONE_NUMBER.getValue())) {
            userInfo.setPhoneNumber(phoneData.phoneNumber());
        }
        if (accessTokenInfo.getClaims().contains(AuthUserInfoClaims.PHONE_VERIFIED.getValue())) {
            userInfo.setPhoneNumberVerified(phoneData.phoneNumberVerified());
        }
    }

    public record PhoneData(String phoneNumber, boolean phoneNumberVerified) {}

    public PhoneData getPhoneDataIfSMSIsDefault(UserProfile userProfile) {
        var retrievedMfaMethods = mfaMethodsService.getMfaMethods(userProfile.getEmail());
        if (retrievedMfaMethods.isFailure()) {
            LOG.warn("Default MFA retrieval failed, error: {}", retrievedMfaMethods.getFailure());
            return new PhoneData(null, false);
        }

        var defaultMfaMethod =
                retrievedMfaMethods.getSuccess().stream()
                        .filter(
                                method ->
                                        Objects.equals(
                                                method.getPriority(),
                                                PriorityIdentifier.DEFAULT.toString()))
                        .findFirst();
        if (defaultMfaMethod.isEmpty()) {
            LOG.warn("No default MFA method found");
            return new PhoneData(null, false);
        }

        if (Objects.equals(
                defaultMfaMethod.get().getMfaMethodType(), MFAMethodType.SMS.getValue())) {
            return new PhoneData(
                    defaultMfaMethod.get().getDestination(),
                    defaultMfaMethod.get().isMethodVerified());
        }
        return new PhoneData(null, false);
    }

    private void addClaimsFromSession(
            AccessTokenStore accessTokenInfo, AuthSessionItem authSession, UserInfo userInfo) {
        if (accessTokenInfo
                .getClaims()
                .contains(AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE.getValue())) {
            userInfo.setClaim(
                    AuthUserInfoClaims.VERIFIED_MFA_METHOD_TYPE.getValue(),
                    authSession.getVerifiedMfaMethodType());
            LOG.info("verified_mfa value: {}", authSession.getVerifiedMfaMethodType());
        }

        if (accessTokenInfo.getClaims().contains(AuthUserInfoClaims.UPLIFT_REQUIRED.getValue())) {
            userInfo.setClaim(
                    AuthUserInfoClaims.UPLIFT_REQUIRED.getValue(), authSession.getUpliftRequired());
            LOG.info("uplift_required value: {}", authSession.getUpliftRequired());
        }

        if (accessTokenInfo
                .getClaims()
                .contains(AuthUserInfoClaims.ACHIEVED_CREDENTIAL_STRENGTH.getValue())) {
            userInfo.setClaim(
                    AuthUserInfoClaims.ACHIEVED_CREDENTIAL_STRENGTH.getValue(),
                    authSession.getAchievedCredentialStrength());
            LOG.info(
                    "achieved_credential_strength value: {}",
                    authSession.getAchievedCredentialStrength());
        }
    }

    private static String bytesToBase64(ByteBuffer byteBuffer) {
        byte[] byteArray = new byte[byteBuffer.remaining()];
        byteBuffer.get(byteArray);
        return Base64.getEncoder().encodeToString(byteArray);
    }
}
