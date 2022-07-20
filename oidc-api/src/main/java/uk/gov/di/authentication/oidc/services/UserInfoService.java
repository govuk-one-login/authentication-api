package uk.gov.di.authentication.oidc.services;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.app.services.DynamoDocAppService;
import uk.gov.di.authentication.oidc.entity.AccessTokenInfo;
import uk.gov.di.authentication.oidc.exceptions.UserInfoException;
import uk.gov.di.authentication.shared.entity.CustomScopeValue;
import uk.gov.di.authentication.shared.entity.ValidClaims;
import uk.gov.di.authentication.shared.serialization.Json;
import uk.gov.di.authentication.shared.services.AuthenticationService;
import uk.gov.di.authentication.shared.services.CloudwatchMetricsService;
import uk.gov.di.authentication.shared.services.ConfigurationService;
import uk.gov.di.authentication.shared.services.DynamoIdentityService;
import uk.gov.di.authentication.shared.services.SerializationService;

import java.util.Map;
import java.util.Objects;

public class UserInfoService {

    private final AuthenticationService authenticationService;
    private final DynamoIdentityService identityService;
    private final DynamoDocAppService dynamoDocAppService;
    private final CloudwatchMetricsService cloudwatchMetricsService;
    private final ConfigurationService configurationService;
    protected final Json objectMapper = SerializationService.getInstance();

    private static final Logger LOG = LogManager.getLogger(UserInfoService.class);

    public UserInfoService(
            AuthenticationService authenticationService,
            DynamoIdentityService identityService,
            DynamoDocAppService dynamoDocAppService,
            CloudwatchMetricsService cloudwatchMetricsService,
            ConfigurationService configurationService) {
        this.authenticationService = authenticationService;
        this.identityService = identityService;
        this.dynamoDocAppService = dynamoDocAppService;
        this.cloudwatchMetricsService = cloudwatchMetricsService;
        this.configurationService = configurationService;
    }

    public UserInfo populateUserInfo(AccessTokenInfo accessTokenInfo) {
        LOG.info("Populating UserInfo");
        var userInfo = new UserInfo(new Subject(accessTokenInfo.getSubject()));
        if (accessTokenInfo.getScopes().contains(CustomScopeValue.DOC_CHECKING_APP.getValue())) {
            return populateDocAppUserInfo(accessTokenInfo, userInfo);
        }
        var userProfile =
                authenticationService.getUserProfileFromSubject(
                        accessTokenInfo.getAccessTokenStore().getInternalSubjectId());
        if (accessTokenInfo.getScopes().contains(OIDCScopeValue.EMAIL.getValue())) {
            userInfo.setEmailAddress(userProfile.getEmail());
            userInfo.setEmailVerified(userProfile.isEmailVerified());
        }
        if (accessTokenInfo.getScopes().contains(OIDCScopeValue.PHONE.getValue())) {
            userInfo.setPhoneNumber(userProfile.getPhoneNumber());
            userInfo.setPhoneNumberVerified(userProfile.isPhoneNumberVerified());
        }
        if (accessTokenInfo.getScopes().contains(CustomScopeValue.GOVUK_ACCOUNT.getValue())) {
            userInfo.setClaim("legacy_subject_id", userProfile.getLegacySubjectID());
        }
        if (configurationService.isIdentityEnabled()
                && Objects.nonNull(accessTokenInfo.getIdentityClaims())) {
            return populateIdentityInfo(accessTokenInfo, userInfo);
        } else {
            LOG.info("No identity claims present");
            return userInfo;
        }
    }

    private UserInfo populateIdentityInfo(AccessTokenInfo accessTokenInfo, UserInfo userInfo) {
        LOG.info("Populating IdentityInfo");
        var identityCredentials =
                identityService.getIdentityCredentials(accessTokenInfo.getSubject()).orElse(null);
        if (Objects.isNull(identityCredentials)) {
            LOG.info("No identity credentials present");
            return userInfo;
        }
        var coreIdentityClaimIsPresent =
                accessTokenInfo.getIdentityClaims().stream()
                        .anyMatch(t -> t.equals(ValidClaims.CORE_IDENTITY_JWT.getValue()));
        if (Objects.nonNull(identityCredentials.getCoreIdentityJWT())
                && coreIdentityClaimIsPresent) {
            LOG.info("Setting coreIdentityJWT claim in userinfo response");
            userInfo.setClaim(
                    ValidClaims.CORE_IDENTITY_JWT.getValue(),
                    identityCredentials.getCoreIdentityJWT());
            incrementClaimIssuedCounter(
                    ValidClaims.CORE_IDENTITY_JWT.getValue(), accessTokenInfo.getClientID());
        }
        if (Objects.nonNull(identityCredentials.getAdditionalClaims())) {
            identityCredentials.getAdditionalClaims().entrySet().stream()
                    .filter(t -> accessTokenInfo.getIdentityClaims().contains(t.getKey()))
                    .forEach(
                            t -> {
                                try {
                                    userInfo.setClaim(
                                            t.getKey(),
                                            objectMapper.readValue(t.getValue(), JSONArray.class));
                                    incrementClaimIssuedCounter(
                                            t.getKey(), accessTokenInfo.getClientID());
                                } catch (Json.JsonException e) {
                                    LOG.error("Unable to deserialize additional identity claims");
                                    throw new RuntimeException();
                                }
                            });
        }
        LOG.info("UserInfo populated with Identity claims");
        return userInfo;
    }

    private UserInfo populateDocAppUserInfo(AccessTokenInfo accessTokenInfo, UserInfo userInfo) {
        LOG.info("Populating DocAppUserInfo");
        return dynamoDocAppService
                .getDocAppCredential(accessTokenInfo.getSubject())
                .map(
                        docAppCredential -> {
                            userInfo.setClaim(
                                    "doc-app-credential", docAppCredential.getCredential());
                            incrementClaimIssuedCounter(
                                    "doc-app-credential", accessTokenInfo.getClientID());
                            return userInfo;
                        })
                .orElseThrow(
                        () -> {
                            LOG.error("Unable to retrieve docAppCredential for Subject.");
                            throw new UserInfoException(
                                    "Unable to retrieve docAppCredential for Subject.");
                        });
    }

    private void incrementClaimIssuedCounter(String claimName, String clientID) {
        cloudwatchMetricsService.incrementCounter(
                "ClaimIssued",
                Map.of(
                        "Environment",
                        configurationService.getEnvironment(),
                        "Client",
                        clientID,
                        "Claim",
                        claimName));
    }
}
