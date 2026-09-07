package uk.gov.di.authentication.shared.helpers;

import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.TermsAndConditions;
import uk.gov.di.authentication.shared.entity.UserCredentials;
import uk.gov.di.authentication.shared.entity.UserProfile;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

class InactiveAccountFailsafeCheckHelperTest {

    private static final Clock FIXED_CLOCK =
            Clock.fixed(Instant.parse("2026-09-04T14:00:00Z"), ZoneOffset.UTC);

    private static final String OLD_TIMESTAMP = "2019-01-01T10:00:00.000000";
    private static final String RECENT_TIMESTAMP = "2025-06-15T10:00:00.000000";

    @Test
    void shouldReturnNotRecentlyActiveWhenAllTimestampsOlderThanFiveYears() {
        var userProfile =
                createUserProfile(
                        OLD_TIMESTAMP,
                        OLD_TIMESTAMP,
                        new TermsAndConditions("1.0", OLD_TIMESTAMP),
                        OLD_TIMESTAMP);
        var userCredentials = createUserCredentials(OLD_TIMESTAMP, OLD_TIMESTAMP);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(false));
        assertThat(result.triggeringAttribute(), is((String) null));
    }

    @Test
    void shouldReturnRecentlyActiveWhenUserProfileCreatedWithinThreshold() {
        var userProfile =
                createUserProfile(
                        RECENT_TIMESTAMP,
                        OLD_TIMESTAMP,
                        new TermsAndConditions("1.0", OLD_TIMESTAMP),
                        OLD_TIMESTAMP);
        var userCredentials = createUserCredentials(OLD_TIMESTAMP, OLD_TIMESTAMP);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(true));
        assertThat(result.triggeringAttribute(), is("UserProfile.Created"));
    }

    @Test
    void shouldReturnRecentlyActiveWhenUserProfileUpdatedWithinThreshold() {
        var userProfile =
                createUserProfile(
                        OLD_TIMESTAMP,
                        RECENT_TIMESTAMP,
                        new TermsAndConditions("1.0", OLD_TIMESTAMP),
                        OLD_TIMESTAMP);
        var userCredentials = createUserCredentials(OLD_TIMESTAMP, OLD_TIMESTAMP);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(true));
        assertThat(result.triggeringAttribute(), is("UserProfile.Updated"));
    }

    @Test
    void shouldReturnRecentlyActiveWhenTermsAndConditionsTimestampWithinThreshold() {
        var userProfile =
                createUserProfile(
                        OLD_TIMESTAMP,
                        OLD_TIMESTAMP,
                        new TermsAndConditions("1.0", RECENT_TIMESTAMP),
                        OLD_TIMESTAMP);
        var userCredentials = createUserCredentials(OLD_TIMESTAMP, OLD_TIMESTAMP);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(true));
        assertThat(result.triggeringAttribute(), is("UserProfile.termsAndConditions.timestamp"));
    }

    @Test
    void shouldReturnRecentlyActiveWhenLastSignedInWithinThreshold() {
        var userProfile =
                createUserProfile(
                        OLD_TIMESTAMP,
                        OLD_TIMESTAMP,
                        new TermsAndConditions("1.0", OLD_TIMESTAMP),
                        RECENT_TIMESTAMP);
        var userCredentials = createUserCredentials(OLD_TIMESTAMP, OLD_TIMESTAMP);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(true));
        assertThat(result.triggeringAttribute(), is("UserProfile.LastSignedIn"));
    }

    @Test
    void shouldReturnRecentlyActiveWhenUserCredentialsCreatedWithinThreshold() {
        var userProfile =
                createUserProfile(
                        OLD_TIMESTAMP,
                        OLD_TIMESTAMP,
                        new TermsAndConditions("1.0", OLD_TIMESTAMP),
                        OLD_TIMESTAMP);
        var userCredentials = createUserCredentials(RECENT_TIMESTAMP, OLD_TIMESTAMP);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(true));
        assertThat(result.triggeringAttribute(), is("UserCredentials.Created"));
    }

    @Test
    void shouldReturnRecentlyActiveWhenUserCredentialsUpdatedWithinThreshold() {
        var userProfile =
                createUserProfile(
                        OLD_TIMESTAMP,
                        OLD_TIMESTAMP,
                        new TermsAndConditions("1.0", OLD_TIMESTAMP),
                        OLD_TIMESTAMP);
        var userCredentials = createUserCredentials(OLD_TIMESTAMP, RECENT_TIMESTAMP);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(true));
        assertThat(result.triggeringAttribute(), is("UserCredentials.Updated"));
    }

    @Test
    void shouldReturnNotRecentlyActiveWhenAllTimestampsNull() {
        var userProfile = createUserProfile(null, null, null, null);
        var userCredentials = createUserCredentials(null, null);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(false));
        assertThat(result.triggeringAttribute(), is((String) null));
    }

    @Test
    void shouldReturnNotRecentlyActiveWhenUserCredentialsNull() {
        var userProfile = createUserProfile(null, null, null, null);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, null, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(false));
        assertThat(result.triggeringAttribute(), is((String) null));
    }

    @Test
    void shouldSkipUnparseableTimestampAndAllowDeletionWhenNoOtherRecentTimestamps() {
        var userProfile = createUserProfile("not-a-date", OLD_TIMESTAMP, null, null);
        var userCredentials = createUserCredentials(null, null);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(false));
        assertThat(result.triggeringAttribute(), is((String) null));
    }

    @Test
    void shouldSkipUnparseableTimestampAndStillDetectRecentActivityOnLaterField() {
        var userProfile = createUserProfile("not-a-date", RECENT_TIMESTAMP, null, null);
        var userCredentials = createUserCredentials(null, null);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(true));
        assertThat(result.triggeringAttribute(), is("UserProfile.Updated"));
    }

    @Test
    void shouldSafelySkipNullTermsAndConditionsObject() {
        var userProfile = createUserProfile(OLD_TIMESTAMP, OLD_TIMESTAMP, null, OLD_TIMESTAMP);
        var userCredentials = createUserCredentials(OLD_TIMESTAMP, OLD_TIMESTAMP);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(false));
        assertThat(result.triggeringAttribute(), is((String) null));
    }

    @Test
    void shouldSafelySkipNullTermsAndConditionsTimestamp() {
        var userProfile =
                createUserProfile(
                        OLD_TIMESTAMP,
                        OLD_TIMESTAMP,
                        new TermsAndConditions("1.0", null),
                        OLD_TIMESTAMP);
        var userCredentials = createUserCredentials(OLD_TIMESTAMP, OLD_TIMESTAMP);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(false));
        assertThat(result.triggeringAttribute(), is((String) null));
    }

    @Test
    void shouldReturnNotRecentlyActiveWhenTimestampExactlyAtThresholdBoundary() {
        var boundaryTimestamp = "2021-09-04T14:00:00";
        var userProfile = createUserProfile(boundaryTimestamp, null, null, null);
        var userCredentials = createUserCredentials(null, null);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(false));
        assertThat(result.triggeringAttribute(), is((String) null));
    }

    @Test
    void shouldReturnRecentlyActiveWhenTimestampJustInsideThreshold() {
        var justInsideTimestamp = "2021-09-04T14:00:01";
        var userProfile = createUserProfile(justInsideTimestamp, null, null, null);
        var userCredentials = createUserCredentials(null, null);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(true));
        assertThat(result.triggeringAttribute(), is("UserProfile.Created"));
    }

    @Test
    void shouldHandleTimestampWithUtcOffsetSuffix() {
        var timestampWithOffset = "2025-01-15T10:30:00.000Z";
        var userProfile = createUserProfile(timestampWithOffset, null, null, null);
        var userCredentials = createUserCredentials(null, null);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(true));
        assertThat(result.triggeringAttribute(), is("UserProfile.Created"));
    }

    @Test
    void shouldCheckUserProfileFieldsBeforeCredentialsFields() {
        var userProfile = createUserProfile(RECENT_TIMESTAMP, null, null, null);
        var userCredentials = createUserCredentials(null, RECENT_TIMESTAMP);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, userCredentials, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(true));
        assertThat(result.triggeringAttribute(), is("UserProfile.Created"));
    }

    @Test
    void shouldOnlyCheckUserProfileFieldsWhenCredentialsNull() {
        var userProfile = createUserProfile(null, RECENT_TIMESTAMP, null, null);

        var result =
                InactiveAccountFailsafeCheckHelper.checkForRecentActivity(
                        userProfile, null, FIXED_CLOCK);

        assertThat(result.recentlyActive(), is(true));
        assertThat(result.triggeringAttribute(), is("UserProfile.Updated"));
    }

    private UserProfile createUserProfile(
            String created, String updated, TermsAndConditions tc, String lastSignedIn) {
        var userProfile = new UserProfile();
        userProfile.setCreated(created);
        userProfile.setUpdated(updated);
        userProfile.setTermsAndConditions(tc);
        userProfile.setLastSignedIn(lastSignedIn);
        return userProfile;
    }

    private UserCredentials createUserCredentials(String created, String updated) {
        var userCredentials = new UserCredentials();
        userCredentials.setCreated(created);
        userCredentials.setUpdated(updated);
        return userCredentials;
    }
}
