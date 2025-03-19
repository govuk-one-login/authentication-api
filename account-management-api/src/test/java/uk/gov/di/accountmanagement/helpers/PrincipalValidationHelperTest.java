package uk.gov.di.accountmanagement.helpers;

import com.nimbusds.oauth2.sdk.id.Subject;
import org.junit.jupiter.api.Test;
import uk.gov.di.authentication.shared.entity.UserProfile;
import uk.gov.di.authentication.shared.helpers.ClientSubjectHelper;
import uk.gov.di.authentication.shared.helpers.SaltHelper;
import uk.gov.di.authentication.shared.services.AuthenticationService;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PrincipalValidationHelperTest {

    private final AuthenticationService authenticationService = mock(AuthenticationService.class);
    private static final String INTERNAL_SECTOR_URI = "https://test.account.gov.uk";
    private final Map<String, Object> authorizerParams = new HashMap<>();

    @Test
    void shouldReturnTrueWhenNoPrincipalIdIsPresent() {
        assertTrue(
                PrincipalValidationHelper.principalIsInvalid(
                        new UserProfile(),
                        INTERNAL_SECTOR_URI,
                        authenticationService,
                        authorizerParams));
    }

    @Test
    void shouldReturnFalseWhenPrincipalMatchesPairwiseSubjectId() {
        var internalSubject = new Subject();
        var salt = SaltHelper.generateNewSalt();
        var userProfile = new UserProfile().withSubjectID(internalSubject.getValue());
        var internalPairwiseIdentifier =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        internalSubject.getValue(), "test.account.gov.uk", salt);
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(salt);
        authorizerParams.put("principalId", internalPairwiseIdentifier);

        assertFalse(
                PrincipalValidationHelper.principalIsInvalid(
                        userProfile, INTERNAL_SECTOR_URI, authenticationService, authorizerParams));
    }

    @Test
    void shouldReturnTrueWhenPrincipalDoesNotMatchPairwiseSubjectId() {
        var salt = SaltHelper.generateNewSalt();
        var userProfile =
                new UserProfile()
                        .withSubjectID(new Subject().getValue())
                        .withPublicSubjectID(new Subject().getValue());
        var internalPairwiseIdentifier =
                ClientSubjectHelper.calculatePairwiseIdentifier(
                        new Subject().getValue(), "test.account.gov.uk", salt);
        when(authenticationService.getOrGenerateSalt(userProfile)).thenReturn(salt);
        authorizerParams.put("principalId", internalPairwiseIdentifier);

        assertTrue(
                PrincipalValidationHelper.principalIsInvalid(
                        userProfile, INTERNAL_SECTOR_URI, authenticationService, authorizerParams));
    }
}
