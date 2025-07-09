package uk.gov.di.authentication.shared.services.permissions;

import uk.gov.di.authentication.shared.entity.CountType;

import java.util.Map;

/**
 * Interface for managing user permissions and authentication lockouts.
 * This interface provides methods to check if a user is locked out from specific actions
 * and to record failed authentication attempts.
 */
public interface UserPermissions {
    
    // Login-related permissions
    
    /**
     * Checks if a user is locked out from logging in due to too many incorrect password attempts.
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     * @return true if the user is locked out from logging in, false otherwise
     */
    boolean isUserLockedOutFromLogin(String internalCommonSubjectId);
    
    /**
     * Checks if a user is locked out from reauthentication due to too many failed attempts.
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     * @return true if the user is locked out from reauthentication, false otherwise
     */
    boolean isUserLockedOutFromReauth(String internalCommonSubjectId);
    
    /**
     * Checks if a user is locked out from reauthentication, considering both user ID and pairwise ID counts.
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     * @param rpPairwiseId The relying party pairwise ID
     * @return true if the user is locked out from reauthentication, false otherwise
     */
    boolean isUserLockedOutFromReauth(String internalCommonSubjectId, String rpPairwiseId);
    
    // MFA-related permissions
    
    /**
     * Checks if a user is locked out from entering MFA codes due to too many incorrect attempts.
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     * @return true if the user is locked out from MFA verification, false otherwise
     */
    boolean isUserLockedOutFromMfaVerification(String internalCommonSubjectId);
    
    /**
     * Checks if a user is locked out from entering auth app codes during reauthentication.
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     * @return true if the user is locked out from auth app verification, false otherwise
     */
    boolean isUserLockedOutFromReauthAuthApp(String internalCommonSubjectId);
    
    // Recording failed attempts
    
    /**
     * Records a failed login attempt (incorrect password).
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     */
    void recordFailedLoginAttempt(String internalCommonSubjectId);
    
    /**
     * Records a failed reauthentication password attempt.
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     */
    void recordFailedReauthPasswordAttempt(String internalCommonSubjectId);
    
    /**
     * Records a failed auth app code attempt during reauthentication.
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     */
    void recordFailedReauthAuthAppAttempt(String internalCommonSubjectId);
    
    /**
     * Records a failed MFA code verification attempt.
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     */
    void recordFailedMfaAttempt(String internalCommonSubjectId);
    
    // Clearing lockouts after successful authentication
    
    /**
     * Clears all reauthentication-related lockouts for a user after successful authentication.
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     */
    void clearReauthLockouts(String internalCommonSubjectId);
    
    // Low-level access for audit and debugging
    
    /**
     * Gets all current attempt counts for a user in reauthentication journey.
     * Used primarily for audit logging and debugging.
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     * @return A map of count types to their current values
     */
    Map<CountType, Integer> getReauthAttemptCounts(String internalCommonSubjectId);
    
    /**
     * Gets combined reauthentication attempt counts from both user ID and pairwise ID.
     * Used primarily for audit logging and debugging.
     * 
     * @param internalCommonSubjectId The internal common subject ID of the user
     * @param rpPairwiseId The relying party pairwise ID
     * @return A map of count types to their combined current values
     */
    Map<CountType, Integer> getCombinedReauthAttemptCounts(String internalCommonSubjectId, String rpPairwiseId);
}