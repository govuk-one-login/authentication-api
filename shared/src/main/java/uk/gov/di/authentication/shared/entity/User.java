package uk.gov.di.authentication.shared.entity;

public class User {

    private final UserProfile userProfile;
    private final UserCredentials userCredentials;

    public User(UserProfile userProfile, UserCredentials userCredentials) {
        this.userProfile = userProfile;
        this.userCredentials = userCredentials;
    }

    public UserProfile getUserProfile() {
        return userProfile;
    }

    public UserCredentials getUserCredentials() {
        return userCredentials;
    }
}
