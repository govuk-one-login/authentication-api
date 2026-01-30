package uk.gov.di.authentication.frontendapi.entity;

public enum AMCJourneyType {
    SFAD(new String[] {AMCScope.ACCOUNT_DELETE.getValue()});

    private final String[] scopes;

    AMCJourneyType(String[] scopes) {
        this.scopes = scopes;
    }

    public String[] getScopes() {
        return scopes.clone();
    }
}
