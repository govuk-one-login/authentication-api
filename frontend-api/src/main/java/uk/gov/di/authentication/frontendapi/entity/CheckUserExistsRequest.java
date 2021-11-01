package uk.gov.di.authentication.frontendapi.entity;

public class CheckUserExistsRequest extends BaseFrontendRequest {

    public CheckUserExistsRequest() {}

    public CheckUserExistsRequest(String email) {
        this.email = email;
    }

    @Override
    public String toString() {
        return "CheckUserExistsRequest{" + "email='" + email + '\'' + '}';
    }
}
