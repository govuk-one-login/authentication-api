package uk.gov.di.authentication.sharedtest.helper;

import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.authentication.shared.helpers.IdGenerator;

public class SubjectHelper {
    public static Subject govUkSignInSubject() {
        return new Subject("urn:fdc:gov.uk:2022:" + IdGenerator.generate());
    }
}
