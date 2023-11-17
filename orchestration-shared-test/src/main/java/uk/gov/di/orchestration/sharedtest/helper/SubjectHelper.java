package uk.gov.di.orchestration.sharedtest.helper;

import com.nimbusds.oauth2.sdk.id.Subject;
import uk.gov.di.orchestration.shared.helpers.IdGenerator;

public class SubjectHelper {
    public static Subject govUkSignInSubject() {
        return new Subject("urn:fdc:gov.uk:2022:" + IdGenerator.generate());
    }
}
