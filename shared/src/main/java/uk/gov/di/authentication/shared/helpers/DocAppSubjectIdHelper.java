package uk.gov.di.authentication.shared.helpers;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientSession;

import java.net.URI;
import java.util.Objects;

public class DocAppSubjectIdHelper {

    private static final Logger LOG = LogManager.getLogger(DocAppSubjectIdHelper.class);

    private DocAppSubjectIdHelper() {}

    public static Subject calculateDocAppSubjectId(
            ClientSession clientSession, boolean isCustomDocAppClaimEnabled, URI docAppDomain) {
        try {
            LOG.info(
                    "Calculating DocAppSubjectId. CustomDocAppClaim is enabled: {}",
                    isCustomDocAppClaimEnabled);
            var authRequest = AuthenticationRequest.parse(clientSession.getAuthRequestParams());
            var secureRequestSubject =
                    authRequest.getRequestObject().getJWTClaimsSet().getSubject();
            if (isCustomDocAppClaimEnabled && Objects.nonNull(secureRequestSubject)) {
                LOG.info("CustomDocAppClaimEnabled and SecureRequestObject contains Subject claim");
                return new Subject(secureRequestSubject);
            } else {
                LOG.info("Generating Pairwise ID for DocAPpSubjectId");
                return new Subject(
                        ClientSubjectHelper.calculatePairwiseIdentifier(
                                new Subject().getValue(),
                                docAppDomain,
                                SaltHelper.generateNewSalt()));
            }
        } catch (ParseException | java.text.ParseException e) {
            LOG.error("Unable to parse secure request object when calculating DocAppSubjectId", e);
            throw new RuntimeException(e);
        }
    }
}
