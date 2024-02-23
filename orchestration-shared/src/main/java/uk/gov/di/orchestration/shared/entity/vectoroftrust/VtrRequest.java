package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import manifold.ext.delegation.rt.api.link;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.JSONParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;

import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;

/**
 * Represent a VTR Request i.e. a list of requested {@link VectorOfTrust}. These VoTs may be un-normalised.
 */
public class VtrRequest implements List<VectorOfTrust> {

    private static final Logger LOG = LogManager.getLogger(VtrRequest.class);

    @link private final List<VectorOfTrust> delegate;

    public VtrRequest(List<VectorOfTrust> delegate) {
        this.delegate = delegate.stream().distinct().toList();
    }

    public static VtrRequest empty() {
        return new VtrRequest(Collections.emptyList());
    }

    public static VtrRequest of(VectorOfTrust first, VectorOfTrust... rest) {
        return new VtrRequest(Arrays.stream(rest).beginWith(first).toList());
    }

    public static VtrRequest parseFromAuthRequestAttribute(List<String> vtr) {
        if (!vtr.isNullOrEmpty()) {
            JSONParser parser = new JSONParser(DEFAULT_PERMISSIVE_MODE);
            JSONArray vtrJsonArray;
            try {
                if (vtr.size() != 1) {
                    throw new IllegalArgumentException("Expected VTR to have single entry.");
                }

                // The nimbus package parses the vtr from the auth request as a list with one element
                // which is a json list
                // The .get(0) below returns the json list - it doesn't just get the first element of
                // the Vector of Trust
                var vtrStr = vtr.get(0);
                if (!vtrStr.isNullOrEmpty()) {
                    vtrJsonArray = (JSONArray)parser.parse(vtrStr);
                    return new VtrRequest(vtrJsonArray
                            .stream()
                            .map(String.class::cast)
                            .map(VectorOfTrust::parse)
                            .toList());
                }
            } catch (net.minidev.json.parser.ParseException | ClassCastException | IllegalArgumentException e) {
                LOG.error("Error when parsing VTR attribute.", e);
                throw new IllegalArgumentException("Invalid VTR attribute.", e);
            }
        }

        LOG.info("VTR attribute is not present so defaulting to empty.");
        return VtrRequest.empty();
    }

    /**
     * Choose a {@link VectorOfTrust} from this VTR Request. The minimum VoT will be chosen. This means the VoT that
     * represents the least level of trust, first by the identity component and then by the authentication component.
     * If the VTR Request is empty an empty VoT will be chosen as the minimum.
     * @param versions A set of one or more {@link VotVocabVersion} that the VoTs will be validated and then normalised
     *                 against in order to choose the minimum VoT. The first version that all VoTs can be validated
     *                 against will be used.
     * @return A {@link VtrSummary} containing this VTR Request, the chosen un-normalised VoT, the effective normalised
     * VoT, and the {@link VotVocabVersion} used to normalise.
     */
    public VtrSummary chooseLevel(EnumSet<VotVocabVersion> versions) {
        if (versions.isEmpty()) {
            throw new IllegalArgumentException("At least one version must be provided.");
        }

        return versions
                .stream()
                .filter(ver -> ver.validateRequest(this))
                .map(ver -> stream()
                        .map(vot -> new VtrSummary(this,
                                                   vot,
                                                   ver.normaliseVector(vot),
                                                   ver))
                        .min(Comparator
                                .comparing((VtrSummary sum) -> sum.effectiveVector().identComponent())
                                .thenComparing((VtrSummary sum) -> sum.effectiveVector().authComponent()))
                        .orElseGet(() -> new VtrSummary(this,
                                                        VectorOfTrust.empty(),
                                                        ver.normaliseVector(VectorOfTrust.empty()),
                                                        ver)))
                .findFirst()
                .orElseThrow(() ->
                        new IllegalArgumentException(MessageFormat.format(
                                "Could not find VoT valid against versions [{0}] in VTR [{1}].",
                                versions.format(", "),
                                this.format(", "))));
    }

    public List<VotComponent<AuthId>> credentialComponents() {
        return stream().map(VectorOfTrust::authComponent).toList();
    }

    public List<VotComponent<IdentId>> identityComponents() {
        return stream().map(VectorOfTrust::identComponent).toList();
    }
}
