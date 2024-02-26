package uk.gov.di.orchestration.shared.entity.vectoroftrust;

import com.google.gson.annotations.Expose;
import net.minidev.json.JSONArray;
import net.minidev.json.parser.JSONParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import uk.gov.di.orchestration.shared.exceptions.VotValidationException;

import java.text.MessageFormat;
import java.util.Collections;
import java.util.List;

import static net.minidev.json.parser.JSONParser.DEFAULT_PERMISSIVE_MODE;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_SUPPORTED_SET;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.AUTH_VALID_SET;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_SUPPORTED_SET;
import static uk.gov.di.orchestration.shared.entity.vectoroftrust.VotConstants.IDENT_VALID_SET;

/**
 * A summary of a parsed, validated and processed VTR request.
 * @param vtr A list of {@link VectorOfTrust}. The original VTR request. The VoTs in this list will be un-normalised,
 *            exactly as they were in the original request.
 * @param chosenVot The chosen un-normalised VoT taken directly from the VTR request. An empty VoT is used as a default
 *                  in the event of a null or empty VTR.
 * @param effectiveVot The normalised equivalent VoT to the chosen VoT.
 * @see VectorOfTrust#getNormalised()
 */
public record VtrSummary(@NotNull
                         @Expose
                         List<VectorOfTrust> vtr,
                         @NotNull
                         @Expose
                         VectorOfTrust chosenVot,
                         @NotNull
                         @Expose
                         VectorOfTrust effectiveVot) {
    private static final Logger LOG = LogManager.getLogger(VtrSummary.class);

    public static VtrSummary generateFromAuthRequestAttribute(List<String> authRequestVtrAttr) {
        var vtr = parseFromAuthRequestAttribute(authRequestVtrAttr);

        try {
            validateVtr(vtr);
        } catch (VotValidationException e) {
            LOG.error("Failed to validate VTR.", e);
            throw new IllegalArgumentException("VTR failed validation.", e);
        }

        var chosenVot = vtr
                .stream()
                .min(VectorOfTrust::compareTo)
                .orElseGet(VectorOfTrust::empty);

        var effectiveVot = chosenVot.getNormalised();

        return new VtrSummary(vtr, chosenVot, effectiveVot);
    }

    private static List<VectorOfTrust> parseFromAuthRequestAttribute(List<String> vtr) {
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
                    return vtrJsonArray
                            .stream()
                            .map(String.class::cast)
                            .map(VectorOfTrust::parse)
                            .toList();
                }
            } catch (net.minidev.json.parser.ParseException | ClassCastException | IllegalArgumentException e) {
                LOG.error("Error when parsing VTR attribute.", e);
                throw new IllegalArgumentException("Invalid VTR attribute.", e);
            }
        }

        LOG.info("VTR attribute is not present so defaulting to empty.");
        return Collections.emptyList();
    }

    private static void validateVtr(List<VectorOfTrust> vtr) throws VotValidationException {
        for (var vot : vtr) {
            validateVot(vot);
        }

        var allVotAuthOnly = vtr
                .stream()
                .allMatch(vot -> vot.requiresAuthOnly());
        var allVotAuthIpcv = vtr
                .stream()
                .allMatch(vot -> vot.requiresAuthIpvc());

        if (!(allVotAuthIpcv || allVotAuthOnly)) {
            throw new VotValidationException(MessageFormat
                    .format("Mixture of auth-only and auth-ipvc VoTs in VTR [\"{0}\"].",
                            vtr.format("\", \"", VectorOfTrust::getNormalised)));
        }
    }

    private static void validateVot(VectorOfTrust vot) throws VotValidationException {
        var normalisedVot = vot.getNormalised();
        var authComponent = normalisedVot.getAuthComponent();
        var identComponent = normalisedVot.getIdentComponent();

        if(!normalisedVot.requiresAuthOnly() && !normalisedVot.requiresAuthIpvc()) {
            throw new VotValidationException(MessageFormat
                    .format("Invalid combination of authentication component \"{0}\" and identity component \"{1}\" in VoT \"{2}\".",
                            authComponent,
                            identComponent
                            normalisedVot));
        }

        if (!AUTH_VALID_SET.contains(authComponent)) {
            throw new VotValidationException(MessageFormat
                    .format("Invalid authentication component \"{0}\" in VoT \"{1}\".",
                            authComponent,
                            normalisedVot));
        }

        if (!IDENT_VALID_SET.contains(identComponent)) {
            throw new VotValidationException(MessageFormat
                    .format("Invalid identity component \"{0}\" in VoT \"{1}\".",
                            identComponent,
                            normalisedVot));
        }

        if (!AUTH_SUPPORTED_SET.contains(authComponent)) {
            throw new VotValidationException(MessageFormat
                    .format("Unsupported authentication component \"{0}\" in VoT \"{1}\".",
                            authComponent,
                            normalisedVot));
        }

        if (!IDENT_SUPPORTED_SET.contains(identComponent)) {
            throw new VotValidationException(MessageFormat
                    .format("Unsupported identity component \"{0}\" in VoT \"{1}\".",
                            identComponent,
                            normalisedVot));
        }
    }
}