package uk.gov.di.authentication.frontendapi.entity;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.frontendapi.exceptions.JourneyTypeNotSupportedException;
import uk.gov.di.authentication.shared.entity.JourneyType;
import uk.gov.di.authentication.shared.entity.MFAMethodType;
import uk.gov.di.authentication.shared.services.ConfigurationService;

import java.util.List;

public abstract class AbstractMfaMethod {

    protected final ConfigurationService configurationService;
    protected final JourneyType journeyType;
    protected final Logger LOG = LogManager.getLogger(this.getClass());

    public AbstractMfaMethod(ConfigurationService configurationService, JourneyType journeyType) {
        this.configurationService = configurationService;
        this.journeyType = journeyType;
    }

    public abstract MFAMethodType getMfaMethodType();

    protected void validateJourneyTypes(List<JourneyType> supportedJourneyTypes) {
        if (!supportedJourneyTypes.contains(journeyType)) {
            LOG.error(
                    "JourneyType: {} not supported for MFA Method: {}",
                    journeyType.getValue(),
                    getMfaMethodType());
            throw new JourneyTypeNotSupportedException(getMfaMethodType());
        }
    }
}
