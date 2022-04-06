package uk.gov.di.authentication.oidc.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.authentication.shared.entity.ClientRegistry;

import static uk.gov.di.authentication.shared.helpers.LogLineHelper.LogFieldName.CLIENT_ID;
import static uk.gov.di.authentication.shared.helpers.LogLineHelper.attachLogFieldToLogs;

public class BackChannelLogoutService {

    private static final Logger LOGGER = LogManager.getLogger(BackChannelLogoutService.class);

    public void sendLogoutMessage(ClientRegistry clientRegistry) {
        attachLogFieldToLogs(CLIENT_ID, clientRegistry.getClientID());

        LOGGER.info("Sending logout message");
    }
}
