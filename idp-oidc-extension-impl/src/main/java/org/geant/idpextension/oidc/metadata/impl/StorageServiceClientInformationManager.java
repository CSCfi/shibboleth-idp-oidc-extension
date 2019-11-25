/*
 * Copyright (c) 2017 - 2020, GÉANT
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.geant.idpextension.oidc.metadata.impl;

import java.io.IOException;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.metadata.resolver.ClientInformationManager;
import org.geant.idpextension.oidc.metadata.resolver.ClientInformationManagerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

/**
 * A {@link ClientInfomationManager} exploiting {@link StorageService} for storing the data.
 */
public class StorageServiceClientInformationManager extends BaseStorageServiceClientInformationComponent 
    implements ClientInformationManager {
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(StorageServiceClientInformationResolver.class);

    /**
     * Constructor.
     */
    public StorageServiceClientInformationManager() {
        super();
    }
    
    /** {@inheritDoc} */
    @Override
    public void storeClientInformation(final OIDCClientInformation clientInformation, final Long expiration)
            throws ClientInformationManagerException {
        log.debug("Attempting to store client information");
        final String clientId = clientInformation.getID().getValue();
        //TODO: configurable serialization
        final String serialized = clientInformation.toJSONObject().toJSONString();
        try {
            getStorageService().create(CONTEXT_NAME, clientId, serialized, expiration);
        } catch (IOException e) {
            log.error("Could not store the client information", e);
            throw new ClientInformationManagerException("Could not store the client information", e);
        }
        log.info("Successfully stored the client information for id {}", clientId);
    }

    /** {@inheritDoc} */
    @Override
    public void destroyClientInformation(ClientID clientId) {
        if (clientId == null) {
            log.warn("The null clientId cannot be destroyed, nothing to do");
            return;
        }
        try {
            getStorageService().delete(CONTEXT_NAME, clientId.getValue());
        } catch (IOException e) {
            log.error("Could not delete the client ID {}", clientId.getValue(), e);
        }
    }

}
