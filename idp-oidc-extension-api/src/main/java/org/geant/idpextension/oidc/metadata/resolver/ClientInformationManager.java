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

package org.geant.idpextension.oidc.metadata.resolver;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import net.shibboleth.utilities.java.support.annotation.constraint.Positive;

/**
 * A manager that is capable of managing {@link ClientInformation} instances.
 */
public interface ClientInformationManager {

    /**
     * Store a {@link ClientInformation} object.
     * 
     * @param clientInformation The client information to be stored.
     * @param expiration The expiration for record, or null.
     * @throws ClientInformationManagerException If the client information cannot be stored.
     */
    @Nonnull void storeClientInformation(@Nonnull final OIDCClientInformation clientInformation, 
            @Nullable @Positive final Long expiration) throws ClientInformationManagerException;
    
    /**
     * Invalidates or otherwise removes a {@link ClientInformation} from persistent storage.
     * 
     * @param clientId the unique ID of the client information to destroy.
     * @throws ClientInformationManagerException If the client information cannot be destroyed.
     */
    void destroyClientInformation(@Nonnull final ClientID clientId) throws ClientInformationManagerException;
    
}