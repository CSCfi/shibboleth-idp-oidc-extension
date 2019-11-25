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

package org.geant.idpextension.oidc.messaging.context;

import javax.annotation.Nullable;

import org.opensaml.messaging.context.BaseContext;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

/**
 * Subcontext carrying information on metadata of the relying party. This
 * context appears as a subcontext of the
 * {@link org.opensaml.messaging.context.MessageContext} that carries the actual
 * OIDC request message, in such cases the metadata carried herein applies to
 * the issuer of that message.
 * 
 * This context is just a placeholder for the final solution. At first phase we
 * use only redirect uris.
 */
public class OIDCMetadataContext extends BaseContext {

    /** The client information. */
    @Nullable private OIDCClientInformation clientInformation;
    
    /**
     * Set the client information.
     * 
     * @return The client information.
     */
    @Nullable
    public OIDCClientInformation getClientInformation() {
        return clientInformation;
    }

    /**
     * Set the client information.
     * 
     * @param information The client information.
     */
    public void setClientInformation(@Nullable OIDCClientInformation information) {
        clientInformation = information;
    }
}