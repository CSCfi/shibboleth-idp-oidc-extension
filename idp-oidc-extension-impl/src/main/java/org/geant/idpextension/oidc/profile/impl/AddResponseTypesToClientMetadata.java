/*
 * GÉANT BSD Software License
 *
 * Copyright (c) 2017 - 2020, GÉANT
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the GÉANT nor the names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * Disclaimer:
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.geant.idpextension.oidc.profile.impl;

import java.util.HashSet;
import java.util.Set;

import javax.annotation.Nonnull;

import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;

import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An action that adds response_types to the OIDC client metadata.
 * 
 * TODO: how the supported types are configured.
 */
public class AddResponseTypesToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddRedirectUrisToClientMetadata.class);
    
    @Nonnull
    private Set<ResponseType> supportedTypes;
    
    /** Constructor. */
    public AddResponseTypesToClientMetadata() {
        supportedTypes = new HashSet<>();
        //TODO: revisit how this should be configured, probably in the Profile Configuration.
        supportedTypes.add(new ResponseType(OIDCResponseTypeValue.ID_TOKEN));
    }
    
    public void setSupportedResponseTypes(final Set<ResponseType> types) {
        supportedTypes = Constraint.isNotNull(types, "Supported response types cannot be empty!");
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final Set<ResponseType> requestedTypes = getInputMetadata().getResponseTypes();
        if (requestedTypes != null && !requestedTypes.isEmpty()) {
            final Set<ResponseType> responseTypes = new HashSet<>();
            for (final ResponseType requestedType : requestedTypes) {
                if (supportedTypes.contains(requestedType)) {
                    responseTypes.add(requestedType);
                    log.debug("{} Added supported response type {}", getLogPrefix(), requestedType);
                } else {
                    log.debug("{} Dropping unsupported requested response type {}", getLogPrefix(), requestedType);
                }
            }
            if (responseTypes.isEmpty()) {
                log.error("{} No supported response types requested", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
                return;
            }
        }
        getOutputMetadata().setResponseTypes(supportedTypes);
    }

}