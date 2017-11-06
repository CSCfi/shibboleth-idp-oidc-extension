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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.messaging.context.navigate.OIDCClientRegistrationRequestMetadataLookupFunction;
import org.geant.idpextension.oidc.messaging.context.navigate.OIDCClientRegistrationResponseMetadataLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Abstract action for populating metadata from the {@link ClientRegistrationRequest} message to the response
 * message.
 */
@SuppressWarnings("rawtypes")
public abstract class AbstractOIDCClientRegistrationResponseAction extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractOIDCClientRegistrationResponseAction.class);

    /**
     * Strategy used to locate the {@link OIDCClientMetadata} associated with the request (input).
     */
    @Nonnull private Function<ProfileRequestContext,OIDCClientMetadata> oidcInputMetadataLookupStrategy;

    /**
     * Strategy used to locate the {@link OIDCClientMetadata} associated with the response (output).
     */
    @Nonnull private Function<ProfileRequestContext,OIDCClientMetadata> oidcOutputMetadataLookupStrategy;

    /** The OIDCClientMetadata to populate metadata from. */
    @Nullable private OIDCClientMetadata inputMetadata;
    
    /** The OIDCClientMetadata to populate metadata to. */
    @Nullable private OIDCClientMetadata outputMetadata;
    
    /** Constructor. */
    public AbstractOIDCClientRegistrationResponseAction() {
        oidcInputMetadataLookupStrategy = new OIDCClientRegistrationRequestMetadataLookupFunction();
        oidcOutputMetadataLookupStrategy = new OIDCClientRegistrationResponseMetadataLookupFunction();
    }

    /**
     * Set the strategy used to locate the {@link OIDCClientMetadata} associated with the request (input).
     * 
     * @param strategy The strategy used to locate the {@link OIDCClientMetadata} associated with the request (input).
     */
    public void setOidcInputMetadataLookupStrategy(@Nonnull final Function<ProfileRequestContext,OIDCClientMetadata>
        strategy) {
        oidcInputMetadataLookupStrategy = Constraint.isNotNull(strategy, 
                "The input OIDCClientMetadata lookup strategy cannot be null");
    }
    
    /**
     * Set the strategy used to locate the {@link OIDCClientMetadata} associated with the request (output).
     * 
     * @param strategy The strategy used to locate the {@link OIDCClientMetadata} associated with the request (output).
     */
    public void setOidcOutputMetadataLookupStrategy(@Nonnull final Function<ProfileRequestContext,OIDCClientMetadata>
        strategy) {
        oidcOutputMetadataLookupStrategy = Constraint.isNotNull(strategy, 
                "The output OIDCClientMetadata lookup strategy cannot be null");
    }
    
    /**
     * Get the OIDCClientMetadata to populate metadata from.
     * @return The OIDCClientMetadata to populate metadata from.
     */
    protected OIDCClientMetadata getInputMetadata() {
        return inputMetadata;
    }
    
    /**
     * Get the OIDCClientMetadata to populate metadata to.
     * @return The OIDCClientMetadata to populate metadata to.
     */
    protected OIDCClientMetadata getOutputMetadata() {
        return outputMetadata;
    }
    
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        
        inputMetadata = oidcInputMetadataLookupStrategy.apply(profileRequestContext);
        if (inputMetadata == null) {
            log.debug("{} No input OIDCMetadata associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;                        
        }
        
        outputMetadata = oidcOutputMetadataLookupStrategy.apply(profileRequestContext);
        if (outputMetadata == null) {
            log.debug("{} No output OIDCMetadata associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;                        
        }
        
        return true;
    }

}
