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
public abstract class AbstractOIDCClientMetadataPopulationAction extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractOIDCClientMetadataPopulationAction.class);

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
    public AbstractOIDCClientMetadataPopulationAction() {
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
