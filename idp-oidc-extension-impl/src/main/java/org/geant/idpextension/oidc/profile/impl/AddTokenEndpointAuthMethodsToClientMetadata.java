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

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.config.navigate.TokenEndpointAuthMethodLookupFunction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

import net.shibboleth.utilities.java.support.logic.Constraint;

/**
* An action that adds the token_endpoint_auth_method to the client metadata. If no method is requested, then
* {@link ClientAuthenticationMethod#getDefault()} is used. It also verifies that the requested (or default)
* method is enabled via the attached lookup strategy.
*/
public class AddTokenEndpointAuthMethodsToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddTokenEndpointAuthMethodsToClientMetadata.class);
    
    /** Strategy to obtain enabled token endpoint authentication methods. */
    @Nullable private Function<ProfileRequestContext, List<ClientAuthenticationMethod>> 
        tokenEndpointAuthMethodsLookupStrategy;
    
    /**
     * Constructor.
     */
    public AddTokenEndpointAuthMethodsToClientMetadata() {
        super();
        tokenEndpointAuthMethodsLookupStrategy = new TokenEndpointAuthMethodLookupFunction();
    }
    
    /**
     * Set strategy to obtain enabled token endpoint authentication methods.
     * @param strategy What to set.
     */
    public void setTokenEndpointAuthMethodsLookupStrategy(@Nonnull final Function<ProfileRequestContext, 
            List<ClientAuthenticationMethod>> strategy) {
        tokenEndpointAuthMethodsLookupStrategy = Constraint.isNotNull(strategy, 
                "Strategy to obtain enabled token endpoint authentication methods cannot be null");
        
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final ClientAuthenticationMethod requestedMethod = getInputMetadata().getTokenEndpointAuthMethod() != null ? 
                getInputMetadata().getTokenEndpointAuthMethod() : ClientAuthenticationMethod.getDefault();
        final List<ClientAuthenticationMethod> enabledMethods 
            = tokenEndpointAuthMethodsLookupStrategy.apply(profileRequestContext);
        if (enabledMethods == null || !enabledMethods.contains(requestedMethod)) {
            log.warn("{} Non-supported token_endpoint_auth_method {}", getLogPrefix(), requestedMethod);
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MESSAGE);
            return;
        }
        getOutputMetadata().setTokenEndpointAuthMethod(requestedMethod);
    }
}
