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

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Adds the {@link Scope} from the input metadata to the output {@link OIDCClientMetadata}. If the scope is null
 * or empty, the configurable default {@link Scope} is set. By default, its value is 'openid'.
 */
@SuppressWarnings("rawtypes")
public class AddScopeToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AddRedirectUrisToClientMetadata.class);
    
    /** The default {@link Scope} if it was not defined in the request. */
    private Scope defaultScope;

    /** Constructor. */
    public AddScopeToClientMetadata() {
        defaultScope = new Scope();
        defaultScope.add(OIDCScopeValue.OPENID);
    }
    
    /**
     * Set the default {@link Scope} to be used if it was not defined in the request.
     * @param scope The default {@link Scope} to be used if it was not defined in the request.
     */
    public void setDefaultScope(final Scope scope) {
        defaultScope = Constraint.isNotNull(scope, "The default scope cannot be null");
    }
    
    /**
     * Get the default {@link Scope} to be used if it was not defined in the request.
     * @return The default {@link Scope} to be used if it was not defined in the request.
     */
    public Scope getDefaultScope() {
        return defaultScope;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final Scope requestScope = getInputMetadata().getScope();
        if (requestScope == null || requestScope.isEmpty()) {
            log.debug("{} Scope in the request was null, adding default scope", getLogPrefix());
            getOutputMetadata().setScope(defaultScope);
        } else {
            getOutputMetadata().setScope(requestScope);
        }
    }

}
