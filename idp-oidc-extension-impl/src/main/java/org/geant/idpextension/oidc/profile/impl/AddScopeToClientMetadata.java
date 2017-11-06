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
