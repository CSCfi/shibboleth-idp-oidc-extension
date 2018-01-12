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

import java.util.Iterator;
import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestedScopeLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.Scope;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that validates requested scopes are registered ones. Validated scopes
 * are stored to response context.
 *
 */
@SuppressWarnings("rawtypes")
public class ValidateScope extends AbstractOIDCAuthenticationResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ValidateScope.class);

    /** Strategy used to obtain the requested scope value. */
    @Nonnull
    private Function<ProfileRequestContext, Scope> scopeLookupStrategy;

    /**
     * Constructor.
     */
    public ValidateScope() {
        scopeLookupStrategy = new DefaultRequestedScopeLookupFunction();
    }

    /**
     * Set the strategy used to locate the requested scope to use.
     * 
     * @param strategy
     *            lookup strategy
     */
    public void setScopeLookupStrategy(@Nonnull final Function<ProfileRequestContext, Scope> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        scopeLookupStrategy = Constraint.isNotNull(strategy, "ScopeLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        Scope registeredScopes = getMetadataContext().getClientInformation().getMetadata().getScope();
        if (registeredScopes == null || registeredScopes.isEmpty()) {
            log.debug("{} No registered scopes for client {}, nothing to do", getLogPrefix(),
                    getMetadataContext().getClientInformation().getID());
            return;
        }
        Scope requestedScopes = scopeLookupStrategy.apply(profileRequestContext);
        for (Iterator<Scope.Value> i = requestedScopes.iterator(); i.hasNext();) {
            Scope.Value scope = i.next();
            if (!registeredScopes.contains(scope)) {
                log.warn("{} removing requested scope {} for rp {} as it is not a registered one", getLogPrefix(),
                        scope.getValue(), getMetadataContext().getClientInformation().getID());
                i.remove();
            }
        }
        getOidcResponseContext().setScope(requestedScopes);
    }
}