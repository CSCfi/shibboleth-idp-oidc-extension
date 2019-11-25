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

import java.util.Iterator;
import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestResponseTypeLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestedScopeLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that validates requested scopes are registered ones. Validated scopes are stored to response context.
 * Offline_access scope is ignored in authentication endpoint validation unless response type contains code.
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
     * @param strategy lookup strategy
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
        if (requestedScopes.contains(OIDCScopeValue.OFFLINE_ACCESS)) {
            // DefaultRequestResponseTypeLookupFunction returns response type only in authentication end point. It is enough to
            // remove offline_scope in this first validation turn.
            ResponseType responseType = new DefaultRequestResponseTypeLookupFunction().apply(profileRequestContext);
            if (responseType != null && !responseType.contains(ResponseType.Value.CODE)) {
                requestedScopes.remove(OIDCScopeValue.OFFLINE_ACCESS);
            }
        }
        getOidcResponseContext().setScope(requestedScopes);
    }
}