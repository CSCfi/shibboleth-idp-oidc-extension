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
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.geant.idpextension.oidc.profile.context.navigate.OIDCAuthenticationResponseContextLookupFunction;
import org.opensaml.messaging.context.BaseContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.nimbusds.oauth2.sdk.Scope;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An action that reduces validated scopes of the original authentication request to scopes of token request when using
 * refresh token as a grant and scopes are set.
 * 
 * If in the case we do have scope request parameter we remove token delivery attributes as we have no way of
 * reproducing the circumstances they were produced in. ie. no way of telling if the scope change effects to their
 * release.
 */

public class ReduceValidatedScope extends AbstractOIDCTokenResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(ReduceValidatedScope.class);

    /** Strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext}. */
    @SuppressWarnings("rawtypes")
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> tokenClaimsContextLookupStrategy;

    /** delivery claims to copy to claims set. */
    @Nullable
    private OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx;

    /** Constructor. */
    ReduceValidatedScope() {
        tokenClaimsContextLookupStrategy =
                Functions.compose(new ChildContextLookup<>(OIDCAuthenticationResponseTokenClaimsContext.class),
                        new OIDCAuthenticationResponseContextLookupFunction());
    }

    /**
     * Set the strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    @SuppressWarnings("rawtypes")
    public void setOIDCAuthenticationResponseTokenClaimsContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        tokenClaimsContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCAuthenticationResponseTokenClaimsContextt lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @SuppressWarnings("rawtypes")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        Scope requestedScope = getTokenRequest().getScope();
        if (requestedScope == null) {
            return;
        }
        List<String> validatedScopes = getOidcResponseContext().getScope().toStringList();
        log.debug("{} Original scope {}", getLogPrefix(), getOidcResponseContext().getScope().toString());
        validatedScopes.retainAll(requestedScope.toStringList());
        Scope reducedScope = new Scope();
        for (String scope : validatedScopes) {
            reducedScope.add(scope);
        }
        log.debug("{} Reduced scope {}", getLogPrefix(), reducedScope.toString());
        if (!reducedScope.equals(getOidcResponseContext().getScope())) {
            getOidcResponseContext().setScope(reducedScope);
            tokenClaimsCtx = tokenClaimsContextLookupStrategy.apply(profileRequestContext);
            if (tokenClaimsCtx != null) {
                log.debug("{} Removing token delivery attributes due to reduced scope", getLogPrefix());
                BaseContext parent = tokenClaimsCtx.getParent();
                parent.removeSubcontext(tokenClaimsCtx);
            }
        }
    }
}
