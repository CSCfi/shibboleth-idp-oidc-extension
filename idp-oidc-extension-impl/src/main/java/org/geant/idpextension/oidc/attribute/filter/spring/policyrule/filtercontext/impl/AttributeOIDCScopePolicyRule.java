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

package org.geant.idpextension.oidc.attribute.filter.spring.policyrule.filtercontext.impl;

import java.util.List;

import javax.annotation.Nonnull;
import net.shibboleth.idp.attribute.filter.context.AttributeFilterContext;
import net.shibboleth.idp.attribute.filter.policyrule.impl.AbstractStringPolicyRule;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.navigate.RecursiveTypedParentContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Compare the scopes of oidc authentication request with the provided value.
 */
public class AttributeOIDCScopePolicyRule extends AbstractStringPolicyRule {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AttributeOIDCScopePolicyRule.class);

    /**
     * Compare the authentication request scopes with the provided string.
     * 
     * @param filterContext the context
     * @return whether it matches
     */
    @SuppressWarnings("rawtypes")
    @Override
    public Tristate matches(@Nonnull final AttributeFilterContext filterContext) {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        ProfileRequestContext profileRequestContext =
                new RecursiveTypedParentContextLookup<AttributeFilterContext, ProfileRequestContext>(
                        ProfileRequestContext.class).apply(filterContext);
        if (profileRequestContext == null || profileRequestContext.getOutboundMessageContext() == null) {
            log.trace("{} No outbound message context", getLogPrefix());
            return Tristate.FALSE;
        }
        OIDCAuthenticationResponseContext ctx = profileRequestContext.getOutboundMessageContext()
                .getSubcontext(OIDCAuthenticationResponseContext.class, false);
        if (ctx == null || ctx.getScope() == null) {
            log.trace("{} No verified requested scopes for oidc found", getLogPrefix());
            return Tristate.FALSE;
        }
        List<String> scopes = ctx.getScope().toStringList();
        if (scopes == null || scopes.isEmpty()) {
            log.warn("{} No scopes in oidc request, should not happen", getLogPrefix());
            return Tristate.FAIL;
        }
        for (String scope : scopes) {
            log.debug("{} evaluating scope {}", getLogPrefix(), scope);
            if (stringCompare(scope) == Tristate.TRUE) {
                return Tristate.TRUE;
            }
        }
        return Tristate.FALSE;
    }

}