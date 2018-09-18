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