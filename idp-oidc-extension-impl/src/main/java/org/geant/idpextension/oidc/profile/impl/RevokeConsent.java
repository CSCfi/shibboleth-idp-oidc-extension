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

import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestedPromptLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.Prompt;

import net.shibboleth.idp.consent.context.ConsentManagementContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that revokes consent if offline_access scope or prompt with consent is requested.
 */
@SuppressWarnings("rawtypes")
public class RevokeConsent extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(RevokeConsent.class);

    /** Strategy used to obtain the requested prompt value. */
    @Nonnull
    private Function<ProfileRequestContext, Prompt> promptLookupStrategy;

    /**
     * Constructor.
     */
    public RevokeConsent() {
        promptLookupStrategy = new DefaultRequestedPromptLookupFunction();
    }

    /**
     * Set the strategy used to locate the requested prompt.
     * 
     * @param strategy lookup strategy
     */
    public void setPromptLookupStrategy(@Nonnull final Function<ProfileRequestContext, Prompt> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        promptLookupStrategy = Constraint.isNotNull(strategy, "PromptLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (getOidcResponseContext().getScope().contains(OIDCScopeValue.OFFLINE_ACCESS)) {
            log.debug("{} Pre-existing consent revoked as offline_access scope is requested", getLogPrefix());
            profileRequestContext.getSubcontext(ConsentManagementContext.class, true).setRevokeConsent(true);
            return;
        }
        Prompt prompt = promptLookupStrategy.apply(profileRequestContext);
        if (prompt != null && prompt.contains(Prompt.Type.CONSENT)) {
            log.debug("{} Pre-existing consent revoked as user consent is requested", getLogPrefix());
            profileRequestContext.getSubcontext(ConsentManagementContext.class, true).setRevokeConsent(true);
        }
    }
}