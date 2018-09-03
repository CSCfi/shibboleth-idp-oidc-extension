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

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestLoginHintLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestMaxAgeLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultRequestedPromptLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.Prompt;

/**
 * An action that creates an {@link AuthenticationContext} and attaches it to the current {@link ProfileRequestContext}.
 * 
 * <p>
 * As the incoming message is a OIDC {@link AuthnRequest}, the basic authentication policy (IsPassive, ForceAuthn) is
 * interpreted from the request prompt parameter. If the incoming message has login_hint parameter the value of it is
 * placed to hinted name.
 * </p>
 * 
 * 
 */
@SuppressWarnings("rawtypes")
public class InitializeAuthenticationContext extends AbstractOIDCAuthenticationRequestAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(InitializeAuthenticationContext.class);

    /** Strategy used to obtain the requested prompt value. */
    @Nonnull
    private Function<ProfileRequestContext, Prompt> promptLookupStrategy;

    /** Strategy used to obtain the request login hint value. */
    @Nonnull
    private Function<ProfileRequestContext, String> loginHintLookupStrategy;

    /** Strategy used to obtain the request max_age value. */
    @Nonnull
    private Function<ProfileRequestContext, Long> maxAgeLookupStrategy;

    /**
     * Constructor.
     */
    public InitializeAuthenticationContext() {
        promptLookupStrategy = new DefaultRequestedPromptLookupFunction();
        loginHintLookupStrategy = new DefaultRequestLoginHintLookupFunction();
        maxAgeLookupStrategy = new DefaultRequestMaxAgeLookupFunction();
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

    /**
     * Set the strategy used to locate the request login hint.
     * 
     * @param strategy lookup strategy
     */
    public void setLoginHintLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        loginHintLookupStrategy =
                Constraint.isNotNull(strategy, "LoginHintLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the request max age.
     * 
     * @param strategy lookup strategy
     */
    public void setMaxAgeLookupStrategy(@Nonnull final Function<ProfileRequestContext, Long> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        maxAgeLookupStrategy = Constraint.isNotNull(strategy, "MaxAgeLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        log.debug("{} Initializing authentication context", getLogPrefix());
        final AuthenticationContext authnCtx = new AuthenticationContext();
        Long maxAge = maxAgeLookupStrategy.apply(profileRequestContext);
        if (maxAge != null) {
            if (maxAge==0) {
                authnCtx.setMaxAge(1);
            }else {
                authnCtx.setMaxAge(maxAge*1000);    
            }
        }
        Prompt prompt = promptLookupStrategy.apply(profileRequestContext);
        if (prompt != null) {
            authnCtx.setIsPassive(prompt.contains(Prompt.Type.NONE));
            authnCtx.setForceAuthn(prompt.contains(Prompt.Type.LOGIN));
        }
        String loginHint = loginHintLookupStrategy.apply(profileRequestContext);
        if (loginHint != null) {
            authnCtx.setHintedName(loginHint);
        }
        final AuthenticationContext initialAuthnContext =
                profileRequestContext.getSubcontext(AuthenticationContext.class);
        if (initialAuthnContext != null) {
            authnCtx.setInitialAuthenticationResult(initialAuthnContext.getAuthenticationResult());
        }
        profileRequestContext.addSubcontext(authnCtx, true);
        log.debug("{} Created authentication context: {}", getLogPrefix(), authnCtx);
    }

}