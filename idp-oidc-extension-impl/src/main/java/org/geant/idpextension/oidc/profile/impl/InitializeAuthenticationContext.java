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