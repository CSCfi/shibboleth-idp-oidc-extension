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