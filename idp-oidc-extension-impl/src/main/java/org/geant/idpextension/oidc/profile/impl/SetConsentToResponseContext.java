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

import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseConsentContext;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import net.shibboleth.idp.consent.context.AttributeReleaseContext;
import net.shibboleth.idp.consent.context.ConsentContext;
import net.shibboleth.idp.consent.Consent;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Action that checks for any existing consent information for token delivery. Consent information is stored to
 * {@link OIDCAuthenticationResponseTokenClaimsContext} that is created under {@link OIDCAuthenticationResponseContext}.
 **/

@SuppressWarnings("rawtypes")
public class SetConsentToResponseContext extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetConsentToResponseContext.class);

    /** Consent context. */
    @Nullable
    private ConsentContext consentContext;

    /**
     * Strategy used to find the {@link ConsentContext} from the {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, ConsentContext> consentContextLookupStrategy;

    /** The {@link AttributeReleaseContext} to operate on. */
    @Nullable
    private AttributeReleaseContext attributeReleaseContext;

    /**
     * Strategy used to find the {@link AttributeReleaseContext} from the {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, AttributeReleaseContext> attributeReleaseContextLookupStrategy;

    /** Constructor. */
    SetConsentToResponseContext() {
        consentContextLookupStrategy = new ChildContextLookup<>(ConsentContext.class, false);
        attributeReleaseContextLookupStrategy = new ChildContextLookup<>(AttributeReleaseContext.class, false);
    }

    /**
     * Set the consent context lookup strategy.
     * 
     * @param strategy the consent context lookup strategy
     */
    public void
            setConsentContextLookupStrategy(@Nonnull final Function<ProfileRequestContext, ConsentContext> strategy) {
        consentContextLookupStrategy = Constraint.isNotNull(strategy, "Consent context lookup strategy cannot be null");
    }

    /**
     * Set the attribute release context lookup strategy.
     * 
     * @param strategy the attribute release context lookup strategy
     */
    public void setAttributeReleaseContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, AttributeReleaseContext> strategy) {
        attributeReleaseContextLookupStrategy =
                Constraint.isNotNull(strategy, "Attribute release context lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        consentContext = consentContextLookupStrategy.apply(profileRequestContext);
        if (consentContext == null) {
            log.debug("{} Unable to locate consent context within profile request context, nothing to do",
                    getLogPrefix());
            return false;
        }
        attributeReleaseContext = attributeReleaseContextLookupStrategy.apply(profileRequestContext);
        if (attributeReleaseContext == null) {
            log.debug("{} Unable to locate attribute release context within profile request context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        OIDCAuthenticationResponseConsentContext oidcConsentCtx =
                getOidcResponseContext().getSubcontext(OIDCAuthenticationResponseConsentContext.class, true);
        final Map<String, Consent> consents = consentContext.getCurrentConsents().isEmpty()
                ? consentContext.getPreviousConsents() : consentContext.getCurrentConsents();
        for (String key : consents.keySet()) {
            if (consents.get(key) != null && consents.get(key).isApproved()) {
                oidcConsentCtx.getConsentedAttributes().add(key);
            }
        }
        if (attributeReleaseContext.getConsentableAttributes() != null) {
            oidcConsentCtx.getConsentableAttributes()
                    .addAll(attributeReleaseContext.getConsentableAttributes().keySet());
        }
        log.debug("{} Set to response context consented attributes {} and consentable attributes {}", getLogPrefix(),
                oidcConsentCtx.getConsentedAttributes().toJSONString(),
                oidcConsentCtx.getConsentableAttributes().toJSONString());

    }
}