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
import net.minidev.json.JSONArray;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseConsentContext;
import org.geant.idpextension.oidc.profile.context.navigate.TokenRequestConsentableAttributesLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.TokenRequestConsentedAttributesLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;

/**
 * Action that locates consent from authorization code / access token. For located consent
 * {@link OIDCAuthenticationResponseConsentContext} is created under {@link OIDCAuthenticationResponseContext} and the
 * consent placed there. Token and user info end points use the consent context for forming response.
 **/
@SuppressWarnings("rawtypes")
public class SetConsentFromTokenToResponseContext extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetConsentFromTokenToResponseContext.class);

    /** Strategy used to obtain the consented attributes. */
    @Nonnull
    private Function<ProfileRequestContext, JSONArray> consentedAttributesLookupStrategy;

    /** Strategy used to obtain the consentable attributes */
    @Nonnull
    private Function<ProfileRequestContext, JSONArray> consentableAttributesLookupStrategy;

    /**
     * Constructor.
     */
    public SetConsentFromTokenToResponseContext() {
        consentedAttributesLookupStrategy = new TokenRequestConsentedAttributesLookupFunction();
        consentableAttributesLookupStrategy = new TokenRequestConsentableAttributesLookupFunction();
    }

    /**
     * Set the strategy used to locate the consented attributes.
     * 
     * @param strategy lookup strategy
     */
    public void
            setConsentedAttributesLookupStrategy(@Nonnull final Function<ProfileRequestContext, JSONArray> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        consentedAttributesLookupStrategy =
                Constraint.isNotNull(strategy, "ConsentedAttributesLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the consentable attributes.
     * 
     * @param strategy lookup strategy
     */
    public void
            setConsentableAttributesLookupStrategy(@Nonnull final Function<ProfileRequestContext, JSONArray> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        consentableAttributesLookupStrategy =
                Constraint.isNotNull(strategy, "ConsentableAttributesLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        JSONArray consentedAttributes = consentedAttributesLookupStrategy.apply(profileRequestContext);
        JSONArray consentableAttributes = consentableAttributesLookupStrategy.apply(profileRequestContext);
        if (consentedAttributes != null || consentableAttributes != null) {
            OIDCAuthenticationResponseConsentContext consentClaimsCtx =
                    getOidcResponseContext().getSubcontext(OIDCAuthenticationResponseConsentContext.class, true);
            consentClaimsCtx.getConsentableAttributes().addAll(consentableAttributes);
            consentClaimsCtx.getConsentedAttributes().addAll(consentedAttributes);
        }
    }

}