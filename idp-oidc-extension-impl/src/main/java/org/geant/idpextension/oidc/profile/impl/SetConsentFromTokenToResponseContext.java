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