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