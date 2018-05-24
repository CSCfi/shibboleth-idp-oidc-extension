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
import javax.annotation.Nullable;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultResponseClaimsSetLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.OIDCAuthenticationResponseContextLookupFunction;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

/**
 * Action that adds claims to a {@link ClaimsSet}. Claims are added from
 * {@link OIDCAuthenticationResponseTokenClaimsContext}. The main use cases are adding token delivery attributes to id
 * token in token endpoint response or to user info response.
 */
@SuppressWarnings("rawtypes")
public class AddTokenDeliveryAttributesToClaimsSet extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AddTokenDeliveryAttributesToClaimsSet.class);

    /**
     * Strategy used to locate the response {@link ClaimsSet} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, ClaimsSet> responseClaimsSetLookupStrategy;

    /** Strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext}. */
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> tokenClaimsContextLookupStrategy;

    /** AttributeContext to use. */
    @Nullable
    private AttributeContext attributeCtx;

    /** Claims Set to use. */
    @Nullable
    private ClaimsSet claimsSet;

    /** Whether we are adding claims to ID Token. */
    @Nonnull
    private boolean targetIDToken;

    /** delivery claims to copy to claims set. */
    @Nullable
    private OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx;

    /**
     * Set whether target is id token claims set.
     * 
     * @param flag whether target is id token claims set
     */
    public void setTargetIDToken(boolean flag) {
        targetIDToken = flag;
    }

    /** Constructor. */
    AddTokenDeliveryAttributesToClaimsSet() {
        responseClaimsSetLookupStrategy = new DefaultResponseClaimsSetLookupFunction();
        tokenClaimsContextLookupStrategy =
                Functions.compose(new ChildContextLookup<>(OIDCAuthenticationResponseTokenClaimsContext.class),
                        new OIDCAuthenticationResponseContextLookupFunction());
    }

    /**
     * Set the strategy used to locate the response {@link ClaimsSet} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy strategy used to locate the response {@link ClaimsSet} associated with a given
     *            {@link ProfileRequestContext}
     */
    public void setResponseClaimsSetLookupStrategy(@Nonnull final Function<ProfileRequestContext, ClaimsSet> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        responseClaimsSetLookupStrategy =
                Constraint.isNotNull(strategy, "Response Claims Set lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setOIDCAuthenticationResponseTokenClaimsContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseTokenClaimsContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        tokenClaimsContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCAuthenticationResponseTokenClaimsContextt lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        claimsSet = responseClaimsSetLookupStrategy.apply(profileRequestContext);
        if (claimsSet == null) {
            log.error("{} No claims set to fill", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        tokenClaimsCtx = tokenClaimsContextLookupStrategy.apply(profileRequestContext);
        if (tokenClaimsCtx == null) {
            log.debug("{} No token delivery claims context, nothing to do", getLogPrefix());
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (tokenClaimsCtx.getClaims() != null) {
            claimsSet.putAll(tokenClaimsCtx.getClaims());
        }
        if (tokenClaimsCtx.getIdtokenClaims() != null && targetIDToken) {
            claimsSet.putAll(tokenClaimsCtx.getIdtokenClaims());
        }
        if (tokenClaimsCtx.getUserinfoClaims() != null && !targetIDToken) {
            claimsSet.putAll(tokenClaimsCtx.getUserinfoClaims());
        }
        log.debug("{} claims set after adding token delivery claims {}", getLogPrefix(),
                claimsSet.toJSONObject().toJSONString());
    }
}