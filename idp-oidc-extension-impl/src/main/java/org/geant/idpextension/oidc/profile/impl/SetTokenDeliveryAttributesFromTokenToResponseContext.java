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

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.geant.idpextension.oidc.profile.context.navigate.TokenRequestDeliveryClaimsLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.TokenRequestIDTokenDeliveryClaimsLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.TokenRequestUserInfoDeliveryClaimsLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

/**
 * Action that locates any token delivery claims from authorization code / access token. For located claims
 * {@link OIDCAuthenticationResponseTokenClaimsContext} is created under {@link OIDCAuthenticationResponseContext} and
 * the claims are placed there. Token and user info end points use the context for forming response.
 **/
@SuppressWarnings("rawtypes")
public class SetTokenDeliveryAttributesFromTokenToResponseContext extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetTokenDeliveryAttributesFromTokenToResponseContext.class);

    /** Strategy used to obtain the delivery claims. */
    @Nonnull
    private Function<ProfileRequestContext, ClaimsSet> deliveryClaimsLookupStrategy;

    /** Strategy used to obtain the id token delivery claims. */
    @Nonnull
    private Function<ProfileRequestContext, ClaimsSet> idTokenDeliveryClaimsLookupStrategy;

    /** Strategy used to obtain the user info delivery claims. */
    @Nonnull
    private Function<ProfileRequestContext, ClaimsSet> userinfoDeliveryClaimsLookupStrategy;

    /**
     * Constructor.
     */
    public SetTokenDeliveryAttributesFromTokenToResponseContext() {
        deliveryClaimsLookupStrategy = new TokenRequestDeliveryClaimsLookupFunction();
        idTokenDeliveryClaimsLookupStrategy = new TokenRequestIDTokenDeliveryClaimsLookupFunction();
        userinfoDeliveryClaimsLookupStrategy = new TokenRequestUserInfoDeliveryClaimsLookupFunction();
    }

    /**
     * Set the strategy used to locate the delivery claims.
     * 
     * @param strategy lookup strategy
     */
    public void setDeliveryClaimsLookupStrategy(@Nonnull final Function<ProfileRequestContext, ClaimsSet> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        deliveryClaimsLookupStrategy =
                Constraint.isNotNull(strategy, "DeliveryClaimsLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the id token delivery claims.
     * 
     * @param strategy lookup strategy
     */
    public void setIDTokenDeliveryClaimsLookupStrategy(
            @Nullable final Function<ProfileRequestContext, ClaimsSet> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
    }

    /**
     * Set the strategy used to locate the user info delivery claims.
     * 
     * @param strategy lookup strategy
     */
    public void setUserinfoDeliveryClaimsLookupStrategy(
            @Nullable final Function<ProfileRequestContext, ClaimsSet> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        ClaimsSet claims = deliveryClaimsLookupStrategy.apply(profileRequestContext);
        if (claims != null) {
            OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx =
                    getOidcResponseContext().getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class, true);
            tokenClaimsCtx.getClaims().putAll(claims);
        }
        if (idTokenDeliveryClaimsLookupStrategy != null) {
            claims = idTokenDeliveryClaimsLookupStrategy.apply(profileRequestContext);
            if (claims != null) {
                OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx = getOidcResponseContext()
                        .getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class, true);
                tokenClaimsCtx.getIdtokenClaims().putAll(claims);
            }
        }
        if (userinfoDeliveryClaimsLookupStrategy != null) {
            claims = userinfoDeliveryClaimsLookupStrategy.apply(profileRequestContext);
            if (claims != null) {
                OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx = getOidcResponseContext()
                        .getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class, true);
                tokenClaimsCtx.getUserinfoClaims().putAll(claims);
            }
        }

    }

}