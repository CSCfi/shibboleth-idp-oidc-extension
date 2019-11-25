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
        idTokenDeliveryClaimsLookupStrategy = strategy;
    }

    /**
     * Set the strategy used to locate the user info delivery claims.
     * 
     * @param strategy lookup strategy
     */
    public void setUserinfoDeliveryClaimsLookupStrategy(
            @Nullable final Function<ProfileRequestContext, ClaimsSet> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        userinfoDeliveryClaimsLookupStrategy = strategy;
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