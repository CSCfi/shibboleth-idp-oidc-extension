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
        claimsSet.putAll(tokenClaimsCtx.getClaims());
        if (targetIDToken) {
            claimsSet.putAll(tokenClaimsCtx.getIdtokenClaims());
        } else {
            claimsSet.putAll(tokenClaimsCtx.getUserinfoClaims());
        }
        log.debug("{} claims set after adding token delivery claims {}", getLogPrefix(),
                claimsSet.toJSONObject().toJSONString());
    }
}