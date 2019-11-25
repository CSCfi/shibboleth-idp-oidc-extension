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

import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.minidev.json.JSONObject;
import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.geant.idpextension.oidc.attribute.encoding.impl.AbstractOIDCAttributeEncoder;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.google.common.base.Functions;

/**
 * Action that checks for any released attributes marked for token delivery. For such attributes
 * {@link OIDCAuthenticationResponseTokenClaimsContext} is created under {@link OIDCAuthenticationResponseContext} and
 * the marked attributes are placed there.
 **/

@SuppressWarnings("rawtypes")
public class SetTokenDeliveryAttributesToResponseContext extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(SetTokenDeliveryAttributesToResponseContext.class);

    /**
     * Strategy used to locate the {@link AttributeContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, AttributeContext> attributeContextLookupStrategy;

    /** AttributeContext to use. */
    @Nullable
    private AttributeContext attributeCtx;

    /** Constructor. */
    SetTokenDeliveryAttributesToResponseContext() {
        attributeContextLookupStrategy = Functions.compose(new ChildContextLookup<>(AttributeContext.class),
                new ChildContextLookup<ProfileRequestContext, RelyingPartyContext>(RelyingPartyContext.class));
    }

    /**
     * Set the strategy used to locate the {@link AttributeContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy strategy used to locate the {@link AttributeContext} associated with a given
     *            {@link ProfileRequestContext}
     */
    public void setAttributeContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, AttributeContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        attributeContextLookupStrategy =
                Constraint.isNotNull(strategy, "AttributeContext lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        attributeCtx = attributeContextLookupStrategy.apply(profileRequestContext);
        if (attributeCtx == null) {
            log.debug("{} No AttributeSubcontext available, nothing to do", getLogPrefix());
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        for (IdPAttribute attribute : attributeCtx.getIdPAttributes().values()) {
            final Set<AttributeEncoder<?>> encoders = attribute.getEncoders();
            if (encoders.isEmpty()) {
                log.debug("{} Attribute {} does not have any encoders, nothing to do", getLogPrefix(),
                        attribute.getId());
                continue;
            }
            for (final AttributeEncoder<?> encoder : encoders) {
                try {
                    if (encoder instanceof AbstractOIDCAttributeEncoder) {
                        if (encoder.getActivationCondition() != null
                                && !encoder.getActivationCondition().apply(profileRequestContext)) {
                            log.debug("{} Encoder not active", getLogPrefix());
                            continue;
                        }
                        JSONObject obj = (JSONObject) encoder.encode(attribute);
                        for (String name : obj.keySet()) {
                            if (((AbstractOIDCAttributeEncoder) encoder).getSetToToken()) {
                                log.debug(
                                        "{} Attribute {} marked not to be recreatable, adding a token delivery claim to response context for code/token creation.",
                                        getLogPrefix(), name);
                                OIDCAuthenticationResponseTokenClaimsContext tokenClaimsCtx = getOidcResponseContext()
                                        .getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class, true);
                                if (((AbstractOIDCAttributeEncoder) encoder).getPlaceToIDToken()
                                        && !((AbstractOIDCAttributeEncoder) encoder).getDenyUserinfo()) {
                                    // Deliver for userinfo and id token
                                    tokenClaimsCtx.getClaims().setClaim(name, obj.get(name));
                                } else if (((AbstractOIDCAttributeEncoder) encoder).getPlaceToIDToken()) {
                                    // Deliver only for idtoken
                                    tokenClaimsCtx.getIdtokenClaims().setClaim(name, obj.get(name));
                                } else if (!((AbstractOIDCAttributeEncoder) encoder).getDenyUserinfo()) {
                                    // Deliver only for userinfo
                                    tokenClaimsCtx.getUserinfoClaims().setClaim(name, obj.get(name));
                                }

                            }
                        }
                    }
                } catch (AttributeEncodingException e) {
                    log.warn("{} Unable to encode attribute {} as OIDC attribute", getLogPrefix(), attribute.getId(),
                            e);
                }
            }
        }
    }
}