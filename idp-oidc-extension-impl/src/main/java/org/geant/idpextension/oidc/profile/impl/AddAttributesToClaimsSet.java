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

import java.util.List;
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
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseConsentContext;
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
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

/**
 * Action that adds claims to a {@link ClaimsSet}. Claims are formed of resolved attributes having OIDC encoder. Action
 * verifies user has consented to release attribute, if consent information is available. Actions will not add claims
 * listed as reserved.
 */
@SuppressWarnings("rawtypes")
public class AddAttributesToClaimsSet extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AddAttributesToClaimsSet.class);

    /**
     * Strategy used to locate the {@link AttributeContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, AttributeContext> attributeContextLookupStrategy;

    /**
     * Strategy used to locate the response {@link ClaimsSet} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, ClaimsSet> responseClaimsSetLookupStrategy;

    /** AttributeContext to use. */
    @Nullable
    private AttributeContext attributeCtx;

    /** Claims Set to use. */
    @Nullable
    private ClaimsSet claimsSet;

    /** Whether we are adding claims to ID Token. */
    @Nonnull
    private boolean targetIDToken;

    /** Whether we can add claims to IDToken by default i.e. response type is "id_token". */
    @Nonnull
    private boolean addToIDTokenByDefault;

    /** Strategy used to locate the {@link OIDCAuthenticationResponseConsentContext}. */
    @Nonnull
    private Function<ProfileRequestContext, OIDCAuthenticationResponseConsentContext> consentContextLookupStrategy;

    /** List of claim names that will not be added. */
    @Nullable
    private List<String> reservedClaimNames;

    /** Constructor. */
    AddAttributesToClaimsSet() {
        attributeContextLookupStrategy = Functions.compose(new ChildContextLookup<>(AttributeContext.class),
                new ChildContextLookup<ProfileRequestContext, RelyingPartyContext>(RelyingPartyContext.class));
        responseClaimsSetLookupStrategy = new DefaultResponseClaimsSetLookupFunction();
        consentContextLookupStrategy =
                Functions.compose(new ChildContextLookup<>(OIDCAuthenticationResponseConsentContext.class),
                        new OIDCAuthenticationResponseContextLookupFunction());
    }

    /**
     * Set list of claim names that will not be added.
     * 
     * @param claimNames list of claim names that will not be added.
     */
    public void setReservedClaimNames(List<String> claimNames) {
        reservedClaimNames = claimNames;
    }

    /**
     * Set whether target is id token claims set. If this flag is set addToIDTokenByDefault flag is active.
     * 
     * @param flag whether target is id token claims set
     */
    public void setTargetIDToken(boolean flag) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        targetIDToken = flag;
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

    /**
     * Set the strategy used to locate the {@link OIDCAuthenticationResponseTokenClaimsContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setOIDCAuthenticationResponseConsentContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, OIDCAuthenticationResponseConsentContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        consentContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCAuthenticationResponseConsentContext lookup strategy cannot be null");
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
        claimsSet = responseClaimsSetLookupStrategy.apply(profileRequestContext);
        if (claimsSet == null) {
            log.error("{} No claims set to fill", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        if (targetIDToken) {
            Object msg = profileRequestContext.getInboundMessageContext().getMessage();
            if (msg instanceof AuthenticationRequest) {
                addToIDTokenByDefault =
                        !((AuthenticationRequest) msg).getResponseType().contains(ResponseType.Value.TOKEN);
            }
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        OIDCAuthenticationResponseConsentContext consentCtx = consentContextLookupStrategy.apply(profileRequestContext);
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
                        if (targetIDToken) {
                            if (!addToIDTokenByDefault
                                    && !((AbstractOIDCAttributeEncoder) encoder).getPlaceToIDToken()) {
                                log.debug("{} Attribute {} not targeted for ID Token", getLogPrefix(),
                                        attribute.getId());
                                continue;
                            }
                        } else if (((AbstractOIDCAttributeEncoder) encoder).getDenyUserinfo()) {
                            log.debug("{} Attribute {} not targeted for Userinfo response", getLogPrefix(),
                                    attribute.getId());
                            continue;
                        }
                        JSONObject obj = (JSONObject) encoder.encode(attribute);
                        for (String name : obj.keySet()) {
                            if (reservedClaimNames != null && reservedClaimNames.contains(name)) {
                                log.debug("{} claim has a reserved name {}. Not added to claims set", getLogPrefix(),
                                        name);
                                continue;
                            }
                            if (consentCtx != null && consentCtx.getConsentableAttributes().contains(name)
                                    && !consentCtx.getConsentedAttributes().contains(name)) {
                                log.debug("{} Consentable attribute {} has no consent. Not added to claims set",
                                        getLogPrefix(), name);
                                continue;
                            }
                            log.debug("{} Adding claim {} with value {}", getLogPrefix(), name, obj.get(name));
                            claimsSet.setClaim(name, obj.get(name));
                        }
                    }
                } catch (AttributeEncodingException e) {
                    log.warn("{} Unable to encode attribute {} as OIDC attribute", getLogPrefix(), attribute.getId(),
                            e);
                }
            }
        }
        log.debug("{} claims set after mapping attributes to claims {}", getLogPrefix(),
                claimsSet.toJSONObject().toJSONString());
    }
}