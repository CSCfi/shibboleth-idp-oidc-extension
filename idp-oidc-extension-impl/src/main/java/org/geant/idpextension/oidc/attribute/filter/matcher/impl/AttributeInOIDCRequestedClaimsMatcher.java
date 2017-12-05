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

package org.geant.idpextension.oidc.attribute.filter.matcher.impl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.attribute.encoding.impl.AbstractOIDCAttributeEncoder;
import org.opensaml.messaging.context.BaseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableSet;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.filter.Matcher;
import net.shibboleth.idp.attribute.filter.context.AttributeFilterContext;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentSupport;

/** Class for matching attribute to requested claims. */
public class AttributeInOIDCRequestedClaimsMatcher extends AbstractIdentifiableInitializableComponent implements
        Matcher {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AttributeInOIDCRequestedClaimsMatcher.class);

    /** Whether to return a match if the request contains no requested claims. */
    private boolean matchIfRequestedClaimsSilent;

    /** Whether to look for a match only in id token part. */
    private boolean matchOnlyIDToken;

    /** Whether to look for a match only in user info part. */
    private boolean matchOnlyUserInfo;

    /** Whether to drop non essential claims. */
    private boolean onlyIfEssential;

    /** The String used to prefix log message. */
    private String logPrefix;

   
    /**
     * Gets whether to drop non essential claims.
     * 
     * @return whether to drop non essential claims
     */
    public boolean getOnlyIfEssential() {
        return onlyIfEssential;
    }

    /**
     * Sets whether to drop non essential claims.
     * 
     * @param flag
     *            whether to drop non essential claims
     */
    public void setOnlyIfEssential(boolean flag) {
        onlyIfEssential = flag;
    }

    /**
     * Gets whether to match only id token part of the requested claims.
     * 
     * @return whether to match only id token part of the requested claims
     */
    public boolean getMatchOnlyIDToken() {
        return matchOnlyIDToken;
    }

    /**
     * Sets whether to match only id token part of the requested claims.
     * 
     * @param flag
     *            whether to match only id token part of the requested claims
     */
    public void setMatchOnlyIDToken(boolean flag) {
        this.matchOnlyIDToken = flag;
    }

    /**
     * Gets whether to match only user info part of the requested claims.
     * 
     * @return whether to match only user info part of the requested claims
     */
    public boolean getMatchOnlyUserInfo() {
        return matchOnlyUserInfo;
    }

    /**
     * Sets whether to match only user info part of the requested claims.
     * 
     * @param flag
     *            whether to match only user info part of the requested claims
     */
    public void setMatchOnlyUserInfo(boolean flag) {
        this.matchOnlyUserInfo = flag;
    }

    /**
     * Gets whether to matched if the request contains no requested claims.
     * 
     * @return whether to match if the request contains no requested claims
     */
    public boolean getMatchIRequestedClaimsSilent() {
        return matchIfRequestedClaimsSilent;
    }

    /**
     * Sets whether to match if the request contains no requested claims.
     * 
     * @param flag
     *            whether to match if the request contains no requested claims
     */
    public void setMatchIfRequestedClaimsSilent(final boolean flag) {
        matchIfRequestedClaimsSilent = flag;
    }

    /**
     * Resolve oidc encoder names for the attribute.
     * 
     * @param set
     *            attached to attribute
     * @return list of names
     */
    private List<String> resolveClaimNames(Set<AttributeEncoder<?>> set) {
        List<String> names = new ArrayList<String>();
        if (set != null) {
            for (AttributeEncoder<?> encoder : set) {
                if (encoder instanceof AbstractOIDCAttributeEncoder) {
                    names.add(((AbstractOIDCAttributeEncoder) encoder).getName());
                }
            }
        }
        return names;

    }

// Checkstyle: CyclomaticComplexity OFF
    @Override
    public Set<IdPAttributeValue<?>> getMatchingValues(@Nonnull IdPAttribute attribute,
            @Nonnull AttributeFilterContext filtercontext) {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        List<String> names = resolveClaimNames(attribute.getEncoders());
        if (names.isEmpty()) {
            // This is always a failure.
            log.debug("{} No oidc encoders attached to attribute", getLogPrefix());
            return null;
        }
        AuthenticationRequest request = getAuthenticationRequest(getInboundMessageContext(filtercontext));
        if (request == null) {
            // This is always a failure.
            log.debug("{} No oidc request found for this comparison", getLogPrefix());
            return null;
        }
        if (request.getClaims() == null
                || (request.getClaims().getIDTokenClaims() == null && 
                request.getClaims().getUserInfoClaims() == null)) {
            log.debug("{} No claims in request", getLogPrefix());
            if (getMatchIRequestedClaimsSilent()) {
                log.debug("{} all values matched as in silent mode", getLogPrefix());
                return ImmutableSet.copyOf(attribute.getValues());
            } else {
                log.debug("{} none of the values matched as not silent mode", getLogPrefix());
                return null;
            }
        }
        if (request.getClaims().getIDTokenClaimNames(false) != null && !getMatchOnlyUserInfo()) {
            if (!Collections.disjoint(request.getClaims().getIDTokenClaimNames(false), names)) {
                log.debug("{} all values matched as {} is requested id token claims", 
                        getLogPrefix(), attribute.getId());
                log.warn("{} Essential checking not implemented yet", getLogPrefix());
                // TODO: value based filtering with option onlyEssential
                return ImmutableSet.copyOf(attribute.getValues());
            }
        }
        if (request.getClaims().getUserInfoClaimNames(false) != null && !getMatchOnlyIDToken()) {
            if (!Collections.disjoint(request.getClaims().getUserInfoClaimNames(false), names)) {
                log.debug("{} all values matched as {} is requested user info claims", getLogPrefix(),
                        attribute.getId());
                log.warn("{} Essential checking not implemented yet", getLogPrefix());
                // TODO: value based filtering with option onlyEssential
                return ImmutableSet.copyOf(attribute.getValues());
            }
        }
        log.debug("{} attribute {} was not a requested claim, none of the values matched", getLogPrefix(),
                attribute.getId());
        return null;
    }
// Checkstyle: CyclomaticComplexity ON

    /**
     * return a string which is to be prepended to all log messages.
     * 
     * @return "Attribute Filter '<filterID>' :"
     */
    @Nonnull
    protected String getLogPrefix() {
        // local cache of cached entry to allow unsynchronised clearing.
        String prefix = logPrefix;
        if (null == prefix) {
            final StringBuilder builder = new StringBuilder("Attribute Filter '").append(getId()).append("':");
            prefix = builder.toString();
            if (null == logPrefix) {
                logPrefix = prefix;
            }
        }
        return prefix;
    }

    // TODO: move these 2 following helpers to some common code.

    /**
     * Helper method to locate inbound message context.
     * 
     * @param ctx
     *            any context decendant from profile request context,
     * @return Inbound message context or null if not found.
     */
    @SuppressWarnings("rawtypes")
    private MessageContext getInboundMessageContext(BaseContext ctx) {
        if (ctx == null) {
            return null;
        }
        BaseContext ctxRunner = ctx;
        while (ctxRunner.getParent() != null) {
            ctxRunner = ctxRunner.getParent();
        }
        if (ctxRunner instanceof ProfileRequestContext) {
            return ((ProfileRequestContext) ctxRunner).getInboundMessageContext();
        }
        return null;
    }

    /**
     * Returns oidc authentication request from message context.
     * 
     * @param msgCtx
     *            Inbound message context.
     * @return authentication request or null if not found.
     */
    @SuppressWarnings("rawtypes")
    private AuthenticationRequest getAuthenticationRequest(MessageContext msgCtx) {
        if (msgCtx == null) {
            return null;
        }
        Object message = msgCtx.getMessage();
        if (message == null || !(message instanceof AuthenticationRequest)) {
            return null;
        }
        return (AuthenticationRequest) message;
    }

}
