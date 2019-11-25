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

package org.geant.idpextension.oidc.attribute.filter.matcher.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.attribute.encoding.impl.AbstractOIDCAttributeEncoder;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.BaseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.RecursiveTypedParentContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest.Entry;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;

import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.filter.Matcher;
import net.shibboleth.idp.attribute.filter.PolicyRequirementRule.Tristate;
import net.shibboleth.idp.attribute.filter.context.AttributeFilterContext;
import net.shibboleth.utilities.java.support.component.AbstractIdentifiableInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentSupport;

/** Class for matching attribute to requested claims. */
public class AttributeInOIDCRequestedClaimsMatcher extends AbstractIdentifiableInitializableComponent
        implements Matcher {

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
     * @param flag whether to drop non essential claims
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
     * @param flag whether to match only id token part of the requested claims
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
     * @param flag whether to match only user info part of the requested claims
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
     * @param flag whether to match if the request contains no requested claims
     */
    public void setMatchIfRequestedClaimsSilent(final boolean flag) {
        matchIfRequestedClaimsSilent = flag;
    }

    /**
     * Resolve oidc encoder names for the attribute.
     * 
     * @param set attached to attribute
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

    /**
     * If any of the names have a matching claims request essentiality is verified.
     * 
     * @param claims claims request claims
     * @param names names of the claims to be encoded
     * @return false if any of the names of claims to be encoded match a claims request claim and essentiality check is
     *         not passed.
     */
    private boolean verifyEssentiality(Collection<Entry> claims, List<String> names) {
        boolean bEssentialityCheckFailed = false;
        for (Entry entry : claims) {
            if (names.contains(entry.getClaimName())) {
                bEssentialityCheckFailed =
                        onlyIfEssential && !ClaimRequirement.ESSENTIAL.equals(entry.getClaimRequirement());
            }
        }
        return !bEssentialityCheckFailed;
    }

    // Checkstyle: CyclomaticComplexity OFF
    @SuppressWarnings("rawtypes")
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
        ProfileRequestContext profileRequestContext =
                new RecursiveTypedParentContextLookup<AttributeFilterContext, ProfileRequestContext>(
                        ProfileRequestContext.class).apply(filtercontext);
        if (profileRequestContext == null || profileRequestContext.getOutboundMessageContext() == null) {
            log.trace("{} No outbound message context", getLogPrefix());
            return null;
        }
        OIDCAuthenticationResponseContext respCtx = profileRequestContext.getOutboundMessageContext()
                .getSubcontext(OIDCAuthenticationResponseContext.class, false);
        if (respCtx == null) {
            // This is always a failure.
            log.debug("{} No oidc response ctx for this comparison", getLogPrefix());
            return null;
        }
        ClaimsRequest request = respCtx.getRequestedClaims();
        if (request == null || (request.getIDTokenClaims() == null && request.getUserInfoClaims() == null)) {
            log.debug("{} No claims in request", getLogPrefix());
            if (getMatchIRequestedClaimsSilent()) {
                log.debug("{} all values matched as in silent mode", getLogPrefix());
                return ImmutableSet.copyOf(attribute.getValues());
            } else {
                log.debug("{} none of the values matched as not silent mode", getLogPrefix());
                return Collections.emptySet();
            }
        }
        // Are we able to release the values based on claim being requested for id token?
        if (request.getIDTokenClaimNames(false) != null && !getMatchOnlyUserInfo()) {
            if (!Collections.disjoint(request.getIDTokenClaimNames(false), names)) {
                if (verifyEssentiality(request.getIDTokenClaims(), names)) {
                    log.debug("{} all values matched as {} is requested id token claims", getLogPrefix(),
                            attribute.getId());
                    return ImmutableSet.copyOf(attribute.getValues());
                }
            }
        }
        // Are we able to release the values based on claim being requested for user info response?
        if (request.getUserInfoClaimNames(false) != null && !getMatchOnlyIDToken()) {
            if (!Collections.disjoint(request.getUserInfoClaimNames(false), names)) {
                if (verifyEssentiality(request.getUserInfoClaims(), names)) {
                    log.debug("{} all values matched as {} is requested user info claims", getLogPrefix(),
                            attribute.getId());
                    return ImmutableSet.copyOf(attribute.getValues());
                }
            }
        }
        log.debug("{} attribute {} was not a requested claim, none of the values matched", getLogPrefix(),
                attribute.getId());
        return Collections.emptySet();
    }
    // Checkstyle: CyclomaticComplexity ON

    /**
     * return a string which is to be prepended to all log messages.
     * 
     * @return "Attribute Filter '<filterID>' :"
     */
    @Nonnull
    protected String getLogPrefix() {
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

}
