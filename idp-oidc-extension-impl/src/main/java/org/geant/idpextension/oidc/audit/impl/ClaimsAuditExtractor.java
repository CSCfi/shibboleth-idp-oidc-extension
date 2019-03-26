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

package org.geant.idpextension.oidc.audit.impl;

import java.util.Collection;
import java.util.Collections;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.profile.context.navigate.DefaultResponseClaimsSetLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.UserInfoResponseClaimsSetLookupFunction;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.google.common.base.Predicate;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.logic.Constraint;

/** {@link Function} that returns the released claims for the endpoint. */
public class ClaimsAuditExtractor implements Function<ProfileRequestContext, Collection<String>> {

    /** Lookup strategy for id token claims to read from. */
    @Nonnull
    private final Function<ProfileRequestContext, ClaimsSet> idTokenClaimsLookupStrategy;

    /** Lookup strategy for user info claims to read from. */
    @Nonnull
    private final Function<ProfileRequestContext, ClaimsSet> userInfoClaimsLookupStrategy;

    /** Constructor. */

    public ClaimsAuditExtractor() {
        idTokenClaimsLookupStrategy = new DefaultResponseClaimsSetLookupFunction();
        userInfoClaimsLookupStrategy = new UserInfoResponseClaimsSetLookupFunction();
    }

    /**
     * Constructor.
     * 
     * @param idTokenClaimsStrategy Strategy to look for id token claims.
     * @param userInfoClaimsStrategy Strategy to look for user info claims.
     */

    public ClaimsAuditExtractor(@Nonnull final Function<ProfileRequestContext, ClaimsSet> idTokenClaimsStrategy,
            @Nonnull final Function<ProfileRequestContext, ClaimsSet> userInfoClaimsStrategy) {
        idTokenClaimsLookupStrategy =
                Constraint.isNotNull(idTokenClaimsStrategy, "IdTokenClaimsStrategy lookup strategy cannot be null");
        userInfoClaimsLookupStrategy =
                Constraint.isNotNull(userInfoClaimsStrategy, "userInfoClaimsStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public Collection<String> apply(@Nullable final ProfileRequestContext input) {
        ClaimsSet claims = idTokenClaimsLookupStrategy.apply(input);
        if (claims != null) {
            return claims.toJSONObject().keySet();
        }
        claims = userInfoClaimsLookupStrategy.apply(input);
        if (claims != null) {
            return claims.toJSONObject().keySet();
        }
        return Collections.emptyList();

    }

}