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

package org.geant.idpextension.oidc.audit.impl;

import java.util.Collection;
import java.util.Collections;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.geant.idpextension.oidc.profile.context.navigate.DefaultResponseClaimsSetLookupFunction;
import org.geant.idpextension.oidc.profile.context.navigate.UserInfoResponseClaimsSetLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

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