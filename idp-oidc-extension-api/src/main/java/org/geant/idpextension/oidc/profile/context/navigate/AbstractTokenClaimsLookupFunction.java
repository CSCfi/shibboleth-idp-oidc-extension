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

package org.geant.idpextension.oidc.profile.context.navigate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Abstract function extended by lookups searching fields from tokens (Authorization Code, Access Token).
 * 
 * @param <T> type of lookup result to return.
 */
@SuppressWarnings("rawtypes")
public abstract class AbstractTokenClaimsLookupFunction<T>
        implements ContextDataLookupFunction<ProfileRequestContext, T> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractTokenClaimsLookupFunction.class);

    /**
     * Implemented to perform the actual lookup.
     * 
     * @param tokenClaims token claims set to perform the lookup from.
     * @return lookup value.
     */
    abstract T doLookup(@Nonnull TokenClaimsSet tokenClaims);

    @Override
    @Nullable
    public T apply(@Nullable final ProfileRequestContext input) {
        if (input == null || input.getOutboundMessageContext() == null) {
            return null;
        }
        OIDCAuthenticationResponseContext oidcResponseContext =
                input.getOutboundMessageContext().getSubcontext(OIDCAuthenticationResponseContext.class, false);
        if (oidcResponseContext == null) {
            return null;
        }
        TokenClaimsSet tokenClaims = oidcResponseContext.getTokenClaimsSet();
        if (tokenClaims == null) {
            return null;
        }
        return doLookup(tokenClaims);

    }

}