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
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;

import com.nimbusds.jwt.JWT;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

/**
 * A Abstract function extended by lookups searching fields from authentication request.
 * 
 * @param <T> type of lookup result to return.
 */
@SuppressWarnings("rawtypes")
public abstract class AbstractAuthenticationRequestLookupFunction<T>
        implements ContextDataLookupFunction<ProfileRequestContext, T> {

    protected JWT requestObject;

    /**
     * Implemented to perform the actual lookup.
     * 
     * @param req authentication request to perform the lookup from.
     * @return lookup value.
     */
    abstract T doLookup(@Nonnull AuthenticationRequest req);

    /** {@inheritDoc} */
    @Override
    @Nullable
    public T apply(@Nullable final ProfileRequestContext input) {
        if (input == null || input.getInboundMessageContext() == null || input.getOutboundMessageContext() == null) {
            return null;
        }
        Object message = input.getInboundMessageContext().getMessage();
        if (message == null || !(message instanceof AuthenticationRequest)) {
            return null;
        }
        OIDCAuthenticationResponseContext ctx =
                input.getOutboundMessageContext().getSubcontext(OIDCAuthenticationResponseContext.class, false);
        if (ctx == null) {
            return null;
        }
        requestObject = ctx.getRequestObject();
        return doLookup((AuthenticationRequest) message);
    }
}