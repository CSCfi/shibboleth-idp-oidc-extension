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

package org.geant.idpextension.oidc.profile.context.navigate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import com.nimbusds.oauth2.sdk.TokenRequest;

/**
 * A Abstract function extended by lookups searching fields from token request.
 * 
 * @param <T> type of lookup result to return.
 */
@SuppressWarnings("rawtypes")
public abstract class AbstractTokenRequestLookupFunction<T>
        implements ContextDataLookupFunction<ProfileRequestContext, T> {

    /**
     * Implemented to perform the actual lookup.
     * 
     * @param req token request to perform the lookup from.
     * @return lookup value.
     */
    abstract T doLookup(@Nonnull TokenRequest req);

    /** {@inheritDoc} */
    @Override
    @Nullable
    public T apply(@Nullable final ProfileRequestContext input) {
        if (input == null || input.getInboundMessageContext() == null) {
            return null;
        }
        Object message = input.getInboundMessageContext().getMessage();
        if (message == null || !(message instanceof TokenRequest)) {
            return null;
        }
        return doLookup((TokenRequest) message);
    }
}