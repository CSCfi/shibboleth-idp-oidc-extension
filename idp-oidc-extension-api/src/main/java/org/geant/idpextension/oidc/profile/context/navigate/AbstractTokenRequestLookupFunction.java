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
        if (!(message instanceof TokenRequest)) {
            return null;
        }
        return doLookup((TokenRequest) message);
    }
}