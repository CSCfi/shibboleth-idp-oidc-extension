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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;

import com.google.common.base.Function;

/**
 * Looks up the value of the simple class name from the inbound message context's message object.
 */
public class InboundMessageClassLookupFunction implements Function<ProfileRequestContext, String> {
    
    /**
     * Constructor. 
     */
    public InboundMessageClassLookupFunction() {

    }

    /**
     * The simple name of the message class in the inbound message context. Null if it doesn't exist.
     * 
     * {@inheritDoc}
     */
    @Nullable @Override
    public String apply(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (profileRequestContext.getInboundMessageContext() == null) {
            return null;
        }
        Object message = profileRequestContext.getInboundMessageContext().getMessage();
        if (message == null) {
            return null;
        }
        return message.getClass().getSimpleName();
    }
}
