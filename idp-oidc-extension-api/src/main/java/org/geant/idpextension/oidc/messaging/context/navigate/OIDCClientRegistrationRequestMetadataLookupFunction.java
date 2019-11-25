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

package org.geant.idpextension.oidc.messaging.context.navigate;

import javax.annotation.Nonnull;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;

/**
 * A function that returns {@link OIDCClientMetadata} if such is available in the message from a {@link MessageContext}
 * obtained via {@link ProfileRequestContext#getInboundMessageContext()}.
 * 
 * <p>If the metadata is unavailable, a null value is returned.</p>
 */
public class OIDCClientRegistrationRequestMetadataLookupFunction 
    implements ContextDataLookupFunction<ProfileRequestContext,OIDCClientMetadata> {
    
    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OIDCClientRegistrationRequestMetadataLookupFunction.class);

    /** {@inheritDoc} */
    @Override
    public OIDCClientMetadata apply(ProfileRequestContext input) {
        final MessageContext msgCtx = input.getInboundMessageContext();
        if (msgCtx != null) {
            Object message = msgCtx.getMessage();
            if (message != null && msgCtx.getMessage() instanceof OIDCClientRegistrationRequest) {
                return ((OIDCClientRegistrationRequest)message).getOIDCClientMetadata();
            }
        }
        log.debug("No request OIDCClientMetadata found from the profile request context!");
        return null;
    }

}
