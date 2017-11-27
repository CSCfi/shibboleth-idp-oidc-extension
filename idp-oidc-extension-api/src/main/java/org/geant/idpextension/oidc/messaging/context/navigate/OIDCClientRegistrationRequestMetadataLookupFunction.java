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
