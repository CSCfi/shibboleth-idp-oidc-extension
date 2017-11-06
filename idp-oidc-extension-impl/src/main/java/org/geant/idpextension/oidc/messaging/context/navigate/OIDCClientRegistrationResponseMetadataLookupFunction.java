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

import org.geant.idpextension.oidc.messaging.context.OIDCClientRegistrationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * A function that returns {@link OIDCClientMetadata} if such is available in the message from a 
 * {@link OIDCClientRegistrationResponseContext}. It is obtained via {@link MessageContext} that is obtained via 
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 * 
 * <p>If the metadata is unavailable, a null value is returned.</p>
 */
public class OIDCClientRegistrationResponseMetadataLookupFunction 
    implements ContextDataLookupFunction<ProfileRequestContext,OIDCClientMetadata> {
    
    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OIDCClientRegistrationResponseMetadataLookupFunction.class);
   
    /**
     * Strategy used to locate the {@link OIDCClientRegistrationResponseContext} associated with a given 
     * {@link MessageContext}.
     */
    @Nonnull private Function<MessageContext,OIDCClientRegistrationResponseContext> oidcResponseContextLookupStrategy;
    
    /** Constructor. */
    public OIDCClientRegistrationResponseMetadataLookupFunction() {
        oidcResponseContextLookupStrategy = new ChildContextLookup<>(OIDCClientRegistrationResponseContext.class);
    }
    
    /**
     * Set the strategy used to locate the {@link OIDCClientRegistrationResponseContext} associated with a given
     * {@link MessageContext}.
     * 
     * @param strategy strategy used to locate the {@link OIDCClientRegistrationResponseContext} associated with a 
     *         given {@link MessageContext}
     */
    public void setOidcResponseContextLookupStrategy(
            @Nonnull final Function<MessageContext,OIDCClientRegistrationResponseContext> strategy) {
        oidcResponseContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCClientRegistrationResponseContext lookup strategy cannot be null");
    }
   
    /** {@inheritDoc} */
    @Override
    public OIDCClientMetadata apply(ProfileRequestContext input) {
        final MessageContext msgCtx = input.getOutboundMessageContext();
        if (msgCtx != null) {
            final OIDCClientRegistrationResponseContext oidcResponseCtx 
                = oidcResponseContextLookupStrategy.apply(msgCtx);
            if (oidcResponseCtx != null) {
                return oidcResponseCtx.getClientMetadata();
            }
        }
        log.debug("No response OIDCClientMetadata found from the profile request context!");
        return null;
    }

}
