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
