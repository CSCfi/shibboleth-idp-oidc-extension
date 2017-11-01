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

package org.geant.idpextension.oidc.profile.impl;

import java.util.Date;

import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.messaging.context.OIDCClientRegistrationResponseContext;
import org.joda.time.DateTime;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * An action that uses the information from {@link OIDCClientRegistrationResponseContext} attached to the message
 * context for creating a new {@link ClientInformationResponse}. It will be set as the outbound message.
 */
@SuppressWarnings("rawtypes")
public class BuildClientInformation extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(BuildClientInformation.class);
    
    /**
     * Strategy used to locate the {@link OIDCClientRegistrationResponseContext} associated with a given 
     * {@link MessageContext}.
     */
    @Nonnull private Function<MessageContext,OIDCClientRegistrationResponseContext> oidcResponseContextLookupStrategy;

    /** Constructor. */
    public BuildClientInformation() {
        super();
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
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        
        oidcResponseContextLookupStrategy = Constraint.isNotNull(strategy,
                "OIDCClientRegistrationResponseContext lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }
        return true;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        final OIDCClientRegistrationResponseContext oidcContext = 
                oidcResponseContextLookupStrategy.apply(profileRequestContext.getOutboundMessageContext());
        final ClientID clientId = new ClientID(oidcContext.getClientId());
        final Secret clientSecret;
        if (oidcContext.getClientSecret() != null) {
            final DateTime secretExpiresAt = oidcContext.getClientSecretExpiresAt();
            if (secretExpiresAt != null) {
                clientSecret = new Secret(oidcContext.getClientSecret(), secretExpiresAt.toDate());                
            } else {
                clientSecret = new Secret(oidcContext.getClientSecret());
            }
        } else {
            clientSecret = null;
        }
        
        final OIDCClientInformation clientInformation = new OIDCClientInformation(clientId, new Date(), 
                oidcContext.getClientMetadata(), clientSecret);
        final OIDCClientInformationResponse response = new OIDCClientInformationResponse(clientInformation);
        profileRequestContext.getOutboundMessageContext().setMessage(response);
        log.info("{} Client information successfully added to the outbound context", getLogPrefix());
        
    }    
}