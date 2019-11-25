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
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

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
        final OIDCClientMetadata metadata = oidcContext.getClientMetadata();
        final ClientAuthenticationMethod tokenAuthMethod = metadata.getTokenEndpointAuthMethod();
        
        final boolean secretNeeded = (tokenAuthMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) ||
                tokenAuthMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT) ||
                tokenAuthMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_POST));
        
        final Secret clientSecret;
        if (secretNeeded && oidcContext.getClientSecret() != null) {
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
                metadata, clientSecret);
        final OIDCClientInformationResponse response = new OIDCClientInformationResponse(clientInformation);
        profileRequestContext.getOutboundMessageContext().setMessage(response);
        log.info("{} Client information successfully added to the outbound context", getLogPrefix());
        
    }    
}