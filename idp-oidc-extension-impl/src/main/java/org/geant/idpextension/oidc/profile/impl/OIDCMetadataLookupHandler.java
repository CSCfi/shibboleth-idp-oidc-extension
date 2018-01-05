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

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.AbstractMessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.geant.idpextension.oidc.criterion.ClientIDCriterion;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.metadata.resolver.ClientInformationResolver;
import org.geant.idpextension.util.RequestFieldResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AbstractRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

/**
 * Handler for inbound OIDC protocol messages that attempts to locate OIDC
 * metadata for a rp, and attaches it with a {@link OIDCMetadataContext} as a
 * child of a pre-existing instance of {@link MessagesContext}.
 */
@SuppressWarnings("rawtypes")
public class OIDCMetadataLookupHandler extends AbstractMessageHandler {

    /** Logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OIDCMetadataLookupHandler.class);

    /** Resolver used to look up OIDC client information. */
    @NonnullAfterInit
    private ClientInformationResolver clientResolver;

    /**
     * Set the {@link ClientInformationResolver} to use.
     * 
     * @param resolver
     *            The resolver to use.
     */
    public void setClientInformationResolver(@Nonnull final ClientInformationResolver resolver) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        clientResolver = Constraint.isNotNull(resolver, "ClientInformationResolver cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (clientResolver == null) {
            throw new ComponentInitializationException("ClientInformationResolver cannot be null");
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void doInvoke(@Nonnull final MessageContext messageContext) throws MessageHandlerException {
        ComponentSupport.ifNotInitializedThrowUninitializedComponentException(this);
        // Resolve client id from inbound message
        final ClientID clientId = RequestFieldResolver.getClientID((AbstractRequest) messageContext.getMessage());
        // Resolve metadata for client id
        final ClientIDCriterion clientCriterion = new ClientIDCriterion(clientId);
        final CriteriaSet criteria = new CriteriaSet(clientCriterion);
        try {
            final OIDCClientInformation clientInformation = clientResolver.resolveSingle(criteria);
            if (clientInformation == null) {
                log.warn("{} No client information returned for {}", getLogPrefix(), clientId);
                return;
            }
            final OIDCMetadataContext oidcCtx = new OIDCMetadataContext();
            oidcCtx.setClientInformation(clientInformation);
            messageContext.addSubcontext(oidcCtx);
            // Based on that info we know 1) client is valid 2) we know valid
            // redirect uris
            log.debug("{} {} added to MessageContext as child of {}", getLogPrefix(),
                    OIDCMetadataContext.class.getName(), messageContext.getClass().getName());
        } catch (ResolverException e) {
            log.error("{} ResolverException thrown during client information lookup", getLogPrefix(), e);
        }
    }
}