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
import org.geant.idpextension.oidc.profile.context.navigate.DefaultClientIDLookupFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

/**
 * Handler for inbound OIDC protocol messages that attempts to locate OIDC metadata for a rp, and attaches it with a
 * {@link OIDCMetadataContext} as a child of a pre-existing instance of {@link MessagesContext}.
 */
@SuppressWarnings("rawtypes")
public class OIDCMetadataLookupHandler extends AbstractMessageHandler {

    /** Logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OIDCMetadataLookupHandler.class);

    /** Resolver used to look up OIDC client information. */
    @NonnullAfterInit
    private ClientInformationResolver clientResolver;

    /** Strategy used to obtain the client id value for authorize/token request. */
    @Nonnull
    private Function<MessageContext, ClientID> clientIDLookupStrategy;

    /**
     * Constructor.
     */
    public OIDCMetadataLookupHandler() {
        clientIDLookupStrategy = new DefaultClientIDLookupFunction();
    }

    /**
     * Set the strategy used to locate the client id of the request.
     * 
     * @param strategy lookup strategy
     */
    public void setClientIDLookupStrategy(@Nonnull final Function<MessageContext, ClientID> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        clientIDLookupStrategy =
                Constraint.isNotNull(strategy, "ClientIDLookupStrategy lookup strategy cannot be null");
    }

    /**
     * Set the {@link ClientInformationResolver} to use.
     * 
     * @param resolver The resolver to use.
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
        final ClientID clientId = clientIDLookupStrategy.apply(messageContext);
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