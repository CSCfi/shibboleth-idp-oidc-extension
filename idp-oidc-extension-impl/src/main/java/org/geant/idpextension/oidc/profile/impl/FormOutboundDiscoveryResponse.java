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
import org.geant.idpextension.oidc.messaging.JSONSuccessResponse;
import org.geant.idpextension.oidc.metadata.resolver.ProviderMetadataResolver;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
 * This action builds a response for the OP configuration discovery request. The response contains the contents of the
 * attached {@link ProviderMetadataResolver}, possibly containing dynamic values.
 */
@SuppressWarnings("rawtypes")
public class FormOutboundDiscoveryResponse extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(FormOutboundDiscoveryResponse.class);

    /** The resolver for the metadata that is being distributed. */
    private ProviderMetadataResolver metadataResolver;

    /** metadata to publish. */
    private OIDCProviderMetadata metadata;;

    /** Constructor. */
    public FormOutboundDiscoveryResponse() {
        super();
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (metadataResolver == null) {
            throw new ComponentInitializationException("The metadata resolver cannot be null!");
        }
    }

    /**
     * Set the resolver for the metadata that is being distributed.
     * 
     * @param resolver What to set.
     */
    public void setMetadataResolver(final ProviderMetadataResolver resolver) {
        metadataResolver = Constraint.isNotNull(resolver, "The metadata resolver cannot be null!");
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        try {
            metadata = metadataResolver.resolveSingle(profileRequestContext);
        } catch (ResolverException e) {
            log.error("{} Could not resolve provider metadata", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return false;
        }
        if (metadata == null) {
            log.error("{} Could not resolve provider metadata", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.IO_ERROR);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        profileRequestContext.getOutboundMessageContext().setMessage(new JSONSuccessResponse(metadata.toJSONObject()));
    }
}
