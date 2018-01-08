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
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Abstract class for actions performing actions on
 * {@link OIDCAuthenticationResponseContext} located under
 * {@link ProfileRequestContext#getOutboundMessageContext()}. Extends baseclass
 * that offers actions on {@link TokenRequest} found via
 * {@link ProfileRequestContext#getInboundMessageContext()#getMessage()}.
 */
@SuppressWarnings("rawtypes")
abstract class AbstractOIDCTokenResponseAction extends AbstractOIDCTokenRequestAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AbstractOIDCTokenResponseAction.class);

    /** oidc response context. */
    @Nonnull
    private OIDCAuthenticationResponseContext oidcResponseContext;

    /** OIDC Metadata context. */
    @Nonnull
    private OIDCMetadataContext oidcMetadataContext;

    /**
     * Returns oidc response context.
     * 
     * @return ctx.
     */
    @Nonnull
    public OIDCAuthenticationResponseContext getOidcResponseContext() {
        return oidcResponseContext;
    }

    /**
     * Returns the OIDC Metadata context.
     * 
     * @return The OIDC Metadata context.
     */
    public OIDCMetadataContext getMetadataContext() {
        return oidcMetadataContext;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (!super.doPreExecute(profileRequestContext)) {
            log.error("{} pre-execute failed", getLogPrefix());
            return false;
        }
        final MessageContext outboundMessageCtx = profileRequestContext.getOutboundMessageContext();
        if (outboundMessageCtx == null) {
            log.error("{} No outbound message context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        oidcResponseContext = outboundMessageCtx.getSubcontext(OIDCAuthenticationResponseContext.class, false);
        if (oidcResponseContext == null) {
            log.error("{} No oidc response context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        oidcMetadataContext = profileRequestContext.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class,
                false);
        if (oidcMetadataContext == null) {
            log.error("{} No metadata found for relying party", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }
        return true;
    }

}