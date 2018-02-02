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

package org.geant.idpextension.oidc.encoding.impl;

import javax.annotation.Nonnull;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncoder;
import org.opensaml.profile.action.MessageEncoderFactory;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.Response;

import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * A {@link MessageEncoderFactory} implementation that first verifies message being an instace of Nimbus
 * {@link Response} and then returns the attached {@link MessageEncoder}.
 */
@SuppressWarnings("rawtypes")
public class OIDCResponseEncoderFactory extends AbstractInitializableComponent implements MessageEncoderFactory {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(OIDCResponseEncoderFactory.class);
    
    /** The message encoder to be returned by this factory. */
    @Nonnull MessageEncoder messageEncoder;
    
    /**
     * Set the message encoder to be returned by this factory.
     * @param encoder What to set.
     */
    public void setMessageEncoder(@Nonnull final MessageEncoder encoder) {
        messageEncoder = Constraint.isNotNull(encoder, "The message encoder cannot be null");
    }
    
    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (messageEncoder == null) {
            throw new ComponentInitializationException("The message encoder cannot be null");
        }
    }

    /** {@inheritDoc} */
    @Override
    public MessageEncoder getMessageEncoder(ProfileRequestContext profileRequestContext) {
        final MessageContext messageContext = profileRequestContext.getOutboundMessageContext();
        if (messageContext == null) {
            log.error("No outbound message context available in profile request context");
            return null;
        }
        final Object message = messageContext.getMessage();
        if (message == null || !(message instanceof Response)) {
            log.error("Unexpected message in the outbound message context: {}", message);
        }
        return messageEncoder;
    }
}
