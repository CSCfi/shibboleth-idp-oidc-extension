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
    @Nonnull private MessageEncoder messageEncoder;
    
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
