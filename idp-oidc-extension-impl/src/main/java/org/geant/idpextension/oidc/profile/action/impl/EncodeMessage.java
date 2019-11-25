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

package org.geant.idpextension.oidc.profile.action.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncoder;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.profile.action.AbstractProfileAction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.action.MessageEncoderFactory;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Based on {@link org.opensaml.profile.action.impl.EncodeMessage}.
 * 
 * The difference is having encoder also directly injected without factory. TODO: Consider if we want to apply message
 * encoder factory and loose the direct injection. In the long run we should get rid of this copied class.
 * 
 * Action that encodes an outbound response from the outbound {@link MessageContext}.
 * 
 * <p>
 * The {@link MessageEncoderFactory} is used to obtain a new {@link MessageEncoder} to use, and the encoder is destroyed
 * upon completion.
 * </p>
 *
 * 
 * @event {@link EventIds#PROCEED_EVENT_ID}
 * @event {@link EventIds#INVALID_MSG_CTX}
 * @event {@link EventIds#UNABLE_TO_ENCODE}
 * 
 * @post If ProfileRequestContext.getOutboundMessageContext() != null, it will be injected and encoded.
 */
@SuppressWarnings("rawtypes")
public class EncodeMessage extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(EncodeMessage.class);

    /** The factory to use to obtain an encoder. */
    private MessageEncoderFactory encoderFactory;

    /** Message encoder. */
    private MessageEncoder encoder;

    /**
     * An optional {@link MessageHandler} instance to be invoked after {@link MessageEncoder#prepareContext()} and prior
     * to {@link MessageEncoder#encode()}.
     */
    @Nullable
    private MessageHandler messageHandler;

    /** The outbound MessageContext to encode. */
    @Nullable
    private MessageContext msgContext;

    /**
     * Set the encoder factory to use.
     * 
     * @param factory factory to use
     */
    public void setMessageEncoderFactory(@Nonnull final MessageEncoderFactory factory) {
        encoderFactory = Constraint.isNotNull(factory, "MessageEncoderFactory cannot be null");
    }

    /**
     * Set the encoder factory to use.
     * 
     * @param factory factory to use
     */
    public void setMessageEncoder(@Nonnull final MessageEncoder enc) {
        encoder = Constraint.isNotNull(enc, "MessageEncoder cannot be null");
    }

    /**
     * <p>
     * The supplied {@link MessageHandler} will be invoked on the {@link MessageContext} after
     * {@link MessageEncoder#prepareContext()}, and prior to invoking {@link MessageEncoder#encode()}. Its use is
     * optional and primarily used for transport/binding-specific message handling, as opposed to more generalized
     * message handling operations which would typically be invoked earlier than this action. For more details see
     * {@link MessageEncoder}.
     * </p>
     * 
     * @param handler a message handler
     */
    public void setMessageHandler(@Nullable final MessageHandler handler) {
        messageHandler = handler;
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (encoderFactory == null && encoder == null) {
            throw new ComponentInitializationException("MessageEncoderFactory and Encoder cannot both be null");
        }
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        msgContext = profileRequestContext.getOutboundMessageContext();
        if (msgContext == null) {
            log.debug("{} Outbound message context was null", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        }

        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        if (encoder == null) {
            encoder = encoderFactory.getMessageEncoder(profileRequestContext);
        }
        if (encoder == null) {
            log.error("{} Unable to locate an outbound message encoder", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCODE);
            return;
        }

        try {
            log.debug("{} Encoding outbound response using message encoder of type {} for this response",
                    getLogPrefix(), encoder.getClass().getName());

            if (!encoder.isInitialized()) {
                log.debug("{} Encoder was not initialized, injecting MessageContext and initializing", getLogPrefix());
                encoder.setMessageContext(msgContext);
                encoder.initialize();
            } else {
                log.debug("{} Encoder was already initialized, skipping MessageContext injection and init",
                        getLogPrefix());
            }

            encoder.prepareContext();

            if (messageHandler != null) {
                log.debug("{} Invoking message handler of type {} for this response", getLogPrefix(),
                        messageHandler.getClass().getName());
                messageHandler.invoke(msgContext);
            }

            encoder.encode();

            if (msgContext.getMessage() != null) {
                log.debug("{} Outbound message encoded from a message of type {}", getLogPrefix(),
                        msgContext.getMessage().getClass().getName());
            } else {
                log.debug("{} Outbound message was encoded from protocol-specific data "
                        + "rather than MessageContext#getMessage()", getLogPrefix());
            }

        } catch (final MessageEncodingException | ComponentInitializationException | MessageHandlerException e) {
            log.error("{} Unable to encode outbound response", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, EventIds.UNABLE_TO_ENCODE);
        } finally {
            // TODO: do we want to destroy the encoder here?
            encoder.destroy();
        }
    }

}