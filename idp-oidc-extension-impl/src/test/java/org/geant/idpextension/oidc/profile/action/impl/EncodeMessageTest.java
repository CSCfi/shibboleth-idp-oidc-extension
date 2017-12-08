package org.geant.idpextension.oidc.profile.action.impl;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.AbstractMessageEncoder;
import org.opensaml.messaging.encoder.MessageEncoder;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.profile.action.ActionTestingSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.action.MessageEncoderFactory;
import org.opensaml.profile.action.impl.MockMessage;
import org.opensaml.profile.context.ProfileRequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

/**
 * Unit test for {@link EncodeMessage}. Tests that the original copied
 * functionality works still. Based on
 * {@link org.opensaml.profile.action.impl.EncodeMessageTest}
 */
public class EncodeMessageTest {

    private MockMessage message;

    private MockMessageEncoder encoder;

    private MessageContext<MockMessage> messageContext;

    @SuppressWarnings("rawtypes")
    private ProfileRequestContext profileCtx;

    private String expectedMessage;

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        message = new MockMessage();
        message.getProperties().put("foo", "3");
        message.getProperties().put("bar", "1");
        message.getProperties().put("baz", "2");

        // Encoded mock message, keys sorted alphabetically, per
        // MockMessage#toString
        expectedMessage = "bar=1&baz=2&foo=3";

        messageContext = new MessageContext<>();
        messageContext.setMessage(message);

        profileCtx = new ProfileRequestContext();
        profileCtx.setOutboundMessageContext(messageContext);

        encoder = new MockMessageEncoder();
        // Note: we don't init the encoder, b/c that is done by the action after
        // setting the message context
    }

    @Test(expectedExceptions = ComponentInitializationException.class)
    public void testNoFactory() throws ComponentInitializationException {
        final EncodeMessage action = new EncodeMessage();
        action.initialize();
    }

    /** Test that the action proceeds properly if the message can be decoded. */
    @SuppressWarnings("unchecked")
    @Test
    public void testDecodeMessage() throws Exception {
        EncodeMessage action = new EncodeMessage();
        action.setMessageEncoderFactory(new MockEncoderFactory());
        action.initialize();

        action.execute(profileCtx);
        ActionTestingSupport.assertProceedEvent(profileCtx);

        Assert.assertEquals(encoder.getEncodedMessage(), expectedMessage);
    }

    /**
     * Test that the action errors out properly if the message can not be
     * decoded.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testThrowException() throws Exception {
        encoder.setThrowException(true);

        EncodeMessage action = new EncodeMessage();
        action.setMessageEncoderFactory(new MockEncoderFactory());
        action.initialize();

        action.execute(profileCtx);
        ActionTestingSupport.assertEvent(profileCtx, EventIds.UNABLE_TO_ENCODE);
    }

    /**
     * Mock implementation of {@link MessageEncoder} which either returns a
     * {@link MessageContext} with a mock message or throws a
     * {@link MessageDecodingException}.
     */
    private class MockMessageEncoder extends AbstractMessageEncoder<MockMessage> {

        /**
         * Whether a {@link MessageEncodingException} should be thrown by
         * {@link #doEncode()}.
         */
        private boolean throwException = false;

        /** Mock encoded message. */
        private String message;

        /**
         * Get the encoded message
         * 
         * @return the string buffer
         */
        public String getEncodedMessage() {
            return message;
        }

        /**
         * Sets whether a {@link MessageEncodingException} should be thrown by
         * {@link #doEncode()}.
         * 
         * @param shouldThrowDecodeException
         *            true if an exception should be thrown, false if not
         */
        public void setThrowException(final boolean shouldThrowDecodeException) {
            throwException = shouldThrowDecodeException;
        }

        /** {@inheritDoc} */
        @Override
        protected void doEncode() throws MessageEncodingException {
            if (throwException) {
                throw new MessageEncodingException();
            } else {
                message = getMessageContext().getMessage().getEncoded();
            }
        }
    }

    private class MockEncoderFactory implements MessageEncoderFactory {

        /** {@inheritDoc} */
        @SuppressWarnings("rawtypes")
        @Override
        @Nullable
        public MessageEncoder getMessageEncoder(@Nonnull final ProfileRequestContext profileRequestContext) {
            return encoder;
        }

    }

}
