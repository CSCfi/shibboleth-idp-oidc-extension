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

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletResponse;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.encoder.servlet.AbstractHttpServletResponseMessageEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import net.shibboleth.utilities.java.support.codec.HTMLEncoder;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.net.HttpServletSupport;

/**
 * A message encodes that encodes the Nimbus {@link Response} in the message context inside the attached
 * {@link HttpServletResponse}.
 */
public class NimbusResponseEncoder extends AbstractHttpServletResponseMessageEncoder<Response> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(NimbusResponseEncoder.class);

    /** Default template ID for using FORM POST response mode. */
    @Nonnull
    public static final String DEFAULT_TEMPLATE_ID = "/templates/oidc-form-post.vm";

    /** Velocity engine used to evaluate the template when using FORM POST response mode. */
    @Nullable
    private VelocityEngine velocityEngine;

    /** ID of the Velocity template used when using FORM POST response mode. */
    @Nonnull
    private String velocityTemplateId = DEFAULT_TEMPLATE_ID;

    /**
     * Set the Velocity template id.
     * 
     * <p>
     * Defaults to {@link #DEFAULT_TEMPLATE_ID}.
     * </p>
     * 
     * @param newVelocityTemplateId the new Velocity template id
     */
    public void setVelocityTemplateId(final String newVelocityTemplateId) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        Constraint.isNotEmpty(newVelocityTemplateId, "Velocity template id must not not be null or empty");
        velocityTemplateId = newVelocityTemplateId;
    }

    /**
     * Set the VelocityEngine instance.
     * 
     * @param newVelocityEngine the new VelocityEngine instane
     */
    public void setVelocityEngine(final VelocityEngine newVelocityEngine) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        velocityEngine = newVelocityEngine;
    }

    /**
     * Whether we should use FORM POST response encoding.
     * 
     * @param response response message.
     * @return true if DORM POST should be used.
     */
    private boolean impliesFormPost(Response response) {
        return (response instanceof AuthorizationResponse)
                && ResponseMode.FORM_POST.equals(((AuthorizationResponse) response).getResponseMode());
    }

    /**
     * Set response message to FORM POST velocity context.
     * 
     * @param message response message.
     * @return response message as velocity context.
     */
    private VelocityContext doPostEncode(AuthorizationResponse message) {
        final VelocityContext context = new VelocityContext();
        for (Map.Entry<String, String> entry : message.toParameters().entrySet()) {
            context.put(entry.getKey(), entry.getValue());
        }
        context.put("action", HTMLEncoder.encodeForHTMLAttribute(message.getRedirectionURI().toString()));
        return context;
    }

    /** {@inheritDoc} */
    protected void doEncode() throws MessageEncodingException {
        try {
            final HttpServletResponse response = getHttpServletResponse();
            if (impliesFormPost(getMessageContext().getMessage())) {
                if (velocityEngine == null) {
                    throw new MessageEncodingException("VelocityEngine must be supplied for form post response mode");
                }
                VelocityContext context = doPostEncode((AuthorizationResponse) getMessageContext().getMessage());
                HttpServletSupport.addNoCacheHeaders(response);
                HttpServletSupport.setUTF8Encoding(response);
                HttpServletSupport.setContentType(response, "text/html");
                final Writer out = new OutputStreamWriter(response.getOutputStream(), "UTF-8");
                velocityEngine.mergeTemplate(velocityTemplateId, "UTF-8", context, out);
                out.flush();
                //TODO: log outbound message
                return;
            }
            final HTTPResponse resp = getMessageContext().getMessage().toHTTPResponse();
            log.debug("Outbound response {}", ResponseUtil.toString(resp));
            ServletUtils.applyHTTPResponse(resp, response);
        } catch (IOException e) {
            throw new MessageEncodingException("Problem encoding response", e);
        }
    }

}
