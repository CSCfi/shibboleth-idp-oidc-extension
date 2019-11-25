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

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

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
        for (Entry<String, List<String>> entry : message.toParameters().entrySet()) {
            context.put(entry.getKey(), entry.getValue().get(0));
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
                out.close();
                // Write it also to log
                final StringWriter writer = new StringWriter();
                velocityEngine.mergeTemplate(velocityTemplateId, "UTF-8", context, writer);
                log.debug("Outbound response {}", ResponseUtil.toString(response, writer.toString()));
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
