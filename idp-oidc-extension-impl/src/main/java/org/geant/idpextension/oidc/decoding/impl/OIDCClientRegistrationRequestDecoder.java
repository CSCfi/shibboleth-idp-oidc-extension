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

package org.geant.idpextension.oidc.decoding.impl;

import java.io.IOException;

import javax.annotation.Nonnull;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecoder;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.decoder.servlet.AbstractHttpServletRequestMessageDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;

import net.minidev.json.JSONObject;

/**
 * Message decoder decoding OpenID Connect {@link ClientRegistrationRequest}s.
 */
public class OIDCClientRegistrationRequestDecoder 
    extends AbstractHttpServletRequestMessageDecoder<OIDCClientRegistrationRequest>
    implements MessageDecoder<OIDCClientRegistrationRequest> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OIDCClientRegistrationRequestDecoder.class);

    /** {@inheritDoc} */
    @Override
    protected void doDecode() throws MessageDecodingException {
        final MessageContext<OIDCClientRegistrationRequest> messageContext = new MessageContext<>();
        try {
            final HTTPRequest httpRequest = ServletUtils.createHTTPRequest(getHttpServletRequest());
            log.trace("Raw query: {}", httpRequest.getQuery());
            final JSONObject requestJson = httpRequest.getQueryAsJSONObject();
            //TODO: Nimbus seems to be interpreting scope in different way as many RPs, currently the scope
            //is removed in this phase, better solution TODO.
            if (requestJson.containsKey("scope")) {
                log.debug("Removed 'scope'");
                requestJson.remove("scope");
                httpRequest.setQuery(requestJson.toJSONString());
            }
            
            log.trace("JSON object: {}", httpRequest.getQueryAsJSONObject().toJSONString());
            final OIDCClientRegistrationRequest request = OIDCClientRegistrationRequest.parse(httpRequest);
            messageContext.setMessage(request);
        } catch (IOException e) {
            log.error("Could not create HTTP request from the request", e);
            throw new MessageDecodingException(e);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            log.error("Unable to decode oidc request: {}", e.getMessage());
            throw new MessageDecodingException(e);
        }
        log.debug("Decoded OIDC client registration request {}", messageContext.getMessage().toHTTPRequest());
        setMessageContext(messageContext);
    }

}