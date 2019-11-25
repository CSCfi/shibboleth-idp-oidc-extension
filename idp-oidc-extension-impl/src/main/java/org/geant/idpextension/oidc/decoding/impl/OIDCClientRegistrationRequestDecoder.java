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