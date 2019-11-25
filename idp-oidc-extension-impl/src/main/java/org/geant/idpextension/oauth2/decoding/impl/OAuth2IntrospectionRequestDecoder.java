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

package org.geant.idpextension.oauth2.decoding.impl;

import java.io.IOException;
import javax.annotation.Nonnull;

import org.geant.idpextension.oidc.decoding.impl.RequestUtil;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecoder;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.decoder.servlet.AbstractHttpServletRequestMessageDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.ServletUtils;

/**
 * Message decoder decoding OpenID Connect {@link TokenIntrospectionRequest}s.
 */
public class OAuth2IntrospectionRequestDecoder
        extends AbstractHttpServletRequestMessageDecoder<TokenIntrospectionRequest>
        implements MessageDecoder<TokenIntrospectionRequest> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OAuth2IntrospectionRequestDecoder.class);

    /** {@inheritDoc} */
    @Override
    protected void doDecode() throws MessageDecodingException {
        MessageContext<TokenIntrospectionRequest> messageContext = new MessageContext<>();
        TokenIntrospectionRequest req = null;
        try {
            HTTPRequest httpReq = ServletUtils.createHTTPRequest(getHttpServletRequest());
            log.debug("Inbound request {}", RequestUtil.toString(httpReq));
            req = TokenIntrospectionRequest.parse(httpReq);
        } catch (com.nimbusds.oauth2.sdk.ParseException | IOException e) {
            log.error("Unable to decode inbound request: {}", e.getMessage());
            throw new MessageDecodingException(e);
        }
        messageContext.setMessage(req);
        setMessageContext(messageContext);
    }

}