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

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import org.geant.idpextension.oidc.messaging.OIDCWebFingerRequest;
import org.geant.idpextension.oidc.messaging.impl.OIDCWebFingerRequestImpl;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecoder;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.decoder.servlet.AbstractHttpServletRequestMessageDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * A message decoder for {@link OIDCWebFingerRequest}.
 */
public class OIDCWebFingerRequestDecoder 
    extends AbstractHttpServletRequestMessageDecoder<OIDCWebFingerRequest>
    implements MessageDecoder<OIDCWebFingerRequest> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OIDCWebFingerRequestDecoder.class);

    /** {@inheritDoc} */
    @Override
    protected void doDecode() throws MessageDecodingException {
        final MessageContext<OIDCWebFingerRequest> messageContext = new MessageContext<>();
        final HttpServletRequest httpRequest = getHttpServletRequest();
        final String resource = StringSupport.trimOrNull(httpRequest.getParameter("resource"));
        if (resource == null) {
            log.error("No resource parameter value found from the request");
            throw new MessageDecodingException("Mandatory value for resource is missing");
        }
        final String rel = StringSupport.trim(httpRequest.getParameter("rel"));
        if (rel == null) {
            log.error("No rel parameter value found from the request");
            throw new MessageDecodingException("Mandatory value for rel is missing");
        }
        final OIDCWebFingerRequestImpl request = new OIDCWebFingerRequestImpl(resource, rel);
        log.debug("Decoded Web Finger request with resource = {} and rel = {}", resource, rel);
        messageContext.setMessage(request);
        setMessageContext(messageContext);
    }
}
