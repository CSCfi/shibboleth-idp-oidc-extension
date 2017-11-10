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
