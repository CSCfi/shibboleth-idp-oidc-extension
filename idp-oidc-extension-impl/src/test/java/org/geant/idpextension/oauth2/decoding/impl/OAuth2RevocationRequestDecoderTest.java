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

package org.geant.idpextension.oauth2.decoding.impl;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;

/**
 * Unit tests for {@link OAuth2RevocationRequestDecoder}.
 */
public class OAuth2RevocationRequestDecoderTest {

    private MockHttpServletRequest httpRequest;

    private OAuth2RevocationRequestDecoder decoder;

    @BeforeMethod
    protected void setUp() throws Exception {
        httpRequest = new MockHttpServletRequest();
        httpRequest.setMethod("POST");
        httpRequest.addHeader("Content-Type", "application/x-www-form-urlencoded");
        httpRequest.addParameter("token", "45ghiukldjahdnhzdauz");
        httpRequest.addParameter("token_type_hint", "refresh_token");
        httpRequest.addParameter("client_id", "123456");
        decoder = new OAuth2RevocationRequestDecoder();
        decoder.setHttpServletRequest(httpRequest);
        decoder.initialize();
    }

    @Test
    public void testRequestDecoding() throws MessageDecodingException {
        decoder.decode();
        MessageContext<TokenRevocationRequest> messageContext = decoder.getMessageContext();
        // We are not testing nimbus itself here, i.e. we are happy to decode
        // one parameter successfully
        Assert.assertEquals(messageContext.getMessage().getClientID().toString(), "123456");

    }

    @Test(expectedExceptions = MessageDecodingException.class)
    public void testInvalidRequestDecoding() throws MessageDecodingException {
        httpRequest.removeParameter("token");
        decoder.decode();
    }
}