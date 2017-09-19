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

import java.io.File;
import java.io.IOException;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.io.Files;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest.Method;

/**
 * Unit tests for {@link OIDCClientRegistrationRequestDecoder}.
 */
public class OIDCClientRegistrationRequestDecoderTest {
    
    private MockHttpServletRequest httpRequest;
    private OIDCClientRegistrationRequestDecoder decoder;

    @BeforeMethod
    protected void setUp() throws Exception {
        httpRequest = new MockHttpServletRequest();
        httpRequest.setMethod(Method.POST.toString());
        decoder = new OIDCClientRegistrationRequestDecoder();
        decoder.setHttpServletRequest(httpRequest);
        decoder.initialize();
    }

    @Test(expectedExceptions = MessageDecodingException.class)
    public void testWrongMethod() throws MessageDecodingException {
        httpRequest.setMethod(Method.GET.toString());
        decoder.decode();
    }

    @Test(expectedExceptions = MessageDecodingException.class)
    public void testInvalidJson() throws MessageDecodingException {
        httpRequest.setContent("\"test\" : \"test\" }".getBytes());
        httpRequest.setContentType("application/json");
        decoder.decode();
    }
    
    @Test
    public void testRequestDecoding() throws MessageDecodingException, IOException {
        byte[] bytes = Files.toByteArray(new File("src/test/resources/org/geant/idpextension/oidc/decoding/impl/client-registration-request.json"));
        httpRequest.setContent(bytes);
        httpRequest.setContentType("application/json");
        decoder.decode();
        final MessageContext<ClientRegistrationRequest> messageContext = decoder
                .getMessageContext();
        final ClientRegistrationRequest message = messageContext.getMessage();
        // We are not testing nimbus itself here, i.e. we are happy to decode
        // one parameter successfully
        Assert.assertEquals(message.getClientMetadata().getName(), "My Example");
    }
}