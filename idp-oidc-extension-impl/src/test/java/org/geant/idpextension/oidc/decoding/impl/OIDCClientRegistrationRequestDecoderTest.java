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

import java.io.File;
import java.io.IOException;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.io.Files;
import com.nimbusds.oauth2.sdk.http.HTTPRequest.Method;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;

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
        final MessageContext<OIDCClientRegistrationRequest> messageContext = decoder
                .getMessageContext();
        final OIDCClientRegistrationRequest message = messageContext.getMessage();
        // We are not testing nimbus itself here, i.e. we are happy to decode
        // one parameter successfully
        Assert.assertEquals(message.getClientMetadata().getName(), "My Example");
    }
}