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

package org.geant.idpextension.oidc.profile.flow;

import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.webflow.test.MockExternalContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Response;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;

import net.shibboleth.idp.test.flows.AbstractFlowTest;
import net.shibboleth.utilities.java.support.net.HttpServletRequestResponseContext;

/**
 * Abstract unit test for the OIDC flows.
 */
public abstract class AbstractOidcFlowTest<ResponseType extends Response> extends AbstractFlowTest {
    
    /**
     * Initialize mock request, response, and external context. Overrides to remove authorization header.
     */
    @BeforeMethod public void initializeMocks() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        externalContext = new MockExternalContext();
        externalContext.setNativeRequest(request);
        externalContext.setNativeResponse(response);
    }
    
    /**
     * {@link HttpServletRequestResponseContext#loadCurrent(HttpServletRequest, HttpServletResponse)}
     */
    @BeforeMethod public void initializeThreadLocals() {
        HttpServletRequestResponseContext.loadCurrent((HttpServletRequest) request, (HttpServletResponse) response);
    }
    
    protected void assertSuccess() throws ParseException, UnsupportedEncodingException {
        ResponseType parsedResponse = parseSuccessResponse();
        Assert.assertTrue(parsedResponse.indicatesSuccess());        
    }
    
    protected HTTPResponse parseResponse() throws ParseException, UnsupportedEncodingException {
        HTTPResponse httpResponse = new HTTPResponse(response.getStatus());
        httpResponse.setContentType(response.getContentType());
        httpResponse.setContent(response.getContentAsString());
        return httpResponse;
    }
    
    protected void assertErrorCode(String errorCode) throws UnsupportedEncodingException, ParseException {
        HTTPResponse httpResponse = new HTTPResponse(response.getStatus());
        httpResponse.setContentType(response.getContentType());
        httpResponse.setContent(response.getContentAsString());
        Assert.assertFalse(httpResponse.indicatesSuccess());
        Assert.assertEquals((String) httpResponse.getContentAsJSONObject().get("error"), errorCode);
    }
    
    protected void setJsonRequest(String method, String body) {
        setRequest(method, body, "application/json");
    }
    
    protected void setRequest(String method, String body, String contentType) {
        request.setMethod(method);
        request.setContentType(contentType);
        request.setContent(body.getBytes());   
    }
    
    protected abstract ResponseType parseSuccessResponse() throws ParseException, UnsupportedEncodingException;


}
