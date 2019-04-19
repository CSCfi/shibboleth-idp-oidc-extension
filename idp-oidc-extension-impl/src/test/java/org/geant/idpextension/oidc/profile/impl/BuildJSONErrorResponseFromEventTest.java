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

package org.geant.idpextension.oidc.profile.impl;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.geant.idpextension.oidc.messaging.JSONErrorResponse;
import org.mockito.Mockito;
import org.opensaml.profile.context.EventContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.ErrorObject;

import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link BuildJSONErrorResponseFromEvent}.
 */
public class BuildJSONErrorResponseFromEventTest {
    
    protected RequestContext requestCtx;
    protected ProfileRequestContext profileRequestCtx;
    
    String eventId = "mockEventId";
    
    protected BuildJSONErrorResponseFromEvent initializeAction(Map<String, ErrorObject> mappedErrors, String eventId)
            throws ComponentInitializationException {
        BuildJSONErrorResponseFromEvent action = new BuildJSONErrorResponseFromEvent();
        if (eventId != null) {
            Function<ProfileRequestContext, EventContext> function = Mockito.mock(Function.class);
            EventContext eventContext = new EventContext();
            eventContext.setEvent(eventId);
            Mockito.when(function.apply((ProfileRequestContext)Mockito.any())).thenReturn(eventContext);
            action.setEventContextLookupStrategy(function);
        }
        action.setMappedErrors(mappedErrors);
        action.initialize();
        return action;
    }
    
    protected BuildJSONErrorResponseFromEvent initializeAction(String eventId) throws ComponentInitializationException {
        return initializeAction(new HashMap<String, ErrorObject>(), eventId);
    }    
    
    protected BuildJSONErrorResponseFromEvent initializeAction() throws ComponentInitializationException {
        return initializeAction(new HashMap<String, ErrorObject>(), null);
    }

    @BeforeMethod
    protected void setUpContext() throws ComponentInitializationException {
        requestCtx = new RequestContextBuilder().setInboundMessage(null).buildRequestContext();
        profileRequestCtx = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
    }
    
    @Test
    public void doPreExecute_shouldReturnFalseWithoutOutboundMessageContext() throws ComponentInitializationException {
        BuildJSONErrorResponseFromEvent action = initializeAction();
        profileRequestCtx.setOutboundMessageContext(null);
        Assert.assertFalse(action.doPreExecute(profileRequestCtx));
    }

    @Test
    public void doPreExecute_shouldReturnTrueWithOutboundMessageContext() throws ComponentInitializationException {
        BuildJSONErrorResponseFromEvent action = initializeAction();
        Assert.assertTrue(action.doPreExecute(profileRequestCtx));
    }
    
    @Test
    public void execute_shouldNotSetMessageWhenNoEventContext() throws ComponentInitializationException {
        BuildJSONErrorResponseFromEvent action = initializeAction();
        action.execute(requestCtx);
        Assert.assertNull(profileRequestCtx.getOutboundMessageContext().getMessage());
    }

    @Test
    public void execute_shouldSetMessageWhenEventContext() throws ComponentInitializationException {
        BuildJSONErrorResponseFromEvent action = initializeAction(eventId);
        action.execute(requestCtx);
        Object rawMessage = profileRequestCtx.getOutboundMessageContext().getMessage();
        Assert.assertNotNull(rawMessage);
        Assert.assertTrue(rawMessage instanceof JSONErrorResponse);
        JSONErrorResponse response = (JSONErrorResponse) rawMessage;
        ErrorObject error = response.getErrorObject();
        Assert.assertEquals(error.getCode(), AbstractBuildErrorResponseFromEvent.DEFAULT_ERROR_CODE);
        Assert.assertEquals(error.getDescription(), eventId);
        Assert.assertEquals(error.getHTTPStatusCode(), AbstractBuildErrorResponseFromEvent.DEFAULT_HTTP_STATUS_CODE);
    }
    
    @Test
    public void execute_shouldSetCustomMessageWhenConfiguredAndEventContext() throws ComponentInitializationException {
        String errorCode = "mockCode";
        String errorDescription = "mockDescription";
        int errorStatusCode = 503;
        BuildJSONErrorResponseFromEvent action = initializeAction(Collections.singletonMap(eventId, 
                new ErrorObject(errorCode, errorDescription, errorStatusCode)), eventId);
        action.execute(requestCtx);
        Object rawMessage = profileRequestCtx.getOutboundMessageContext().getMessage();
        Assert.assertNotNull(rawMessage);
        Assert.assertTrue(rawMessage instanceof JSONErrorResponse);
        JSONErrorResponse response = (JSONErrorResponse) rawMessage;
        ErrorObject error = response.getErrorObject();
        Assert.assertEquals(error.getCode(), errorCode);
        Assert.assertEquals(error.getDescription(), errorDescription);
        Assert.assertEquals(error.getHTTPStatusCode(), errorStatusCode);
    }

}
