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
