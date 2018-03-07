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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link AddResponseTypesToClientMetadata}.
 */
public class AddResponseTypesToClientMetadataTest extends BaseOIDCClientMetadataPopulationTest {

    @Override
    protected AbstractOIDCClientMetadataPopulationAction constructAction() {
        AddResponseTypesToClientMetadata newAction = new AddResponseTypesToClientMetadata();
        Predicate<ProfileRequestContext> predicate = Predicates.alwaysTrue();
        newAction.setAuthorizationCodeFlowEnabled(predicate);
        newAction.setImplicitFlowEnabled(predicate);
        Map<ResponseType, Predicate<ProfileRequestContext>>supportedResponseTypes = new HashMap<>();
        supportedResponseTypes.put(new ResponseType(ResponseType.Value.CODE), predicate);
        supportedResponseTypes.put(new ResponseType(OIDCResponseTypeValue.ID_TOKEN), predicate);
        supportedResponseTypes.put(new ResponseType(ResponseType.Value.TOKEN, OIDCResponseTypeValue.ID_TOKEN), 
                predicate);
        supportedResponseTypes.put(new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN), 
                predicate);
        supportedResponseTypes.put(new ResponseType(ResponseType.Value.CODE, ResponseType.Value.TOKEN), 
                predicate);
        supportedResponseTypes.put(new ResponseType(ResponseType.Value.CODE, ResponseType.Value.TOKEN, 
                OIDCResponseTypeValue.ID_TOKEN), predicate);
        newAction.setSupportedResponseTypes(supportedResponseTypes);
        return newAction;
    }
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        action = constructAction();
        action.initialize();
    }
    
    @Test
    public void testNoRequest() throws ComponentInitializationException {
        OIDCClientMetadata request = new OIDCClientMetadata();
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Assert.assertNull(action.execute(requestCtx));
        Set<ResponseType> resultTypes = result.getResponseTypes();
        Assert.assertNotNull(resultTypes);
        Assert.assertEquals(resultTypes.size(), 1);
        Assert.assertTrue(resultTypes.contains(new ResponseType(ResponseType.Value.CODE)));
    }

    @Test
    public void testNotSupported() throws ComponentInitializationException {
        testResponseTypes(Arrays.asList(new ResponseType[] { new ResponseType(OIDCResponseTypeValue.NONE) }), 
                EventIds.INVALID_MESSAGE,
                new ResponseType(OIDCResponseTypeValue.NONE));
    }

    @Test
    public void testOneNotSupported() throws ComponentInitializationException {
        testResponseTypes(Arrays.asList(new ResponseType[] { new ResponseType(OIDCResponseTypeValue.NONE) }), null,
                new ResponseType(OIDCResponseTypeValue.ID_TOKEN), new ResponseType(OIDCResponseTypeValue.NONE));
    }
    
    @Test
    public void testToken() throws ComponentInitializationException {
        testResponseTypes(new ArrayList<ResponseType>(), EventIds.INVALID_MESSAGE, 
                new ResponseType(ResponseType.Value.TOKEN));
    }

    @Test
    public void testIdToken() throws ComponentInitializationException {
        testResponseTypes(new ResponseType(OIDCResponseTypeValue.ID_TOKEN));
    }

    @Test
    public void testCode() throws ComponentInitializationException {
        testResponseTypes(new ResponseType(ResponseType.Value.CODE));
    }
    
    @Test
    public void testTwo() throws ComponentInitializationException {
        testResponseTypes(new ResponseType(OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.CODE));
    }

    @Test
    public void testAll() throws ComponentInitializationException {
        testResponseTypes(new ResponseType(OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.CODE, 
                ResponseType.Value.TOKEN)); 
    }

    protected void testResponseTypes(ResponseType... responseTypes) throws ComponentInitializationException {
        testResponseTypes(new ArrayList<ResponseType>(), null, responseTypes);
    }

    protected void testResponseTypes(List<ResponseType> ignoredTypes, String expectedEventId, 
            ResponseType... responseTypes) 
            throws ComponentInitializationException {
        OIDCClientMetadata request = new OIDCClientMetadata();
        request.setResponseTypes(new HashSet<ResponseType>(Arrays.asList(responseTypes)));
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Event event = action.execute(requestCtx);
        if (expectedEventId != null) {
            ActionTestingSupport.assertEvent(event, expectedEventId);
            return;
        }
        Assert.assertNull(event);
        Set<ResponseType> resultTypes = result.getResponseTypes();
        Assert.assertNotNull(resultTypes);
        int length = (ignoredTypes == null) ? responseTypes.length : responseTypes.length - ignoredTypes.size();
        Assert.assertEquals(resultTypes.size(), length);
        for (ResponseType responseType : responseTypes) {
            if (ignoredTypes.contains(responseType)) {
                Assert.assertFalse(resultTypes.contains(responseType));
            } else {
                Assert.assertTrue(resultTypes.contains(responseType));
            }
        }
    }
}
