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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link AddGrantTypeToClientMetadata}.
 */
public class AddGrantTypeToClientMetadataTest extends BaseOIDCClientMetadataPopulationTest {

    @Override
    protected AbstractOIDCClientMetadataPopulationAction constructAction() {
        AddGrantTypeToClientMetadata newAction = new AddGrantTypeToClientMetadata();
        Predicate<ProfileRequestContext> predicate = Predicates.alwaysTrue();
        newAction.setAuthorizationCodeFlowEnabled(predicate);
        newAction.setImplicitFlowEnabled(predicate);
        newAction.setRefreshTokensEnabled(predicate);
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
        Set<GrantType> resultTypes = result.getGrantTypes();
        Assert.assertNotNull(resultTypes);
        Assert.assertEquals(resultTypes.size(), 3);
        Assert.assertTrue(resultTypes.contains(GrantType.AUTHORIZATION_CODE));
        Assert.assertTrue(resultTypes.contains(GrantType.IMPLICIT));
        Assert.assertTrue(resultTypes.contains(GrantType.REFRESH_TOKEN));
    }

    @Test
    public void testNotSupported() throws ComponentInitializationException {
        testGrantTypes(Arrays.asList(new GrantType[] { GrantType.CLIENT_CREDENTIALS }), EventIds.INVALID_MESSAGE,
                GrantType.CLIENT_CREDENTIALS);
    }

    @Test
    public void testOneNotSupported() throws ComponentInitializationException {
        testGrantTypes(Arrays.asList(new GrantType[] { GrantType.CLIENT_CREDENTIALS }), null,
                GrantType.AUTHORIZATION_CODE, GrantType.CLIENT_CREDENTIALS);
    }
    
    @Test
    public void testAuthzCode() throws ComponentInitializationException {
        testGrantTypes(GrantType.AUTHORIZATION_CODE);
    }
    
    @Test
    public void testImplicit() throws ComponentInitializationException {
        testGrantTypes(GrantType.IMPLICIT);
    }
    
    @Test
    public void testRefresh() throws ComponentInitializationException {
        testGrantTypes(GrantType.REFRESH_TOKEN);
    }

    @Test
    public void testTwo() throws ComponentInitializationException {
        testGrantTypes(GrantType.REFRESH_TOKEN, GrantType.IMPLICIT);
    }

    @Test
    public void testAll() throws ComponentInitializationException {
        testGrantTypes(GrantType.AUTHORIZATION_CODE, GrantType.IMPLICIT, GrantType.REFRESH_TOKEN);
    }

    protected void testGrantTypes(GrantType... grantTypes) throws ComponentInitializationException {
        testGrantTypes(new ArrayList<GrantType>(), null, grantTypes);
    }

    protected void testGrantTypes(List<GrantType> ignoredTypes, String expectedEventId, GrantType... grantTypes) 
            throws ComponentInitializationException {
        OIDCClientMetadata request = new OIDCClientMetadata();
        request.setGrantTypes(new HashSet<GrantType>(Arrays.asList(grantTypes)));
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Event event = action.execute(requestCtx);
        if (expectedEventId != null) {
            ActionTestingSupport.assertEvent(event, expectedEventId);
            return;
        }
        Assert.assertNull(event);
        Set<GrantType> resultTypes = result.getGrantTypes();
        Assert.assertNotNull(resultTypes);
        int length = (ignoredTypes == null) ? grantTypes.length : grantTypes.length - ignoredTypes.size();
        Assert.assertEquals(resultTypes.size(), length);
        for (GrantType grantType : grantTypes) {
            if (ignoredTypes.contains(grantType)) {
                Assert.assertFalse(resultTypes.contains(grantType));
            } else {
                Assert.assertTrue(resultTypes.contains(grantType));
            }
        }
    }
}
