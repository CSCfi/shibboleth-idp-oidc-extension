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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.opensaml.profile.context.ProfileRequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

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
        testGrantTypes(Arrays.asList(new GrantType[] { GrantType.CLIENT_CREDENTIALS }), 
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
        testGrantTypes(new ArrayList<GrantType>(), grantTypes);
    }

    protected void testGrantTypes(List<GrantType> ignoredTypes, GrantType... grantTypes) 
            throws ComponentInitializationException {
        OIDCClientMetadata request = new OIDCClientMetadata();
        request.setGrantTypes(new HashSet<GrantType>(Arrays.asList(grantTypes)));
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Assert.assertNull(action.execute(requestCtx));
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
