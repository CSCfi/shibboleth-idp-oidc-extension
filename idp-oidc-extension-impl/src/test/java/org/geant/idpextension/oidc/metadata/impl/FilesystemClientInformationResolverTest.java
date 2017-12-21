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

package org.geant.idpextension.oidc.metadata.impl;

import java.io.File;
import java.util.Set;

import org.geant.idpextension.oidc.criterion.ClientIDCriterion;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;

/**
 * Unit tests for {@link FilesystemClientInformationResolver}.
 */
public class FilesystemClientInformationResolverTest {

    FilesystemClientInformationResolver resolver;
    
    String clientId;
    
    @BeforeMethod
    public void initTests() throws Exception {
        clientId = "demo_rp";
        final File file = new File("../roles/oidc-extension/templates/oidc-client.json");
        resolver = new FilesystemClientInformationResolver(file);
        resolver.setId("mockId");
        resolver.initialize();
    }
    
    @Test
    public void testNotFound() throws Exception {
        final ClientIDCriterion criterion = new ClientIDCriterion(new ClientID("not_found"));
        final ClientInformation clientInfo = resolver.resolveSingle(new CriteriaSet(criterion));
        Assert.assertNull(clientInfo);
    }
    
    @Test
    public void testSuccess() throws Exception {
        final ClientIDCriterion criterion = new ClientIDCriterion(new ClientID(clientId));
        final OIDCClientInformation clientInfo = resolver.resolveSingle(new CriteriaSet(criterion));
        Assert.assertNotNull(clientInfo);
        Assert.assertEquals(clientInfo.getID().getValue(), clientId);
        final Scope scope = clientInfo.getOIDCMetadata().getScope();
        Assert.assertEquals(scope.size(), 6);
        Assert.assertTrue(scope.contains(OIDCScopeValue.OPENID));
        Assert.assertTrue(scope.contains(OIDCScopeValue.ADDRESS));
        Assert.assertTrue(scope.contains(OIDCScopeValue.EMAIL));
        Assert.assertTrue(scope.contains(OIDCScopeValue.PHONE));
        Assert.assertTrue(scope.contains(OIDCScopeValue.PROFILE));
        Assert.assertTrue(scope.contains("info"));
        final Set<ResponseType> responseTypes = clientInfo.getOIDCMetadata().getResponseTypes();
        Assert.assertEquals(responseTypes.size(), 1);
        Assert.assertTrue(responseTypes.contains(new ResponseType(OIDCResponseTypeValue.ID_TOKEN)));
    }
}