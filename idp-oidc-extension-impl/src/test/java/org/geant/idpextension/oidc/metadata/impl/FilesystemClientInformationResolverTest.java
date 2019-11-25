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

package org.geant.idpextension.oidc.metadata.impl;

import java.io.File;
import java.net.URI;
import java.util.Set;

import org.geant.idpextension.oidc.criterion.ClientIDCriterion;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.testng.Assert;
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
    String clientId2;
    URI redirectUri;
    URI redirectUri2;
    
    public void initTest(final String filename) throws Exception {
        clientId = "demo_rp";
        clientId2 = "demo_rp2";
        final Resource file = new ClassPathResource(filename);
        resolver = new FilesystemClientInformationResolver(file);
        resolver.setId("mockId");
        resolver.initialize();
        redirectUri = new URI("https://192.168.0.150/static");
        redirectUri2 = new URI("https://192.168.0.150/static2");
    }
    
    @Test
    public void testNotFound() throws Exception {
        initTest("/org/geant/idpextension/oidc/metadata/impl/oidc-client.json");
        final ClientIDCriterion criterion = new ClientIDCriterion(new ClientID("not_found"));
        final ClientInformation clientInfo = resolver.resolveSingle(new CriteriaSet(criterion));
        Assert.assertNull(clientInfo);
    }
    
    @Test
    public void testSingleSuccess() throws Exception {
        initTest("/org/geant/idpextension/oidc/metadata/impl/oidc-client.json");
        final ClientIDCriterion criterion = new ClientIDCriterion(new ClientID(clientId));
        final OIDCClientInformation clientInfo = resolver.resolveSingle(new CriteriaSet(criterion));
        Assert.assertNotNull(clientInfo);
        Assert.assertEquals(clientInfo.getID().getValue(), clientId);
        final Set<URI> redirectUris = clientInfo.getOIDCMetadata().getRedirectionURIs();
        Assert.assertEquals(redirectUris.size(), 1);
        Assert.assertTrue(redirectUris.contains(redirectUri));
        testScope(clientInfo.getOIDCMetadata().getScope());
        final Set<ResponseType> responseTypes = clientInfo.getOIDCMetadata().getResponseTypes();
        Assert.assertEquals(responseTypes.size(), 2);
        Assert.assertTrue(responseTypes.contains(new ResponseType(OIDCResponseTypeValue.ID_TOKEN)));
    }

    @Test
    public void testArraySuccess() throws Exception {
        initTest("/org/geant/idpextension/oidc/metadata/impl/oidc-clients.json");
        final ClientIDCriterion criterion = new ClientIDCriterion(new ClientID(clientId2));
        final OIDCClientInformation clientInfo = resolver.resolveSingle(new CriteriaSet(criterion));
        Assert.assertNotNull(clientInfo);
        Assert.assertEquals(clientInfo.getID().getValue(), clientId2);
        final Set<URI> redirectUris = clientInfo.getOIDCMetadata().getRedirectionURIs();
        Assert.assertEquals(redirectUris.size(), 1);
        Assert.assertTrue(redirectUris.contains(redirectUri2));
        testScope(clientInfo.getOIDCMetadata().getScope());
        final Set<ResponseType> responseTypes = clientInfo.getOIDCMetadata().getResponseTypes();
        Assert.assertEquals(responseTypes.size(), 2);
        Assert.assertTrue(responseTypes.contains(new ResponseType(OIDCResponseTypeValue.ID_TOKEN)));
    }

    protected static void testScope(final Scope scope) {
        Assert.assertEquals(scope.size(), 6);
        Assert.assertTrue(scope.contains(OIDCScopeValue.OPENID));
        Assert.assertTrue(scope.contains(OIDCScopeValue.ADDRESS));
        Assert.assertTrue(scope.contains(OIDCScopeValue.EMAIL));
        Assert.assertTrue(scope.contains(OIDCScopeValue.PHONE));
        Assert.assertTrue(scope.contains(OIDCScopeValue.PROFILE));
        Assert.assertTrue(scope.contains("info"));
    }
}