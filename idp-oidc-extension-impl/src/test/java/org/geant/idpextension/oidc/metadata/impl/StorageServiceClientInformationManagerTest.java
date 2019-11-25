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

import java.util.Date;

import org.geant.idpextension.oidc.criterion.ClientIDCriterion;
import org.opensaml.storage.impl.MemoryStorageService;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;

/**
 * Unit tests for {@link StorageServiceClientInformationManager}.
 */
public class StorageServiceClientInformationManagerTest {
    
    StorageServiceClientInformationManager manager;
    StorageServiceClientInformationResolver resolver;
    
    MemoryStorageService storageService;
    
    String clientIdValue;
    
    @BeforeMethod
    public void setupTests() throws Exception {
        storageService = new MemoryStorageService();
        storageService.setId("mockId");
        storageService.initialize();
        
        manager = new StorageServiceClientInformationManager();
        manager.setStorageService(storageService);
        manager.setId("mockId");
        manager.initialize();
        
        resolver = new StorageServiceClientInformationResolver();
        resolver.setStorageService(storageService);
        resolver.setId("mockId");
        resolver.initialize();
        
        clientIdValue = "mockClientId";
    }

    @Test
    public void testStore() throws Exception {
        final OIDCClientInformation clientInformation = initializeInformation();
        manager.storeClientInformation(clientInformation, null);
        final CriteriaSet criteria = initializeCriteria();
        final OIDCClientInformation result = resolver.resolveSingle(criteria);
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getID().getValue(), clientIdValue);
    }

    @Test
    public void testNullDestroy() throws Exception {
        final OIDCClientInformation clientInformation = initializeInformation();
        manager.storeClientInformation(clientInformation, null);
        manager.destroyClientInformation(null);
        final CriteriaSet criteria = initializeCriteria();
        final OIDCClientInformation result = resolver.resolveSingle(criteria);
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getID().getValue(), clientIdValue);
    }

    @Test
    public void testDestroy() throws Exception {
        final OIDCClientInformation clientInformation = initializeInformation();
        manager.storeClientInformation(clientInformation, null);
        manager.destroyClientInformation(new ClientID(clientIdValue));
        final CriteriaSet criteria = initializeCriteria();
        final OIDCClientInformation result = resolver.resolveSingle(criteria);
        Assert.assertNull(result);
    }

    @Test
    public void testExpiration() throws Exception {
        final OIDCClientInformation clientInformation = initializeInformation();
        manager.storeClientInformation(clientInformation, System.currentTimeMillis() + new Long(2000));
        final CriteriaSet criteria = initializeCriteria();
        final OIDCClientInformation result = resolver.resolveSingle(criteria);
        Assert.assertNotNull(result);
        Assert.assertEquals(result.getID().getValue(), clientIdValue);
        
        Thread.sleep(2100);
        
        final OIDCClientInformation delayedResult = resolver.resolveSingle(criteria);
        Assert.assertNull(delayedResult);
    }
    
    protected OIDCClientInformation initializeInformation() {
        final ClientID clientId = new ClientID(clientIdValue);
        final OIDCClientMetadata metadata = new OIDCClientMetadata();
        return new OIDCClientInformation(clientId, new Date(), metadata, null);
    }
    
    protected CriteriaSet initializeCriteria() {
        final CriteriaSet criteria = new CriteriaSet();
        criteria.add(new ClientIDCriterion(new ClientID(clientIdValue)));
        return criteria;
    }
}
