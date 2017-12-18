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
