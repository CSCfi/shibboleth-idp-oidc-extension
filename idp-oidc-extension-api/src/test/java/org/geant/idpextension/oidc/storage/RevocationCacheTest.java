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

package org.geant.idpextension.oidc.storage;

import java.nio.charset.Charset;
import java.util.Random;

import org.opensaml.storage.impl.client.ClientStorageService;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.Test;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import org.testng.annotations.BeforeMethod;
import org.testng.Assert;
import org.opensaml.storage.impl.MemoryStorageService;;

/**
 * Tests for {@link RevocationCache}
 */
public class RevocationCacheTest {

    
    private MemoryStorageService storageService;
    
    private RevocationCache revocationCache;

    @BeforeMethod
    protected void setUp() throws Exception {
    
        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.initialize();
        
        revocationCache = new RevocationCache();
        revocationCache.setEntryExpiration(500);
        revocationCache.setStorage(storageService);
        revocationCache.initialize();
    }
    
    @AfterMethod
    protected void tearDown() {
        revocationCache.destroy();
        revocationCache = null;
        
        storageService.destroy();
        storageService = null;
    }
    
    @Test
    public void testInit() {
        revocationCache = new RevocationCache();
        try {
            revocationCache.setStorage(null);
            Assert.fail("Null StorageService should have caused constraint violation");
        } catch (Exception e) {
        }

        try {
            revocationCache.setStorage(new ClientStorageService());
            
            Assert.fail("ClientStorageService should have caused constraint violation");
        } catch (Exception e) {
        }
    }
    
    
    @Test
    public void testStrictSetter() throws ComponentInitializationException {
        Assert.assertFalse(revocationCache.isStrict());
        revocationCache = new RevocationCache();
        revocationCache.setStorage(storageService);
        revocationCache.setStrict(true);
        revocationCache.initialize();
        Assert.assertTrue(revocationCache.isStrict());
    }
    
    @Test (expectedExceptions = ConstraintViolationException.class)
    public void testExpirationSetter() throws ComponentInitializationException {
        //Must be zero or more
        revocationCache.setEntryExpiration(0);
    }
    
    @Test 
    public void testStorageGetter() throws ComponentInitializationException {
        Assert.assertEquals(storageService, revocationCache.getStorage());
    }
    
    @Test 
    public void testRevocationSuccess() throws ComponentInitializationException {
        Assert.assertFalse(revocationCache.isRevoked("context", "item"));
        Assert.assertTrue(revocationCache.revoke("context", "item"));
        Assert.assertTrue(revocationCache.isRevoked("context", "item"));
    }
    
    @Test 
    public void testRevocationSuccessLongContext() throws ComponentInitializationException {
        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.setContextSize(50);
        storageService.initialize();
        
        revocationCache = new RevocationCache();
        revocationCache.setStorage(storageService);
        revocationCache.initialize();
        
        byte[] array = new byte[storageService.getCapabilities().getContextSize()*2];
        new Random().nextBytes(array);
        String context = new String(array, Charset.forName("UTF-8"));
        Assert.assertTrue(context.length()>storageService.getCapabilities().getContextSize());
        Assert.assertTrue(revocationCache.isRevoked(context, "item"));
        Assert.assertFalse(revocationCache.revoke(context, "item"));
    }
    
    @Test 
    public void testRevocationSuccessLongLongItem() throws ComponentInitializationException {
        storageService = new MemoryStorageService();
        storageService.setId("test");
        storageService.setKeySize(50);
        storageService.initialize();
        revocationCache = new RevocationCache();
        revocationCache.setStorage(storageService);
        revocationCache.initialize();
        byte[] array = new byte[storageService.getCapabilities().getKeySize()*2];
        new Random().nextBytes(array);
        String item = new String(array, Charset.forName("UTF-8"));
        Assert.assertTrue(item.length()>storageService.getCapabilities().getKeySize());
        Assert.assertFalse(revocationCache.isRevoked("context", item));
        Assert.assertTrue(revocationCache.revoke("context", item));
        Assert.assertTrue(revocationCache.isRevoked("context", item));
    }
    
    @Test 
    public void testRevocationExpirationSuccess() throws ComponentInitializationException, InterruptedException {
        //Test expiration of entry (500ms)
        Assert.assertFalse(revocationCache.isRevoked("context", "item"));
        Assert.assertTrue(revocationCache.revoke("context", "item"));
        Thread.sleep(600L);
        Assert.assertFalse(revocationCache.isRevoked("context", "item"));
        //Test rolling window, second revoke updates expiration past original 500ms
        Assert.assertTrue(revocationCache.revoke("context", "item"));
        Thread.sleep(300L);
        Assert.assertTrue(revocationCache.revoke("context", "item"));
        Thread.sleep(300L);
        Assert.assertTrue(revocationCache.isRevoked("context", "item"));
    }
}