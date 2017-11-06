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

import java.util.Map;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.langtag.LangTagException;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link AddClientNameToClientMetadata}.
 */
public class AddClientNameToClientMetadataTest extends BaseOIDCClientMetadataPopulationTest {

    AddClientNameToClientMetadata action;
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        action = new AddClientNameToClientMetadata();
        action.initialize();
    }
    
    @Override
    protected AbstractOIDCClientMetadataPopulationAction constructAction() {
        return new AddClientNameToClientMetadata();
    }
    
    @Test
    public void testNull() throws ComponentInitializationException {
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(new OIDCClientMetadata(), result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertNull(result.getName());
        Assert.assertTrue(result.getNameEntries().isEmpty());
    }
    
    @Test
    public void testEmpty() throws ComponentInitializationException {
        OIDCClientMetadata request = new OIDCClientMetadata();
        request.setName("");
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertNull(result.getName());
        Assert.assertTrue(result.getNameEntries().isEmpty());
    }

    @Test
    public void testNoTag() throws ComponentInitializationException {
        OIDCClientMetadata request = new OIDCClientMetadata();
        String name = "client name";
        request.setName(name);
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(result.getName(), name);
        Map<LangTag, String> map = result.getNameEntries();
        Assert.assertFalse(map.isEmpty());
        Assert.assertEquals(map.size(), 1);
        Assert.assertEquals(map.get(map.keySet().iterator().next()), name);
    }

    @Test
    public void testTags() throws ComponentInitializationException, LangTagException {
        OIDCClientMetadata request = new OIDCClientMetadata();
        String name1 = "client name";
        LangTag tag1 = new LangTag("en");
        String name2 = "asiakkaan nimi";
        LangTag tag2 = new LangTag("fi");
        request.setName(name1, tag1);
        request.setName(name2, tag2);
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertNull(result.getName());
        Map<LangTag, String> map = result.getNameEntries();
        Assert.assertFalse(map.isEmpty());
        Assert.assertEquals(map.size(), 2);
        Assert.assertEquals(map.get(tag1), name1);
        Assert.assertEquals(map.get(tag2), name2);
    }
}
