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
