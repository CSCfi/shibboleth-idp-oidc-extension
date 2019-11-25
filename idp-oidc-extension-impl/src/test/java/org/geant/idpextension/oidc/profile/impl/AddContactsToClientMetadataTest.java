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
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link AddContactsToClientMetadata}.
 */
public class AddContactsToClientMetadataTest extends BaseOIDCClientMetadataPopulationTest {

    AddContactsToClientMetadata action;
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        action = new AddContactsToClientMetadata();
        action.initialize();
    }
    
    @Override
    protected AbstractOIDCClientMetadataPopulationAction constructAction() {
        return new AddContactsToClientMetadata();
    }
    
    @Test
    public void testNull() throws ComponentInitializationException {
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(new OIDCClientMetadata(), result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertNull(result.getEmailContacts());
    }
    
    @Test
    public void testEmpty() throws ComponentInitializationException {
        OIDCClientMetadata request = new OIDCClientMetadata();
        request.setEmailContacts(new ArrayList<String>());
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertNull(result.getEmailContacts());
    }
    
    @Test
    public void testSuccess() throws ComponentInitializationException {
        OIDCClientMetadata request = new OIDCClientMetadata();
        List<String> contacts = new ArrayList<String>();
        String address = "root@example.org";
        contacts.add(address);
        request.setEmailContacts(contacts);
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(request, result);
        Assert.assertNull(action.execute(requestCtx));
        List<String> resultContacts = result.getEmailContacts();
        Assert.assertNotNull(resultContacts);
        Assert.assertEquals(resultContacts.size(), 1);
        Assert.assertEquals(resultContacts.get(0), address);
    }
}
