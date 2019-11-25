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

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/**
 * Unit test for {@link AddScopeToClientMetadata}.
 */
public class AddScopeToClientMetadataTest extends BaseOIDCClientMetadataPopulationTest {
    
    AddScopeToClientMetadata action;
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        action = new AddScopeToClientMetadata();
        action.initialize();
    }

    @Override
    protected AbstractOIDCClientMetadataPopulationAction constructAction() {
        return new AddScopeToClientMetadata();
    }
    
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testNullDefault() {
        action = new AddScopeToClientMetadata();
        action.setDefaultScope(null);
    }
    
    @Test
    public void testNullScope() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getScope(), action.getDefaultScope());
    }
    
    @Test
    public void testEmptyScope() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setScope(new Scope());
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getScope(), action.getDefaultScope());
    }
    
    @Test
    public void testNullScopeCustomDefault() throws ComponentInitializationException {
        action = new AddScopeToClientMetadata();
        Scope defaultScope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.ADDRESS);
        action.setDefaultScope(defaultScope);
        action.initialize();
        OIDCClientMetadata input = new OIDCClientMetadata();
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getScope(), defaultScope);        
    }
    
    @Test
    public void testSetScope() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        Scope scope = new Scope(OIDCScopeValue.OPENID, OIDCScopeValue.ADDRESS);
        input.setScope(scope);
        OIDCClientMetadata output = new OIDCClientMetadata();
        setUpContext(input, output);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(output.getScope(), scope);        
    }

}
