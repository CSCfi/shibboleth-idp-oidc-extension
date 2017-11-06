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
