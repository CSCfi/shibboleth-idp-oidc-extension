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

import com.nimbusds.openid.connect.sdk.rp.ApplicationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link AddApplicationTypeToClientMetadata}.
 */
public class AddApplicationTypeToClientMetadataTest extends BaseOIDCClientMetadataPopulationTest {

    AddApplicationTypeToClientMetadata action;
    
    @BeforeMethod
    public void setUp() throws ComponentInitializationException {
        action = new AddApplicationTypeToClientMetadata();
        action.initialize();
    }
    
    @Test
    public void testDefault() throws ComponentInitializationException {
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(new OIDCClientMetadata(), result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(result.getApplicationType(), ApplicationType.getDefault());
    }

    @Test
    public void testWeb() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setApplicationType(ApplicationType.WEB);
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(input, result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(result.getApplicationType(), ApplicationType.WEB);
    }

    @Test
    public void testNative() throws ComponentInitializationException {
        OIDCClientMetadata input = new OIDCClientMetadata();
        input.setApplicationType(ApplicationType.NATIVE);
        OIDCClientMetadata result = new OIDCClientMetadata();
        setUpContext(input, result);
        Assert.assertNull(action.execute(requestCtx));
        Assert.assertEquals(result.getApplicationType(), ApplicationType.NATIVE);
    }

    @Override
    protected AbstractOIDCClientMetadataPopulationAction constructAction() {
        return new AddApplicationTypeToClientMetadata();
    }
}
