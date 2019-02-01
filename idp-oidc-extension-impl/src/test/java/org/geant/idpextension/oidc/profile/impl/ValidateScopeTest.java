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

import java.net.URI;
import java.net.URISyntaxException;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/** {@link ValidateScope} unit test. */
public class ValidateScopeTest extends BaseOIDCResponseActionTest {

    private ValidateScope action;

    private OIDCClientMetadata metaData;

    @BeforeMethod
    private void init() throws ComponentInitializationException, URISyntaxException {
        action = new ValidateScope();
        action.initialize();
        OIDCMetadataContext oidcCtx =
                profileRequestCtx.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        metaData = new OIDCClientMetadata();
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        scope.add(OIDCScopeValue.OFFLINE_ACCESS);
        metaData.setScope(scope);
        metaData.setRedirectionURI(new URI("https://notmatching.org"));
        OIDCClientInformation information =
                new OIDCClientInformation(new ClientID("test"), null, metaData, null, null, null);
        oidcCtx.setClientInformation(information);
    }

    /**
     * Test that action filters our non valid scopes.
     */
    @Test
    public void testSuccess() throws ComponentInitializationException {
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        // input is openid, profile, offline_access and email. profile and offline_access should be filtered out
        // (offline because the request is implicit).
        Assert.assertTrue(respCtx.getScope().contains(OIDCScopeValue.OPENID));
        Assert.assertTrue(respCtx.getScope().contains(OIDCScopeValue.EMAIL));
        Assert.assertTrue(!respCtx.getScope().contains(OIDCScopeValue.OFFLINE_ACCESS));
        Assert.assertTrue(!respCtx.getScope().contains(OIDCScopeValue.PROFILE));
    }

    /**
     * Test that action copes if there are no registered scopes.
     */
    @Test
    public void testSuccessNoScopes() throws ComponentInitializationException {
        metaData.setScope(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(respCtx.getScope());
    }

}