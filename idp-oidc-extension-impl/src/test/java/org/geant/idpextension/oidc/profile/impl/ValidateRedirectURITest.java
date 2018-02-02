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
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.geant.idpextension.oidc.profile.OidcEventIds;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/** {@link InitializeAuthenticationContext} unit test. */
public class ValidateRedirectURITest extends BaseOIDCResponseActionTest {

    private ValidateRedirectURI action;

    private void init() throws ComponentInitializationException {
        action = new ValidateRedirectURI();
        action.initialize();
    }

    /**
     * Test that action copes with no oidc metadata contextcontext.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoCtx() throws ComponentInitializationException {
        init();
        profileRequestCtx.getInboundMessageContext().removeSubcontext(OIDCMetadataContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test case of not having matching redirect uri.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     */
    @SuppressWarnings("rawtypes")
    @Test
    public void testNoMatch() throws ComponentInitializationException, URISyntaxException {
        init();
        final ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        OIDCMetadataContext oidcCtx = prc.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        OIDCClientMetadata metaData = new OIDCClientMetadata();
        metaData.setRedirectionURI(new URI("https://notmatching.org"));
        OIDCClientInformation information = new OIDCClientInformation(new ClientID("test"), null, metaData, null, null, null);
        oidcCtx.setClientInformation(information);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, OidcEventIds.INVALID_REDIRECT_URI);
        Assert.assertNull(respCtx.getRedirectURI());
    }

    /**
     * Test case of having a match for redirect uri.
     * 
     * @throws ComponentInitializationException
     * @throws URISyntaxException
     */
    @SuppressWarnings("rawtypes")
    @Test
    public void testMatch() throws ComponentInitializationException, URISyntaxException {
        init();
        final ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        OIDCMetadataContext oidcCtx = prc.getInboundMessageContext().getSubcontext(OIDCMetadataContext.class, true);
        OIDCClientMetadata metaData = new OIDCClientMetadata();
        metaData.setRedirectionURI(new URI("https://client.example.org/cb"));
        OIDCClientInformation information = new OIDCClientInformation(new ClientID("test"), null, metaData, null, null, null);
        oidcCtx.setClientInformation(information);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(respCtx.getRedirectURI());
    }
}