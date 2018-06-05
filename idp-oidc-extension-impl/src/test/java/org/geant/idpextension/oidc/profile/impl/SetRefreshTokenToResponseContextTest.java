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

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.DataSealerException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Date;
import org.geant.idpextension.oidc.token.support.AccessTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.geant.idpextension.oidc.token.support.RefreshTokenClaimsSet;
import org.geant.idpextension.oidc.token.support.TokenClaimsSet;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;

/** {@link SetAccessTokenToResponseContext} unit test. */
public class SetRefreshTokenToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetRefreshTokenToResponseContext action;

    private void init() throws ComponentInitializationException, NoSuchAlgorithmException, URISyntaxException {
        respCtx.setScope(new Scope());
        TokenClaimsSet claims = new AuthorizeCodeClaimsSet(new idStrat(), new ClientID(), "issuer", "userPrin",
                "subject", new ACR("0"), new Date(), new Date(), new Nonce(), new Date(), new URI("http://example.com"),
                new Scope(), null, null, null, null, null, null);
        respCtx.setTokenClaimsSet(claims);
        action = new SetRefreshTokenToResponseContext(getDataSealer());
        action.initialize();
    }

    /**
     * Basic success case.
     * 
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * @throws URISyntaxException
     * @throws DataSealerException
     * @throws ParseException
     */
    @Test
    public void testSuccess() throws ComponentInitializationException, NoSuchAlgorithmException, URISyntaxException,
            ParseException, DataSealerException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(respCtx.getRefreshToken());
        RefreshTokenClaimsSet rt = RefreshTokenClaimsSet.parse(respCtx.getRefreshToken().getValue(), getDataSealer());
        Assert.assertNotNull(rt);
    }

    /**
     * fails as there is no rp ctx.
     * 
     * @throws URISyntaxException
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * 
     * 
     */
    @Test
    public void testFailNoRPCtx()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        init();
        profileRequestCtx.removeSubcontext(RelyingPartyContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, IdPEventIds.INVALID_RELYING_PARTY_CTX);
    }

    /**
     * fails as there is no profile conf.
     * 
     * @throws URISyntaxException
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * 
     * 
     */
    @Test
    public void testFailNoProfileConf()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        init();
        RelyingPartyContext rpCtx = profileRequestCtx.getSubcontext(RelyingPartyContext.class, false);
        rpCtx.setProfileConfig(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, IdPEventIds.INVALID_RELYING_PARTY_CTX);
    }

    /**
     * fails as the token is of wrong type.
     * 
     * @throws URISyntaxException
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * 
     * 
     */
    @Test
    public void testFailTokenNotCodeOrRefresh()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        init();
        TokenClaimsSet claims = new AccessTokenClaimsSet(new idStrat(), new ClientID(), "issuer", "userPrin", "subject",
                new ACR("0"), new Date(), new Date(), new Nonce(), new Date(), new URI("http://example.com"),
                new Scope(), null, null, null, null, null);
        respCtx.setTokenClaimsSet(claims);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * fails as there no token to derive refresh token from.
     * 
     * @throws URISyntaxException
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * 
     * 
     */
    @Test
    public void testFailNoToken()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        init();
        respCtx.setTokenClaimsSet(null);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

}