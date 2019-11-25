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
import com.nimbusds.openid.connect.sdk.OIDCScopeValue;
import com.nimbusds.openid.connect.sdk.claims.ACR;

/** {@link SetRefreshTokenToResponseContext} unit test. */
public class SetRefreshTokenToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetRefreshTokenToResponseContext action;

    private void init() throws ComponentInitializationException, NoSuchAlgorithmException, URISyntaxException {
        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OFFLINE_ACCESS);
        respCtx.setScope(scope);
        TokenClaimsSet claims = new AuthorizeCodeClaimsSet.Builder(idGenerator, new ClientID(), "issuer", "userPrin",
                "subject", new Date(), new Date(), new Date(), new URI("http://example.com"),
                new Scope()).setACR(new ACR("0")).build();
        respCtx.setTokenClaimsSet(claims);
        action = new SetRefreshTokenToResponseContext(getDataSealer());
        action.initialize();
    }

    /**
     * Basic success case.
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
     * There is no offline_access scope.
     */
    @Test
    public void testNoToken() throws ComponentInitializationException, NoSuchAlgorithmException, URISyntaxException,
            ParseException, DataSealerException {
        init();
        respCtx.setScope(new Scope());
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(respCtx.getRefreshToken());
    }

    /**
     * fails as there is no rp ctx.
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
     */
    @Test
    public void testFailTokenNotCodeOrRefresh()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        init();
        TokenClaimsSet claims =  new AccessTokenClaimsSet.Builder(idGenerator, new ClientID(), "issuer",
                "userPrin", "subject", new Date(), new Date(), new Date(), new URI("http://example.com"), new Scope()).build();
        respCtx.setTokenClaimsSet(claims);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /**
     * fails as there no token to derive refresh token from.
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