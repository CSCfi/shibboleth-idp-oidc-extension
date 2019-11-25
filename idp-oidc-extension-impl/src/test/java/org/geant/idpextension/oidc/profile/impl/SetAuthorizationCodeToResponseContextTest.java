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

import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.security.DataSealerException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseConsentContext;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.geant.idpextension.oidc.token.support.AuthorizeCodeClaimsSet;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

/** {@link SetAuthorizationCodeToResponseContext} unit test. */
public class SetAuthorizationCodeToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetAuthorizationCodeToResponseContext action;

    private void init() throws ComponentInitializationException, NoSuchAlgorithmException, URISyntaxException {
        respCtx.setScope(new Scope());
        respCtx.setSubject("subject");
        respCtx.setAuthTime(System.currentTimeMillis());
        respCtx.setAcr("0");
        respCtx.setRedirectURI(new URI("http://example.com"));
        action = new SetAuthorizationCodeToResponseContext(getDataSealer());
        action.initialize();
        SubjectContext subjectCtx = profileRequestCtx.getSubcontext(SubjectContext.class, true);
        subjectCtx.setPrincipalName("userPrin");
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
        Assert.assertNotNull(respCtx.getAuthorizationCode());
        AuthorizeCodeClaimsSet ac =
                AuthorizeCodeClaimsSet.parse(respCtx.getAuthorizationCode().getValue(), getDataSealer());
        Assert.assertNotNull(ac);
    }

    /**
     * Basic success case plus consent.
     */
    @Test
    public void testSuccessConsent() throws ComponentInitializationException, NoSuchAlgorithmException,
            URISyntaxException, ParseException, DataSealerException {
        init();
        OIDCAuthenticationResponseConsentContext consCtx = (OIDCAuthenticationResponseConsentContext) respCtx
                .addSubcontext(new OIDCAuthenticationResponseConsentContext());
        consCtx.getConsentableAttributes().add("1");
        consCtx.getConsentableAttributes().add("2");
        consCtx.getConsentedAttributes().add("3");
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(respCtx.getAuthorizationCode());
        AuthorizeCodeClaimsSet ac =
                AuthorizeCodeClaimsSet.parse(respCtx.getAuthorizationCode().getValue(), getDataSealer());
        Assert.assertNotNull(ac);
        Assert.assertEquals(ac.getConsentableClaims(), consCtx.getConsentableAttributes());
        Assert.assertEquals(ac.getConsentedClaims(), consCtx.getConsentedAttributes());
    }

    /**
     * Basic success case plus delivery claims
     */
    @Test
    public void testSuccessWithTokenDelivery() throws ComponentInitializationException, NoSuchAlgorithmException,
            URISyntaxException, ParseException, DataSealerException {
        init();
        OIDCAuthenticationResponseTokenClaimsContext tokenCtx = (OIDCAuthenticationResponseTokenClaimsContext) respCtx
                .addSubcontext(new OIDCAuthenticationResponseTokenClaimsContext());
        tokenCtx.getClaims().setClaim("1", "1");
        tokenCtx.getIdtokenClaims().setClaim("2", "2");
        tokenCtx.getUserinfoClaims().setClaim("3", "3");
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(respCtx.getAuthorizationCode());
        AuthorizeCodeClaimsSet ac =
                AuthorizeCodeClaimsSet.parse(respCtx.getAuthorizationCode().getValue(), getDataSealer());
        Assert.assertNotNull(ac);
        Assert.assertNotNull(ac.getDeliveryClaims().getClaim("1"));
        Assert.assertNotNull(ac.getIDTokenDeliveryClaims().getClaim("2"));
        Assert.assertNotNull(ac.getUserinfoDeliveryClaims().getClaim("3"));
    }

    /**
     * Test PKCE with default challenge method.
     */
    @Test
    public void testSuccessPKCE() throws ComponentInitializationException, NoSuchAlgorithmException, URISyntaxException,
            ParseException, DataSealerException, com.nimbusds.oauth2.sdk.ParseException {
        init();
        request = AuthenticationRequest.parse(
                "code_challenge=123456&code_challenge_method=S256&response_type=id_token+token&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20email%20profile%20offline_access&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
        setAuthenticationRequest(request);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(respCtx.getAuthorizationCode());
        AuthorizeCodeClaimsSet ac =
                AuthorizeCodeClaimsSet.parse(respCtx.getAuthorizationCode().getValue(), getDataSealer());
        Assert.assertNotNull(ac);
        Assert.assertEquals(ac.getCodeChallenge(), "S256123456");
    }

    /**
     * Test PKCE with default challenge method.
     */
    @Test
    public void testSuccessPKCEDefault() throws ComponentInitializationException, NoSuchAlgorithmException,
            URISyntaxException, ParseException, DataSealerException, com.nimbusds.oauth2.sdk.ParseException {
        init();
        request = AuthenticationRequest.parse(
                "code_challenge=123456&response_type=id_token+token&client_id=s6BhdRkqt3&login_hint=foo&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb&scope=openid%20email%20profile%20offline_access&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj");
        setAuthenticationRequest(request);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNotNull(respCtx.getAuthorizationCode());
        AuthorizeCodeClaimsSet ac =
                AuthorizeCodeClaimsSet.parse(respCtx.getAuthorizationCode().getValue(), getDataSealer());
        Assert.assertNotNull(ac);
        Assert.assertEquals(ac.getCodeChallenge(), "plain123456");
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
     * fails as there is no subject ctx.
     */
    @Test
    public void testFailNoSubjectCtx()
            throws NoSuchAlgorithmException, ComponentInitializationException, URISyntaxException {
        init();
        profileRequestCtx.removeSubcontext(SubjectContext.class);
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
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

}