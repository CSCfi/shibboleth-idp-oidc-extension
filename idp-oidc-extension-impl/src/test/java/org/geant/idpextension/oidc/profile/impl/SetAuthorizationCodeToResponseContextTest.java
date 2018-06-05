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
        Assert.assertNotNull(respCtx.getAuthorizationCode());
        AuthorizeCodeClaimsSet ac =
                AuthorizeCodeClaimsSet.parse(respCtx.getAuthorizationCode().getValue(), getDataSealer());
        Assert.assertNotNull(ac);
    }

    /**
     * Basic success case plus consent.
     * 
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * @throws URISyntaxException
     * @throws DataSealerException
     * @throws ParseException
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
     * 
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * @throws URISyntaxException
     * @throws DataSealerException
     * @throws ParseException
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
     * fails as there is no subject ctx.
     * 
     * @throws URISyntaxException
     * @throws ComponentInitializationException
     * @throws NoSuchAlgorithmException
     * 
     * 
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

}