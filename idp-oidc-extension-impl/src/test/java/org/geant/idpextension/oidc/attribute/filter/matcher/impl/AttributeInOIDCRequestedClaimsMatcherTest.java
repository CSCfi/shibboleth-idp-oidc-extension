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

package org.geant.idpextension.oidc.attribute.filter.matcher.impl;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.filter.context.AttributeFilterContext;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

import org.geant.idpextension.oidc.attribute.encoding.impl.OIDCStringAttributeEncoder;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.geant.idpextension.oidc.messaging.context.OIDCMetadataContext;
import org.junit.Assert;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

public class AttributeInOIDCRequestedClaimsMatcherTest {

    private AttributeInOIDCRequestedClaimsMatcher matcher;
    @SuppressWarnings("rawtypes")
    private ProfileRequestContext prc;
    private MessageContext<AuthenticationRequest> msgCtx;
    private OIDCMetadataContext ctx;
    IdPAttribute attribute;
    Collection<AttributeEncoder<?>> encoders;
    AttributeFilterContext filtercontext;

    @SuppressWarnings("unchecked")
    private void setUp(boolean idtoken, boolean userinfo) throws Exception {
        matcher = new AttributeInOIDCRequestedClaimsMatcher();
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        msgCtx = new MessageContext<AuthenticationRequest>();
        prc.setInboundMessageContext(msgCtx);
        //We use the same ctx for outbonud, outbound is olnly used here for fetching response context.
        prc.setOutboundMessageContext(msgCtx);
        OIDCAuthenticationResponseContext respCtx = new OIDCAuthenticationResponseContext();
        msgCtx.addSubcontext(respCtx);
        if (!idtoken && !userinfo) {
            msgCtx.setMessage(new AuthenticationRequest(new URI("htts://example.org"), ResponseType.getDefault(),
                    new Scope("openid"), new ClientID(), new URI("htts://example.org"), new State(), new Nonce()));
            
        } else {

            msgCtx.setMessage(new AuthenticationRequest(new URI("htts://example.org"), ResponseType.getDefault(), null,
                    new Scope("openid"), new ClientID(), new URI("htts://example.org"), new State(), new Nonce(), null,
                    null, 0, null, null, null, null, null, getClaimsRequest(idtoken, userinfo), null, null, null, null));
            respCtx.setRequestedClaims(getClaimsRequest(idtoken, userinfo));
        }
        
        // shortcut, may break the test
        filtercontext = prc.getSubcontext(AttributeFilterContext.class, true);
        ctx = new OIDCMetadataContext();
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        OIDCClientInformation information = new OIDCClientInformation(new ClientID(), new Date(), metadata,
                new Secret());
        ctx.setClientInformation(information);
        msgCtx.addSubcontext(ctx);
        attribute = new IdPAttribute("test");
        OIDCStringAttributeEncoder encoder = new OIDCStringAttributeEncoder();
        encoder.setName("test");
        encoders = new ArrayList<AttributeEncoder<?>>();
        encoders.add(encoder);
        attribute.setEncoders(encoders);
        matcher.setId("componentId");
    }

    private ClaimsRequest getClaimsRequest(boolean idtoken, boolean userinfo) {
        ClaimsRequest request = new ClaimsRequest();
        request.addIDTokenClaim("any");
        request.addUserInfoClaim("any");
        if (idtoken)
            request.addIDTokenClaim("test");
        if (userinfo)
            request.addUserInfoClaim("test");
        return request;
    }

    @Test
    public void testNoEncoders() throws Exception {
        setUp(false, false);
        matcher.initialize();
        attribute.setEncoders(null);
        Assert.assertNull(matcher.getMatchingValues(attribute, filtercontext));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testFailNoMsgCtx() throws Exception {
        setUp(false, false);
        matcher.initialize();
        prc.setInboundMessageContext(null);
        Assert.assertNull(matcher.getMatchingValues(attribute, filtercontext));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testFailNoMsg() throws Exception {
        setUp(false, false);
        matcher.initialize();
        prc.getInboundMessageContext().setMessage(null);
        Assert.assertNull(matcher.getMatchingValues(attribute, filtercontext));
    }

    @Test
    public void testNoClaims() throws Exception {
        setUp(false, false);
        matcher.initialize();
        Assert.assertNull(matcher.getMatchingValues(attribute, filtercontext));
    }

    @Test
    public void testNoClaimsSilent() throws Exception {
        setUp(false, false);
        matcher.setMatchIfRequestedClaimsSilent(true);
        matcher.initialize();
        Assert.assertNotNull(matcher.getMatchingValues(attribute, filtercontext));
    }

    @Test
    public void testAnyMatchIdToken() throws Exception {
        setUp(true, false);
        matcher.initialize();
        Assert.assertNotNull(matcher.getMatchingValues(attribute, filtercontext));
    }

    @Test
    public void testAnyMatchUserInfo() throws Exception {
        setUp(false, true);
        matcher.initialize();
        Assert.assertNotNull(matcher.getMatchingValues(attribute, filtercontext));
    }

    @Test
    public void testIdTokenMatchFail() throws Exception {
        setUp(false, true);
        matcher.setMatchOnlyIDToken(true);
        matcher.initialize();
        Assert.assertNull(matcher.getMatchingValues(attribute, filtercontext));
    }

    @Test
    public void testUserInfoMatchFail() throws Exception {
        setUp(true, false);
        matcher.setMatchOnlyUserInfo(true);
        matcher.initialize();
        Assert.assertNull(matcher.getMatchingValues(attribute, filtercontext));
    }

    @Test
    public void testIdTokenMatch() throws Exception {
        setUp(true, false);
        matcher.setMatchOnlyIDToken(true);
        matcher.initialize();
        Assert.assertNotNull(matcher.getMatchingValues(attribute, filtercontext));
    }

    @Test
    public void testUserInfoMatch() throws Exception {
        setUp(false, true);
        matcher.setMatchOnlyUserInfo(true);
        matcher.initialize();
        Assert.assertNotNull(matcher.getMatchingValues(attribute, filtercontext));
    }

}