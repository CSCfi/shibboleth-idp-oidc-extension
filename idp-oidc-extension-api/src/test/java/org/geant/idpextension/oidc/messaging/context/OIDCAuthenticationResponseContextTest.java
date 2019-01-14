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

package org.geant.idpextension.oidc.messaging.context;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import junit.framework.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

/** Tests for {@link OIDCAuthenticationResponseContext}.*/
public class OIDCAuthenticationResponseContextTest {

    private OIDCAuthenticationResponseContext ctx;

    @BeforeMethod
    protected void setUp() throws Exception {
        ctx = new OIDCAuthenticationResponseContext();
    }

    @Test
    public void testInitialState() {
        Assert.assertNull(ctx.getRequestedSubject());
        Assert.assertNull(ctx.getAcr());
        Assert.assertNull(ctx.getAuthTime());
        Assert.assertNull(ctx.getIDToken());
        Assert.assertNull(ctx.getSubject());
        Assert.assertNull(ctx.getRedirectURI());
        Assert.assertNull(ctx.getScope());
        Assert.assertNull(ctx.getProcessedToken());
        Assert.assertNull(ctx.getRequestedClaims());
        Assert.assertNull(ctx.getTokenClaimsSet());
        Assert.assertNull(ctx.getAuthorizationCode());
        Assert.assertNull(ctx.getAccessToken());
        Assert.assertNull(ctx.getRefreshToken());
        Assert.assertNull(ctx.getSubjectType());
        Assert.assertNull(ctx.getUserInfo());
    }

    @Test
    public void testSetters() throws URISyntaxException, ParseException {
        ctx.setAcr("acrValue");
        ctx.setAuthTime(1);
        Issuer issuer = new Issuer("iss");
        Subject sub = new Subject("sub");
        List<Audience> aud = new ArrayList<Audience>();
        aud.add(new Audience("aud"));
        IDTokenClaimsSet token = new IDTokenClaimsSet(issuer, sub, aud, new Date(), new Date());
        ctx.setIDToken(token);
        ctx.setSubject("sub");
        URI uri = new URI("https://example.org");
        ctx.setRedirectURI(uri);
        ctx.setRequestedSubject("sub");
        Scope scope = new Scope();
        ctx.setScope(scope);
        JWSHeader header = new JWSHeader(JWSAlgorithm.ES256);
        SignedJWT sJWT = new SignedJWT(header, token.toJWTClaimsSet());
        ctx.setProcessedToken(sJWT);
        Assert.assertEquals(ctx.getAcr().toString(), "acrValue");
        ctx.setAcr(null);
        ClaimsRequest claims = new ClaimsRequest();
        ctx.setRequestedClaims(claims);
        ctx.setSubjectType("pairwise");
        UserInfo info = new UserInfo(sub);
        ctx.setUserInfo(info);
        Assert.assertNull(ctx.getAcr());
        Assert.assertEquals(ctx.getAuthTime(), new Date(1));
        Assert.assertEquals(ctx.getIDToken(), token);
        Assert.assertEquals(ctx.getSubject(), "sub");
        Assert.assertEquals(ctx.getProcessedToken(), sJWT);
        Assert.assertEquals(ctx.getRedirectURI(), uri);
        Assert.assertEquals(ctx.getRequestedSubject(), "sub");
        Assert.assertEquals(ctx.getScope(), scope);
        Assert.assertEquals(claims, ctx.getRequestedClaims());
        Assert.assertEquals("pairwise", ctx.getSubjectType());
        Assert.assertEquals(info, ctx.getUserInfo());
    }
}