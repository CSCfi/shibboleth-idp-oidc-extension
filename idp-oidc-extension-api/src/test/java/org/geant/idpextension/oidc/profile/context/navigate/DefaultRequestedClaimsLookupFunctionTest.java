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

package org.geant.idpextension.oidc.profile.context.navigate;

import java.net.URI;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import junit.framework.Assert;

public class DefaultRequestedClaimsLookupFunctionTest extends BaseDefaultRequestLookupFunctionTest {

    private DefaultRequestedClaimsLookupFunction lookup;

    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new DefaultRequestedClaimsLookupFunction();
    }

    @Test
    public void testSuccessNoReqObject() {
        ClaimsRequest cr = new ClaimsRequest();
        cr.addIDTokenClaim(IDTokenClaimsSet.SUB_CLAIM_NAME, ClaimRequirement.ESSENTIAL);
        cr.addUserInfoClaim(UserInfo.BIRTHDATE_CLAIM_NAME, ClaimRequirement.ESSENTIAL);
        AuthenticationRequest req =
                new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), new ClientID("000123"),
                        URI.create("https://example.com/callback")).claims(cr).state(new State()).build();
        msgCtx.setMessage(req);
        Assert.assertEquals(cr.toJSONObject(), lookup.apply(prc).toJSONObject());
    }

    @Test
    public void testSuccessReqObject() {
        ClaimsRequest crParameter = new ClaimsRequest();
        crParameter.addIDTokenClaim(IDTokenClaimsSet.SUB_CLAIM_NAME, ClaimRequirement.ESSENTIAL);
        ClaimsRequest crRequestObject = new ClaimsRequest();
        crRequestObject.addIDTokenClaim(IDTokenClaimsSet.SUB_CLAIM_NAME, ClaimRequirement.ESSENTIAL);
        crRequestObject.addUserInfoClaim(UserInfo.BIRTHDATE_CLAIM_NAME, ClaimRequirement.ESSENTIAL);
        JWTClaimsSet ro = new JWTClaimsSet.Builder().claim("claims", crRequestObject.toJSONObject()).build();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).claims(crParameter)
                        .requestObject(new PlainJWT(ro)).state(new State()).build();
        msgCtx.setMessage(req);
        oidcCtx.setRequestObject(req.getRequestObject());
        Assert.assertEquals(crRequestObject.toJSONObject(), lookup.apply(prc).toJSONObject());
    }
}