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