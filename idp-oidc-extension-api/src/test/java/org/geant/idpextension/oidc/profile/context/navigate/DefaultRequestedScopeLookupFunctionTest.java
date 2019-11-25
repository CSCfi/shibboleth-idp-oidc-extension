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

import junit.framework.Assert;

public class DefaultRequestedScopeLookupFunctionTest extends BaseDefaultRequestLookupFunctionTest {

    private DefaultRequestedScopeLookupFunction lookup;

    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new DefaultRequestedScopeLookupFunction();
    }

    @Test
    public void testSuccessNoReqObject() {
        Scope parameterScope = new Scope("openid", "email");
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), parameterScope,
                new ClientID("000123"), URI.create("https://example.com/callback")).state(new State()).build();
        msgCtx.setMessage(req);
        Assert.assertTrue(lookup.apply(prc).contains("openid"));
        Assert.assertTrue(lookup.apply(prc).contains("email"));
        Assert.assertEquals(2, lookup.apply(prc).size());
    }

    @Test
    public void testSuccessReqObject() {
        Scope parameterScope = new Scope("openid");
        JWTClaimsSet ro = new JWTClaimsSet.Builder().claim("scope", "openid email").build();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), parameterScope,
                new ClientID("000123"), URI.create("https://example.com/callback")).state(new State())
                        .requestObject(new PlainJWT(ro)).build();
        msgCtx.setMessage(req);
        oidcCtx.setRequestObject(req.getRequestObject());
        Assert.assertTrue(lookup.apply(prc).contains("openid"));
        Assert.assertTrue(lookup.apply(prc).contains("email"));
        Assert.assertEquals(2, lookup.apply(prc).size());
    }

}