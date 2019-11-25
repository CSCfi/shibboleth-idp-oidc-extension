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

public class DefaultRequestMaxAgeFunctionTest extends BaseDefaultRequestLookupFunctionTest {

    private  DefaultRequestMaxAgeLookupFunction lookup;
    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new  DefaultRequestMaxAgeLookupFunction();
    }

    @Test
    public void testSuccessNoMaxAge() {
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback"))
                        .state(new State()).build();
        msgCtx.setMessage(req);
        Assert.assertNull(lookup.apply(prc));
    }
    
    @Test
    public void testSuccessMaxAgeRequestParameter() {
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).maxAge(300)
                        .state(new State()).build();
        msgCtx.setMessage(req);
        Assert.assertEquals(new Long(300),(Long)lookup.apply(prc));
    }
    
    @Test
    public void testSuccessMaxAgeRequestObject() {
        JWTClaimsSet ro = new JWTClaimsSet.Builder().claim("max_age", 600).build();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).maxAge(300).requestObject(new PlainJWT(ro))
                        .state(new State()).build();
        msgCtx.setMessage(req);
        oidcCtx.setRequestObject(req.getRequestObject());
        Assert.assertEquals(new Long(600),(Long)lookup.apply(prc));
    }

}