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

public class DefaultRequestStateLookupFunctionTest extends BaseDefaultRequestLookupFunctionTest {

    private DefaultRequestStateLookupFunction lookup;

     @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new DefaultRequestStateLookupFunction();
    }

    @Test
    public void testSuccessNoReqObject() {
        String stateReqParam = "requestparameterstate";
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).loginHint("hint")
                        .state(new State(stateReqParam)).build();
        msgCtx.setMessage(req);
        Assert.assertEquals(stateReqParam, lookup.apply(prc).getValue());
    }

    @Test
    public void testSuccessReqObject() {
        String stateReqParam = "requestparameterstate";
        String stateReqObj = "requestobjectstate";
        JWTClaimsSet ro = new JWTClaimsSet.Builder().claim("state", stateReqObj).build();
        AuthenticationRequest req = new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"),
                new ClientID("000123"), URI.create("https://example.com/callback")).loginHint("hint")
                        .state(new State(stateReqParam)).requestObject(new PlainJWT(ro)).build();
        msgCtx.setMessage(req);
        oidcCtx.setRequestObject(req.getRequestObject());
        Assert.assertEquals(stateReqObj, lookup.apply(prc).getValue());
    }

}