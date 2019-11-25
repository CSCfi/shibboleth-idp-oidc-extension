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
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;

import junit.framework.Assert;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;

/** Tests for {@link TokenRequestRedirectURILookupFunction}. */
public class TokenRequestRedirectURILookupFunctionTest {

    private TokenRequestRedirectURILookupFunction lookup;

    @SuppressWarnings("rawtypes")
    protected ProfileRequestContext prc;
    
    @SuppressWarnings({"rawtypes", "unchecked"})
    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new TokenRequestRedirectURILookupFunction();
        final RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        prc.setInboundMessageContext(new MessageContext());
        //AuthorizationGrant grant = new AuthorizationGrant();
        Map<String,List<String>> params = new HashMap<String,List<String>>();
        params.put("grant_type", Arrays.asList("authorization_code"));
        params.put("code", Arrays.asList("xyz_code_abc"));
        params.put("redirect_uri", Arrays.asList("http://example.com/redirect"));
        TokenRequest req = new TokenRequest(new URI("http://example.com"), new ClientID("clientId"),AuthorizationCodeGrant.parse(params));
        prc.getInboundMessageContext().setMessage(req);
    }

    
    @Test
    public void testSuccess() throws URISyntaxException {
        Assert.assertEquals(new URI("http://example.com/redirect"), lookup.apply(prc));
    }
    
    @SuppressWarnings("unchecked")
    @Test
    public void testNoUri() throws URISyntaxException, ParseException {
        Map<String,List<String>> params = new HashMap<String,List<String>>();
        params.put("grant_type", Arrays.asList("authorization_code"));
        params.put("code", Arrays.asList("xyz_code_abc"));
        TokenRequest req = new TokenRequest(new URI("http://example.com"), new ClientID("clientId"),AuthorizationCodeGrant.parse(params));
        prc.getInboundMessageContext().setMessage(req);
        Assert.assertNull(lookup.apply(prc));
    }

}