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