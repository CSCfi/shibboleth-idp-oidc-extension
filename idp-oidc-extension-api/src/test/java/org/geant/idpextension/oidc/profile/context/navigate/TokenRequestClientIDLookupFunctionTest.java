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

import org.opensaml.messaging.context.MessageContext;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import junit.framework.Assert;

/** Tests for {@link TokenRequestClientIDLookupFunction}. */
public class TokenRequestClientIDLookupFunctionTest {

    private TokenRequestClientIDLookupFunction lookup;

    @SuppressWarnings("rawtypes")
    private MessageContext ctx;

    @SuppressWarnings({"rawtypes", "unchecked"})
    @BeforeMethod
    protected void setUp() throws Exception {
        lookup = new TokenRequestClientIDLookupFunction();
        ctx = new MessageContext();
        TokenRequest req = new TokenRequest(new URI("http://example.com"), new ClientID("clientId"),
                new RefreshTokenGrant(new RefreshToken()));
        ctx.setMessage(req);
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testNullInput() {
        // No message ctx
        Assert.assertNull(lookup.apply(null));
        // Wrong type of message
        ctx.setMessage(new String("totallynotmessage"));
        Assert.assertNull(lookup.apply(null));
        // No message
        ctx.setMessage(null);
        Assert.assertNull(lookup.apply(null));
    }

    @Test
    public void testSuccess() {
        Assert.assertEquals(new ClientID("clientId"), lookup.apply(ctx));
    }

}