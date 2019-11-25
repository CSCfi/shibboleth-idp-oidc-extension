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

import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseContext;
import org.opensaml.messaging.context.MessageContext;
import org.testng.annotations.Test;
import junit.framework.Assert;

/** Tests for {@link UserInfoRequestClientIDLookupFunction}. */
public class UserInfoRequestClientIDLookupFunctionTest extends BaseTokenRequestLookupFunctionTest {

    private UserInfoRequestClientIDLookupFunction lookup;

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    public void testNullInput() {
        lookup = new UserInfoRequestClientIDLookupFunction();
        // No message ctx
        Assert.assertNull(lookup.apply(null));
        // No token claims set
        oidcCtx.setTokenClaimsSet(null);
        Assert.assertNull(lookup.apply(prc.getInboundMessageContext()));
        // No response context
        prc.getOutboundMessageContext().removeSubcontext(OIDCAuthenticationResponseContext.class);
        oidcCtx.setTokenClaimsSet(null);
        Assert.assertNull(lookup.apply(prc.getInboundMessageContext()));
        // No outbound message context
        prc.setInboundMessageContext(new MessageContext());
        prc.setOutboundMessageContext(null);
        Assert.assertNull(lookup.apply(prc.getInboundMessageContext()));
    }

    @Test
    public void testSuccess() {
        lookup = new UserInfoRequestClientIDLookupFunction();
        Assert.assertEquals(cliendID, lookup.apply(prc.getOutboundMessageContext()));
    }

}