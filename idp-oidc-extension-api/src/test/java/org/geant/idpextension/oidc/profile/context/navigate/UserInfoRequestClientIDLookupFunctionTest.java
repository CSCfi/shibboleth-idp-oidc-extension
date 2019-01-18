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