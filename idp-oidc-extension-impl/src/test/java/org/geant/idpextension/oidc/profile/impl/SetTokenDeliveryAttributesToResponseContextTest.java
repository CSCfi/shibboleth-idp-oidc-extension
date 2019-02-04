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

package org.geant.idpextension.oidc.profile.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.geant.idpextension.oidc.attribute.encoding.impl.OIDCStringAttributeEncoder;
import org.geant.idpextension.oidc.messaging.context.OIDCAuthenticationResponseTokenClaimsContext;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;

/** {@link SetTokenDeliveryAttributesToResponseContext} unit test. */
public class SetTokenDeliveryAttributesToResponseContextTest extends BaseOIDCResponseActionTest {

    private SetTokenDeliveryAttributesToResponseContext action;

    private void init() throws ComponentInitializationException {
        action = new SetTokenDeliveryAttributesToResponseContext();
        action.initialize();
    }

    private void setAttributeContext() {

        // Attribute to be carried in tokens
        Collection<AttributeEncoder<?>> newEncoders = new ArrayList<AttributeEncoder<?>>();
        OIDCStringAttributeEncoder encoder = new OIDCStringAttributeEncoder();
        encoder.setName("test1");
        encoder.setSetToToken(true);
        newEncoders.add(encoder);
        IdPAttribute attribute1 = new IdPAttribute("test1");
        List<StringAttributeValue> stringAttributeValues1 = new ArrayList<StringAttributeValue>();
        stringAttributeValues1.add(new StringAttributeValue("value1"));
        stringAttributeValues1.add(new StringAttributeValue("value2"));
        attribute1.setValues(stringAttributeValues1);
        attribute1.setEncoders(newEncoders);

        // Attribute not to be carried in tokens but only for id token
        Collection<AttributeEncoder<?>> newEncoders2 = new ArrayList<AttributeEncoder<?>>();
        OIDCStringAttributeEncoder encoder2 = new OIDCStringAttributeEncoder();
        encoder2.setName("test2");
        encoder2.setSetToToken(true);
        encoder2.setDenyUserinfo(true);
        encoder2.setPlaceToIDToken(true);
        newEncoders2.add(encoder2);
        IdPAttribute attribute2 = new IdPAttribute("test2");
        List<StringAttributeValue> stringAttributeValues2 = new ArrayList<StringAttributeValue>();
        stringAttributeValues2.add(new StringAttributeValue("value"));
        attribute2.setValues(stringAttributeValues2);
        attribute2.setEncoders(newEncoders2);

        // Attribute having no encoder
        IdPAttribute attribute3 = new IdPAttribute("test3");
        List<StringAttributeValue> stringAttributeValues3 = new ArrayList<StringAttributeValue>();
        stringAttributeValues3.add(new StringAttributeValue("value3"));
        attribute3.setValues(stringAttributeValues3);
        
        // Attribute to be carried in tokens, also for id token
        Collection<AttributeEncoder<?>> newEncoders4 = new ArrayList<AttributeEncoder<?>>();
        OIDCStringAttributeEncoder encoder4 = new OIDCStringAttributeEncoder();
        encoder4.setName("test4");
        encoder4.setSetToToken(true);
        encoder4.setPlaceToIDToken(true);
        newEncoders4.add(encoder4);
        IdPAttribute attribute4 = new IdPAttribute("test4");
        List<StringAttributeValue> stringAttributeValues4 = new ArrayList<StringAttributeValue>();
        stringAttributeValues4.add(new StringAttributeValue("value4"));
        attribute4.setValues(stringAttributeValues4);
        attribute4.setEncoders(newEncoders4);

        AttributeContext attributeCtx = new AttributeContext();
        Collection<IdPAttribute> attributes = new ArrayList<IdPAttribute>();
        attributes.add(attribute1);
        attributes.add(attribute2);
        attributes.add(attribute3);
        attributes.add(attribute4);
        attributeCtx.setIdPAttributes(attributes);
        profileRequestCtx.getSubcontext(RelyingPartyContext.class).addSubcontext(attributeCtx);

    }

    /**
     * Test that action copes with no attribute context. Action should just move forward without action taken.
     */
    @Test
    public void testNoAttributeCtx() throws ComponentInitializationException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertNull(respCtx.getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class));
    }

    /**
     * Test that action create the context.
     */
    @Test
    public void testSuccess() throws ComponentInitializationException, ParseException {
        init();
        setAttributeContext();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        OIDCAuthenticationResponseTokenClaimsContext respTokenClaims =
                respCtx.getSubcontext(OIDCAuthenticationResponseTokenClaimsContext.class);
        Assert.assertNotNull(respTokenClaims);
        Assert.assertEquals(respTokenClaims.getUserinfoClaims().getClaim("test1"), "value1 value2");
        Assert.assertEquals(respTokenClaims.getIdtokenClaims().getClaim("test2"), "value");
        Assert.assertEquals(respTokenClaims.getClaims().getClaim("test4"), "value4");
    }
}