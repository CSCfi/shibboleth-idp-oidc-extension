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
import java.util.Date;
import java.util.List;

import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.geant.idpextension.oidc.attribute.encoding.impl.OIDCStringAttributeEncoder;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;

/** {@link InitializeAuthenticationContext} unit test. */
public class AddAttributesToClaimsSetTest extends BaseOIDCResponseActionTest {

    private AddAttributesToClaimsSet action;

    private void init() throws ComponentInitializationException {
        action = new AddAttributesToClaimsSet();
        action.initialize();
    }

    @SuppressWarnings({ "rawtypes" })
    private void setAttributeContext() {
        // build 2 attributes

        Collection<AttributeEncoder<?>> newEncoders = new ArrayList<AttributeEncoder<?>>();
        OIDCStringAttributeEncoder encoder = new OIDCStringAttributeEncoder();
        encoder.setName("test1");
        newEncoders.add(encoder);
        IdPAttribute attribute1 = new IdPAttribute("test1");
        List<StringAttributeValue> stringAttributeValues1 = new ArrayList<StringAttributeValue>();
        stringAttributeValues1.add(new StringAttributeValue("value1"));
        stringAttributeValues1.add(new StringAttributeValue("value2"));
        attribute1.setValues(stringAttributeValues1);
        attribute1.setEncoders(newEncoders);

        Collection<AttributeEncoder<?>> newEncoders2 = new ArrayList<AttributeEncoder<?>>();
        OIDCStringAttributeEncoder encoder2 = new OIDCStringAttributeEncoder();
        encoder2.setName("test2");
        newEncoders2.add(encoder2);
        IdPAttribute attribute2 = new IdPAttribute("test2");
        List<StringAttributeValue> stringAttributeValues2 = new ArrayList<StringAttributeValue>();
        stringAttributeValues2.add(new StringAttributeValue("value"));
        attribute2.setValues(stringAttributeValues2);
        attribute2.setEncoders(newEncoders2);
        
        IdPAttribute attribute3 = new IdPAttribute("test3");
        List<StringAttributeValue> stringAttributeValues3 = new ArrayList<StringAttributeValue>();
        stringAttributeValues3.add(new StringAttributeValue("value3"));
        attribute3.setValues(stringAttributeValues3);
        
        final ProfileRequestContext prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);
        AttributeContext attributeCtx = new AttributeContext();
        Collection<IdPAttribute> attributes = new ArrayList<IdPAttribute>();
        attributes.add(attribute1);
        attributes.add(attribute2);
        attributes.add(attribute3);
        attributeCtx.setIdPAttributes(attributes);
        prc.getSubcontext(RelyingPartyContext.class).addSubcontext(attributeCtx);

    }

    /**
     * Test that action copes with no attribute context. Action should just move
     * forward without action taken.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoAttributeCtx() throws ComponentInitializationException {
        init();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);

    }

    /**
     * Test that action copes with no id token in response context.
     * 
     * @throws ComponentInitializationException
     * @throws ParseException
     */
    @Test
    public void testNoIdToken() throws ComponentInitializationException, ParseException {
        init();
        setAttributeContext();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_MSG_CTX);
    }

    /**
     * Test that action copes with no id token in response context.
     * 
     * @throws ComponentInitializationException
     * @throws ParseException
     */
    @Test
    public void testSuccess() throws ComponentInitializationException, ParseException {
        init();
        setIdTokenToResponseContext("iss", "sub", "aud", new Date(), new Date());
        setAttributeContext();
        final Event event = action.execute(requestCtx);
        ActionTestingSupport.assertProceedEvent(event);
        Assert.assertTrue(respCtx.getIDToken().getClaim("test1").equals("value1 value2"));
        Assert.assertTrue(respCtx.getIDToken().getClaim("test2").equals("value"));
        Assert.assertNull(respCtx.getIDToken().getClaim("test3"));
    }

}