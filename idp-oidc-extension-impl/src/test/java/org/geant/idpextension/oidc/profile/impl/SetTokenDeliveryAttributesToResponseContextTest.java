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