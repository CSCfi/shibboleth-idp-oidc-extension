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

package org.geant.idpextension.oidc.profile.logic;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.profile.RequestContextBuilder;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.WebflowRequestContextProfileRequestContextLookup;
import net.shibboleth.idp.saml.attribute.encoding.impl.SAML2StringAttributeEncoder;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import org.geant.idpextension.oidc.attribute.encoding.impl.OIDCStringAttributeEncoder;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.webflow.execution.RequestContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;

/** {@link AttributeResolutionSubjectLookupFunction} unit test. */
public class AttributeResolutionSubjectLookupFunctionTest {

    private AttributeResolutionSubjectLookupFunction lookup;

    @SuppressWarnings("rawtypes")
    protected ProfileRequestContext prc;

    @BeforeMethod
    public void setup() throws ComponentInitializationException {
        lookup = new AttributeResolutionSubjectLookupFunction();
        RequestContext requestCtx = new RequestContextBuilder().buildRequestContext();
        prc = new WebflowRequestContextProfileRequestContextLookup().apply(requestCtx);

        // any attribute
        Collection<AttributeEncoder<?>> newEncoders = new ArrayList<AttributeEncoder<?>>();
        OIDCStringAttributeEncoder encoder = new OIDCStringAttributeEncoder();
        encoder.setName("test1");
        encoder.setPlaceToIDToken(true);
        newEncoders.add(encoder);
        IdPAttribute attribute1 = new IdPAttribute("test1");
        List<StringAttributeValue> stringAttributeValues1 = new ArrayList<StringAttributeValue>();
        stringAttributeValues1.add(new StringAttributeValue("value1"));
        stringAttributeValues1.add(new StringAttributeValue("value2"));
        attribute1.setValues(stringAttributeValues1);
        attribute1.setEncoders(newEncoders);

        // sub attribute
        Collection<AttributeEncoder<?>> newEncoders2 = new ArrayList<AttributeEncoder<?>>();
        OIDCStringAttributeEncoder encoder2 = new OIDCStringAttributeEncoder();
        encoder2.setName("sub");
        newEncoders2.add(encoder2);
        IdPAttribute attribute2 = new IdPAttribute("test2");
        List<StringAttributeValue> stringAttributeValues2 = new ArrayList<StringAttributeValue>();
        stringAttributeValues2.add(new StringAttributeValue("joe"));
        attribute2.setValues(stringAttributeValues2);
        attribute2.setEncoders(newEncoders2);

        // Set attribute context
        AttributeContext attributeCtx = new AttributeContext();
        Collection<IdPAttribute> attributes = new ArrayList<IdPAttribute>();
        attributes.add(attribute1);
        attributes.add(attribute2);
        attributeCtx.setIdPAttributes(attributes);
        prc.getSubcontext(RelyingPartyContext.class, true).addSubcontext(attributeCtx);
    }

    /**
     * Test that lookup is able to locate sub claim.
     */
    @Test
    public void testSuccess() throws ComponentInitializationException {
        Assert.assertEquals(lookup.apply(prc), "joe");
    }

    /**
     * Test that lookup copes with no attribute context.
     */
    @Test
    public void testNoAttributeCtx() throws ComponentInitializationException {
        prc.getSubcontext(RelyingPartyContext.class).removeSubcontext(AttributeContext.class);
        Assert.assertNull(lookup.apply(prc));
    }

    /**
     * Test that lookup copes with no attributes in attribute context.
     */
    @Test
    public void testNoAttributes() throws ComponentInitializationException {
        prc.getSubcontext(RelyingPartyContext.class, true).getSubcontext(AttributeContext.class).setIdPAttributes(null);
        Assert.assertNull(lookup.apply(prc));
    }

    /**
     * Test that lookup does not accept null strategy.
     */
    @Test(expectedExceptions = ConstraintViolationException.class)
    public void testFailNullStrategy() throws ComponentInitializationException {
        lookup = new AttributeResolutionSubjectLookupFunction();
        lookup.setAttributeContextLookupStrategy(null);
    }

    /**
     * Test that lookup is not picking subs with inactive or wrong type of encoders.
     */
    @SuppressWarnings("rawtypes")
    @Test
    public void testOnlyActive() throws ComponentInitializationException {
        prc.getSubcontext(RelyingPartyContext.class).removeSubcontext(AttributeContext.class);
        // sub attribute, not active encoder
        Collection<AttributeEncoder<?>> newEncoders1 = new ArrayList<AttributeEncoder<?>>();
        OIDCStringAttributeEncoder encoder1 = new OIDCStringAttributeEncoder();
        Predicate<ProfileRequestContext> predicate = Predicates.alwaysFalse();
        encoder1.setActivationCondition(predicate);
        encoder1.setName("sub");
        newEncoders1.add(encoder1);
        IdPAttribute attribute1 = new IdPAttribute("test1");
        List<StringAttributeValue> stringAttributeValues1 = new ArrayList<StringAttributeValue>();
        stringAttributeValues1.add(new StringAttributeValue("passiveJoe"));
        attribute1.setValues(stringAttributeValues1);
        attribute1.setEncoders(newEncoders1);

        // sub attribute, wrong type of encoder
        Collection<AttributeEncoder<?>> newEncoders2 = new ArrayList<AttributeEncoder<?>>();
        SAML2StringAttributeEncoder encoder2 = new SAML2StringAttributeEncoder();
        encoder2.setName("sub");
        newEncoders2.add(encoder2);
        IdPAttribute attribute2 = new IdPAttribute("test2");
        List<StringAttributeValue> stringAttributeValues2 = new ArrayList<StringAttributeValue>();
        stringAttributeValues2.add(new StringAttributeValue("saml2Joe"));
        attribute2.setValues(stringAttributeValues2);
        attribute2.setEncoders(newEncoders2);

        // Attribute with no encoders
        IdPAttribute attribute3 = new IdPAttribute("test2");
        List<StringAttributeValue> stringAttributeValues3 = new ArrayList<StringAttributeValue>();
        stringAttributeValues3.add(new StringAttributeValue("noencodersJoe"));

        // Set attribute context
        AttributeContext attributeCtx = new AttributeContext();
        Collection<IdPAttribute> attributes = new ArrayList<IdPAttribute>();
        attributes.add(attribute1);
        attributes.add(attribute2);
        attributes.add(attribute3);
        attributeCtx.setIdPAttributes(attributes);
        prc.getSubcontext(RelyingPartyContext.class).addSubcontext(attributeCtx);
        
        Assert.assertNull(lookup.apply(prc));
    }

}