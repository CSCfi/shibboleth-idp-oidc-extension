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

package org.geant.idpextension.oidc.attribute.encoding.impl;

import java.util.ArrayList;
import java.util.List;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.ByteAttributeValue;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.StringAttributeValue;

public class OIDCStringAttributeEncoderTest {

    private OIDCStringAttributeEncoder encoder;

    @BeforeMethod
    protected void setUp() throws Exception {
        encoder = new OIDCStringAttributeEncoder();
    }

    private void init() throws ComponentInitializationException {
        encoder.setName("attributeName");
        encoder.doInitialize();
    }

    @Test
    public void testInitialize() throws ComponentInitializationException {
        boolean exceptionOccurred = false;
        try {
            encoder.doInitialize();
        } catch (ComponentInitializationException e) {
            exceptionOccurred = true;
        }
        Assert.assertTrue(exceptionOccurred);
        init();
        Assert.assertEquals(encoder.getName(), "attributeName");
    }

    @Test
    public void testEncodingNull() throws ComponentInitializationException, AttributeEncodingException {
        init();
        boolean exceptionOccurred = false;
        try {
            encoder.encode(null);
        } catch (ConstraintViolationException e) {
            exceptionOccurred = true;
        }
        Assert.assertTrue(exceptionOccurred);
    }

    @Test
    public void testEncodingString() throws ComponentInitializationException, AttributeEncodingException {
        init();
        IdPAttribute attribute = new IdPAttribute("test");
        List<StringAttributeValue> stringAttributeValues = new ArrayList<StringAttributeValue>();
        stringAttributeValues.add(new StringAttributeValue("value1"));
        stringAttributeValues.add(new StringAttributeValue("value2"));
        attribute.setValues(stringAttributeValues);
        encoder.setStringDelimiter(";");
        JSONObject object = encoder.encode(attribute);
        Assert.assertTrue(((String) object.get("attributeName")).split(";")[0].equals("value1"));
        Assert.assertTrue(((String) object.get("attributeName")).split(";")[1].equals("value2"));
        Assert.assertTrue(((String) object.get("attributeName")).split(";").length == 2);
        
    }

    @Test
    public void testEncodingStringArray() throws ComponentInitializationException, AttributeEncodingException {
        init();
        IdPAttribute attribute = new IdPAttribute("test");
        List<StringAttributeValue> stringAttributeValues = new ArrayList<StringAttributeValue>();
        stringAttributeValues.add(new StringAttributeValue("value1"));
        stringAttributeValues.add(new StringAttributeValue("value2"));
        attribute.setValues(stringAttributeValues);
        encoder.setAsArray(true);
        JSONObject object = encoder.encode(attribute);
        JSONArray array = (JSONArray)object.get("attributeName");
        Assert.assertEquals("value1",array.get(0));
        Assert.assertEquals("value2",array.get(1));
        Assert.assertTrue(array.size() == 2);
    }
    
    @Test
    public void testEncodingInteger() throws ComponentInitializationException, AttributeEncodingException {
        init();
        IdPAttribute attribute = new IdPAttribute("test");
        List<StringAttributeValue> stringAttributeValues = new ArrayList<StringAttributeValue>();
        stringAttributeValues.add(new StringAttributeValue("value1"));
        stringAttributeValues.add(new StringAttributeValue("2"));
        attribute.setValues(stringAttributeValues);
        encoder.setAsInt(true);
        JSONObject object = encoder.encode(attribute);
        Assert.assertEquals(2,object.get("attributeName"));
    }
    
    @Test
    public void testEncodingBoolean() throws ComponentInitializationException, AttributeEncodingException {
        init();
        IdPAttribute attribute = new IdPAttribute("test");
        List<StringAttributeValue> stringAttributeValues = new ArrayList<StringAttributeValue>();
        stringAttributeValues.add(new StringAttributeValue("true"));
        stringAttributeValues.add(new StringAttributeValue("2"));
        attribute.setValues(stringAttributeValues);
        encoder.setAsBoolean(true);
        JSONObject object = encoder.encode(attribute);
        Assert.assertTrue((boolean)object.get("attributeName"));
    }
    
    @Test
    public void testEncodingJSONObject() throws ComponentInitializationException, AttributeEncodingException {
        init();
        IdPAttribute attribute = new IdPAttribute("test");
        List<StringAttributeValue> stringAttributeValues = new ArrayList<StringAttributeValue>();
        stringAttributeValues.add(new StringAttributeValue("true"));
        stringAttributeValues.add(new StringAttributeValue("2"));
        attribute.setValues(stringAttributeValues);
        encoder.setAsBoolean(true);
        encoder.setAsObject(true);
        encoder.setFieldName("verified");
        JSONObject object = encoder.encode(attribute);
        Assert.assertTrue((boolean)((JSONObject)object.get("attributeName")).get("verified"));
    }

    @Test
    public void testEncodingWrongType() throws ComponentInitializationException, AttributeEncodingException {
        init();
        IdPAttribute attribute = new IdPAttribute("test");
        List<ByteAttributeValue> byteAttributeValues = new ArrayList<ByteAttributeValue>();
        byte[] bytes = new byte[1];
        bytes[0] = 0;
        byteAttributeValues.add(new ByteAttributeValue(bytes));
        attribute.setValues(byteAttributeValues);
        JSONObject object = encoder.encode(attribute);
        Assert.assertNull(object.get("attributeName"));
    }
}