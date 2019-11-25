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

import org.ldaptive.io.Base64;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.StringAttributeValue;

public class OIDCByteAttributeEncoderTest {

    private OIDCByteAttributeEncoder encoder;

    @BeforeMethod
    protected void setUp() throws Exception {
        encoder = new OIDCByteAttributeEncoder();
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
    public void testEncoding() throws ComponentInitializationException, AttributeEncodingException {
        init();
        IdPAttribute attribute = new IdPAttribute("test");
        List<ByteAttributeValue> byteAttributeValues = new ArrayList<ByteAttributeValue>();
        byte[] bytes = new byte[1];
        bytes[0] = 0;
        byteAttributeValues.add(new ByteAttributeValue(bytes));
        attribute.setValues(byteAttributeValues);
        JSONObject object = encoder.encode(attribute);
        String base64Coded = (String) object.get("attributeName");
        Assert.assertEquals(bytes, Base64.decode(base64Coded));
    }
    
    @Test
    public void testEncoding2() throws ComponentInitializationException, AttributeEncodingException {
        init();
        IdPAttribute attribute = new IdPAttribute("test");
        List<ByteAttributeValue> byteAttributeValues = new ArrayList<ByteAttributeValue>();
        byte[] bytes = new byte[2];
        bytes[0] = 0;
        bytes[1] = 1;
        byteAttributeValues.add(new ByteAttributeValue(bytes));
        attribute.setValues(byteAttributeValues);
        encoder.setAsInt(true);
        JSONObject object = encoder.encode(attribute);
        JSONArray array = (JSONArray)object.get("attributeName");
        JSONArray arrayInts = (JSONArray)array.get(0);
        Assert.assertEquals(arrayInts.get(0),0);
        Assert.assertEquals(arrayInts.get(1),1);
    }


    @Test
    public void testEncodingWrongType() throws ComponentInitializationException, AttributeEncodingException {
        init();
        IdPAttribute attribute = new IdPAttribute("test");
        List<StringAttributeValue> stringAttributeValues = new ArrayList<StringAttributeValue>();
        stringAttributeValues.add(new StringAttributeValue("value1"));
        attribute.setValues(stringAttributeValues);
        attribute.setValues(stringAttributeValues);
        JSONObject object = encoder.encode(attribute);
        Assert.assertNull(object.get("attributeName"));
    }
}