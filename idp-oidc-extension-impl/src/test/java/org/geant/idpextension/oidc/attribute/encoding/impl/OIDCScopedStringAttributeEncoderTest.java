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
import net.shibboleth.idp.attribute.ScopedStringAttributeValue;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class OIDCScopedStringAttributeEncoderTest {

    private OIDCScopedStringAttributeEncoder encoder;

    @BeforeMethod
    protected void setUp() throws Exception {
        encoder = new OIDCScopedStringAttributeEncoder();
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
        List<ScopedStringAttributeValue> stringAttributeValues = new ArrayList<ScopedStringAttributeValue>();
        stringAttributeValues.add(new ScopedStringAttributeValue("value1", "scope"));
        stringAttributeValues.add(new ScopedStringAttributeValue("value2", "scope"));
        attribute.setValues(stringAttributeValues);
        JSONObject object = encoder.encode(attribute);
        Assert.assertTrue(((String) object.get("attributeName")).split(" ")[0].equals("value1@scope"));
        Assert.assertTrue(((String) object.get("attributeName")).split(" ")[1].equals("value2@scope"));
        Assert.assertTrue(((String) object.get("attributeName")).split(" ").length == 2);
        encoder.setScopeDelimiter(":");
        encoder.setStringDelimiter(";");
        object = encoder.encode(attribute);
        Assert.assertTrue(((String) object.get("attributeName")).split(";")[0].equals("value1:scope"));
        Assert.assertTrue(((String) object.get("attributeName")).split(";")[1].equals("value2:scope"));
        Assert.assertTrue(((String) object.get("attributeName")).split(";").length == 2);
    }
    
    @Test
    public void testEncoding2() throws ComponentInitializationException, AttributeEncodingException {
        init();
        IdPAttribute attribute = new IdPAttribute("test");
        List<ScopedStringAttributeValue> stringAttributeValues = new ArrayList<ScopedStringAttributeValue>();
        stringAttributeValues.add(new ScopedStringAttributeValue("value1", "scope"));
        stringAttributeValues.add(new ScopedStringAttributeValue("value2", "scope"));
        attribute.setValues(stringAttributeValues);
        encoder.setAsArray(true);
        JSONObject object = encoder.encode(attribute);
        JSONArray array = (JSONArray)object.get("attributeName");
        Assert.assertEquals(array.get(0),"value1@scope");
        Assert.assertEquals(array.get(1),"value2@scope");
        Assert.assertTrue(array.size() == 2);
        encoder.setScopeDelimiter(":");
        object = encoder.encode(attribute);
        array = (JSONArray)object.get("attributeName");
        Assert.assertEquals(array.get(0),"value1:scope");
        Assert.assertEquals(array.get(1),"value2:scope");
        Assert.assertTrue(array.size() == 2);
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