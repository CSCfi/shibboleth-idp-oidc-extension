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

import javax.annotation.Nonnull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.ByteAttributeValue;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Class encoding byte attributes to base64 encoded string json object. Name of the attribute will be set as the key.
 * The string contains base64 coded attribute value. If there are several attribute values they are delimited with
 * space. The output may be set also to array. The output may also be set to be int instead of b64. In that case each
 * value (byte[]) is converted to int array and placed into array.
 */
public class OIDCByteAttributeEncoder extends AbstractOIDCAttributeEncoder {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OIDCByteAttributeEncoder.class);

    // Checkstyle: CyclomaticComplexity OFF
    @SuppressWarnings("rawtypes")
    @Override
    public JSONObject encode(IdPAttribute idpAttribute) throws AttributeEncodingException {
        Constraint.isNotNull(idpAttribute, "Attribute to encode cannot be null");
        String attributeString = "";
        JSONObject obj = new JSONObject();
        JSONArray array = new JSONArray();
        for (IdPAttributeValue value : idpAttribute.getValues()) {
            if (value instanceof ByteAttributeValue && value.getValue() != null) {
                if (getAsInt()) {
                    // int
                    JSONArray innerArray = new JSONArray();
                    for (byte byteValue : ((ByteAttributeValue) value).getValue()) {
                        innerArray.add((int) byteValue);
                    }
                    // each byte array is converted to json int array and placed
                    // to json array.
                    array.add(innerArray);
                } else {
                    // b64
                    if (attributeString.length() > 0 && getStringDelimiter() != null) {
                        attributeString += getStringDelimiter();
                    }
                    attributeString +=
                            Base64Support.encode(((ByteAttributeValue) value).getValue(), Base64Support.UNCHUNKED);
                    if (getAsArray()) {
                        array.add(attributeString.toString());
                        attributeString = "";
                    }
                }
            }
        }
        if (getAsArray() || getAsInt()) {
            obj.put(getName(), array.size() == 0 ? null : array);
        } else {
            obj.put(getName(), attributeString.toString().isEmpty() ? null : attributeString.toString());
        }
        return obj;
    }
    // Checkstyle: CyclomaticComplexity ON

}
