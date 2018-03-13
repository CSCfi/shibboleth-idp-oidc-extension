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
