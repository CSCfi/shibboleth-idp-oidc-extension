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
import net.minidev.json.JSONObject;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Class encoding string attributes to string json object. Name of the attribute
 * will be set as the key. The string contains attribute value. If there are
 * several attribute values they are delimited with space. If no encodable
 * values are found returns null value.
 */
public class OIDCStringAttributeEncoder extends AbstractOIDCAttributeEncoder {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OIDCStringAttributeEncoder.class);

    @SuppressWarnings("rawtypes")
    @Override
    public JSONObject encode(IdPAttribute idpAttribute) throws AttributeEncodingException {
        Constraint.isNotNull(idpAttribute, "Attribute to encode cannot be null");
        String attributeString = "";
        JSONObject obj = new JSONObject();
        for (IdPAttributeValue value : idpAttribute.getValues()) {
            if (value instanceof StringAttributeValue && value.getValue() != null) {
                if (attributeString.length() > 0) {
                    attributeString += " ";
                }
                attributeString += value.getValue();
            }
        }
        obj.put(getName(), attributeString.toString().isEmpty() ? null : attributeString.toString());
        return obj;
    }

}
