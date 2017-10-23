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
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.ScopedStringAttributeValue;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Class encoding scoped string attributes to string json object. Name of the
 * attribute will be set as the key. The string contains attribute value,
 * delimiter and scope catenated. If there are several attribute values they are
 * delimited with delimiter(space is default) or placed to array.
 */
public class OIDCScopedStringAttributeEncoder extends AbstractOIDCAttributeEncoder {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OIDCScopedStringAttributeEncoder.class);

    /** Delimiter used for scopeType. */
    @Nullable
    private String scopeDelimiter;

    /**
     * Constructor.
     *
     */
    public OIDCScopedStringAttributeEncoder() {
        scopeDelimiter = "@";
    }

    /**
     * Set the scope delimiter.
     * 
     * @param newScopeDelimiter
     *            delimiter to set
     */
    public void setScopeDelimiter(@Nullable final String newScopeDelimiter) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        scopeDelimiter = StringSupport.trimOrNull(newScopeDelimiter);
    }

    @SuppressWarnings("rawtypes")
    @Override
    public JSONObject encode(IdPAttribute idpAttribute) throws AttributeEncodingException {
        Constraint.isNotNull(idpAttribute, "Attribute to encode cannot be null");
        Constraint.isNotNull(scopeDelimiter, "Scope delimiter cannot be null");
        StringBuilder attributeString = new StringBuilder();
        JSONObject obj = new JSONObject();
        JSONArray array = new JSONArray();
        for (IdPAttributeValue value : idpAttribute.getValues()) {
            if (value instanceof ScopedStringAttributeValue && value.getValue() != null) {
                if (attributeString.length() > 0) {
                    attributeString.append(getStringDelimiter());
                }
                attributeString.append(value.getValue()).append(scopeDelimiter)
                        .append(((ScopedStringAttributeValue) value).getScope());
                if (getAsArray()) {
                    array.add(attributeString.toString());
                    attributeString.setLength(0);
                }
            }
        }
        if (getAsArray()) {
            obj.put(getName(), array.size() == 0 ? null : array);
        } else {
            obj.put(getName(), attributeString.toString().isEmpty() ? null : attributeString.toString());
        }
        return obj;
    }

}
