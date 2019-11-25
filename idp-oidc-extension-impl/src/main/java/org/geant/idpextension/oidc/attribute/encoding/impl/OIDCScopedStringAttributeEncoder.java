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
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.minidev.json.JSONObject;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.ScopedStringAttributeValue;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Class encoding scoped string attributes to string json object. Name of the attribute will be set as the key. The
 * string contains attribute value, delimiter and scope catenated. If there are several attribute values they are
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
     * @param newScopeDelimiter delimiter to set
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
        JSONObject obj = new JSONObject();
        List<String> values = new ArrayList<String>();
        for (IdPAttributeValue value : idpAttribute.getValues()) {
            if (value instanceof ScopedStringAttributeValue && value.getValue() != null) {
                values.add(value.getValue() + scopeDelimiter + ((ScopedStringAttributeValue) value).getScope());
            }
        }
        obj.put(getName(), values.isEmpty() ? null : encodeValues(values));
        return obj;
    }

}
