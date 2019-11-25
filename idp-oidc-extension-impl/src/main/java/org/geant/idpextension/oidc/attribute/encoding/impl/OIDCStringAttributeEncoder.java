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

import net.minidev.json.JSONObject;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Class encoding string attributes to string json object. Name of the attribute will be set as the key. The string
 * contains attribute value. If there are several attribute values they are delimited with delimiter(space is default)
 * or placed to array. If the value is set to be interpreted as int, only values that may be parsed to int are used. In
 * case output is interpreted as int but not set to array, only the first parsable value is used. If the value is
 * interpreted as boolean the value is true if string value equals to "true" ignoring the case. If boolean values are
 * not set to array the first string value is considered to be the result. Finally, the result may be placed to json
 * Object.
 */
public class OIDCStringAttributeEncoder extends AbstractOIDCAttributeEncoder {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OIDCStringAttributeEncoder.class);

    @Override
    public JSONObject encode(IdPAttribute idpAttribute) throws AttributeEncodingException {
        Constraint.isNotNull(idpAttribute, "Attribute to encode cannot be null");
        log.debug("Encoding attribute {}", idpAttribute.getId());
        JSONObject obj = new JSONObject();
        obj.put(getName(), encodeValues(getValues(idpAttribute.getValues())));
        return obj;
    }

}
