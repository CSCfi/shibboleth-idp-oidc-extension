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
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * Class encoding string attributes to string json object. Name of the attribute
 * will be set as the key. The string contains attribute value. If there are
 * several attribute values they are delimited with delimiter(space is default)
 * or placed to array. If the value is set to be interpreted as int, only values
 * that may be parsed to int are used. In case output is interpreted as int but
 * not set to array, only the first parsable value is used. If the value is
 * interpreted as boolean the value is true if string value equals to "true"
 * ignoring the case. If boolean values are not set to array the first string
 * value is considered to be the result. Finally, the result may be placed to
 * json Object.
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
