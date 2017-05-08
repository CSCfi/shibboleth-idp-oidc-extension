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

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicate;

import net.minidev.json.JSONObject;
import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Class encoding string attributes to flat json object having name as key and
 * string containing attribute values separated by space.
 */
public class OIDCStringAttributeEncoder extends AbstractInitializableComponent implements AttributeEncoder<JSONObject> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OIDCStringAttributeEncoder.class);

    /** The name of the attribute. */
    @NonnullAfterInit
    private String name;

    /** Whether to encode with xsi:type or not. */
    /** TODO, apply value. Now only present as required by template. */
    private boolean encodeType;

    /** Condition for use of this encoder. */
    @SuppressWarnings("rawtypes")
    @Nonnull
    private Predicate<ProfileRequestContext> activationCondition;

    /** Constructor. */
    OIDCStringAttributeEncoder() {
        encodeType = true;
    }

    /**
     * Get whether to encode type information.
     * 
     * <p>
     * Defaults to 'true'
     * </p>
     * 
     * @return true if type information should be encoded
     */
    public boolean encodeType() {
        return encodeType;
    }

    /**
     * Set whether to encode type information.
     * 
     * @param flag
     *            flag to set
     */
    public void setEncodeType(final boolean flag) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        encodeType = flag;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("rawtypes")
    @Override
    @Nonnull
    public Predicate<ProfileRequestContext> getActivationCondition() {
        return activationCondition;
    }

    /**
     * Set the activation condition for this encoder.
     * 
     * @param condition
     *            condition to set
     */
    @SuppressWarnings("rawtypes")
    public void setActivationCondition(@Nonnull final Predicate<ProfileRequestContext> condition) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        activationCondition = Constraint.isNotNull(condition, "Activation condition cannot be null");
    }

    /**
     * Get the name of the attribute.
     * 
     * @return name of the attribute
     */
    @NonnullAfterInit
    public final String getName() {
        return name;
    }

    /**
     * Set the name of the attribute.
     * 
     * @param attributeName
     *            name of the attribute
     */
    public void setName(@Nonnull @NotEmpty final String attributeName) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        name = Constraint.isNotNull(StringSupport.trimOrNull(attributeName), "Attribute name cannot be null or empty");
    }

    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (name == null) {
            throw new ComponentInitializationException("Attribute name cannot be null or empty");
        }
    }

    @SuppressWarnings("rawtypes")
    @Override
    public JSONObject encode(IdPAttribute idpAttribute) throws AttributeEncodingException {
        String attributeString = "";
        JSONObject obj = new JSONObject();
        if (idpAttribute == null) {
            throw new AttributeEncodingException("Attribute is null");
        }
        for (IdPAttributeValue value : idpAttribute.getValues()) {
            if (value.getValue() instanceof String) {
                attributeString += " " + (String) value.getValue();
            }
        }
        obj.put(getName(), attributeString.trim());
        return obj;
    }

    @Override
    public String getProtocol() {
        // TODO: return something meaningful for protocol
        return "TBD";
    }

}
