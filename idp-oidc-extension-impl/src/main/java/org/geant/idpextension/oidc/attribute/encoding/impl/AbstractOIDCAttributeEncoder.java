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

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicate;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.AttributeEncodingException;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.AbstractInitializableComponent;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * abstract class for OIDC attribute encoders.
 */
public abstract class AbstractOIDCAttributeEncoder extends AbstractInitializableComponent
        implements AttributeEncoder<JSONObject> {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractOIDCAttributeEncoder.class);

    /** The name of the attribute. */
    @NonnullAfterInit
    private String name;

    /** Whether to set value to array. */
    private boolean asArray;

    /** Whether to interpret value as integer. */
    private boolean asInt;

    /** Delimiter used for when catenating string values. */
    @Nullable
    private String stringDelimiter;

    /**
     * Whether the attribute should encoded to authorization code / access token.
     */
    @Nullable
    private boolean setToToken;

    /** Whether to wrap the value to JSON Object. */
    private boolean asObject;

    /** Name of the key field if the value is wrapped into JSON Object. */
    private String fieldName;

    /** Whether to to interpret value as boolean. */
    private boolean asBoolean;

    /** Condition for use of this encoder. */
    @SuppressWarnings("rawtypes")
    @Nonnull
    private Predicate<ProfileRequestContext> activationCondition;

    /** Default constructor. */
    public AbstractOIDCAttributeEncoder() {
        stringDelimiter = " ";
    }

    /**
     * Gets whether to wrap the value to JSON Object.
     * 
     * @return whether to wrap the value to JSON Object
     */
    public boolean getAsObject() {
        return asObject;
    }

    /**
     * Sets whether to wrap the value to JSON Object.
     * 
     * @param flag whether to wrap the value to JSON Object
     */
    public void setAsObject(boolean flag) {
        asObject = flag;
    }

    /**
     * Gets name of the key field if the value is wrapped into JSON Object.
     * 
     * @return name of the key field if the value is wrapped into JSON Object
     */
    public String getFieldName() {
        return fieldName;
    }

    /**
     * Sets name of the key field if the value is wrapped into JSON Object.
     * 
     * @param field of the key field if the value is wrapped into JSON Object
     */
    public void setFieldName(String field) {
        fieldName = field;
    }

    /**
     * Gets Whether to to interpret value as boolean.
     * 
     * @return whether to to interpret value as boolean
     */
    public boolean getAsBoolean() {
        return asBoolean;
    }

    /**
     * Sets whether to to interpret value as boolean.
     * 
     * @param flag whether to to interpret value as boolean
     */
    public void setAsBoolean(boolean flag) {
        asBoolean = flag;
    }

    /**
     * Gets whether to set value to array.
     * 
     * @return whether to set value to array
     */
    public boolean getAsArray() {
        return asArray;
    }

    /**
     * Sets whether to set value to array.
     * 
     * @param flag whether to set value to array
     */
    public void setAsArray(boolean flag) {
        asArray = flag;
    }

    /**
     * Gets whether to interpret value as integer.
     * 
     * @return whether to interpret value as integer
     */
    public boolean getAsInt() {
        return asInt;
    }

    /**
     * Sets whether the attribute should encoded to authorization code / access token.
     * 
     * @param flag whether the attribute should encoded to authorization code / access token
     */
    public void setSetToToken(boolean flag) {
        setToToken = flag;
    }

    /**
     * Gets whether the attribute should encoded to authorization code / access token.
     * 
     * @return whhether the attribute should encoded to authorization code / access token.
     */
    public boolean getSetToToken() {
        return setToToken;
    }

    /**
     * Sets whether to interpret value as integer.
     * 
     * @param flag whether to interpret value as integer
     */
    public void setAsInt(boolean flag) {
        asInt = flag;
    }

    /**
     * Gets delimiter used when catenating string values.
     * 
     * @return delimiter used when catenating string values
     */
    public String getStringDelimiter() {
        return stringDelimiter;
    }

    /**
     * Sets delimiter used when catenating string values.
     * 
     * @param delimeter delimiter used when catenating string values
     */
    public void setStringDelimiter(@Nullable String delimeter) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        stringDelimiter = delimeter;
    }

    /**
     * Set whether to encode type information. Not Supported. Encoder parser sets this if defined.
     * 
     * @param flag flag to set
     */
    public void setEncodeType(final boolean flag) {
        log.warn("Encode type parameter is not supported");
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
     * @param condition condition to set
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
     * @param attributeName name of the attribute
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
        if (asObject && (fieldName == null || fieldName.length() == 0)) {
            throw new ComponentInitializationException("JSON Object field name cannot be null");
        }
    }

    /**
     * Wraps object to JSON object if flag is set.
     * 
     * @param obj to be wrapped
     * @return original object or object wrapped to JSON object
     */
    private Object wrapToJSONObject(Object obj) {
        if (getAsObject()) {
            log.debug("value instructed to be wrapped to a JSON object with key{} ", fieldName);
            JSONObject jsonObj = new JSONObject();
            jsonObj.put(fieldName, obj);
            return jsonObj;
        }
        return obj;
    }

    // Checkstyle: CyclomaticComplexity OFF
    /**
     * Either catenates a list of string or places them to array depending on configuration. The result may still be
     * wrapped to JSON object depending on configuration.
     * 
     * @param <T> Integer, Boolean or String
     * @param values list of strings
     * @return String, JSON Array or JSON Object
     */
    protected <T extends Object> Object encodeValues(List<T> values) {
        if (values == null) {
            return null;
        }
        if (getAsArray()) {
            log.debug("value(s) instructed to be set to array");
            JSONArray array = new JSONArray();
            for (T value : values) {
                array.add(value);
            }
            return wrapToJSONObject(array);
        } else {
            log.debug("value(s) instructed to be set as single value");
            String attributeString = "";
            for (T value : values) {
                if (value instanceof Integer || value instanceof Boolean) {
                    log.debug("for int and boolean first value is considered the result");
                    return wrapToJSONObject(value);
                }
                if (value instanceof String) {
                    if (attributeString.length() > 0 && getStringDelimiter() != null) {
                        attributeString += getStringDelimiter();
                    }
                    attributeString += value;
                } else {
                    log.warn("unrecognised type of value, {}", value.getClass().getName());
                    return null;
                }
            }
            return attributeString.length() != 0 ? wrapToJSONObject(attributeString) : null;
        }
    }
    // Checkstyle: CyclomaticComplexity ON

    /**
     * Converts string idp attribute values to List of Integer, String or Boolean depending on configuration.
     * 
     * @param attributevalues string idp attribute values
     * @return list of strings, boolean or integer
     */
    protected List<?> getValues(List<IdPAttributeValue<?>> attributevalues) {
        if (getAsInt()) {
            log.debug("String values instructed to be interpreted as integer");
            return getIntValues(attributevalues);
        }
        if (getAsBoolean()) {
            log.debug("String values instructed to be interpreted as boolean");
            return getBooleanValues(attributevalues);
        }
        log.debug("String values instructed to be interpreted as string");
        return getStringValues(attributevalues);

    }

    /**
     * Converts string idp attribute values to List of Strings.
     * 
     * @param attributevalues string idp attribute values
     * @return list of strings
     */
    private List<String> getStringValues(List<IdPAttributeValue<?>> attributevalues) {
        if (attributevalues == null) {
            return null;
        }
        List<String> values = new ArrayList<String>();
        for (IdPAttributeValue<?> value : attributevalues) {
            if (value instanceof StringAttributeValue) {
                log.debug("value {} added", ((StringAttributeValue) value).getValue());
                values.add(((StringAttributeValue) value).getValue());
            }
        }
        return values;
    }

    /**
     * Converts string idp attribute values to List of Integers.
     * 
     * @param attributevalues string idp attribute values
     * @return list of integers
     */
    private List<Integer> getIntValues(List<IdPAttributeValue<?>> attributevalues) {
        if (attributevalues == null) {
            return null;
        }
        List<Integer> values = new ArrayList<Integer>();
        for (IdPAttributeValue<?> value : attributevalues) {
            if (value instanceof StringAttributeValue) {
                try {
                    int intValue = Integer.parseInt((String) value.getValue());
                    log.debug("value {} added", intValue);
                    values.add(intValue);
                } catch (NumberFormatException e) {
                    log.debug("value {} not parsable integer", (String) value.getValue());
                }
            }
        }
        return values;
    }

    /**
     * Converts string idp attribute values to List of Booleans.
     * 
     * @param attributevalues string idp attribute values
     * @return list of booleans
     */
    private List<Boolean> getBooleanValues(List<IdPAttributeValue<?>> attributevalues) {
        if (attributevalues == null) {
            return null;
        }
        List<Boolean> values = new ArrayList<Boolean>();
        for (IdPAttributeValue<?> value : attributevalues) {
            if (value instanceof StringAttributeValue) {
                log.debug("value {} added as {}", (String) value.getValue(),
                        ((StringAttributeValue) value).getValue().equalsIgnoreCase(Boolean.TRUE.toString()));
                values.add(((StringAttributeValue) value).getValue() != null
                        && ((StringAttributeValue) value).getValue().equalsIgnoreCase(Boolean.TRUE.toString()));
            }
        }
        return values;
    }

    @Override
    public abstract JSONObject encode(IdPAttribute idpAttribute) throws AttributeEncodingException;

    @Override
    public String getProtocol() {
        return "http://openid.net/specs/openid-connect-core-1_0.html";
    }

}
