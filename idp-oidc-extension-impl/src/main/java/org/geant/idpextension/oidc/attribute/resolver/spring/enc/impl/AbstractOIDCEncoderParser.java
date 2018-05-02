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

package org.geant.idpextension.oidc.attribute.resolver.spring.enc.impl;

import net.shibboleth.idp.attribute.resolver.spring.enc.BaseAttributeEncoderParser;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import javax.annotation.Nonnull;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

/**
 * Base class for Spring bean definition parser for oidc attribute encoders.
 */
public abstract class AbstractOIDCEncoderParser extends BaseAttributeEncoderParser {

    /** Local name of as array attribute. */
    @Nonnull
    @NotEmpty
    public static final String AS_ARRAY_ATTRIBUTE_NAME = "asArray";

    /** Local name of as int attribute. */
    @Nonnull
    @NotEmpty
    public static final String AS_INT_ATTRIBUTE_NAME = "asInt";

    /** Local name of string delimeter attribute. */
    @Nonnull
    @NotEmpty
    public static final String STRING_DELIMETER_ATTRIBUTE_NAME = "stringDelimiter";

    /** Local name of set to token attribute. */
    @Nonnull
    @NotEmpty
    public static final String SET_TO_TOKEN_ATTRIBUTE_NAME = "setToToken";

    /** Local name of as object attribute. */
    @Nonnull
    @NotEmpty
    public static final String AS_OBJECT_ATTRIBUTE_NAME = "asObject";

    /** Local name of as object attribute. */
    @Nonnull
    @NotEmpty
    public static final String FIELD_NAME_ATTRIBUTE_NAME = "fieldName";

    /** Local name of as boolean attribute. */
    @Nonnull
    @NotEmpty
    public static final String AS_BOOLEAN_ATTRIBUTE_NAME = "asBoolean";

    /** {@inheritDoc} */
    @Override
    protected void doParse(@Nonnull final Element config, @Nonnull final ParserContext parserContext,
            @Nonnull final BeanDefinitionBuilder builder) {

        super.doParse(config, parserContext, builder);
        if (config.hasAttributeNS(null, AS_ARRAY_ATTRIBUTE_NAME)) {
            builder.addPropertyValue("asArray",
                    StringSupport.trimOrNull(config.getAttributeNS(null, AS_ARRAY_ATTRIBUTE_NAME)));
        }
        if (config.hasAttributeNS(null, AS_INT_ATTRIBUTE_NAME)) {
            builder.addPropertyValue("asInt",
                    StringSupport.trimOrNull(config.getAttributeNS(null, AS_INT_ATTRIBUTE_NAME)));
        }
        if (config.hasAttributeNS(null, SET_TO_TOKEN_ATTRIBUTE_NAME)) {
            builder.addPropertyValue("setToToken",
                    StringSupport.trimOrNull(config.getAttributeNS(null, SET_TO_TOKEN_ATTRIBUTE_NAME)));
        }
        if (config.hasAttributeNS(null, STRING_DELIMETER_ATTRIBUTE_NAME)) {
            builder.addPropertyValue("stringDelimiter",
                    StringSupport.trimOrNull(config.getAttributeNS(null, STRING_DELIMETER_ATTRIBUTE_NAME)));
        }
        if (config.hasAttributeNS(null, AS_OBJECT_ATTRIBUTE_NAME)) {
            builder.addPropertyValue("asObject",
                    StringSupport.trimOrNull(config.getAttributeNS(null, AS_OBJECT_ATTRIBUTE_NAME)));
        }
        if (config.hasAttributeNS(null, FIELD_NAME_ATTRIBUTE_NAME)) {
            builder.addPropertyValue("fieldName",
                    StringSupport.trimOrNull(config.getAttributeNS(null, FIELD_NAME_ATTRIBUTE_NAME)));
        }
        if (config.hasAttributeNS(null, AS_BOOLEAN_ATTRIBUTE_NAME)) {
            builder.addPropertyValue("asBoolean",
                    StringSupport.trimOrNull(config.getAttributeNS(null, AS_BOOLEAN_ATTRIBUTE_NAME)));
        }
    }

}