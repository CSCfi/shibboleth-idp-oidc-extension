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
   
    /** Local name of as boolean attribute. */
    @Nonnull
    @NotEmpty
    public static final String AS_BOOLEAN_ATTRIBUTE_NAME = "asBoolean";

    /** Local name of force to id token attribute. */
    @Nonnull
    @NotEmpty
    public static final String PLACE_TO_IDTOKEN_ATTRIBUTE_NAME = "placeToIDToken";

    /** Local name of deny userinfo attribute. */
    @Nonnull
    @NotEmpty
    public static final String DENY_USERINFO_ATTRIBUTE_NAME = "denyUserinfo";

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
        if (config.hasAttributeNS(null, AS_BOOLEAN_ATTRIBUTE_NAME)) {
            builder.addPropertyValue("asBoolean",
                    StringSupport.trimOrNull(config.getAttributeNS(null, AS_BOOLEAN_ATTRIBUTE_NAME)));
        }
        if (config.hasAttributeNS(null, PLACE_TO_IDTOKEN_ATTRIBUTE_NAME)) {
            builder.addPropertyValue("placeToIDToken",
                    StringSupport.trimOrNull(config.getAttributeNS(null, PLACE_TO_IDTOKEN_ATTRIBUTE_NAME)));
        }
        if (config.hasAttributeNS(null, DENY_USERINFO_ATTRIBUTE_NAME)) {
            builder.addPropertyValue("denyUserinfo",
                    StringSupport.trimOrNull(config.getAttributeNS(null, DENY_USERINFO_ATTRIBUTE_NAME)));
        }
    }

}