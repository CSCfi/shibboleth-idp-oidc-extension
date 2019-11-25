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

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.geant.idpextension.oidc.attribute.encoding.impl.OIDCScopedStringAttributeEncoder;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

/**
 * Spring bean definition parser for {@link OIDCScopedStringAttributeEncoder}.
 */
public class OIDCScopedStringEncoderParser extends AbstractOIDCEncoderParser {

    /** Schema type name:. */
    @Nonnull
    public static final QName TYPE_NAME = new QName(AttributeEncoderNamespaceHandler.NAMESPACE, "OIDCScopedString");

    /** Local name of scope delimeter attribute. */
    @Nonnull
    @NotEmpty
    public static final String SCOPE_DELIMETER_ATTRIBUTE_NAME = "scopeDelimiter";

    /** Constructor. */
    public OIDCScopedStringEncoderParser() {
        setNameRequired(true);
    }

    /** {@inheritDoc} */
    @Override
    protected Class<OIDCScopedStringAttributeEncoder> getBeanClass(@Nullable final Element element) {
        return OIDCScopedStringAttributeEncoder.class;
    }

    /** {@inheritDoc} */
    @Override
    protected void doParse(@Nonnull final Element config, @Nonnull final ParserContext parserContext,
            @Nonnull final BeanDefinitionBuilder builder) {

        super.doParse(config, parserContext, builder);

        if (config.hasAttributeNS(null, SCOPE_DELIMETER_ATTRIBUTE_NAME)) {
            builder.addPropertyValue("scopeDelimiter",
                    StringSupport.trimOrNull(config.getAttributeNS(null, SCOPE_DELIMETER_ATTRIBUTE_NAME)));
        }
    }

}