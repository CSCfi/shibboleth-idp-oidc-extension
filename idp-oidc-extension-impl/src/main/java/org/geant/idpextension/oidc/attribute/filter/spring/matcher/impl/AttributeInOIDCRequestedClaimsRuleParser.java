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

package org.geant.idpextension.oidc.attribute.filter.spring.matcher.impl;

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;
import net.shibboleth.idp.attribute.filter.spring.matcher.BaseAttributeValueMatcherParser;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import org.geant.idpextension.oidc.attribute.filter.matcher.impl.AttributeInOIDCRequestedClaimsMatcher;
import org.geant.idpextension.oidc.attribute.filter.spring.impl.AttributeFilterNamespaceHandler;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

/**
 * Bean definition parser for {@link AttributeInOIDCRequestedClaimsMatcher}.
 */
public class AttributeInOIDCRequestedClaimsRuleParser extends BaseAttributeValueMatcherParser {

    /** Schema type - afp. */
    public static final QName SCHEMA_TYPE_AFP =
            new QName(AttributeFilterNamespaceHandler.NAMESPACE, "AttributeInOIDCRequestedClaims");

    /** {@inheritDoc} */
    @Override
    protected QName getAFPName() {
        return SCHEMA_TYPE_AFP;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    protected Class<AttributeInOIDCRequestedClaimsMatcher> getNativeBeanClass() {
        return AttributeInOIDCRequestedClaimsMatcher.class;
    }

    /** {@inheritDoc} */
    @Override
    protected void doNativeParse(@Nonnull final Element config, @Nonnull final ParserContext parserContext,
            @Nonnull final BeanDefinitionBuilder builder) {
        super.doParse(config, builder);

        if (config.hasAttributeNS(null, "onlyIfEssential")) {
            builder.addPropertyValue("onlyIfEssential",
                    StringSupport.trimOrNull(config.getAttributeNS(null, "onlyIfEssential")));
        }

        if (config.hasAttributeNS(null, "matchOnlyIDToken")) {
            builder.addPropertyValue("matchOnlyIDToken",
                    StringSupport.trimOrNull(config.getAttributeNS(null, "matchOnlyIDToken")));
        }

        if (config.hasAttributeNS(null, "matchOnlyUserInfo")) {
            builder.addPropertyValue("matchOnlyUserInfo",
                    StringSupport.trimOrNull(config.getAttributeNS(null, "matchOnlyUserInfo")));
        }

        if (config.hasAttributeNS(null, "matchIfRequestedClaimsSilent")) {
            builder.addPropertyValue("matchIfRequestedClaimsSilent",
                    StringSupport.trimOrNull(config.getAttributeNS(null, "matchIfRequestedClaimsSilent")));
        }

    }
}