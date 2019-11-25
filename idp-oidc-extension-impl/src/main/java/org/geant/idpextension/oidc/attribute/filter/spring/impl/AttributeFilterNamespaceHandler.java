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

package org.geant.idpextension.oidc.attribute.filter.spring.impl;

import org.geant.idpextension.oidc.attribute.filter.spring.matcher.impl.AttributeInOIDCRequestedClaimsRuleParser;
import org.geant.idpextension.oidc.attribute.filter.spring.policyrule.impl.AttributeOIDCScopeRuleParser;

import net.shibboleth.ext.spring.util.BaseSpringNamespaceHandler;

/** Namespace handler for the oidc specific attribute filter engine functions. */
public class AttributeFilterNamespaceHandler extends BaseSpringNamespaceHandler {

    /** oidc namespace. */
    public static final String NAMESPACE = "org.geant.idpextension.oidc.attribute.filter";

    /** {@inheritDoc} */
    @Override
    public void init() {
        // Policy rules
        registerBeanDefinitionParser(AttributeOIDCScopeRuleParser.SCHEMA_TYPE_AFP, new AttributeOIDCScopeRuleParser());
        // Matchers
        registerBeanDefinitionParser(AttributeInOIDCRequestedClaimsRuleParser.SCHEMA_TYPE_AFP,
                new AttributeInOIDCRequestedClaimsRuleParser());
    }
}