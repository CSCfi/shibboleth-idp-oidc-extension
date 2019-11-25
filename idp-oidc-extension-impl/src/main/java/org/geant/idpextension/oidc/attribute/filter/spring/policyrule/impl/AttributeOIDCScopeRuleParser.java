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

package org.geant.idpextension.oidc.attribute.filter.spring.policyrule.impl;

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;
import org.geant.idpextension.oidc.attribute.filter.spring.impl.AttributeFilterNamespaceHandler;
import org.geant.idpextension.oidc.attribute.filter.spring.policyrule.filtercontext.impl.AttributeOIDCScopePolicyRule;
import net.shibboleth.idp.attribute.filter.spring.policyrule.impl.AbstractStringPolicyRuleParser;

/**
 * Bean definition parser for {@link AttributeOIDCScopePolicyRule}.
 */
public class AttributeOIDCScopeRuleParser extends AbstractStringPolicyRuleParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE_AFP = new QName(AttributeFilterNamespaceHandler.NAMESPACE, "OIDCScope");

    /** {@inheritDoc} */
    @Override
    protected QName getAFPName() {
        return SCHEMA_TYPE_AFP;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    protected Class<AttributeOIDCScopePolicyRule> getNativeBeanClass() {
        return AttributeOIDCScopePolicyRule.class;
    }

}
