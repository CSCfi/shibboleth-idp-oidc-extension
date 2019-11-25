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

import javax.annotation.Nonnull;

import net.shibboleth.ext.spring.util.BaseSpringNamespaceHandler;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/** Namespace handler for the oidc attribute resolver. */
public class AttributeEncoderNamespaceHandler extends BaseSpringNamespaceHandler {

    /** Namespace for this handler. */
    @Nonnull
    @NotEmpty
    public static final String NAMESPACE = "org.geant.idpextension.oidc.attribute.encoder";

    /** {@inheritDoc} */
    @Override
    public void init() {
        registerBeanDefinitionParser(OIDCStringEncoderParser.TYPE_NAME, new OIDCStringEncoderParser());
        registerBeanDefinitionParser(OIDCScopedStringEncoderParser.TYPE_NAME, new OIDCScopedStringEncoderParser());
        registerBeanDefinitionParser(OIDCByteEncoderParser.TYPE_NAME, new OIDCByteEncoderParser());
    }

}