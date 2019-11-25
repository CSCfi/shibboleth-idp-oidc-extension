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
import javax.annotation.Nullable;
import javax.xml.namespace.QName;
import org.geant.idpextension.oidc.attribute.encoding.impl.OIDCByteAttributeEncoder;
import org.w3c.dom.Element;

/**
 * Spring bean definition parser for {@link OIDCByteAttributeEncoder}.
 */
public class OIDCByteEncoderParser extends AbstractOIDCEncoderParser {

    /** Schema type name:. */
    @Nonnull
    public static final QName TYPE_NAME = new QName(AttributeEncoderNamespaceHandler.NAMESPACE, "OIDCByte");

    /** Constructor. */
    public OIDCByteEncoderParser() {
        setNameRequired(true);
    }

    /** {@inheritDoc} */
    @Override
    protected Class<OIDCByteAttributeEncoder> getBeanClass(@Nullable final Element element) {
        return OIDCByteAttributeEncoder.class;
    }

}