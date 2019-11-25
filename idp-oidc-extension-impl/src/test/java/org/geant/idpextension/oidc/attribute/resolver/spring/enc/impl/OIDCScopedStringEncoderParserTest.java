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

import org.geant.idpextension.oidc.attribute.encoding.impl.OIDCScopedStringAttributeEncoder;
import org.springframework.context.support.GenericApplicationContext;
import org.testng.Assert;
import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.resolver.spring.BaseAttributeDefinitionParserTest;

public class OIDCScopedStringEncoderParserTest extends BaseAttributeDefinitionParserTest {

    public static final String ENCODER_FILE_PATH = "org/geant/idpextension/oidc/attribute/resolver/spring/enc/";

    @Test
    public void resolver() {
        final OIDCScopedStringAttributeEncoder encoder = getAttributeEncoder("oidcscopedstring.xml",
                OIDCScopedStringAttributeEncoder.class);
        Assert.assertEquals(encoder.getName(), "OIDCScopedString_ATTRIBUTE_NAME");
        Assert.assertEquals(encoder.getAsArray(), true);
        Assert.assertEquals(encoder.getStringDelimiter(), "|");
    }

    @SuppressWarnings("rawtypes")
    @Override
    protected <Type extends AttributeEncoder> Type getAttributeEncoder(final String fileName, final Class<Type> claz,
            final GenericApplicationContext context) {

        return getBean(ENCODER_FILE_PATH + fileName, claz, context);

    }

}
