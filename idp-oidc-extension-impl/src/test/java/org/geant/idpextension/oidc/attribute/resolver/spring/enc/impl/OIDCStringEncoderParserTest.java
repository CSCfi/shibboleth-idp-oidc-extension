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

import org.geant.idpextension.oidc.attribute.encoding.impl.OIDCStringAttributeEncoder;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.context.support.GenericApplicationContext;

import net.shibboleth.idp.attribute.AttributeEncoder;
import net.shibboleth.idp.attribute.resolver.spring.BaseAttributeDefinitionParserTest;

public class OIDCStringEncoderParserTest extends BaseAttributeDefinitionParserTest {

    public static final String ENCODER_FILE_PATH = "org/geant/idpextension/oidc/attribute/resolver/spring/enc/";

    @Test
    public void resolver() {
        final OIDCStringAttributeEncoder encoder = getAttributeEncoder("oidcstring.xml",
                OIDCStringAttributeEncoder.class);

        Assert.assertEquals(encoder.getName(), "OIDCString_ATTRIBUTE_NAME");
        Assert.assertEquals(encoder.getAsArray(), true);
        Assert.assertEquals(encoder.getAsBoolean(), true);
        Assert.assertEquals(encoder.getAsInt(), false);
        Assert.assertEquals(encoder.getAsObject(), true);
        Assert.assertEquals(encoder.getFieldName(), "field");
        Assert.assertEquals(encoder.getStringDelimiter(), "|");
    }

    @SuppressWarnings("rawtypes")
    @Override
    protected <Type extends AttributeEncoder> Type getAttributeEncoder(final String fileName, final Class<Type> claz,
            final GenericApplicationContext context) {

        return getBean(ENCODER_FILE_PATH + fileName, claz, context);

    }

}
