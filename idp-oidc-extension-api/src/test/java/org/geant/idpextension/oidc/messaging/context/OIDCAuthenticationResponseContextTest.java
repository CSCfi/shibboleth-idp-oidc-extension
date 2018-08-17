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

package org.geant.idpextension.oidc.messaging.context;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.xml.namespace.QName;

import junit.framework.Assert;
import net.shibboleth.utilities.java.support.collection.LockableClassToInstanceMultiMap;

import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.NamespaceManager;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.util.IDIndex;
import org.opensaml.saml.saml2.core.NameID;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.w3c.dom.Element;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

public class OIDCAuthenticationResponseContextTest {

    private OIDCAuthenticationResponseContext ctx;

    @BeforeMethod
    protected void setUp() throws Exception {
        ctx = new OIDCAuthenticationResponseContext();
    }

    @Test
    public void testInitialState() {
        Assert.assertNull(ctx.getRequestedSubject());
        Assert.assertNull(ctx.getAcr());
        Assert.assertNull(ctx.getAuthTime());
        Assert.assertNull(ctx.getIDToken());
        Assert.assertNull(ctx.getSubject());
        Assert.assertNull(ctx.getRedirectURI());
        Assert.assertNull(ctx.getScope());
        Assert.assertNull(ctx.getProcessedToken());
    }

    @Test
    public void testSetters() throws URISyntaxException, ParseException {
        ctx.setAcr("acrValue");
        ctx.setAuthTime(1);
        Issuer issuer = new Issuer("iss");
        Subject sub = new Subject("sub");
        List<Audience> aud = new ArrayList<Audience>();
        aud.add(new Audience("aud"));
        IDTokenClaimsSet token = new IDTokenClaimsSet(issuer, sub, aud, new Date(), new Date());
        ctx.setIDToken(token);
        NameID id = new MockNameID();
        ctx.setSubject(id.getValue());
        URI uri = new URI("https://example.org");
        ctx.setRedirectURI(uri);
        ctx.setRequestedSubject("sub");
        Scope scope = new Scope();
        ctx.setScope(scope);
        JWSHeader header = new JWSHeader(JWSAlgorithm.ES256);
        SignedJWT sJWT = new SignedJWT(header, token.toJWTClaimsSet());
        ctx.setProcessedToken(sJWT);
        Assert.assertEquals(ctx.getAcr().toString(), "acrValue");
        ctx.setAcr(null);
        Assert.assertNull(ctx.getAcr());
        Assert.assertEquals(ctx.getAuthTime(), new Date(1));
        Assert.assertEquals(ctx.getIDToken(), token);
        Assert.assertEquals(ctx.getSubject(), id.getValue());
        Assert.assertEquals(ctx.getProcessedToken(), sJWT);
        Assert.assertEquals(ctx.getRedirectURI(), uri);
        Assert.assertEquals(ctx.getRequestedSubject(), "sub");
        Assert.assertEquals(ctx.getScope(), scope);
    }

    class MockNameID implements NameID {

        @Override
        public void detach() {

        }

        @Override
        public Element getDOM() {
            return null;
        }

        @Override
        public QName getElementQName() {
            return null;
        }

        @Override
        public IDIndex getIDIndex() {
            return null;
        }

        @Override
        public NamespaceManager getNamespaceManager() {
            return null;
        }

        @Override
        public Set<Namespace> getNamespaces() {
            return null;
        }

        @Override
        public String getNoNamespaceSchemaLocation() {
            return null;
        }

        @Override
        public LockableClassToInstanceMultiMap<Object> getObjectMetadata() {
            return null;
        }

        @Override
        public List<XMLObject> getOrderedChildren() {
            return null;
        }

        @Override
        public XMLObject getParent() {
            return null;
        }

        @Override
        public String getSchemaLocation() {
            return null;
        }

        @Override
        public QName getSchemaType() {
            return null;
        }

        @Override
        public boolean hasChildren() {
            return false;
        }

        @Override
        public boolean hasParent() {
            return false;
        }

        @Override
        public Boolean isNil() {
            return null;
        }

        @Override
        public XSBooleanValue isNilXSBoolean() {
            return null;
        }

        @Override
        public void releaseChildrenDOM(boolean arg0) {
        }

        @Override
        public void releaseDOM() {
        }

        @Override
        public void releaseParentDOM(boolean arg0) {
        }

        @Override
        public XMLObject resolveID(String arg0) {
            return null;
        }

        @Override
        public XMLObject resolveIDFromRoot(String arg0) {
            return null;
        }

        @Override
        public void setDOM(Element arg0) {
        }

        @Override
        public void setNil(Boolean arg0) {
        }

        @Override
        public void setNil(XSBooleanValue arg0) {
        }

        @Override
        public void setNoNamespaceSchemaLocation(String arg0) {
        }

        @Override
        public void setParent(XMLObject arg0) {
        }

        @Override
        public void setSchemaLocation(String arg0) {
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public String getNameQualifier() {
            return null;
        }

        @Override
        public String getSPNameQualifier() {
            return null;
        }

        @Override
        public String getSPProvidedID() {
            return null;
        }

        @Override
        public String getValue() {
            return null;
        }

        @Override
        public void setFormat(String arg0) {
        }

        @Override
        public void setNameQualifier(String arg0) {
        }

        @Override
        public void setSPNameQualifier(String arg0) {
        }

        @Override
        public void setSPProvidedID(String arg0) {
        }

        @Override
        public void setValue(String arg0) {
        }

    }

}