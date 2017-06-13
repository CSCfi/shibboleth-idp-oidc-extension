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

package org.geant.idpextension.oidc.profile.impl;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import javax.annotation.Nonnull;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.geant.idpextension.oidc.messaging.context.OIDCResponseContext;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

/**
 * Action that creates a {@link IDTokenClaimsSet} object shell , and sets it to
 * work context {@link OIDCResponseContext} located under
 * {@link ProfileRequestContext#getOutboundMessageContext()}.
 *
 */
@SuppressWarnings("rawtypes")
public class AddIDTokenShell extends AbstractOIDCResponseAction {

    /** Class logger. */
    @Nonnull
    private Logger log = LoggerFactory.getLogger(AddIDTokenShell.class);

    /** Strategy used to obtain the response issuer value. */
    @Nonnull
    private Function<ProfileRequestContext, String> issuerLookupStrategy;

    /** EntityID to populate into Issuer element. */
    @Nonnull
    private String issuerId;

    /** Subject context. */
    private SubjectContext subjectCtx;

    /**
     * Set the strategy used to locate the issuer value to use.
     * 
     * @param strategy
     *            lookup strategy
     */
    public void setIssuerLookupStrategy(@Nonnull final Function<ProfileRequestContext, String> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        issuerLookupStrategy = Constraint.isNotNull(strategy, "IssuerLookupStrategy lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        issuerId = issuerLookupStrategy.apply(profileRequestContext);
        subjectCtx = profileRequestContext.getSubcontext(SubjectContext.class, false);
        if (subjectCtx == null) {
            log.error("{} No subject context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return super.doPreExecute(profileRequestContext);
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        /**
         * aud REQUIRED. Audience(s) that this ID Token is intended for. It MUST
         * contain the OAuth 2.0 client_id of the Relying Party as an audience
         * value. It MAY also contain identifiers for other audiences. In the
         * general case, the aud value is an array of case sensitive strings. In
         * the common special case when there is one audience, the aud value MAY
         * be a single case sensitive string.
         * 
         * NOTE. TODO. We allow only single value in this first version.
         */
        List<Audience> aud = new ArrayList<Audience>();
        aud.add(new Audience(getAuthenticationRequest().getClientID().getValue()));
        /**
         * exp REQUIRED. Expiration time on or after which the ID Token MUST NOT
         * be accepted for processing. The processing of this parameter requires
         * that the current date/time MUST be before the expiration date/time
         * listed in the value. Implementers MAY provide for some small leeway,
         * usually no more than a few minutes, to account for clock skew. Its
         * value is a JSON number representing the number of seconds from
         * 1970-01-01T0:0:0Z as measured in UTC until the date/time. See RFC
         * 3339 [RFC3339] for details regarding date/times in general and UTC in
         * particular.
         * 
         * NOTE. We set here exp to +180s unless set in response context.
         */
        Date exp = getOidcResponseContext().getExp();
        if (exp == null) {
            Calendar calExp = Calendar.getInstance();
            calExp.add(Calendar.SECOND, 180);
            exp = calExp.getTime();
        }

        /**
         * iss REQUIRED. Issuer Identifier for the Issuer of the response. The
         * iss value is a case sensitive URL using the https scheme that
         * contains scheme, host, and optionally, port number and path
         * components and no query or fragment components.
         * 
         * NOTE! TODO. We set the "entity id" as issuer. No scheme validation is
         * in place.
         */

        /**
         * sub REQUIRED. Subject Identifier. A locally unique and never
         * reassigned identifier within the Issuer for the End-User, which is
         * intended to be consumed by the Client, e.g., 24400320 or
         * AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255 ASCII
         * characters in length. The sub value is a case sensitive string.
         * 
         * 
         * Note. We use principalname as the sub.
         * 
         */

        /**
         * iat REQUIRED. Time at which the JWT was issued. Its value is a JSON
         * number representing the number of seconds from 1970-01-01T0:0:0Z as
         * measured in UTC until the date/time.
         * 
         * Note. We consider time of idtoken shell generation as iat.
         */
        IDTokenClaimsSet idToken = new IDTokenClaimsSet(new Issuer(issuerId),
                new Subject(subjectCtx.getPrincipalName()), aud, exp, new Date());
        log.debug("{} Setting id token shell to response context {}", getLogPrefix(), idToken.toJSONObject()
                .toJSONString());
        getOidcResponseContext().setIDToken(idToken);
    }

}