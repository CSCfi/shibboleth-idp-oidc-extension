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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletResponse;

import org.geant.idpextension.oidc.messaging.OIDCWebFingerRequest;
import org.geant.idpextension.oidc.messaging.OIDCWebFingerResponse;
import org.geant.idpextension.oidc.messaging.OIDCWebFingerResponse.Link;
import org.geant.idpextension.oidc.messaging.impl.OIDCWebFingerResponseImpl;
import org.geant.idpextension.oidc.messaging.impl.OIDCWebFingerResponseLinkImpl;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;

import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.logic.Constraint;

/**
 * This action builds a response for the OIDC Web Finger. The resource value from the request is directly used as
 * a subject. The issuer link value must be configured.
 */
public class BuildWebFingerResponse extends AbstractProfileAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(BuildWebFingerResponse.class);
    
    /** The OIDC WebFinger request. */
    protected OIDCWebFingerRequest request;
    
    /** The OIDC issuer name to be used in the responses. */
    private String oidcIssuer;

    /** Constructor. */
    public BuildWebFingerResponse() {
    }
    
    /**
     * Set the OIDC issuer name to be used in the responses.
     * @param issuer The OIDC issuer name to be used in the responses.
     */
    public void setIssuer(final String issuer) {
        oidcIssuer = Constraint.isNotEmpty(issuer, "The issuer cannot be null!");
    }
    
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        
        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }
        if (profileRequestContext.getInboundMessageContext() == null) {
            log.debug("{} No inbound message context associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;            
        }
        Object message = profileRequestContext.getInboundMessageContext().getMessage();
        if (message == null || !(message instanceof OIDCWebFingerRequest)) {
            log.debug("{} No inbound message associated with this profile request", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;                        
        }
        request = (OIDCWebFingerRequest) message;
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        final HttpServletResponse servletResponse = getHttpServletResponse();
        final Link link = new OIDCWebFingerResponseLinkImpl(request.getRel(), oidcIssuer);
        final List<Link> links = new ArrayList<>();
        links.add(link);
        final OIDCWebFingerResponse response = new OIDCWebFingerResponseImpl(request.getResource(), links);
        servletResponse.setContentType("application/jrd+json");
        servletResponse.setCharacterEncoding("UTF-8");
        final Gson gson = new Gson();
        try {
            gson.toJson(gson.toJsonTree(response), gson.newJsonWriter(servletResponse.getWriter()));
        } catch (IOException e) {
            log.error("{} Could not encode the JSON response to the servlet response", getLogPrefix(), e);
            return;
        }
        
        log.debug("{} WebFinger response successfully applied to the HTTP response", getLogPrefix());
    }
}
