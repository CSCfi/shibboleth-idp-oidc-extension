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

import javax.annotation.Nonnull;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.SubjectType;

import net.shibboleth.utilities.java.support.logic.Constraint;

/**
* An action that adds the subject_type to the client metadata.
*/
public class AddSubjectTypeToClientMetadata extends AbstractOIDCClientMetadataPopulationAction {

   /** Class logger. */
   @Nonnull
   private final Logger log = LoggerFactory.getLogger(AddSubjectTypeToClientMetadata.class);

   /** The default {@link SubjectType} if it was not defined in the request. */
   private SubjectType defaultSubjectType;

   /** Constructor. */
   public AddSubjectTypeToClientMetadata() {
       defaultSubjectType = SubjectType.PUBLIC;
   }

   /**
    * Set the default {@link SubjectType} to be used if it was not defined in the request.
    * @param subjectType The default {@link SubjectType} to be used if it was not defined in the request.
    */
   public void setDefaultSubjectType(final SubjectType subjectType) {
       defaultSubjectType = Constraint.isNotNull(subjectType, "The default subjectType cannot be null");
   }

   /** {@inheritDoc} */
   @Override
   protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
       final SubjectType requestedType = getInputMetadata().getSubjectType();
       if (requestedType == null) {
           log.debug("{} No subject type requested, using default {}", getLogPrefix(), defaultSubjectType);
           getOutputMetadata().setSubjectType(defaultSubjectType);
       } else {
           //TODO: should be configurable which ones are allowed and to whom
           getOutputMetadata().setSubjectType(requestedType);
       }
   }

}