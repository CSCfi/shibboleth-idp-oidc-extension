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

package org.geant.idpextension.oidc.algorithm.descriptors;

import junit.framework.Assert;

import org.geant.idpextension.oidc.crypto.support.EncryptionConstants;
import org.geant.idpextension.oidc.crypto.support.JCAConstantExtension;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.xmlsec.algorithm.AlgorithmDescriptor.AlgorithmType;
import org.testng.annotations.Test;

/**
 * Unit tests for {@link EncryptionA256CBC_HS512}
 */
public class EncryptionA256CBC_HS512Test {

	private EncryptionA256CBC_HS512 algorithm = new EncryptionA256CBC_HS512();

	@Test
	public void testInitialState() {
		Assert.assertEquals(JCAConstants.KEY_ALGO_AES, algorithm.getKey());
		Assert.assertEquals(EncryptionConstants.ALGO_ID_ENC_ALG_A256CBC_HS512, algorithm.getURI());
		Assert.assertEquals(AlgorithmType.BlockEncryption, algorithm.getType());
		Assert.assertEquals("AES/CBC/PKCS5Padding", algorithm.getJCAAlgorithmID());
		Assert.assertEquals(new Integer(256), algorithm.getKeyLength());
		Assert.assertEquals(JCAConstants.CIPHER_MODE_CBC, algorithm.getCipherMode());
		Assert.assertEquals(JCAConstantExtension.CIPHER_PADDING_PKCS5, algorithm.getPadding());
	}

}