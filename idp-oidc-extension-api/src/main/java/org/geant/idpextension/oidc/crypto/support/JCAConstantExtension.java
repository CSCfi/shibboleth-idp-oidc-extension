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
package org.geant.idpextension.oidc.crypto.support;

/**
 * Additional constants to {@link JCAConstants} defined in and/or used with the
 * Java Cryptography Architecture (JCA) specification.
 */
public final class JCAConstantExtension {

	/** Cipher padding: "PKCS5Padding". */
	public static final String CIPHER_PADDING_PKCS5 = "PKCS5Padding";
	/** Cipher padding "OAEP". */
	public static final String CIPHER_PADDING_OAEP = "OAEPWithSHA-1AndMGF1Padding";
	/** Cipher padding "OAEP-256". */
	public static final String CIPHER_PADDING_OAEP_256 = "OAEPWithSHA-256AndMGF1Padding";
}
