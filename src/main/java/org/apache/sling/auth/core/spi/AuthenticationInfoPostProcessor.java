/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.sling.auth.core.spi;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.SlingException;
import org.apache.sling.api.resource.LoginException;
import org.osgi.annotation.versioning.ConsumerType;

/**
 * Service interface which allows bundles to modify the {@code AuthenticationInfo} object
 * right after one {@code AuthenticationHandler} has returned an {{@code AuthenticationInfo}
 * from the {@link AuthenticationHandler#extractCredentials(HttpServletRequest, HttpServletResponse)}
 * method or an anonymous {@code AuthenticationInfo} has been created. This service is called
 * before the {@code ResourceResolver} is created and any login into the resource providers
 * (such as a JCR repository or other data store) happens. However, the {@code AuthenticationHandler}
 * might actually do such a login and pass on the information to the resource provider through
 * the {@code AuthenticationInfo}.
 * This service interface is useful to access and modify the {{@code AuthenticationInfo} before
 * it is passed to the {@code ResourceResolverFactory} to create a {@code ResourceResolver}.
 */
@ConsumerType
public interface AuthenticationInfoPostProcessor {

    /**
     * The name under which an implementation of this interface must be
     * registered to be used as an authentication info post processor.
     */
    static final String SERVICE_NAME = "org.apache.sling.auth.core.spi.AuthenticationInfoPostProcessor";

    /**
     * Perform some post-processing on the AuthenticationInfo object.
     *
     * @param info The authentication info
     * @param request The current request
     * @param response The current response
     * @throws LoginException if SlingAuthenticator should handle the exception (eg.
     *         set the correct status in the response)
     *         SlingException will not be caught by SlingAuthenticator, in this case
     *         the method has to set the accurate status in the response
     * @throws SlingException may be thrown to convey any problem while handling the
     * 		   credentials
     */
    void postProcess(AuthenticationInfo info, HttpServletRequest request, HttpServletResponse response)
    	throws LoginException;

}
