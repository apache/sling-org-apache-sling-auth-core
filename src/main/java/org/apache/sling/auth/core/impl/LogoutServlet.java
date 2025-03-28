/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.auth.core.impl;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.auth.Authenticator;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.auth.core.AuthUtil;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.propertytypes.ServiceDescription;
import org.osgi.service.component.propertytypes.ServiceVendor;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The <code>LogoutServlet</code> lets the Authenticator
 * do the logout.
 */
@Component(
        service = Servlet.class,
        property = {"sling.servlet.paths=" + LogoutServlet.SERVLET_PATH})
@ServiceDescription("Authenticator Logout Servlet")
@ServiceVendor("The Apache Software Foundation")
@Designate(ocd = LogoutServlet.Config.class)
public class LogoutServlet extends SlingAllMethodsServlet {

    @ObjectClassDefinition(
            name = "Apache Sling Authentication Logout Servlet",
            description = "Servlet for logging out users through the authenticator service.")
    public @interface Config {

        @AttributeDefinition(name = "Method", description = "Supported Methods")
        String[] sling_servlet_methods() default {"GET", "POST"}; // NOSONAR
    }

    /** serialization UID */
    private static final long serialVersionUID = -1L;

    /** default log */
    private final transient Logger log = LoggerFactory.getLogger(getClass());

    @Reference(policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.OPTIONAL)
    private volatile Authenticator authenticator; // NOSONAR

    /**
     * The servlet is registered on this path.
     */
    public static final String SERVLET_PATH = "/system/sling/logout"; // NOSONAR

    @Override
    protected void service(SlingHttpServletRequest request, SlingHttpServletResponse response) {

        final Authenticator authenticatorRef = this.authenticator;
        if (authenticatorRef != null) {
            try {
                AuthUtil.setLoginResourceAttribute(request, null);
                authenticatorRef.logout(request, response);
                return;
            } catch (IllegalStateException ise) {
                log.error("service: Response already committed, cannot logout");
                return;
            }
        }

        log.error("service: Authenticator service missing, cannot logout");

        // well, we don't really have something to say here, do we ?
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }
}
