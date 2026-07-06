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
package org.apache.sling.auth.core.spi;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.sling.api.auth.Authenticator;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class AbstractJakartaAuthenticationFormServletTest {

    private static class TestFormServlet extends AbstractJakartaAuthenticationFormServlet {
        private final String reason;

        TestFormServlet(String reason) {
            this.reason = reason;
        }

        @Override
        protected String getReason(HttpServletRequest request) {
            return reason;
        }

        @Override
        protected String getDefaultFormPath() {
            return "test-login-form.html";
        }

        @Override
        protected String getCustomFormPath() {
            return "does-not-exist.html";
        }
    }

    private HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    private HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    @Test
    public void test_doGet_rendersForm() throws Exception {
        TestFormServlet servlet = new TestFormServlet("Reason!");
        Mockito.when(request.getContextPath()).thenReturn("");
        StringWriter sw = new StringWriter();
        Mockito.when(response.getWriter()).thenReturn(new PrintWriter(sw));

        servlet.doGet(request, response);

        String out = sw.toString();
        Assert.assertTrue(out.contains("reason=[Reason!]"));
        Mockito.verify(response).setContentType("text/html");
        Mockito.verify(response).flushBuffer();
    }

    @Test
    public void test_doPost_rendersForm() throws Exception {
        TestFormServlet servlet = new TestFormServlet("");
        Mockito.when(request.getContextPath()).thenReturn("");
        StringWriter sw = new StringWriter();
        Mockito.when(response.getWriter()).thenReturn(new PrintWriter(sw));

        servlet.doPost(request, response);
        Assert.assertTrue(sw.toString().contains("<html>"));
    }

    @Test
    public void test_getForm_substitutes_and_escapes() throws Exception {
        TestFormServlet servlet = new TestFormServlet("<b>&\"'");
        Mockito.when(request.getContextPath()).thenReturn("");
        Mockito.when(request.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/valid/path");

        String form = servlet.getForm(request);
        Assert.assertTrue(form.contains("resource=[/valid/path]"));
        // reason escaped
        Assert.assertTrue(form.contains("&lt;b&gt;&amp;%22%27"));
    }

    @Test
    public void test_getForm_invalid_resource_cleansed() throws Exception {
        TestFormServlet servlet = new TestFormServlet("");
        Mockito.when(request.getContextPath()).thenReturn("");
        // an invalid (non-normalized) redirect target must be cleansed to empty
        Mockito.when(request.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/invalid//path");

        String form = servlet.getForm(request);
        Assert.assertTrue(form.contains("resource=[]"));
    }

    @Test
    public void test_getResource_default_empty() {
        TestFormServlet servlet = new TestFormServlet("");
        Assert.assertEquals("", servlet.getResource(request));
    }

    @Test
    public void test_getContextPath_from_resource() {
        TestFormServlet servlet = new TestFormServlet("");
        Mockito.when(request.getParameter(Authenticator.LOGIN_RESOURCE)).thenReturn("/foo/bar/?x=1");
        Assert.assertEquals("/foo/bar", servlet.getContextPath(request));
    }

    @Test
    public void test_getContextPath_fallback_to_servlet_context() {
        TestFormServlet servlet = new TestFormServlet("");
        Mockito.when(request.getContextPath()).thenReturn("/ctx");
        Assert.assertEquals("/ctx", servlet.getContextPath(request));
    }

    @Test
    public void test_handle_ioexception_sends_error() throws Exception {
        TestFormServlet servlet = new TestFormServlet("");
        jakarta.servlet.ServletConfig config = Mockito.mock(jakarta.servlet.ServletConfig.class);
        Mockito.when(config.getServletContext()).thenReturn(Mockito.mock(jakarta.servlet.ServletContext.class));
        servlet.init(config);
        Mockito.when(request.getContextPath()).thenReturn("");
        Mockito.when(response.getWriter()).thenThrow(new IOException("no writer"));

        servlet.doGet(request, response);
        Mockito.verify(response).sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }

    @Test
    public void test_default_paths() {
        AbstractJakartaAuthenticationFormServlet servlet = new AbstractJakartaAuthenticationFormServlet() {
            @Override
            protected String getReason(HttpServletRequest request) {
                return "";
            }
        };
        Assert.assertEquals("login.html", servlet.getDefaultFormPath());
        Assert.assertEquals("custom_login.html", servlet.getCustomFormPath());
    }
}
