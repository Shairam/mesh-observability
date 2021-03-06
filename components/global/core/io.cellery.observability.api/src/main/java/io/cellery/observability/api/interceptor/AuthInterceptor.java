/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.cellery.observability.api.interceptor;

import io.cellery.observability.api.Constants;
import io.cellery.observability.api.exception.oidc.OIDCProviderException;
import io.cellery.observability.api.internal.ServiceHolder;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.wso2.msf4j.Request;
import org.wso2.msf4j.Response;
import org.wso2.msf4j.interceptor.RequestInterceptor;

import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;

/**
 * This class is used for securing backend APIs with Access Token.
 */
public class AuthInterceptor implements RequestInterceptor {

    private static final Logger log = Logger.getLogger(AuthInterceptor.class);

    @Override
    public boolean interceptRequest(Request request, Response response) {

        if (!request.getHttpMethod().equalsIgnoreCase(HttpMethod.OPTIONS) &&
                request.getHeader(HttpHeaders.AUTHORIZATION) != null) {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            Cookie oAuthCookie = request.getHeaders().getCookies().get(Constants.HTTP_ONLY_SESSION_COOKIE);
            if (StringUtils.isNotEmpty(header) && oAuthCookie != null
                    && StringUtils.isNotEmpty(oAuthCookie.getValue())) {
                String accessToken = header.split(" ")[1] + oAuthCookie.getValue();

                try {
                    if (!ServiceHolder.getOidcOauthManager().validateToken(accessToken)) {
                        response.setStatus(401);
                        return false;
                    }
                } catch (OIDCProviderException e) {
                    log.debug("Error occurred while authenticating the access token", e);
                    response.setStatus(401);
                    return false;
                }
            } else {
                response.setStatus(401);
                return false;
            }
        }
        return true;
    }
}
