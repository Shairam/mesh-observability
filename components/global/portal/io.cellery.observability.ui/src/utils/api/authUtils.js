/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import axios from "axios";
import jwtDecode from "jwt-decode";
import {StateHolder} from "../../components/common/state";
import Constants from "../constants";

/**
 * Authentication/Authorization related utilities.
 */
const idpAddress = Constants.Dashboard.APIM_HOSTNAME;

class AuthUtils {

    /**
     * Sign in the user.
     *
     * @param {string} username The user to be signed in
     * @param {StateHolder} globalState The global state provided to the current component
     */
    static signIn = (username, globalState) => {
        // TODO: Implement User Login
        if (username) {
            const user = {
                username: username
            };
            localStorage.setItem(StateHolder.USER, JSON.stringify(user));
            globalState.set(StateHolder.USER, user);
        } else {
            throw Error(`Username provided cannot be "${username}"`);
        }
    };

    static redirectLoginIDP = () => {
        window.location.href = `https://${idpAddress}/oauth2/authorize?response_type=code`
            + "&client_id=H87NsL_4MG_FVsx8hzRmfEeCxFQa&"
            + "redirect_uri=http://localhost:3000&nonce=abc&scope=openid";
    };

    static getTokens = (oneTimeToken, globalState) => {
        axios.post(`https://${idpAddress}/oauth2/token?grant_type=authorization_code&code=${
            oneTimeToken}&redirect_uri=http://localhost:3000`, null, {
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Authorization:
                    "Basic SDg3TnNMXzRNR19GVnN4OGh6Um1mRWVDeEZRYTpzSm5oVUNLSGdmV2o2SXFmbTRyY1F3eWtEa2dh"
            }
        }).then((response) => {
            localStorage.setItem("idToken", response.data.id_token);
            const decoded = jwtDecode(response.data.id_token);
            localStorage.setItem("access_token", response.data.access_token);
            const user1 = {
                username: decoded.sub
            };
            AuthUtils.signIn(user1.username, globalState);
        });
    };

    /**
     * Sign out the current user.
     * The provided global state will be updated accordingly as well.
     *
     * @param {StateHolder} globalState The global state provided to the current component
     */
    static signOut = (globalState) => {
        // TODO: Implement User Logout
        globalState.unset(StateHolder.USER);
        localStorage.removeItem(StateHolder.USER);
        window.location.href = `https://${idpAddress}/oidc/logout?id_token_hint=
            ${localStorage.getItem("idToken")}&post_logout_redirect_uri=http://localhost:3000`;
    };

    /**
     * Get the currently authenticated user.
     *
     * @returns {string} The current user
     */

    static getAuthenticatedUser = () => {
        let user;
        try {
            user = JSON.parse(localStorage.getItem(StateHolder.USER));
        } catch {
            user = null;
            localStorage.removeItem(StateHolder.USER);
        }
        return user;
    };

}

export default AuthUtils;
