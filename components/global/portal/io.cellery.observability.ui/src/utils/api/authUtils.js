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

import Constants from "../constants";
import HttpUtils from "./httpUtils";
import {StateHolder} from "../../components/common/state";
import jwtDecode from "jwt-decode";

/**
 * Authentication/Authorization related utilities.
 */

const idpAddress = Constants.Dashboard.APIM_HOSTNAME;

class AuthUtils {

    /**
     * Sign in the user.
     *
     * @param {Object} user The user to be signed in
     * @param {StateHolder} globalState The global state provided to the current component
     */
    static signIn = (user, globalState) => {
        // TODO: Implement User Login
        if (user.username) {
            localStorage.setItem(StateHolder.USER, JSON.stringify(user));
            globalState.set(StateHolder.USER, user);
        } else {
            throw Error(`Username provided cannot be "${user.username}"`);
        }
    };

    /**
     * Redirects the user to IDP for authentication.
     *
     * @param {StateHolder} globalState The global state provided to the current component
     */
    static redirectToIDP(globalState) {
        HttpUtils.callObservabilityAPI(
            {
                url: "/user-auth/getCredentials/client",
                method: "GET"
            },
            globalState).then((resp) => {
            window.location.href = `https://${idpAddress}/oauth2/authorize?response_type=code`
                + `&client_id=${resp}&`
                + "redirect_uri=http://cellery-dashboard&nonce=abc&scope=openid";
        }).catch((err) => {
            localStorage.setItem("error2", err.toString());
        });
    }

    /**
     * Requests the API backend for tokens in exchange for authorization code.
     *
     * @param {number} oneTimeCode The one time Authorization code given by the IDP.
     * @param {StateHolder} globalState The global state provided to the current component
     */
    static getTokens(oneTimeCode, globalState) {
        HttpUtils.callObservabilityAPI(
            {
                url: `/user-auth/requestToken/${oneTimeCode}`,
                method: "GET"
            },
            globalState).then((resp) => {
            localStorage.setItem("idToken", resp.id_token);
            const decoded = jwtDecode(resp.id_token);
            localStorage.setItem("access_token", resp.access_token);
            const user1 = {
                username: decoded.sub,
                accessToken: resp.access_token,
                idToken: resp.id_token
            };

            AuthUtils.signIn(user1, globalState);
        }).catch((err) => {
            localStorage.setItem("error", err.toString());
        });
    }

    /**
     * Sign out the current user.
     * The provided global state will be updated accordingly as well.
     *
     * @param {StateHolder} globalState The global state provided to the current component
     */
    static signOut = (globalState) => {
        // TODO: Implement User Logout
        const idToken = globalState.get(StateHolder.USER).idToken;
        globalState.unset(StateHolder.USER);
        localStorage.removeItem(StateHolder.USER);

        window.location.href = `https://${idpAddress}/oidc/logout?id_token_hint=
            ${idToken}&post_logout_redirect_uri=http://cellery-dashboard`;
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
