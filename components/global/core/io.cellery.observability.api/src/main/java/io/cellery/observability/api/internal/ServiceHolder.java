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
package io.cellery.observability.api.internal;

import io.cellery.observability.api.siddhi.SiddhiStoreQueryManager;
import io.cellery.observability.model.generator.ModelManager;
import org.wso2.carbon.kernel.CarbonRuntime;
import org.wso2.msf4j.MicroservicesRunner;

/**
 * This is a static class which holds the references of the OSGI services registered.
 */
public class ServiceHolder {
    private static CarbonRuntime carbonRuntime;
    private static MicroservicesRunner microservicesRunner;
    private static ModelManager modelManager;
    private static SiddhiStoreQueryManager siddhiStoreQueryManager;
    private static String clientId;
    private static char[] clientSecret;

    public static String getClientId() {
        return clientId;
    }

    public static void setClientId(String clientId) {
        ServiceHolder.clientId = clientId;
    }

    public static String getClientSecret() {
        return String.valueOf(clientSecret);
    }

    public static void setClientSecret(String clientSecret) {
        ServiceHolder.clientSecret = clientSecret.toCharArray();
    }

    private ServiceHolder() {
    }

    public static CarbonRuntime getCarbonRuntime() {
        return carbonRuntime;
    }

    public static void setCarbonRuntime(CarbonRuntime carbonRuntime) {
        ServiceHolder.carbonRuntime = carbonRuntime;
    }

    public static MicroservicesRunner getMicroservicesRunner() {
        return microservicesRunner;
    }

    public static void setMicroservicesRunner(MicroservicesRunner microservicesRunner) {
        ServiceHolder.microservicesRunner = microservicesRunner;
    }

    public static ModelManager getModelManager() {
        return modelManager;
    }

    public static void setModelManager(ModelManager modelManager) {
        ServiceHolder.modelManager = modelManager;
    }

    public static SiddhiStoreQueryManager getSiddhiStoreQueryManager() {
        return siddhiStoreQueryManager;
    }

    public static void setSiddhiStoreQueryManager(SiddhiStoreQueryManager siddhiStoreQueryManager) {
        ServiceHolder.siddhiStoreQueryManager = siddhiStoreQueryManager;
    }
}
