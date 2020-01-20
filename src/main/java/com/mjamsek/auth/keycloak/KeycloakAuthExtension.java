package com.mjamsek.auth.keycloak;

import com.kumuluz.ee.common.Extension;
import com.kumuluz.ee.common.config.EeConfig;
import com.kumuluz.ee.common.dependencies.*;
import com.kumuluz.ee.common.wrapper.KumuluzServerWrapper;
import com.mjamsek.auth.keycloak.config.KeycloakInitializator;

import java.util.logging.Logger;

@EeExtensionDef(name = "keycloak-mj", group = EeExtensionGroup.SECURITY)
@EeComponentDependencies({
    @EeComponentDependency(EeComponentType.SERVLET),
    @EeComponentDependency(EeComponentType.CDI),
    @EeComponentDependency(EeComponentType.JAX_RS)
})
public class KeycloakAuthExtension implements Extension {
    
    private static final Logger log = Logger.getLogger(KeycloakAuthExtension.class.getName());
    
    @Override
    public void load() {
        log.info("Initializing security implemented by Keycloak.");
    }
    
    @Override
    public void init(KumuluzServerWrapper kumuluzServerWrapper, EeConfig eeConfig) {
        KeycloakInitializator.getInstance().initializeConfiguration();
        log.info("Initialized security implemented by Keycloak.");
    }
}
