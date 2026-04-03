package com.six2dez.burp.aiagent

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.EnhancedCapability

class BurpAiAgentExtension : BurpExtension {
    override fun enhancedCapabilities(): Set<EnhancedCapability> =
        setOf(EnhancedCapability.AI_FEATURES)

    override fun initialize(api: MontoyaApi) {
        App.initialize(api)
        api.extension().registerUnloadingHandler {
            App.shutdown()
        }
    }
}
