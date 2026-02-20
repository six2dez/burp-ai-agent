package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.collaborator.CollaboratorClient
import java.util.concurrent.ConcurrentHashMap

object CollaboratorRegistry {
    private const val MAX_ENTRIES = 100
    private val clients = ConcurrentHashMap<String, CollaboratorClient>()
    private val insertionOrder = java.util.concurrent.ConcurrentLinkedDeque<String>()

    fun put(key: String, client: CollaboratorClient) {
        if (clients.putIfAbsent(key, client) == null) {
            insertionOrder.addLast(key)
            evictIfNeeded()
        } else {
            clients[key] = client
            insertionOrder.remove(key)
            insertionOrder.addLast(key)
        }
    }

    fun get(key: String): CollaboratorClient? = clients[key]

    fun remove(key: String) {
        clients.remove(key)
        insertionOrder.remove(key)
    }

    fun clear() {
        clients.clear()
        insertionOrder.clear()
    }

    private fun evictIfNeeded() {
        while (clients.size > MAX_ENTRIES) {
            val oldest = insertionOrder.pollFirst() ?: break
            clients.remove(oldest)
        }
    }
}
