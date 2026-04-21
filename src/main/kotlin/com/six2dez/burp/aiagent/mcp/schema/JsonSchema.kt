package com.six2dez.burp.aiagent.mcp.schema

import io.modelcontextprotocol.kotlin.sdk.Tool
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.reflect.KClass
import kotlin.reflect.full.memberProperties

fun getJsonSchemaForProperty(kType: kotlin.reflect.KType): JsonElement =
    when (kType.classifier) {
        String::class ->
            JsonObject(mapOf("type" to JsonPrimitive("string")))

        Int::class, Long::class ->
            JsonObject(mapOf("type" to JsonPrimitive("integer")))

        Float::class, Double::class ->
            JsonObject(mapOf("type" to JsonPrimitive("number")))

        Boolean::class ->
            JsonObject(mapOf("type" to JsonPrimitive("boolean")))

        List::class, Array::class -> {
            val argType = kType.arguments.firstOrNull()?.type
            val itemsSchema =
                when {
                    argType != null -> getJsonSchemaForProperty(argType)
                    else -> JsonObject(mapOf("type" to JsonPrimitive("object")))
                }
            JsonObject(mapOf("type" to JsonPrimitive("array"), "items" to itemsSchema))
        }

        Map::class -> {
            val valueType = kType.arguments.getOrNull(1)?.type
            val valueSchema =
                when {
                    valueType != null -> getJsonSchemaForProperty(valueType)
                    else -> JsonObject(mapOf("type" to JsonPrimitive("object")))
                }
            JsonObject(mapOf("type" to JsonPrimitive("object"), "additionalProperties" to valueSchema))
        }

        else ->
            JsonObject(mapOf("type" to JsonPrimitive("object")))
    }

fun KClass<*>.asInputSchema(): Tool.Input {
    val properties = mutableMapOf<String, JsonElement>()
    val required = mutableListOf<String>()

    for (prop in memberProperties) {
        properties[prop.name] = getJsonSchemaForProperty(prop.returnType)
        if (!prop.returnType.isMarkedNullable) {
            required.add(prop.name)
        }
    }

    return Tool.Input(
        properties = JsonObject(properties),
        required = required,
    )
}
