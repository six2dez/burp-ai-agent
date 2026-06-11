package com.six2dez.burp.aiagent.util

// Local SOURCE-retained replacement for net.jcip.annotations.GuardedBy.
// JCIP (net.jcip) and jsr305 are deliberately NOT on the classpath (zero-new-deps,
// MIT/fat-JAR control). SOURCE retention keeps this annotation out of the compiled
// output entirely — zero runtime/class footprint, no split-package/JPMS risk.
// Target includes both FIELD and PROPERTY because a Kotlin `private val x = linkedMapOf(...)`
// is a property; both use-sites are needed for the annotation to be applied without a
// @field: use-site qualifier.
@Target(AnnotationTarget.FIELD, AnnotationTarget.PROPERTY)
@Retention(AnnotationRetention.SOURCE)
annotation class GuardedBy(
    val lock: String,
)
