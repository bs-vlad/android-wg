package com.wireguard.config

import com.wireguard.util.NonNullForAll

@NonNullForAll
class Attribute private constructor(val key: String, val value: String) {
    companion object {
        private val LINE_PATTERN = "(\\w+)\\s*=\\s*([^\\s#][^#]*)".toRegex()
        private const val LIST_SEPARATOR = "\\s*,\\s*"

        fun join(values: Iterable<*>): String = values.joinToString(", ") { it.toString() }

        fun parse(line: CharSequence): Attribute? =
            LINE_PATTERN.matchEntire(line)?.let { matchResult ->
                Attribute(matchResult.groupValues[1], matchResult.groupValues[2])
            }

        fun split(value: CharSequence): Array<String> = value.split(LIST_SEPARATOR.toRegex()).toTypedArray()
    }
}
