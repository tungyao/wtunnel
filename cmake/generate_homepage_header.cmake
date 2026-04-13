# CMake script to generate homepage_html.h from code.html

if(NOT EXISTS "${INPUT_FILE}")
    message(FATAL_ERROR "Input file not found: ${INPUT_FILE}")
endif()

file(READ "${INPUT_FILE}" HTML_CONTENT)

# Escape quotes and backslashes for C++ string literal
string(REPLACE "\\" "\\\\" HTML_CONTENT "${HTML_CONTENT}")
string(REPLACE "\"" "\\\"" HTML_CONTENT "${HTML_CONTENT}")
string(REPLACE "\n" "\\n\"\n\"" HTML_CONTENT "${HTML_CONTENT}")

# Generate header content
set(HEADER_CONTENT "// Auto-generated homepage HTML
#pragma once

namespace homepage {

const char* const HTML = \"${HTML_CONTENT}\";

inline std::string build_http_response() {
    std::string html = HTML;
    return \"HTTP/1.1 200 OK\\r\\n\"
           \"Content-Type: text/html; charset=utf-8\\r\\n\"
           \"Connection: close\\r\\n\"
           \"Content-Length: \" + std::to_string(html.size()) + \"\\r\\n\\r\\n\" + html;
}

}
")

file(WRITE "${OUTPUT_FILE}" "${HEADER_CONTENT}")
message(STATUS "Generated: ${OUTPUT_FILE}")
